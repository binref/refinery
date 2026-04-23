"""
PowerShell constant folding transforms.
"""
from __future__ import annotations

import base64
import codecs
import re

from collections.abc import Iterator

from refinery.lib.scripts.ps1.deobfuscation.constants import PS1_ENV_CONSTANTS
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    LocalFunctionAwareTransformer,
    StringMethodError,
    apply_string_method,
    collect_byte_array,
    collect_format_arguments,
    collect_int_arguments,
    collect_string_arguments,
    detect_encoding_chain,
    extract_foreach_scriptblock,
    get_body,
    get_member_name,
    is_array_reverse_call,
    is_static_type_call,
    is_truthy,
    make_string_literal,
    string_value,
    unwrap_integer,
    unwrap_parens,
    unwrap_single_paren,
    unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.deobfuscation.names import (
    COMPARISON_OPS,
    ENCODING_MAP,
    apply_format_string,
)
from refinery.lib.scripts.ps1.deobfuscation.typenames import (
    is_known_member,
    resolve_member_type,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HashLiteral,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1RangeExpression,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1UnaryExpression,
    Ps1Variable,
)

_REGEX_OPTION_FLAGS: dict[str, int] = {
    'ignorecase'              : re.IGNORECASE,
    'multiline'               : re.MULTILINE,
    'singleline'              : re.DOTALL,
    'ignorepatternwhitespace' : re.VERBOSE,
    'none'                    : 0,
}

_REGEX_OPTION_INT: dict[int, int] = {
    1  : re.IGNORECASE,
    2  : re.MULTILINE,
    16 : re.DOTALL,
    32 : re.VERBOSE,
}

_RIGHT_TO_LEFT = 64
_MAX_STRING_EXPAND = 0x1000
_MAX_RANGES_EXPAND = 15


def _is_static_regex_call(node: Ps1InvokeMember) -> bool:
    return is_static_type_call(node, 'system.text.regularexpressions.regex')


def _parse_regex_options(node: Expression) -> tuple[int, bool] | None:
    """
    Parse a RegexOptions argument (string or integer) into Python re flags
    and a right_to_left boolean.
    """
    sv = string_value(node)
    if sv is not None:
        flags = 0
        right_to_left = False
        for part in sv.split(','):
            key = part.strip().lower()
            if not key:
                continue
            if key == 'righttoleft':
                right_to_left = True
                continue
            flag = _REGEX_OPTION_FLAGS.get(key)
            if flag is None:
                return None
            flags |= flag
        return flags, right_to_left
    if isinstance(node, Ps1IntegerLiteral):
        value = node.value
        right_to_left = bool(value & _RIGHT_TO_LEFT)
        flags = 0
        for bit, flag in _REGEX_OPTION_INT.items():
            if value & bit:
                flags |= flag
        return flags, right_to_left
    return None


def _iter_regex_matches(node: Ps1InvokeMember) -> Iterator[str] | None:
    """
    Yield matched strings from a call to

        [Regex]::Match/Matches(input, pattern[, options])

    Returns `None` if the arguments cannot be resolved.
    """
    if len(node.arguments) not in (2, 3):
        return None
    input = string_value(node.arguments[0])
    pattern = string_value(node.arguments[1])
    if input is None or pattern is None:
        return None
    if len(node.arguments) == 3:
        if (options := _parse_regex_options(node.arguments[2])) is None:
            return None
        flags, right_to_left = options
    else:
        flags, right_to_left = 0, False
    direction = (
        lambda m: m,
        lambda m: m[::-1],
    )[right_to_left]
    try:
        return (direction(m[0]) for m in re.finditer(pattern, direction(input), flags))
    except re.error:
        return None


def _compute_regex_matches(node: Ps1InvokeMember) -> list[str] | None:
    if it := _iter_regex_matches(node):
        return list(it)


def _compute_regex_match(node: Ps1InvokeMember) -> str | None:
    if it := _iter_regex_matches(node):
        return next(it, '')


_INTEGER_RESULT_TYPES = frozenset({
    'system.int16',
    'system.int32',
    'system.int64',
    'system.uint16',
    'system.uint32',
    'system.uint64',
    'system.byte',
    'system.sbyte',
})


def _foreach_extracts_value(sb: Ps1ScriptBlock) -> bool:
    """
    Check whether a ForEach scriptblock body is of the form `$_.Value`,
    `$_.Groups.Value`, or `$_.Groups.Captures.Groups.Value` — i.e. it
    extracts the string value from Match objects.
    """
    if sb.body is None or len(sb.body) != 1:
        return False
    stmt = sb.body[0]
    if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
        return False
    node = stmt.expression
    if not isinstance(node, Ps1Pipeline):
        expr = node
    elif len(node.elements) == 1 and node.elements[0].expression is not None:
        expr = node.elements[0].expression
    else:
        return False
    if not isinstance(expr, Ps1MemberAccess):
        return False
    member = expr.member if isinstance(expr.member, str) else None
    if member is None or member.lower() != 'value':
        return False
    inner = expr.object
    while isinstance(inner, Ps1MemberAccess):
        prop = inner.member if isinstance(inner.member, str) else None
        if prop is None or prop.lower() not in ('groups', 'captures'):
            return False
        inner = inner.object
    return isinstance(inner, Ps1Variable) and inner.name == '_'


def _escape_for_expandable(text: str) -> str:
    """
    Escape characters that are special inside double-quoted strings.
    """
    return text.replace('`', '``').replace('$', '`$')


def _variable_raw(var: Ps1Variable) -> str:
    """
    Produce the braced variable reference for use inside an expandable string.
    """
    prefix = '@' if var.splatted else '$'
    scope = var.scope.value
    if scope:
        return F'{prefix}{{{scope}:{var.name}}}'
    return F'{prefix}{{{var.name}}}'


def _variable_string_to_expandable(
    var: Ps1Variable,
    text: str,
    *,
    var_first: bool,
) -> Ps1ExpandableString:
    """
    Fold `$var + 'text'` or `'text' + $var` into a
    `refinery.lib.scripts.ps1.model.Ps1ExpandableString`.
    """
    escaped = _escape_for_expandable(text)
    var_raw = _variable_raw(var)
    text_part = Ps1StringLiteral(value=text, raw=F"'{text}'")
    if var_first:
        raw = F'"{var_raw}{escaped}"'
        parts = [var, text_part]
    else:
        raw = F'"{escaped}{var_raw}"'
        parts = [text_part, var]
    return Ps1ExpandableString(parts=parts, raw=raw)


def _resolve_index_values(index: Expression) -> int | list[int] | None:
    n = unwrap_integer(index)
    if n is not None:
        return n.value
    array = unwrap_to_array_literal(index)
    if array is not None:
        result: list[int] = []
        for elem in array.elements:
            n = unwrap_integer(elem)
            if n is None:
                return None
            result.append(n.value)
        return result
    return None


def _index_into_string(s: str, indices: int | list[int]) -> Expression | None:
    n = len(s)
    if isinstance(indices, int):
        if -n <= indices < n:
            return make_string_literal(s[indices])
        return None
    selected: list[Expression] = []
    for i in indices:
        if not (-n <= i < n):
            return None
        selected.append(make_string_literal(s[i]))
    return Ps1ArrayLiteral(elements=selected)


def _index_into_array(
    array: Ps1ArrayLiteral, indices: int | list[int],
) -> Expression | None:
    n = len(array.elements)
    if isinstance(indices, int):
        if -n <= indices < n:
            return array.elements[indices]
        return None
    selected: list[Expression] = []
    for i in indices:
        if not (-n <= i < n):
            return None
        selected.append(array.elements[i])
    return Ps1ArrayLiteral(elements=selected)


def _lookup_hashtable(ht: Ps1HashLiteral, index: Expression) -> Expression | None:
    key = string_value(index)
    if key is None:
        return None
    lower = key.lower()
    for pair_key, pair_value in ht.pairs:
        k = string_value(pair_key)
        if k is not None and k.lower() == lower:
            return pair_value
    return None


class Ps1ConstantFolding(LocalFunctionAwareTransformer):

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        return None

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        if len(node.elements) == 2:
            result = self._try_fold_regex_pipeline(node)
            if result is not None:
                return result
        self.generic_visit(node)
        return None

    @staticmethod
    def _fold_regex_call_result(
        invoke: Ps1InvokeMember, member_lower: str,
    ) -> Expression | None:
        if member_lower == 'matches':
            matches = _compute_regex_matches(invoke)
            if matches is not None:
                elements: list[Expression] = [make_string_literal(s) for s in matches]
                return Ps1ArrayLiteral(elements=elements)
        elif member_lower == 'match':
            result = _compute_regex_match(invoke)
            if result is not None:
                return make_string_literal(result)
        return None

    def _try_fold_regex_pipeline(self, node: Ps1Pipeline) -> Expression | None:
        first = node.elements[0].expression
        second_expr = node.elements[1].expression
        if not isinstance(first, Ps1InvokeMember) or not _is_static_regex_call(first):
            return None
        member = get_member_name(first.member)
        if member is None:
            return None
        sb = extract_foreach_scriptblock(second_expr) if second_expr else None
        if sb is None or not _foreach_extracts_value(sb):
            return None
        return self._fold_regex_call_result(first, member.lower())

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        member = get_member_name(node.member)
        if member is None:
            return None
        obj = node.object
        if obj is None:
            return None
        member_type = resolve_member_type(obj, member)
        if member_type in _INTEGER_RESULT_TYPES:
            s = string_value(obj)
            if s is not None:
                return Ps1IntegerLiteral(value=len(s), raw=str(len(s)))
            array = unwrap_to_array_literal(obj)
            if array is not None:
                return Ps1IntegerLiteral(
                    value=len(array.elements), raw=str(len(array.elements)))
        if (
            string_value(obj) is not None
            or isinstance(obj, Ps1IntegerLiteral)
        ):
            if not is_known_member(obj, member):
                return Ps1Variable(name='Null')
        result = self._try_fold_regex_member_access(node, member)
        if result is not None:
            return result
        return None

    def _try_fold_regex_member_access(
        self, node: Ps1MemberAccess, member: str,
    ) -> Expression | None:
        chain: list[str] = [member]
        inner = node.object
        while isinstance(inner, Ps1MemberAccess):
            prop = get_member_name(inner.member)
            if prop is None:
                return None
            chain.append(prop)
            inner = inner.object
        chain.reverse()
        if not isinstance(inner, Ps1InvokeMember) or not _is_static_regex_call(inner):
            return None
        normalized = [c.lower() for c in chain]
        if normalized[-1] != 'value':
            return None
        for c in normalized[:-1]:
            if c not in ('groups', 'captures'):
                return None
        call_member = inner.member if isinstance(inner.member, str) else None
        if call_member is None:
            return None
        return self._fold_regex_call_result(inner, call_member.lower())

    @staticmethod
    def _try_join_regex_matches(operand: Expression) -> Expression | None:
        unwrapped = unwrap_parens(operand)
        if not isinstance(unwrapped, Ps1InvokeMember) or not _is_static_regex_call(unwrapped):
            return None
        member = unwrapped.member if isinstance(unwrapped.member, str) else None
        if member is None or member.lower() != 'matches':
            return None
        matches = _compute_regex_matches(unwrapped)
        if matches is None:
            return None
        return make_string_literal(''.join(matches))

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        if node.operand is None:
            return None
        op = node.operator.lower()
        if op == '-join':
            return self._handle_unary_join(node)
        if op == '-bnot':
            n = unwrap_integer(node.operand)
            if n is not None:
                return Ps1IntegerLiteral(value=~n.value, raw=str(~n.value))
        if op in ('-not', '!'):
            truth = is_truthy(node.operand)
            if truth is not None:
                return Ps1Variable(name='False' if truth else 'True')
        return None

    def _handle_unary_join(self, node: Ps1UnaryExpression) -> Expression | None:
        operand = node.operand
        if operand is None:
            return None
        scalar = string_value(operand)
        if scalar is not None:
            return make_string_literal(scalar)
        result = self._try_join_regex_matches(operand)
        if result is not None:
            return result
        array = unwrap_to_array_literal(operand)
        if array is None:
            if isinstance(operand, Ps1ArrayExpression) and len(operand.body) == 1:
                stmt = operand.body[0]
                if isinstance(stmt, Ps1ExpressionStatement):
                    sv = string_value(stmt.expression) if stmt.expression else None
                    if sv is not None:
                        return make_string_literal(sv)
            return None
        args = collect_string_arguments(array)
        if args is None:
            return None
        return make_string_literal(''.join(args))

    def visit_Ps1RangeExpression(self, node: Ps1RangeExpression):
        self.generic_visit(node)
        if isinstance(node.parent, Ps1RangeExpression):
            return None
        lower = unwrap_integer(node.start)
        upper = unwrap_integer(node.end)
        if lower is None or upper is None:
            return None
        step = 1 if (b := upper.value) >= (a := lower.value) else -1
        count = abs(b - a) + 1
        if count > _MAX_RANGES_EXPAND:
            return None
        return Ps1ArrayLiteral(elements=[
            Ps1IntegerLiteral(value=v, raw=str(v)) for v in range(a, b + step, step)])

    def visit_Ps1IndexExpression(self, node: Ps1IndexExpression):
        self.generic_visit(node)
        if node.index is None or node.object is None:
            return None
        if isinstance(node.object, Ps1HashLiteral):
            return _lookup_hashtable(node.object, node.index)
        indices = _resolve_index_values(node.index)
        if indices is None:
            return None
        obj_str = string_value(node.object)
        if obj_str is not None:
            return _index_into_string(obj_str, indices)
        array = unwrap_to_array_literal(node.object)
        if array is not None:
            return _index_into_array(array, indices)
        return None

    def visit_Ps1ExpressionStatement(self, node: Ps1ExpressionStatement):
        self.generic_visit(node)
        var = is_array_reverse_call(node)
        if var is not None and self._try_apply_array_reverse(node, var):
            return node
        return None

    def _try_apply_array_reverse(
        self, node: Ps1ExpressionStatement, var: Ps1Variable,
    ) -> bool:
        body = get_body(node.parent)
        if body is None:
            return False
        try:
            idx = body.index(node)
        except ValueError:
            return False
        var_name = var.name.lower()
        for i in range(idx - 1, -1, -1):
            stmt = body[i]
            if not isinstance(stmt, Ps1ExpressionStatement):
                continue
            expr = stmt.expression
            if not isinstance(expr, Ps1AssignmentExpression):
                continue
            if expr.operator != '=':
                continue
            target = expr.target
            if not isinstance(target, Ps1Variable):
                continue
            if target.name.lower() != var_name:
                continue
            value = expr.value
            if isinstance(value, Ps1ArrayLiteral):
                value.elements.reverse()
                node.expression = None
                self.mark_changed()
                return True
            if isinstance(value, Ps1ArrayExpression) and len(value.body) == 1:
                inner = value.body[0]
                if (
                    isinstance(inner, Ps1ExpressionStatement)
                    and isinstance(inner.expression, Ps1ArrayLiteral)
                ):
                    inner.expression.elements.reverse()
                    node.expression = None
                    self.mark_changed()
                    return True
            sv = string_value(value)
            if sv is not None:
                replacement = make_string_literal(sv[::-1])
                replacement.parent = expr
                expr.value = replacement
                node.expression = None
                self.mark_changed()
                return True
            return False
        return False

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        member_name = get_member_name(node.member)
        if member_name is None:
            return None
        lower = member_name.lower()
        return (
            self._try_fold_invoke_redirect(node, lower)
            or self._try_fold_instance_method(node, lower)
            or self._try_fold_static_method(node, lower)
        ) or None

    @staticmethod
    def _try_fold_invoke_redirect(
        node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if lower == 'invoke' and isinstance(node.object, Ps1MemberAccess):
            return Ps1InvokeMember(
                offset=node.offset,
                object=node.object.object,
                member=node.object.member,
                arguments=node.arguments,
                access=node.object.access,
            )
        return None

    @staticmethod
    def _try_fold_instance_method(
        node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        obj_str = string_value(node.object) if node.object else None
        if obj_str is None:
            return None
        coerced: list[str | int] = []
        for arg in node.arguments:
            sv = string_value(arg)
            if sv is not None:
                coerced.append(sv)
                continue
            if isinstance(arg, Ps1IntegerLiteral):
                coerced.append(arg.value)
                continue
            return None
        try:
            result = apply_string_method(obj_str, lower, coerced)
        except StringMethodError:
            return None
        if isinstance(result, str):
            return make_string_literal(result)
        if isinstance(result, bool):
            return Ps1Variable(name='True' if result else 'False')
        if isinstance(result, int):
            return Ps1IntegerLiteral(value=result, raw=str(result))
        if isinstance(result, list):
            elements: list[Expression] = [make_string_literal(p) for p in result]
            return Ps1ArrayLiteral(elements=elements)
        return None

    def _try_fold_static_method(
        self, node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if is_static_type_call(node, 'system.convert'):
            return self._try_fold_convert(node, lower)
        encoding_name = detect_encoding_chain(node)
        if encoding_name is not None:
            if len(node.arguments) == 1:
                arg = unwrap_single_paren(node.arguments[0])
                if isinstance(arg, Ps1ArrayExpression) and len(arg.body) == 1:
                    stmt = arg.body[0]
                    if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression:
                        arg = stmt.expression
                int_values = collect_int_arguments(arg)
                if int_values is not None:
                    try:
                        raw_bytes = bytearray(int_values)
                    except (ValueError, OverflowError):
                        return None
                    encoding = ENCODING_MAP.get(
                        encoding_name.lower(), encoding_name)
                    try:
                        codecs.lookup(encoding)
                    except LookupError:
                        encoding = 'utf-8'
                    try:
                        decoded_str = raw_bytes.decode(encoding)
                    except Exception:
                        return None
                    return make_string_literal(decoded_str)
        if is_static_type_call(node, 'system.string'):
            if lower == 'concat' and len(node.arguments) >= 1:
                parts: list[str] = []
                for arg in node.arguments:
                    if (sv := string_value(arg)) is None:
                        break
                    parts.append(sv)
                else:
                    return make_string_literal(''.join(parts))
            if lower == 'join' and len(node.arguments) >= 2:
                separator = string_value(node.arguments[0])
                if separator is not None:
                    joined: list[str] = []
                    for arg in node.arguments[1:]:
                        if (sv := string_value(arg)) is None:
                            break
                        joined.append(sv)
                    else:
                        return make_string_literal(separator.join(joined))
                    if len(node.arguments) == 2:
                        array = unwrap_to_array_literal(node.arguments[1])
                        if array is not None:
                            args = collect_string_arguments(array)
                            if args is not None:
                                return make_string_literal(separator.join(args))
        if _is_static_regex_call(node) and lower == 'replace':
            return self._handle_regex_replace(node)
        if is_static_type_call(node, 'system.bitconverter') and lower == 'tostring':
            return self._try_fold_bitconverter_tostring(node)
        if (
            is_static_type_call(node, 'system.environment')
            and lower == 'getenvironmentvariable'
            and len(na := node.arguments) == 1
            and (_en := string_value(na[0])) is not None
            and (_ev := PS1_ENV_CONSTANTS.get(_en.lower())) is not None
        ):
            return make_string_literal(_ev)
        return None

    _CONVERT_INT_METHODS = {
        'tobyte'  : (0, 0xFF),
        'toint16' : (-0x8000, 0x7FFF),
        'toint32' : (-0x80000000, 0x7FFFFFFF),
        'toint64' : (-0x8000000000000000, 0x7FFFFFFFFFFFFFFF),
        'tosbyte' : (-0x80, 0x7F),
        'touint16': (0, 0xFFFF),
        'touint32': (0, 0xFFFFFFFF),
        'touint64': (0, 0xFFFFFFFFFFFFFFFF),
    }

    def _try_fold_convert(
        self, node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if lower == 'frombase64string' and len(node.arguments) == 1:
            b64_str = string_value(node.arguments[0])
            if b64_str is not None:
                try:
                    decoded = base64.b64decode(b64_str)
                except Exception:
                    return None
                elements: list[Expression] = [
                    Ps1IntegerLiteral(value=b, raw=F'0x{b:02X}') for b in decoded
                ]
                array = Ps1ArrayLiteral(elements=elements)
                return Ps1ArrayExpression(
                    body=[Ps1ExpressionStatement(expression=array)])
        bounds = self._CONVERT_INT_METHODS.get(lower)
        if bounds is not None:
            return self._fold_convert_int(node, bounds)
        if lower == 'tochar':
            n = unwrap_integer(node.arguments[0]) if len(node.arguments) == 1 else None
            if n is not None:
                try:
                    return make_string_literal(chr(n.value))
                except (ValueError, OverflowError):
                    pass
        return None

    def _fold_convert_int(
        self, node: Ps1InvokeMember, bounds: tuple[int, int],
    ) -> Expression | None:
        lo, hi = bounds
        if len(node.arguments) == 1:
            n = unwrap_integer(node.arguments[0])
            if n is not None and lo <= n.value <= hi:
                return Ps1IntegerLiteral(value=n.value, raw=str(n.value))
            sv = string_value(node.arguments[0])
            if sv is not None:
                sv = sv.strip()
                try:
                    value = int(sv, 0)
                except (ValueError, OverflowError):
                    return None
                if lo <= value <= hi:
                    return Ps1IntegerLiteral(value=value, raw=str(value))
        elif len(node.arguments) == 2:
            sv = string_value(node.arguments[0])
            base_int = unwrap_integer(node.arguments[1])
            if sv is not None and base_int is not None and base_int.value in (2, 8, 10, 16):
                try:
                    value = int(sv, base_int.value)
                except (ValueError, OverflowError):
                    return None
                if lo <= value <= hi:
                    return Ps1IntegerLiteral(value=value, raw=str(value))
        return None

    @staticmethod
    def _try_fold_bitconverter_tostring(node: Ps1InvokeMember) -> Expression | None:
        if not node.arguments:
            return None
        data = collect_byte_array(node.arguments[0])
        if data is None:
            return None
        offset = 0
        length = len(data)
        if len(node.arguments) >= 2:
            n = unwrap_integer(node.arguments[1])
            if n is None:
                return None
            offset = n.value
        if len(node.arguments) >= 3:
            n = unwrap_integer(node.arguments[2])
            if n is None:
                return None
            length = n.value
        if offset < 0 or length < 0 or offset + length > len(data):
            return None
        segment = data[offset:offset + length]
        return make_string_literal('-'.join(F'{b:02X}' for b in segment))

    def _handle_regex_replace(self, node: Ps1InvokeMember) -> Expression | None:
        if len(node.arguments) not in (3, 4):
            return None
        input_str = string_value(node.arguments[0])
        pattern_str = string_value(node.arguments[1])
        replacement_str = string_value(node.arguments[2])
        if input_str is None or pattern_str is None or replacement_str is None:
            return None
        flags = 0
        right_to_left = False
        if len(node.arguments) == 4:
            opts = _parse_regex_options(node.arguments[3])
            if opts is None:
                return None
            flags, right_to_left = opts
        try:
            if right_to_left:
                result = re.sub(
                    pattern_str, lambda _: replacement_str, input_str[::-1], flags=flags)
                result = result[::-1]
            else:
                result = re.sub(
                    pattern_str, lambda _: replacement_str, input_str, flags=flags)
        except re.error:
            return None
        return make_string_literal(result)

    _ARITHMETIC_OPS = {
        '+'     : int.__add__,
        '-'     : int.__sub__,
        '*'     : int.__mul__,
        '/'     : int.__floordiv__,
        '%'     : int.__mod__,
        '-band' : int.__and__,
        '-bor'  : int.__or__,
        '-bxor' : int.__xor__,
        '-shl'  : int.__lshift__,
        '-shr'  : int.__rshift__,
    }

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        op = node.operator.lower()
        if op == '-f':
            return self._handle_format(node)
        if op == '+':
            return self._handle_concat(node) or self._handle_arithmetic(node, op)
        if op == '*':
            return self._handle_string_multiply(node) or self._handle_arithmetic(node, op)
        if op == '-join':
            return self._handle_binary_join(node)
        if op in ('-replace', '-creplace', '-ireplace'):
            return self._handle_binary_replace(node, op)
        if op in ('-split', '-csplit', '-isplit'):
            return self._handle_binary_split(node, op)
        return self._handle_comparison(node, op) or self._handle_arithmetic(node, op)

    def _handle_arithmetic(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        left = unwrap_integer(node.left)
        right = unwrap_integer(node.right)
        if left is None or right is None:
            return None
        fn = self._ARITHMETIC_OPS.get(op)
        if fn is None:
            return None
        try:
            result = fn(left.value, right.value)
        except (ZeroDivisionError, ValueError, OverflowError):
            return None
        return Ps1IntegerLiteral(value=result, raw=str(result))

    @staticmethod
    def _handle_string_multiply(node: Ps1BinaryExpression) -> Expression | None:
        s = string_value(node.left) if node.left else None
        n = unwrap_integer(node.right)
        if s is None or n is None:
            s = string_value(node.right) if node.right else None
            n = unwrap_integer(node.left)
        if s is None or n is None:
            return None
        count = n.value
        if count < 0:
            count = 0
        if len(s) * count > _MAX_STRING_EXPAND:
            return None
        return make_string_literal(s * count)

    def _handle_comparison(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        left = unwrap_integer(node.left)
        right = unwrap_integer(node.right)
        if left is None or right is None:
            return None
        fn = COMPARISON_OPS.get(op)
        if fn is None:
            return None
        result = fn(left.value, right.value)
        return Ps1Variable(name='True' if result else 'False')

    def _handle_format(self, node: Ps1BinaryExpression) -> Expression | None:
        fmt_str = string_value(node.left) if node.left else None
        if fmt_str is None or node.right is None:
            return None
        args = collect_format_arguments(node.right)
        if args is None:
            return None
        result = apply_format_string(fmt_str, args)
        if result is None:
            return None
        return make_string_literal(result)

    def _handle_concat(self, node: Ps1BinaryExpression) -> Expression | None:
        left_str = string_value(node.left) if node.left else None
        right_str = string_value(node.right) if node.right else None
        if left_str is not None and right_str is not None:
            return make_string_literal(left_str + right_str)
        if right_str is not None and isinstance(node.left, Ps1BinaryExpression):
            if node.left.operator == '+':
                inner_right_str = string_value(node.left.right) if node.left.right else None
                if inner_right_str is not None:
                    node.left.right = make_string_literal(inner_right_str + right_str)
                    return node.left
        if right_str is not None and isinstance(node.left, Ps1ArrayLiteral):
            elements = list(node.left.elements)
            elements.append(make_string_literal(right_str))
            return Ps1ArrayLiteral(elements=elements)
        is_inner_concat = (
            isinstance(node.parent, Ps1BinaryExpression)
            and node.parent.operator == '+'
            and node.parent.left is node
        )
        if not is_inner_concat:
            if isinstance(node.left, Ps1Variable) and right_str is not None:
                return _variable_string_to_expandable(node.left, right_str, var_first=True)
            if isinstance(node.right, Ps1Variable) and left_str is not None:
                return _variable_string_to_expandable(node.right, left_str, var_first=False)
        return None

    def _handle_binary_join(self, node: Ps1BinaryExpression) -> Expression | None:
        separator = string_value(node.right) if node.right else None
        if separator is None or node.left is None:
            return None
        # Binary -Join on a scalar string is a no-op.
        scalar = string_value(node.left)
        if scalar is not None:
            return make_string_literal(scalar)
        array = unwrap_to_array_literal(node.left)
        if array is None:
            return None
        args = collect_string_arguments(array)
        if args is None:
            return None
        return make_string_literal(separator.join(args))

    def _handle_binary_replace(
        self, node: Ps1BinaryExpression, op: str,
    ) -> Expression | None:
        haystack = string_value(node.left) if node.left else None
        if haystack is None or node.right is None:
            return None
        if isinstance(node.right, Ps1ArrayLiteral) and len(node.right.elements) == 2:
            needle_str = string_value(node.right.elements[0])
            insert_str = string_value(node.right.elements[1])
        else:
            return None
        if needle_str is None or insert_str is None:
            return None
        flags = re.IGNORECASE if op != '-creplace' else 0
        try:
            result = re.sub(needle_str, lambda _: insert_str, haystack, flags=flags)
        except re.error:
            return None
        return make_string_literal(result)

    def _handle_binary_split(
        self, node: Ps1BinaryExpression, op: str,
    ) -> Expression | None:
        if node.right is None or node.left is None:
            return None
        pattern_str = string_value(node.right)
        if pattern_str is None:
            return None
        flags = re.IGNORECASE if op != '-csplit' else 0
        left_str = string_value(node.left)
        if left_str is not None:
            inputs = [left_str]
        else:
            array = unwrap_to_array_literal(node.left)
            if array is None:
                return None
            inputs_opt = collect_string_arguments(array)
            if inputs_opt is None:
                return None
            inputs = inputs_opt
        try:
            parts: list[str] = []
            for s in inputs:
                parts.extend(re.split(pattern_str, s, flags=flags))
        except re.error:
            return None
        elements: list[Expression] = [make_string_literal(p) for p in parts]
        return Ps1ArrayLiteral(elements=elements)
