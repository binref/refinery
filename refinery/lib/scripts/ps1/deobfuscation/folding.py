"""
PowerShell constant folding transforms.
"""
from __future__ import annotations

import base64
import codecs
import re

from collections.abc import Iterator

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _COMPARISON_OPS,
    _ENCODING_MAP,
    _KNOWN_ALIAS,
    SIMPLE_IDENTIFIER,
    _case_normalize_name,
    _collect_int_arguments,
    _collect_string_arguments,
    _extract_foreach_scriptblock,
    _get_body,
    _is_array_reverse_call,
    _is_static_type_call,
    _make_string_literal,
    _string_value,
    _unwrap_integer,
    _unwrap_paren_to_array,
    _unwrap_parens,
    _unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.deobfuscation.typenames import (
    is_known_member,
    resolve_member_type,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)

_SYSTEM_CONVERT_NAMES = frozenset({
    'system.convert',
})

_SYSTEM_TEXT_ENCODING_NAMES = frozenset({
    'system.text.encoding',
    'text.encoding',
})

_STRING_TYPE_NAMES = frozenset({
    'string',
    'system.string',
})

_REGEX_TYPE_NAMES = frozenset({
    'regex',
    'text.regularexpressions.regex',
})

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


def _is_static_regex_call(node: Ps1InvokeMember) -> bool:
    return _is_static_type_call(node, _REGEX_TYPE_NAMES)


def _parse_regex_options(node: Expression) -> tuple[int, bool] | None:
    """
    Parse a RegexOptions argument (string or integer) into Python re flags
    and a right_to_left boolean.
    """
    sv = _string_value(node)
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
    input = _string_value(node.arguments[0])
    pattern = _string_value(node.arguments[1])
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


def _is_static_convert_call(node: Ps1InvokeMember) -> bool:
    return _is_static_type_call(node, _SYSTEM_CONVERT_NAMES)


def _is_static_encoding_chain(node: Ps1InvokeMember) -> tuple[str, bool] | None:
    member_name = node.member if isinstance(node.member, str) else None
    if member_name is None or member_name.lower() != 'getstring':
        return None
    obj = node.object
    if not isinstance(obj, Ps1MemberAccess):
        return None
    if obj.access != Ps1AccessKind.STATIC:
        return None
    if not isinstance(obj.object, Ps1TypeExpression):
        return None
    type_name = obj.object.name.lower().replace(' ', '')
    if type_name not in _SYSTEM_TEXT_ENCODING_NAMES:
        return None
    encoding_name = obj.member if isinstance(obj.member, str) else None
    if encoding_name is None:
        return None
    return encoding_name, True


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


class Ps1ConstantFolding(Transformer):

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        if isinstance(node.name, Ps1StringLiteral):
            name_lower = node.name.value.lower()
            target = _KNOWN_ALIAS.get(name_lower)
            if target is not None and target != node.name.value:
                if not self._has_function_definition(node, name_lower):
                    node.name = Ps1StringLiteral(
                        offset=node.name.offset,
                        value=target,
                        raw=target,
                    )
                    node.name.parent = node
                    self.mark_changed()
        return None

    @staticmethod
    def _has_function_definition(node: Node, name_lower: str) -> bool:
        cursor = node.parent
        while cursor is not None:
            if isinstance(cursor, Ps1FunctionDefinition):
                if cursor.name and cursor.name.lower() == name_lower:
                    return True
            cursor = cursor.parent
        root = node
        while root.parent is not None:
            root = root.parent
        for n in root.walk():
            if isinstance(n, Ps1FunctionDefinition) and n.name:
                if n.name.lower() == name_lower:
                    return True
        return False

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        if len(node.elements) == 2:
            result = self._try_fold_regex_pipeline(node)
            if result is not None:
                return result
        self.generic_visit(node)
        return None

    def _try_fold_regex_pipeline(self, node: Ps1Pipeline) -> Expression | None:
        first = node.elements[0].expression
        second_expr = node.elements[1].expression
        if not isinstance(first, Ps1InvokeMember) or not _is_static_regex_call(first):
            return None
        member = first.member if isinstance(first.member, str) else None
        if member is None:
            return None
        sb = _extract_foreach_scriptblock(second_expr) if second_expr else None
        if sb is None or not _foreach_extracts_value(sb):
            return None
        lower = member.lower()
        if lower == 'matches':
            matches = _compute_regex_matches(first)
            if matches is not None:
                elements: list[Expression] = [_make_string_literal(s) for s in matches]
                return Ps1ArrayLiteral(elements=elements)
        elif lower == 'match':
            result = _compute_regex_match(first)
            if result is not None:
                return _make_string_literal(result)
        return None

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        member = node.member if isinstance(node.member, str) else None
        if member is None:
            return None
        obj = node.object
        if obj is None:
            return None
        member_type = resolve_member_type(obj, member)
        if member_type in _INTEGER_RESULT_TYPES:
            s = _string_value(obj)
            if s is not None:
                return Ps1IntegerLiteral(value=len(s), raw=str(len(s)))
            array = _unwrap_to_array_literal(obj)
            if array is not None:
                return Ps1IntegerLiteral(
                    value=len(array.elements), raw=str(len(array.elements)))
        if (
            _string_value(obj) is not None
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
            prop = inner.member if isinstance(inner.member, str) else None
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
        lower_call = call_member.lower()
        if lower_call == 'matches':
            matches = _compute_regex_matches(inner)
            if matches is not None:
                elements: list[Expression] = [_make_string_literal(s) for s in matches]
                return Ps1ArrayLiteral(elements=elements)
        elif lower_call == 'match':
            result = _compute_regex_match(inner)
            if result is not None:
                return _make_string_literal(result)
        return None

    @staticmethod
    def _try_join_regex_matches(operand: Expression) -> Expression | None:
        unwrapped = _unwrap_parens(operand)
        if not isinstance(unwrapped, Ps1InvokeMember) or not _is_static_regex_call(unwrapped):
            return None
        member = unwrapped.member if isinstance(unwrapped.member, str) else None
        if member is None or member.lower() != 'matches':
            return None
        matches = _compute_regex_matches(unwrapped)
        if matches is None:
            return None
        return _make_string_literal(''.join(matches))

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        if node.operator.lower() != '-join' or node.operand is None:
            return None
        scalar = _string_value(node.operand)
        if scalar is not None:
            return _make_string_literal(scalar)
        result = self._try_join_regex_matches(node.operand)
        if result is not None:
            return result
        array = _unwrap_to_array_literal(node.operand)
        if array is None:
            if isinstance(node.operand, Ps1ArrayExpression) and len(node.operand.body) == 1:
                stmt = node.operand.body[0]
                if isinstance(stmt, Ps1ExpressionStatement):
                    sv = _string_value(stmt.expression) if stmt.expression else None
                    if sv is not None:
                        return _make_string_literal(sv)
            return None
        args = _collect_string_arguments(array)
        if args is None:
            return None
        return _make_string_literal(''.join(args))

    def visit_Ps1IndexExpression(self, node: Ps1IndexExpression):
        self.generic_visit(node)
        obj_str = _string_value(node.object) if node.object else None
        if obj_str is None or node.index is None:
            return None
        if isinstance(node.index, Ps1IntegerLiteral):
            idx = node.index.value
            if 0 <= idx < len(obj_str):
                return _make_string_literal(obj_str[idx])
            return None
        array = _unwrap_to_array_literal(node.index)
        if array is None and isinstance(node.index, Ps1ArrayLiteral):
            array = node.index
        if array is not None:
            chars: list[Expression] = []
            for elem in array.elements:
                if not isinstance(elem, Ps1IntegerLiteral):
                    return None
                idx = elem.value
                if idx < 0 or idx >= len(obj_str):
                    return None
                chars.append(_make_string_literal(obj_str[idx]))
            return Ps1ArrayLiteral(elements=chars)
        return None

    def visit_Ps1ExpressionStatement(self, node: Ps1ExpressionStatement):
        self.generic_visit(node)
        var = _is_array_reverse_call(node)
        if var is not None and self._try_apply_array_reverse(node, var):
            return node
        return None

    def _try_apply_array_reverse(
        self, node: Ps1ExpressionStatement, var: Ps1Variable,
    ) -> bool:
        body = _get_body(node.parent)
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
            sv = _string_value(value)
            if sv is not None:
                replacement = _make_string_literal(sv[::-1])
                replacement.parent = expr
                expr.value = replacement
                node.expression = None
                self.mark_changed()
                return True
            return False
        return False

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        if isinstance(node.member, Ps1StringLiteral):
            name = node.member.value
            if SIMPLE_IDENTIFIER.match(name):
                node.member = name
                self.mark_changed()
        member_name = node.member if isinstance(node.member, str) else None
        if member_name is not None:
            normalized = _case_normalize_name(member_name)
            if normalized != member_name:
                node.member = normalized
                self.mark_changed()
            member_name = normalized
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
        if lower == 'tostring':
            if len(node.arguments) == 0:
                obj_str = _string_value(node.object) if node.object else None
                if obj_str is not None:
                    return _make_string_literal(obj_str)
            return None
        if lower == 'replace':
            if len(node.arguments) == 2:
                obj_str = _string_value(node.object) if node.object else None
                needle_str = _string_value(node.arguments[0])
                insert_str = _string_value(node.arguments[1])
                if obj_str is not None and needle_str is not None and insert_str is not None:
                    return _make_string_literal(obj_str.replace(needle_str, insert_str))
            return None
        if lower == 'split':
            if len(node.arguments) == 1:
                obj_str = _string_value(node.object) if node.object else None
                sep_str = _string_value(node.arguments[0])
                if obj_str is not None and sep_str is not None and sep_str:
                    pattern = '[' + re.escape(sep_str) + ']'
                    parts = re.split(pattern, obj_str)
                    elements: list[Expression] = [_make_string_literal(p) for p in parts]
                    return Ps1ArrayLiteral(elements=elements)
            return None
        obj_str = _string_value(node.object) if node.object else None
        if obj_str is None:
            return None
        if lower == 'substring':
            if len(node.arguments) == 1:
                start = node.arguments[0]
                if isinstance(start, Ps1IntegerLiteral) and 0 <= start.value <= len(obj_str):
                    return _make_string_literal(obj_str[start.value:])
            if len(node.arguments) == 2:
                start = node.arguments[0]
                length = node.arguments[1]
                if (
                    isinstance(start, Ps1IntegerLiteral)
                    and isinstance(length, Ps1IntegerLiteral)
                    and 0 <= start.value
                    and start.value + length.value <= len(obj_str)
                ):
                    return _make_string_literal(
                        obj_str[start.value:start.value + length.value])
            return None
        if lower == 'insert':
            if len(node.arguments) == 2 and isinstance(node.arguments[0], Ps1IntegerLiteral):
                idx = node.arguments[0].value
                val = _string_value(node.arguments[1])
                if val is not None and 0 <= idx <= len(obj_str):
                    return _make_string_literal(obj_str[:idx] + val + obj_str[idx:])
            return None
        if lower == 'remove':
            if len(node.arguments) == 1 and isinstance(node.arguments[0], Ps1IntegerLiteral):
                idx = node.arguments[0].value
                if 0 <= idx <= len(obj_str):
                    return _make_string_literal(obj_str[:idx])
            if (
                len(node.arguments) == 2
                and isinstance(node.arguments[0], Ps1IntegerLiteral)
                and isinstance(node.arguments[1], Ps1IntegerLiteral)
            ):
                idx = node.arguments[0].value
                count = node.arguments[1].value
                if 0 <= idx and idx + count <= len(obj_str):
                    return _make_string_literal(obj_str[:idx] + obj_str[idx + count:])
            return None
        return None

    def _try_fold_static_method(
        self, node: Ps1InvokeMember, lower: str,
    ) -> Expression | None:
        if _is_static_convert_call(node) and lower == 'frombase64string':
            if len(node.arguments) == 1:
                b64_str = _string_value(node.arguments[0])
                if b64_str is not None:
                    try:
                        decoded = base64.b64decode(b64_str)
                    except Exception:
                        return None
                    elements = [
                        Ps1IntegerLiteral(value=b, raw=F'0x{b:02X}')
                        for b in decoded
                    ]
                    array = Ps1ArrayLiteral(elements=elements)
                    return Ps1ArrayExpression(
                        body=[Ps1ExpressionStatement(expression=array)])
        enc_info = _is_static_encoding_chain(node)
        if enc_info is not None:
            encoding_name, _ = enc_info
            if len(node.arguments) == 1:
                arg = _unwrap_paren_to_array(node.arguments[0])
                if isinstance(arg, Ps1ArrayExpression) and len(arg.body) == 1:
                    stmt = arg.body[0]
                    if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression:
                        arg = stmt.expression
                int_values = _collect_int_arguments(arg)
                if int_values is not None:
                    try:
                        raw_bytes = bytearray(int_values)
                    except (ValueError, OverflowError):
                        return None
                    encoding = _ENCODING_MAP.get(
                        encoding_name.lower(), encoding_name)
                    try:
                        codecs.lookup(encoding)
                    except LookupError:
                        encoding = 'utf-8'
                    try:
                        decoded_str = raw_bytes.decode(encoding)
                    except Exception:
                        return None
                    return _make_string_literal(decoded_str)
        if _is_static_type_call(node, _STRING_TYPE_NAMES):
            if lower == 'concat' and len(node.arguments) >= 1:
                parts: list[str] = []
                for arg in node.arguments:
                    sv = _string_value(arg)
                    if sv is None:
                        break
                    parts.append(sv)
                else:
                    return _make_string_literal(''.join(parts))
            if lower == 'join' and len(node.arguments) == 2:
                separator = _string_value(node.arguments[0])
                if separator is not None:
                    second = node.arguments[1]
                    scalar = _string_value(second)
                    if scalar is not None:
                        return _make_string_literal(scalar)
                    array = _unwrap_to_array_literal(second)
                    if array is not None:
                        args = _collect_string_arguments(array)
                        if args is not None:
                            return _make_string_literal(separator.join(args))
        if _is_static_regex_call(node) and lower == 'replace':
            return self._handle_regex_replace(node)
        return None

    def _handle_regex_replace(self, node: Ps1InvokeMember) -> Expression | None:
        if len(node.arguments) not in (3, 4):
            return None
        input_str = _string_value(node.arguments[0])
        pattern_str = _string_value(node.arguments[1])
        replacement_str = _string_value(node.arguments[2])
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
        return _make_string_literal(result)

    _ARITHMETIC_OPS = {
        '+' : int.__add__,
        '-' : int.__sub__,
        '*' : int.__mul__,
        '/' : int.__floordiv__,
        '%' : int.__mod__,
        '-band': int.__and__,
        '-bor' : int.__or__,
        '-bxor': int.__xor__,
        '-shl' : int.__lshift__,
        '-shr' : int.__rshift__,
    }

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        op = node.operator.lower()
        if op == '-f':
            return self._handle_format(node)
        if op == '+':
            return self._handle_concat(node) or self._handle_arithmetic(node, op)
        if op == '-join':
            return self._handle_binary_join(node)
        if op in ('-replace', '-creplace', '-ireplace'):
            return self._handle_binary_replace(node, op)
        if op in ('-split', '-csplit', '-isplit'):
            return self._handle_binary_split(node, op)
        return self._handle_comparison(node, op) or self._handle_arithmetic(node, op)

    def _handle_arithmetic(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        left = _unwrap_integer(node.left)
        right = _unwrap_integer(node.right)
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

    def _handle_comparison(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        left = _unwrap_integer(node.left)
        right = _unwrap_integer(node.right)
        if left is None or right is None:
            return None
        fn = _COMPARISON_OPS.get(op)
        if fn is None:
            return None
        result = fn(left.value, right.value)
        return Ps1Variable(name='True' if result else 'False')

    def _handle_format(self, node: Ps1BinaryExpression) -> Expression | None:
        fmt_str = _string_value(node.left) if node.left else None
        if fmt_str is None or node.right is None:
            return None
        args = _collect_string_arguments(node.right)
        if args is None:
            return None
        try:
            def replacer(m: re.Match) -> str:
                full = m.group(0)
                if full == '{{':
                    return '{'
                if full == '}}':
                    return '}'
                idx = int(m.group(1))
                return args[idx]
            result = re.sub(r'\{\{|\}\}|\{(\d+)\}', replacer, fmt_str)
        except (IndexError, ValueError):
            return None
        return _make_string_literal(result)

    def _handle_concat(self, node: Ps1BinaryExpression) -> Expression | None:
        left_str = _string_value(node.left) if node.left else None
        right_str = _string_value(node.right) if node.right else None
        if left_str is not None and right_str is not None:
            return _make_string_literal(left_str + right_str)
        if right_str is not None and isinstance(node.left, Ps1BinaryExpression):
            if node.left.operator == '+':
                inner_right_str = _string_value(node.left.right) if node.left.right else None
                if inner_right_str is not None:
                    node.left.right = _make_string_literal(inner_right_str + right_str)
                    return node.left
        if right_str is not None and isinstance(node.left, Ps1ArrayLiteral):
            elements = list(node.left.elements)
            elements.append(_make_string_literal(right_str))
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
        separator = _string_value(node.right) if node.right else None
        if separator is None or node.left is None:
            return None
        # Binary -Join on a scalar string is a no-op.
        scalar = _string_value(node.left)
        if scalar is not None:
            return _make_string_literal(scalar)
        array = _unwrap_to_array_literal(node.left)
        if array is None and isinstance(node.left, Ps1ArrayLiteral):
            array = node.left
        if array is None:
            return None
        args = _collect_string_arguments(array)
        if args is None:
            return None
        return _make_string_literal(separator.join(args))

    def _handle_binary_replace(
        self, node: Ps1BinaryExpression, op: str,
    ) -> Expression | None:
        haystack = _string_value(node.left) if node.left else None
        if haystack is None or node.right is None:
            return None
        if isinstance(node.right, Ps1ArrayLiteral) and len(node.right.elements) == 2:
            needle_str = _string_value(node.right.elements[0])
            insert_str = _string_value(node.right.elements[1])
        else:
            return None
        if needle_str is None or insert_str is None:
            return None
        flags = re.IGNORECASE if op != '-creplace' else 0
        try:
            result = re.sub(needle_str, lambda _: insert_str, haystack, flags=flags)
        except re.error:
            return None
        return _make_string_literal(result)

    def _handle_binary_split(
        self, node: Ps1BinaryExpression, op: str,
    ) -> Expression | None:
        if node.right is None or node.left is None:
            return None
        pattern_str = _string_value(node.right)
        if pattern_str is None:
            return None
        flags = re.IGNORECASE if op != '-csplit' else 0
        # Collect input strings: either a single string or an array of strings.
        left_str = _string_value(node.left)
        if left_str is not None:
            inputs = [left_str]
        else:
            array = _unwrap_to_array_literal(node.left)
            if array is None and isinstance(node.left, Ps1ArrayLiteral):
                array = node.left
            if array is None:
                return None
            inputs_opt = _collect_string_arguments(array)
            if inputs_opt is None:
                return None
            inputs = inputs_opt
        try:
            parts: list[str] = []
            for s in inputs:
                parts.extend(re.split(pattern_str, s, flags=flags))
        except re.error:
            return None
        elements: list[Expression] = [_make_string_literal(p) for p in parts]
        return Ps1ArrayLiteral(elements=elements)
