"""
PowerShell constant folding transforms.
"""
from __future__ import annotations

import base64
import codecs
import re

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _ENCODING_MAP,
    _KNOWN_ALIAS,
    SIMPLE_IDENTIFIER,
    _case_normalize_name,
    _collect_int_arguments,
    _collect_string_arguments,
    _make_string_literal,
    _string_value,
    _unwrap_paren_to_array,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1ScopeModifier,
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


def _is_static_convert_call(node: Ps1InvokeMember) -> bool:
    if node.access != Ps1AccessKind.STATIC:
        return False
    if not isinstance(node.object, Ps1TypeExpression):
        return False
    return node.object.name.lower().replace(' ', '') in _SYSTEM_CONVERT_NAMES


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


def _unwrap_to_array_literal(node: Expression) -> Ps1ArrayLiteral | None:
    """
    Unwrap parentheses and array expressions to find an inner Ps1ArrayLiteral.
    """
    while isinstance(node, Ps1ParenExpression) and node.expression is not None:
        node = node.expression
    if isinstance(node, Ps1ArrayLiteral):
        return node
    if isinstance(node, Ps1ArrayExpression) and len(node.body) == 1:
        stmt = node.body[0]
        if isinstance(stmt, Ps1ExpressionStatement) and isinstance(stmt.expression, Ps1ArrayLiteral):
            return stmt.expression
    return None


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
    Fold `$var + 'text'` or `'text' + $var` into a `Ps1ExpandableString`.
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

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        if node.operator.lower() != '-join' or node.operand is None:
            return None
        # -Join on a scalar string is a no-op in PowerShell.
        scalar = _string_value(node.operand)
        if scalar is not None:
            return _make_string_literal(scalar)
        array = _unwrap_to_array_literal(node.operand)
        if array is None:
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
            member_name = node.member
        if member_name is not None and member_name.lower() == 'tostring':
            if len(node.arguments) == 0:
                obj_str = _string_value(node.object) if node.object else None
                if obj_str is not None:
                    return _make_string_literal(obj_str)
        if member_name is not None and member_name.lower() == 'replace':
            if len(node.arguments) == 2:
                obj_str = _string_value(node.object) if node.object else None
                needle_str = _string_value(node.arguments[0])
                insert_str = _string_value(node.arguments[1])
                if obj_str is not None and needle_str is not None and insert_str is not None:
                    result = obj_str.replace(needle_str, insert_str)
                    return _make_string_literal(result)
        if member_name is not None and member_name.lower() == 'split':
            if len(node.arguments) == 1:
                obj_str = _string_value(node.object) if node.object else None
                sep_str = _string_value(node.arguments[0])
                if obj_str is not None and sep_str is not None and sep_str:
                    pattern = '[' + re.escape(sep_str) + ']'
                    parts = re.split(pattern, obj_str)
                    elements: list[Expression] = [_make_string_literal(p) for p in parts]
                    return Ps1ArrayLiteral(elements=elements)
        if member_name is not None and member_name.lower() == 'invoke':
            if isinstance(node.object, Ps1MemberAccess):
                return Ps1InvokeMember(
                    offset=node.offset,
                    object=node.object.object,
                    member=node.object.member,
                    arguments=node.arguments,
                    access=node.object.access,
                )
        if _is_static_convert_call(node):
            if member_name is not None and member_name.lower() == 'frombase64string':
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
                        decoded = raw_bytes.decode(encoding)
                    except Exception:
                        return None
                    return _make_string_literal(decoded)
        if (
            node.access == Ps1AccessKind.STATIC
            and isinstance(node.object, Ps1TypeExpression)
            and node.object.name.lower().replace(' ', '') in _STRING_TYPE_NAMES
            and member_name is not None
            and member_name.lower() == 'join'
            and len(node.arguments) == 2
        ):
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
        return None

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

    _COMPARISON_OPS = {
        '-eq': int.__eq__,
        '-ne': int.__ne__,
        '-lt': int.__lt__,
        '-le': int.__le__,
        '-gt': int.__gt__,
        '-ge': int.__ge__,
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

    @staticmethod
    def _unwrap_integer(node: Expression | None) -> Ps1IntegerLiteral | None:
        while isinstance(node, Ps1ParenExpression):
            node = node.expression
        if isinstance(node, Ps1IntegerLiteral):
            return node
        if (
            isinstance(node, Ps1Variable)
            and node.scope == Ps1ScopeModifier.NONE
            and node.name.lower() == 'null'
        ):
            return Ps1IntegerLiteral(value=0, raw='0')
        if isinstance(node, Ps1UnaryExpression) and node.operator == '-':
            inner = node.operand
            while isinstance(inner, Ps1ParenExpression):
                inner = inner.expression
            if isinstance(inner, Ps1IntegerLiteral):
                return Ps1IntegerLiteral(value=-inner.value, raw=str(-inner.value))
        return None

    def _handle_arithmetic(self, node: Ps1BinaryExpression, op: str) -> Expression | None:
        left = self._unwrap_integer(node.left)
        right = self._unwrap_integer(node.right)
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
        left = self._unwrap_integer(node.left)
        right = self._unwrap_integer(node.right)
        if left is None or right is None:
            return None
        fn = self._COMPARISON_OPS.get(op)
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
            result = re.sub(needle_str, insert_str, haystack, flags=flags)
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
