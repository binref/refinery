"""
PowerShell string evaluation transforms.
"""
from __future__ import annotations

import base64
import codecs
import re

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _SIMPLE_IDENT,
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
    Ps1ExpressionStatement,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1StringLiteral,
    Ps1TypeExpression,
)

_ENCODING_MAP = {
    'ascii'            : 'ascii',
    'bigendianunicode' : 'utf-16be',
    'default'          : 'latin1',
    'unicode'          : 'utf-16le',
}

_SYSTEM_CONVERT_NAMES = frozenset({
    'system.convert',
})

_SYSTEM_TEXT_ENCODING_NAMES = frozenset({
    'system.text.encoding',
    'text.encoding',
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


class Ps1StringOperations(Transformer):

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        if isinstance(node.member, Ps1StringLiteral):
            name = node.member.value
            if _SIMPLE_IDENT.match(name):
                node.member = name
        member_name = node.member if isinstance(node.member, str) else None
        if member_name is not None:
            node.member = _case_normalize_name(member_name)
            member_name = node.member
        if member_name is not None and member_name.lower() == 'replace':
            if len(node.arguments) == 2:
                obj_str = _string_value(node.object) if node.object else None
                needle_str = _string_value(node.arguments[0])
                insert_str = _string_value(node.arguments[1])
                if obj_str is not None and needle_str is not None and insert_str is not None:
                    result = obj_str.replace(needle_str, insert_str)
                    return _make_string_literal(result)
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
        return None

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        op = node.operator.lower()
        if op == '-f':
            return self._handle_format(node)
        if op == '+':
            return self._handle_concat(node)
        if op in ('-replace', '-creplace', '-ireplace'):
            return self._handle_binary_replace(node, op)
        return None

    def _handle_format(self, node: Ps1BinaryExpression) -> Expression | None:
        fmt_str = _string_value(node.left) if node.left else None
        if fmt_str is None or node.right is None:
            return None
        args = _collect_string_arguments(node.right)
        if args is None:
            return None
        try:
            def replacer(m: re.Match) -> str:
                idx = int(m.group(1))
                return args[idx]
            result = re.sub(r'\{(\d+)\}', replacer, fmt_str)
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
        return None

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
