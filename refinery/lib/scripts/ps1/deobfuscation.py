"""
PowerShell AST deobfuscation transforms.
"""
from __future__ import annotations

import base64
import codecs
import re
import string

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)

_KNOWN_NAMES = {name.lower(): name for name in [
    '-BXor',
    '-Exec Bypass',
    '-NoLogo',
    '-NonInter',
    '-Replace',
    '-Windows Hidden',
    '.Invoke',
    'Assembly',
    'Byte',
    'Char',
    'ChildItem',
    'CreateThread',
    'Get-Variable',
    'GetType',
    'IntPtr',
    'Invoke-Expression',
    'Invoke',
    'Length',
    'Net.WebClient',
    'PowerShell',
    'PSVersionTable',
    'Set-Item',
    'Set-Variable',
    'Start-Sleep',
    'ToString',
    'Type',
    'Value',
    'Void',
]}

_ENCODING_MAP = {
    'ascii'           : 'ascii',
    'bigendianunicode' : 'utf-16be',
    'default'         : 'latin1',
    'unicode'         : 'utf-16le',
}

_SIMPLE_IDENT = re.compile(r'^[a-zA-Z_]\w*$')

_SYSTEM_CONVERT_NAMES = frozenset({
    'system.convert',
})

_SYSTEM_TEXT_ENCODING_NAMES = frozenset({
    'system.text.encoding',
    'text.encoding',
})


def _string_value(node: Expression) -> str | None:
    if isinstance(node, Ps1StringLiteral):
        return node.value
    if isinstance(node, Ps1ExpandableString):
        if all(isinstance(p, Ps1StringLiteral) for p in node.parts):
            return ''.join(p.value for p in node.parts)
    return None


def _make_string_literal(value: str) -> Ps1StringLiteral:
    if "'" not in value:
        raw = F"'{value}'"
    elif '"' not in value and '$' not in value and '`' not in value:
        raw = F'"{value}"'
    else:
        raw = "'" + value.replace("'", "''") + "'"
    return Ps1StringLiteral(value=value, raw=raw)


def _collect_string_arguments(node: Expression) -> list[str] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result = []
        for elem in node.elements:
            sv = _string_value(elem)
            if sv is None:
                return None
            result.append(sv)
        return result
    sv = _string_value(node)
    if sv is not None:
        return [sv]
    return None


def _collect_int_arguments(node: Expression) -> list[int] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result = []
        for elem in node.elements:
            if not isinstance(elem, Ps1IntegerLiteral):
                return None
            result.append(elem.value)
        return result
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return _collect_int_arguments(node.expression)
    if isinstance(node, Ps1IntegerLiteral):
        return [node.value]
    return None


def _unwrap_paren_to_array(node: Expression) -> Expression:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return node.expression
    return node


def _case_normalize_name(name: str) -> str:
    lower = name.lower()
    canonical = _KNOWN_NAMES.get(lower)
    if canonical is not None:
        return canonical
    return name


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


class Ps1Deobfuscator(Transformer):

    def visit_Ps1Variable(self, node: Ps1Variable):
        self.generic_visit(node)
        if node.braced and _SIMPLE_IDENT.match(node.name):
            node.braced = False
        return None

    def visit_Ps1ParenExpression(self, node: Ps1ParenExpression):
        self.generic_visit(node)
        inner = node.expression
        if isinstance(inner, (Ps1StringLiteral, Ps1IntegerLiteral, Ps1RealLiteral)):
            return inner
        return None

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        if isinstance(node.member, Ps1StringLiteral):
            name = node.member.value
            if _SIMPLE_IDENT.match(name):
                node.member = _case_normalize_name(name)
                return None
        if isinstance(node.member, str):
            node.member = _case_normalize_name(node.member)
        return None

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

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        tn = node.type_name.lower().replace(' ', '')
        if tn in ('string', 'char[]'):
            if node.operand and _string_value(node.operand) is not None:
                return node.operand
        if tn == 'char':
            if isinstance(node.operand, Ps1IntegerLiteral):
                try:
                    ch = chr(node.operand.value)
                except (ValueError, OverflowError):
                    return None
                return _make_string_literal(ch)
        if tn == 'char[]':
            if node.operand is not None:
                inner = _unwrap_paren_to_array(node.operand)
                int_values = _collect_int_arguments(inner)
                if int_values is not None:
                    try:
                        result_bytes = bytes(int_values)
                        result = result_bytes.decode('ascii')
                        if not all(c in string.printable or c.isspace() for c in result):
                            return None
                    except (ValueError, UnicodeDecodeError, OverflowError):
                        return None
                    return _make_string_literal(result)
        return None

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        if isinstance(node.name, Ps1ParenExpression) and node.name.expression is not None:
            inner = node.name.expression
            if isinstance(inner, Ps1StringLiteral):
                node.name = inner
            elif isinstance(inner, Ps1CommandInvocation):
                cmd_name = self._get_command_name_str(inner)
                if cmd_name is not None and cmd_name.lower() in ('gcm', 'get-command'):
                    if len(inner.arguments) == 1:
                        arg = inner.arguments[0]
                        if isinstance(arg, Ps1CommandArgument):
                            arg = arg.value
                        if isinstance(arg, Ps1StringLiteral):
                            node.name = arg
                        elif isinstance(arg, Ps1ParenExpression):
                            if isinstance(arg.expression, Ps1StringLiteral):
                                node.name = arg.expression
        if node.name and isinstance(node.name, Ps1StringLiteral):
            node.name = Ps1StringLiteral(
                offset=node.name.offset,
                value=_case_normalize_name(node.name.value),
                raw=_case_normalize_name(node.name.value),
            )
        if node.invocation_operator in ('&', '.'):
            if isinstance(node.name, Ps1StringLiteral):
                name_val = node.name.value
                if _SIMPLE_IDENT.match(name_val) or '-' in name_val:
                    node.name = Ps1StringLiteral(
                        offset=node.name.offset,
                        value=name_val,
                        raw=name_val,
                    )
                    node.invocation_operator = ''
        return None

    @staticmethod
    def _get_command_name_str(cmd: Ps1CommandInvocation) -> str | None:
        name = cmd.name
        if isinstance(name, Ps1StringLiteral):
            return name.value
        if hasattr(name, 'raw') and isinstance(getattr(name, 'raw', None), str):
            return name.raw
        return None
