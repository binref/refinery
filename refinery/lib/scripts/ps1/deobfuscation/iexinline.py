"""
Inline constant IEX (Invoke-Expression) calls by parsing the string argument.

When the IEX argument is not a plain string literal but a .NET expression chain
(e.g. base64-decode → decompress → stream-read), the evaluator attempts to
resolve it to a string value at deobfuscation time.
"""
from __future__ import annotations

import base64
import gzip
import zlib

from refinery.lib.scripts import Block, Expression, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import _string_value
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
)

_IEX_NAMES = frozenset({'iex', 'invoke-expression'})

_ENCODING_MAP = {
    'ascii'            : 'ascii',
    'bigendianunicode' : 'utf-16-be',
    'default'          : 'latin-1',
    'unicode'          : 'utf-16-le',
    'utf7'             : 'utf-7',
    'utf8'             : 'utf-8',
    'utf32'            : 'utf-32-le',
}


def _normalize_type_name(name: str) -> str:
    """Lower-case and strip leading ``System.`` prefix from a .NET type name."""
    result = name.lower().replace(' ', '')
    if result.startswith('system.'):
        result = result[7:]
    return result


def _extract_new_object_args(cmd: Ps1CommandInvocation) -> tuple[str, list[Expression]] | None:
    """
    Extract type name and constructor arguments from a ``New-Object`` invocation.

    Returns ``(type_name, [arg_expressions])`` or ``None``.
    """
    if not isinstance(cmd.name, Ps1StringLiteral):
        return None
    if cmd.name.value.lower() != 'new-object':
        return None
    positional: list[Expression] = []
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind != Ps1CommandArgumentKind.POSITIONAL or arg.value is None:
                return None
            positional.append(arg.value)
        elif isinstance(arg, Expression):
            positional.append(arg)
        else:
            return None
    if not positional:
        return None
    type_name_expr = positional[0]
    if not isinstance(type_name_expr, Ps1StringLiteral):
        return None
    type_name = type_name_expr.value
    # Constructor args come as a single Ps1ParenExpression wrapping a Ps1ArrayLiteral
    ctor_args: list[Expression] = []
    if len(positional) >= 2:
        second = positional[1]
        if isinstance(second, Ps1ParenExpression) and second.expression is not None:
            inner = second.expression
            if isinstance(inner, Ps1ArrayLiteral):
                ctor_args = list(inner.elements)
            else:
                ctor_args = [inner]
        else:
            ctor_args = [second]
    return type_name, ctor_args


def _resolve_encoding(expr: Expression) -> str | None:
    """
    Resolve ``[Text.Encoding]::ASCII`` and similar to a Python codec name.
    """
    if not isinstance(expr, Ps1MemberAccess):
        return None
    if expr.access != Ps1AccessKind.STATIC:
        return None
    if not isinstance(expr.object, Ps1TypeExpression):
        return None
    if _normalize_type_name(expr.object.name) != 'text.encoding':
        return None
    if not isinstance(expr.member, str):
        return None
    return _ENCODING_MAP.get(expr.member.lower())


def _try_evaluate(expr: Expression) -> str | bytes | None:
    """
    Recursively evaluate a .NET expression chain to ``str`` or ``bytes``.

    Handles the pattern:
    ``[Convert]::FromBase64String(literal)``
    → ``[IO.MemoryStream]`` cast
    → ``New-Object DeflateStream/GZipStream(stream, Decompress)``
    → ``New-Object StreamReader(stream, encoding)``
    → ``.ReadToEnd()``
    """
    if isinstance(expr, Ps1StringLiteral):
        return expr.value

    if isinstance(expr, Ps1ParenExpression) and expr.expression is not None:
        return _try_evaluate(expr.expression)

    # String concatenation via +
    if isinstance(expr, Ps1BinaryExpression) and expr.operator == '+':
        if expr.left is not None and expr.right is not None:
            left = _try_evaluate(expr.left)
            right = _try_evaluate(expr.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right

    # [Convert]::FromBase64String('...')
    if isinstance(expr, Ps1InvokeMember):
        if (expr.access == Ps1AccessKind.STATIC
                and isinstance(expr.object, Ps1TypeExpression)
                and _normalize_type_name(expr.object.name) == 'convert'
                and isinstance(expr.member, str)
                and expr.member.lower() == 'frombase64string'
                and len(expr.arguments) == 1):
            sv = _string_value(expr.arguments[0])
            if sv is not None:
                try:
                    return base64.b64decode(sv)
                except Exception:
                    return None

        # .ReadToEnd() — pass through string result from inner expression
        if (expr.access == Ps1AccessKind.INSTANCE
                and isinstance(expr.member, str)
                and expr.member.lower() == 'readtoend'
                and len(expr.arguments) == 0
                and expr.object is not None):
            return _try_evaluate(expr.object)

    # [IO.MemoryStream] cast — pass through bytes
    if isinstance(expr, Ps1CastExpression) and expr.operand is not None:
        tn = _normalize_type_name(expr.type_name)
        if tn == 'io.memorystream':
            return _try_evaluate(expr.operand)

    # New-Object IO.Compression.DeflateStream(data, Decompress)
    # New-Object IO.Compression.GZipStream(data, Decompress)
    # New-Object System.IO.StreamReader(stream, encoding)
    if isinstance(expr, Ps1CommandInvocation):
        result = _extract_new_object_args(expr)
        if result is None:
            return None
        type_name, ctor_args = result
        tn = _normalize_type_name(type_name)

        if tn == 'io.compression.deflatestream' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0])
            if isinstance(data, bytes):
                try:
                    return zlib.decompress(data, -15)
                except Exception:
                    return None

        if tn == 'io.compression.gzipstream' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0])
            if isinstance(data, bytes):
                try:
                    return gzip.decompress(data)
                except Exception:
                    return None

        if tn == 'io.streamreader' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0])
            if not isinstance(data, bytes):
                return None
            codec = 'utf-8'
            if len(ctor_args) >= 2:
                resolved = _resolve_encoding(ctor_args[1])
                if resolved is not None:
                    codec = resolved
            try:
                return data.decode(codec)
            except Exception:
                return None

    return None


def _flatten_string_concat(expr: Expression) -> list[Expression] | None:
    """Flatten a binary ``+`` chain into its leaf operands."""
    while isinstance(expr, Ps1ParenExpression) and expr.expression is not None:
        expr = expr.expression
    if isinstance(expr, Ps1BinaryExpression) and expr.operator == '+':
        if expr.left is None or expr.right is None:
            return None
        left = _flatten_string_concat(expr.left)
        right = _flatten_string_concat(expr.right)
        if left is None or right is None:
            return None
        return left + right
    return [expr]


def _try_resolve_concat_lenient(expr: Expression) -> str | None:
    """
    Try to resolve a string concatenation chain where some parts are
    expandable strings with non-evaluable subexpressions.

    In obfuscated PowerShell, this commonly appears as::

        "$( Set-Variable 'ofs' '' )" + 'actual code' + "$( Set-Variable 'ofs' ' ')"

    The subexpressions set the Output Field Separator as a side effect and
    contribute only whitespace to the result.  For these expandable strings
    we extract just the literal text fragments.
    """
    parts = _flatten_string_concat(expr)
    if parts is None or len(parts) < 2:
        return None

    result: list[str] = []
    for part in parts:
        s = _string_value(part)
        if s is not None:
            result.append(s)
            continue
        ev = _try_evaluate(part)
        if isinstance(ev, str):
            result.append(ev)
            continue
        if isinstance(part, Ps1ExpandableString):
            literals = []
            for p in part.parts:
                if isinstance(p, Ps1StringLiteral):
                    literals.append(p.value)
            result.append(''.join(literals))
            continue
        return None

    return ''.join(result)


def _resolve_to_string(expr: Expression) -> str | None:
    """Try to resolve an expression to a string: first as a literal, then via evaluation."""
    s = _string_value(expr)
    if s is not None:
        return s
    result = _try_evaluate(expr)
    if isinstance(result, str):
        return result
    return _try_resolve_concat_lenient(expr)


class Ps1IexInlining(Transformer):
    """
    Replace ``IEX 'constant string'`` and ``'constant string' | IEX``
    with the parsed statements from that string.
    """

    def visit(self, node):
        for container in list(node.walk()):
            body = self._get_body(container)
            if body is None:
                continue
            i = 0
            while i < len(body):
                code = self._try_extract_iex_string(body[i])
                if code is None:
                    code = self._try_extract_piped_iex_string(body[i])
                if code is None:
                    i += 1
                    continue
                parsed = self._try_parse(code)
                if parsed is None:
                    i += 1
                    continue
                for stmt in parsed:
                    stmt.parent = container
                body[i:i + 1] = parsed
                self.mark_changed()
                i += len(parsed)
        return None

    @staticmethod
    def _get_body(node) -> list | None:
        if isinstance(node, (Ps1Script, Block, Ps1ScriptBlock)):
            return node.body
        return None

    @staticmethod
    def _is_bare_iex(cmd) -> bool:
        if not isinstance(cmd, Ps1CommandInvocation):
            return False
        if not isinstance(cmd.name, Ps1StringLiteral):
            return False
        if cmd.name.value.lower() not in _IEX_NAMES:
            return False
        return len(cmd.arguments) == 0

    @staticmethod
    def _try_extract_iex_string(stmt) -> str | None:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        cmd = stmt.expression
        if not isinstance(cmd, Ps1CommandInvocation):
            return None
        if not isinstance(cmd.name, Ps1StringLiteral):
            return None
        if cmd.name.value.lower() not in _IEX_NAMES:
            return None
        if len(cmd.arguments) != 1:
            return None
        arg = cmd.arguments[0]
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                return None
            val = arg.value
        else:
            val = arg
        if val is None:
            return None
        return _resolve_to_string(val)

    @classmethod
    def _try_extract_piped_iex_string(cls, stmt) -> str | None:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        pipeline = stmt.expression
        if not isinstance(pipeline, Ps1Pipeline):
            return None
        if len(pipeline.elements) < 2:
            return None
        last = pipeline.elements[-1]
        if not cls._is_bare_iex(last.expression):
            return None
        if len(pipeline.elements) != 2:
            return None
        source = pipeline.elements[0].expression
        if source is None:
            return None
        return _resolve_to_string(source)

    @staticmethod
    def _try_parse(code: str) -> list | None:
        try:
            from refinery.lib.scripts.ps1.parser import Ps1Parser
            parsed = Ps1Parser(code).parse()
        except Exception:
            return None
        if not parsed.body:
            return None
        return list(parsed.body)
