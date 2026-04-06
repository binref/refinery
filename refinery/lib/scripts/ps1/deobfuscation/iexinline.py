"""
Inline constant IEX (Invoke-Expression) calls by parsing the string argument.

When the IEX argument is not a plain string literal but a .NET expression chain
(e.g. base64-decode -> decompress -> stream-read), the evaluator attempts to
resolve it to a string value at deobfuscation time.
"""
from __future__ import annotations

import base64
import gzip
import zlib

from refinery.lib.scripts import Expression, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _ENCODING_MAP,
    _extract_foreach_scriptblock,
    _get_body,
    _normalize_dotnet_type_name,
    _string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)

_IEX_NAMES = frozenset({'iex', 'invoke-expression'})


def _try_evaluate_byte_array(elements: list) -> bytes | None:
    """
    Convert a list of ``Ps1IntegerLiteral`` elements to ``bytes``.
    """
    values = []
    for elem in elements:
        if not isinstance(elem, Ps1IntegerLiteral):
            return None
        values.append(elem.value)
    try:
        return bytes(bytearray(values))
    except (ValueError, OverflowError):
        return None


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
    if _normalize_dotnet_type_name(expr.object.name) != 'text.encoding':
        return None
    if not isinstance(expr.member, str):
        return None
    return _ENCODING_MAP.get(expr.member.lower())


def _try_evaluate(
    expr: Expression,
    bindings: dict[str, str | bytes] | None = None,
) -> str | bytes | None:
    """
    Recursively evaluate a .NET expression chain to ``str`` or ``bytes``.

    Handles the pattern:
    ``[Convert]::FromBase64String(literal)``
    -> ``[IO.MemoryStream]`` cast
    -> ``New-Object DeflateStream/GZipStream(stream, Decompress)``
    -> ``New-Object StreamReader(stream, encoding)``
    -> ``.ReadToEnd()``

    Also handles pipelines of the form ``expr | %{ body } | %{ body }`` where
    each ForEach-Object stage receives the previous result via ``$_``.
    """
    if isinstance(expr, Ps1StringLiteral):
        return expr.value

    if isinstance(expr, Ps1ParenExpression) and expr.expression is not None:
        return _try_evaluate(expr.expression, bindings)

    if isinstance(expr, Ps1Variable):
        if bindings and expr.name.lower() in bindings:
            return bindings[expr.name.lower()]
        return None

    if isinstance(expr, Ps1ArrayLiteral):
        return _try_evaluate_byte_array(expr.elements)

    if isinstance(expr, Ps1ArrayExpression):
        if len(expr.body) == 1:
            stmt = expr.body[0]
            inner = stmt.expression if isinstance(stmt, Ps1ExpressionStatement) else None
            if isinstance(inner, Ps1ArrayLiteral):
                return _try_evaluate_byte_array(inner.elements)
        return None

    if isinstance(expr, Ps1BinaryExpression) and expr.operator == '+':
        if expr.left is not None and expr.right is not None:
            left = _try_evaluate(expr.left, bindings)
            right = _try_evaluate(expr.right, bindings)
            if isinstance(left, str) and isinstance(right, str):
                return left + right

    if isinstance(expr, Ps1InvokeMember):
        if (
            expr.access == Ps1AccessKind.STATIC
            and isinstance(expr.object, Ps1TypeExpression)
            and _normalize_dotnet_type_name(expr.object.name) == 'convert'
            and isinstance(expr.member, str)
            and expr.member.lower() == 'frombase64string'
            and len(expr.arguments) == 1
        ):
            sv = _string_value(expr.arguments[0])
            if sv is not None:
                try:
                    return base64.b64decode(sv)
                except Exception:
                    return None

        if (
            expr.access == Ps1AccessKind.INSTANCE
            and isinstance(expr.member, str)
            and expr.member.lower() == 'readtoend'
            and len(expr.arguments) == 0
            and expr.object is not None
        ):
            return _try_evaluate(expr.object, bindings)

    if isinstance(expr, Ps1CastExpression) and expr.operand is not None:
        tn = _normalize_dotnet_type_name(expr.type_name)
        if tn == 'io.memorystream':
            return _try_evaluate(expr.operand, bindings)

    if isinstance(expr, Ps1CommandInvocation):
        result = _extract_new_object_args(expr)
        if result is None:
            return None
        type_name, ctor_args = result
        tn = _normalize_dotnet_type_name(type_name)

        if tn == 'io.compression.deflatestream' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0], bindings)
            if isinstance(data, bytes):
                try:
                    return zlib.decompress(data, -15)
                except Exception:
                    return None

        if tn == 'io.compression.gzipstream' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0], bindings)
            if isinstance(data, bytes):
                try:
                    return gzip.decompress(data)
                except Exception:
                    return None

        if tn == 'io.streamreader' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0], bindings)
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

    if isinstance(expr, Ps1Pipeline):
        return _try_evaluate_pipeline(expr, bindings)

    return None


def _try_evaluate_pipeline(
    node: Ps1Pipeline,
    bindings: dict[str, str | bytes] | None = None,
) -> str | bytes | None:
    """
    Evaluate a pipeline ``expr | %{ body } | %{ body }`` by threading the result
    of each stage into the next via ``$_`` bindings.
    """
    if not node.elements:
        return None
    first = node.elements[0]
    if not isinstance(first, Ps1PipelineElement):
        return None
    if first.expression is None:
        return None
    value = _try_evaluate(first.expression, bindings)
    if value is None:
        return None
    for elem in node.elements[1:]:
        if not isinstance(elem, Ps1PipelineElement):
            return None
        if elem.expression is None:
            return None
        script_block = _extract_foreach_scriptblock(elem.expression)
        if script_block is None:
            return None
        if len(script_block.body) != 1:
            return None
        stmt = script_block.body[0]
        if isinstance(stmt, Ps1ExpressionStatement):
            inner_expr = stmt.expression
        elif isinstance(stmt, Expression):
            inner_expr = stmt
        else:
            return None
        if inner_expr is None:
            return None
        stage_bindings: dict[str, str | bytes] = {**(bindings or {}), '_': value}
        value = _try_evaluate(inner_expr, stage_bindings)
        if value is None:
            return None
    return value


def _resolve_to_string(expr: Expression) -> str | None:
    """
    Try to resolve an expression to a string: first as a literal, then via evaluation.
    """
    s = _string_value(expr)
    if s is not None:
        return s
    result = _try_evaluate(expr)
    if isinstance(result, str):
        return result
    return None


class Ps1IexInlining(Transformer):
    """
    Replace ``IEX 'constant string'`` and ``'constant string' | IEX``
    with the parsed statements from that string.
    """

    def visit(self, node):
        self._inline_statements(node)
        self._inline_expressions(node)
        return None

    def _inline_statements(self, node):
        for container in list(node.walk()):
            body = _get_body(container)
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

    def _inline_expressions(self, node):
        for cmd in list(node.walk()):
            if not isinstance(cmd, Ps1CommandInvocation):
                continue
            if isinstance(cmd.parent, Ps1ExpressionStatement):
                continue
            replacement = self._try_inline_expression(cmd)
            if replacement is None:
                continue
            parent = cmd.parent
            for attr_name in vars(parent):
                if attr_name.startswith('_') or attr_name in ('parent', 'offset'):
                    continue
                value = getattr(parent, attr_name)
                if value is cmd:
                    replacement.parent = parent
                    setattr(parent, attr_name, replacement)
                    self.mark_changed()
                    break
                if isinstance(value, list):
                    for idx, item in enumerate(value):
                        if item is cmd:
                            replacement.parent = parent
                            value[idx] = replacement
                            self.mark_changed()
                            break

    def _try_inline_expression(self, node: Ps1CommandInvocation) -> Expression | None:
        if not isinstance(node.name, Ps1StringLiteral):
            return None
        if node.name.value.lower() not in _IEX_NAMES:
            return None
        if len(node.arguments) != 1:
            return None
        arg = node.arguments[0]
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                return None
            val = arg.value
        else:
            val = arg
        if val is None:
            return None
        code = _resolve_to_string(val)
        if code is None:
            return None
        parsed = self._try_parse(code)
        if parsed is None or len(parsed) != 1:
            return None
        stmt = parsed[0]
        if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
            return None
        return stmt.expression

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
