"""
Inline constant IEX (Invoke-Expression) calls by parsing the string argument.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import _string_value
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1Pipeline,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
)

_IEX_NAMES = frozenset({'iex', 'invoke-expression'})


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
        return _string_value(val)

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
        return _string_value(source)

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
