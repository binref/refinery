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
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
)

_IEX_NAMES = frozenset({'iex', 'invoke-expression'})


class Ps1IexInlining(Transformer):
    """
    Replace ``IEX 'constant string'`` with the parsed statements from that string.
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
