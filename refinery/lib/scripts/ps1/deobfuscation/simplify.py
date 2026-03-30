"""
PowerShell syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _SIMPLE_IDENT,
    _case_normalize_name,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1IntegerLiteral,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1Variable,
)


class Ps1Simplifications(Transformer):

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
