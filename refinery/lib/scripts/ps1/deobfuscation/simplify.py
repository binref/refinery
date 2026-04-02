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
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1IntegerLiteral,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)


def _strip_backtick_escapes(name: str) -> str:
    """Remove backtick escapes from a PowerShell braced variable name.

    In braced variable names, a backtick is always a no-op escape: the
    backtick is dropped and the next character is kept literally. This
    differs from string contexts where backtick sequences like ``n`` or
    ``t`` have special meaning.
    """
    result: list[str] = []
    i = 0
    while i < len(name):
        if name[i] == '`' and i + 1 < len(name):
            result.append(name[i + 1])
            i += 2
            continue
        result.append(name[i])
        i += 1
    return ''.join(result)


def _decode_raw_member_name(raw_inner: str) -> str:
    """Re-decode an expandable string's inner text treating all backtick
    escapes as no-ops. This recovers the intended identifier when backtick
    escapes like ``e`` (normally ESC) or ``t`` (normally TAB) are used
    purely for obfuscation in member names.
    """
    result: list[str] = []
    i = 0
    while i < len(raw_inner):
        if raw_inner[i] == '`' and i + 1 < len(raw_inner):
            result.append(raw_inner[i + 1])
            i += 2
            continue
        result.append(raw_inner[i])
        i += 1
    return ''.join(result)


_KNOWN_VARIABLE_NAMES = {name.lower(): name for name in [
    'True',
    'False',
    'Null',
    'ExecutionContext',
]}


class Ps1Simplifications(Transformer):

    def visit_Ps1Variable(self, node: Ps1Variable):
        self.generic_visit(node)
        if '`' in node.name:
            node.name = _strip_backtick_escapes(node.name)
            self.mark_changed()
        if node.braced and _SIMPLE_IDENT.match(node.name):
            node.braced = False
            self.mark_changed()
        canonical = _KNOWN_VARIABLE_NAMES.get(node.name.lower())
        if canonical is not None and canonical != node.name:
            node.name = canonical
            self.mark_changed()
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
            # When an expandable string is used as a member name, backtick
            # escapes like `e (→ ESC) and `t (→ TAB) are decode artifacts;
            # the intent is always the literal character. Re-decode from raw
            # treating all backticks as no-op escapes to recover the name.
            if node.member.raw and node.member.raw[0] == '"' and '`' in node.member.raw:
                name = _decode_raw_member_name(node.member.raw[1:-1])
            if _SIMPLE_IDENT.match(name):
                node.member = _case_normalize_name(name)
                self.mark_changed()
                return None
        if isinstance(node.member, str):
            normalized = _case_normalize_name(node.member)
            if normalized != node.member:
                node.member = normalized
                self.mark_changed()
        return None

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        normalized = _case_normalize_name(node.operator)
        if normalized != node.operator:
            node.operator = normalized
            self.mark_changed()
        return None

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        normalized = _case_normalize_name(node.operator)
        if normalized != node.operator:
            node.operator = normalized
            self.mark_changed()
        return None

    def visit_Ps1CommandArgument(self, node: Ps1CommandArgument):
        self.generic_visit(node)
        if node.kind in (Ps1CommandArgumentKind.SWITCH, Ps1CommandArgumentKind.NAMED):
            normalized = _case_normalize_name(node.name)
            if normalized != node.name:
                node.name = normalized
                self.mark_changed()
        if node.kind == Ps1CommandArgumentKind.POSITIONAL and isinstance(node.value, Ps1StringLiteral):
            if '.' in node.value.value:
                normalized = self._normalize_type_name(node.value.value)
                if normalized != node.value.value:
                    node.value = Ps1StringLiteral(
                        offset=node.value.offset,
                        value=normalized,
                        raw=normalized,
                    )
                    self.mark_changed()
        return None

    def visit_Ps1TypeExpression(self, node: Ps1TypeExpression):
        node.name = self._normalize_type_name(node.name)
        return None

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        node.type_name = self._normalize_type_name(node.type_name)
        return None

    def _normalize_type_name(self, name: str) -> str:
        normalized = _case_normalize_name(name)
        if normalized != name:
            self.mark_changed()
        return normalized

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        old_name = node.name
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
        if node.name is not old_name:
            self.mark_changed()
        if node.name and isinstance(node.name, Ps1StringLiteral):
            new_value = _case_normalize_name(node.name.value)
            if new_value != node.name.value or new_value != node.name.raw:
                node.name = Ps1StringLiteral(
                    offset=node.name.offset,
                    value=new_value,
                    raw=new_value,
                )
                self.mark_changed()
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
                    self.mark_changed()
        return None

    @staticmethod
    def _get_command_name_str(cmd: Ps1CommandInvocation) -> str | None:
        name = cmd.name
        if isinstance(name, Ps1StringLiteral):
            return name.value
        if hasattr(name, 'raw') and isinstance(getattr(name, 'raw', None), str):
            return name.raw
        return None
