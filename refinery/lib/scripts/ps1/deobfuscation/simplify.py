"""
PowerShell syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _KNOWN_ALIAS,
    SIMPLE_IDENTIFIER,
    _case_normalize_name,
    _make_string_literal,
    _string_value,
    _strip_backtick_noop,
)
from refinery.lib.scripts.ps1.model import (
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1IntegerLiteral,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1RealLiteral,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)
from refinery.lib.scripts.win32const import DEFAULT_ENVIRONMENT_TEMPLATE

_KNOWN_VARIABLE_NAMES = {name.lower(): name for name in [
    'True',
    'False',
    'Null',
    'ExecutionContext',
]}

_KNOWN_ENV_NAMES: dict[str, str] = {
    name.lower(): name for name in DEFAULT_ENVIRONMENT_TEMPLATE
}


class Ps1Simplifications(Transformer):

    def __init__(self):
        super().__init__()
        self._local_functions: set[str] = set()
        self._entry = False

    def visit(self, node: Node):
        if self._entry:
            return super().visit(node)
        self._entry = True
        try:
            self._local_functions = {
                n.name.lower()
                for n in node.walk()
                if isinstance(n, Ps1FunctionDefinition) and n.name
            }
            return super().visit(node)
        finally:
            self._entry = False

    def visit_Ps1Variable(self, node: Ps1Variable):
        self.generic_visit(node)
        if '`' in node.name:
            node.name = _strip_backtick_noop(node.name)
            self.mark_changed()
        if node.braced and SIMPLE_IDENTIFIER.match(node.name):
            node.braced = False
            self.mark_changed()
        canonical = _KNOWN_VARIABLE_NAMES.get(node.name.lower())
        if canonical is not None and canonical != node.name:
            node.name = canonical
            self.mark_changed()
        if node.scope == Ps1ScopeModifier.ENV:
            canonical = _KNOWN_ENV_NAMES.get(node.name.lower())
            if canonical is not None and canonical != node.name:
                node.name = canonical
                self.mark_changed()
        return None

    def visit_Ps1FunctionDefinition(self, node: Ps1FunctionDefinition):
        self.generic_visit(node)
        if '`' in node.name:
            node.name = _strip_backtick_noop(node.name)
            self.mark_changed()
        return None

    def visit_Ps1ParenExpression(self, node: Ps1ParenExpression):
        self.generic_visit(node)
        inner = node.expression
        if isinstance(inner, (Ps1StringLiteral, Ps1IntegerLiteral, Ps1RealLiteral)):
            return inner
        return None

    def visit_Ps1SubExpression(self, node: Ps1SubExpression):
        self.generic_visit(node)
        if isinstance(node.parent, Ps1ExpandableString):
            return None
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, Ps1ExpressionStatement):
                inner = stmt.expression
                if isinstance(inner, (Ps1Variable, Ps1StringLiteral, Ps1IntegerLiteral, Ps1RealLiteral)):
                    return inner
        return None

    def visit_Ps1ExpandableString(self, node: Ps1ExpandableString):
        self.generic_visit(node)
        parts: list[str] = []
        for p in node.parts:
            if isinstance(p, Ps1StringLiteral):
                parts.append(p.value)
                continue
            if isinstance(p, Ps1SubExpression) and len(p.body) == 1:
                stmt = p.body[0]
                if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                    sv = _string_value(stmt.expression)
                    if sv is not None:
                        parts.append(sv)
                        continue
            return None
        return _make_string_literal(''.join(parts))

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        if isinstance(node.member, Ps1StringLiteral):
            name = node.member.value
            if node.member.raw and node.member.raw[0] == '"' and '`' in node.member.raw:
                name = _strip_backtick_noop(node.member.raw[1:-1])
            if SIMPLE_IDENTIFIER.match(name):
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
            value = node.value.value
            if '.' in value:
                normalized = self._normalize_type_name(value)
            else:
                normalized = _case_normalize_name(value)
            if normalized != value:
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
            name_lower = node.name.value.lower()
            if name_lower not in self._local_functions:
                alias_target = _KNOWN_ALIAS.get(name_lower)
                if alias_target is not None:
                    new_value = alias_target
                else:
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
                if SIMPLE_IDENTIFIER.match(name_val) or '-' in name_val:
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
        raw = getattr(name, 'raw', None)
        if isinstance(raw, str):
            return raw
        return None
