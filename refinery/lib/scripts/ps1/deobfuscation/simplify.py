"""
PowerShell syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts.ps1.deobfuscation.data import (
    ALL_PARAMETER_NAMES,
    KNOWN_ALIAS,
    KNOWN_CMDLETS,
    KNOWN_PS_OPERATORS,
    KNOWN_PS_SWITCHES,
    PS1_KNOWN_VARIABLES,
    SIMPLE_IDENTIFIER,
    TYPE_ARG_COMMANDS,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    LocalFunctionAwareTransformer,
    get_command_name,
    make_string_literal,
    string_value,
)
from refinery.lib.scripts.ps1.deobfuscation.typenames import canonical_type_name
from refinery.lib.scripts.ps1.model import (
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ClassDefinition,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
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
from refinery.lib.scripts.ps1.token import _strip_backtick_noop
from refinery.lib.scripts.win32const import DEFAULT_ENVIRONMENT_TEMPLATE

_KNOWN_ENV_NAMES: dict[str, str] = {
    name.lower(): name for name in DEFAULT_ENVIRONMENT_TEMPLATE
}


class Ps1Simplifications(LocalFunctionAwareTransformer):

    def visit_Ps1Variable(self, node: Ps1Variable):
        self.generic_visit(node)
        if '`' in node.name:
            node.name = _strip_backtick_noop(node.name)
            self.mark_changed()
        if node.braced and SIMPLE_IDENTIFIER.match(node.name):
            node.braced = False
            self.mark_changed()
        canonical = PS1_KNOWN_VARIABLES.get(node.name.lower())
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

    def visit_Ps1ClassDefinition(self, node: Ps1ClassDefinition):
        self.generic_visit(node)
        if '`' in node.name:
            node.name = _strip_backtick_noop(node.name)
            self.mark_changed()
        return None

    def visit_Ps1ParenExpression(self, node: Ps1ParenExpression):
        self.generic_visit(node)
        inner = node.expression
        if isinstance(inner, (Ps1StringLiteral, Ps1HereString, Ps1IntegerLiteral, Ps1RealLiteral, Ps1TypeExpression)):
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
                if isinstance(inner, (
                    Ps1Variable,
                    Ps1StringLiteral,
                    Ps1IntegerLiteral,
                    Ps1RealLiteral,
                    Ps1TypeExpression,
                    Ps1CastExpression,
                )):
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
                    sv = string_value(stmt.expression)
                    if sv is not None:
                        parts.append(sv)
                        continue
            return None
        return make_string_literal(''.join(parts))

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        self._normalize_member(node)
        return None

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        self._normalize_member(node)
        return None

    def _normalize_member(self, node: Ps1MemberAccess | Ps1InvokeMember):
        if not isinstance(node.member, Ps1StringLiteral):
            return
        name = node.member.value
        if node.member.raw and node.member.raw[0] == '"' and '`' in node.member.raw:
            name = _strip_backtick_noop(node.member.raw[1:-1])
        if SIMPLE_IDENTIFIER.match(name):
            node.member = name
            self.mark_changed()

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        normalized = KNOWN_PS_OPERATORS.get(node.operator.lower(), node.operator)
        if normalized != node.operator:
            node.operator = normalized
            self.mark_changed()
        return None

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        normalized = KNOWN_PS_OPERATORS.get(node.operator.lower(), node.operator)
        if normalized != node.operator:
            node.operator = normalized
            self.mark_changed()
        return None

    def visit_Ps1CommandArgument(self, node: Ps1CommandArgument):
        self.generic_visit(node)
        if node.kind in (Ps1CommandArgumentKind.SWITCH, Ps1CommandArgumentKind.NAMED):
            if '`' in node.name:
                node.name = _strip_backtick_noop(node.name)
                self.mark_changed()
            name_lower = node.name.lower()
            normalized = KNOWN_PS_OPERATORS.get(name_lower)
            if normalized is None:
                normalized = KNOWN_PS_SWITCHES.get(name_lower)
            if normalized is None:
                bare = name_lower.lstrip('-')
                if bare != name_lower:
                    canonical = ALL_PARAMETER_NAMES.get(bare)
                    if canonical is not None:
                        normalized = F'-{canonical}'
            if normalized is not None and normalized != node.name:
                node.name = normalized
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
        canonical = canonical_type_name(name)
        if canonical is not None and canonical != name:
            self.mark_changed()
            return canonical
        return name

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        old_name = node.name
        if isinstance(node.name, Ps1ParenExpression) and node.name.expression is not None:
            inner = node.name.expression
            if isinstance(inner, Ps1StringLiteral):
                node.name = inner
            elif isinstance(inner, Ps1CommandInvocation):
                c = get_command_name(inner)
                if c is not None and c.lower() in ('gcm', 'get-command'):
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
            if '`' in node.name.value:
                stripped = _strip_backtick_noop(node.name.value)
                node.name = Ps1StringLiteral(
                    offset=node.name.offset,
                    value=stripped,
                    raw=stripped,
                )
                self.mark_changed()
            name_lower = node.name.value.lower()
            if name_lower not in self._local_functions:
                alias_target = KNOWN_ALIAS.get(name_lower)
                if alias_target is not None:
                    new_value = alias_target
                else:
                    new_value = KNOWN_CMDLETS.get(name_lower, node.name.value)
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
        if (c := get_command_name(node)) and c.lower() in TYPE_ARG_COMMANDS:
            self._normalize_first_positional_type_arg(node)
        return None

    def _normalize_first_positional_type_arg(self, node: Ps1CommandInvocation):
        for arg in node.arguments:
            if isinstance(arg, Ps1CommandArgument):
                if arg.kind == Ps1CommandArgumentKind.NAMED:
                    if arg.name.lstrip('-').lower() == 'class' and isinstance(arg.value, Ps1StringLiteral):
                        normalized = self._normalize_type_name(arg.value.value)
                        if normalized != arg.value.value:
                            arg.value = nl = Ps1StringLiteral(offset=arg.value.offset, value=normalized, raw=normalized)
                            nl.parent = arg
                    continue
                if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                    continue
                if isinstance(arg.value, Ps1StringLiteral):
                    normalized = self._normalize_type_name(arg.value.value)
                    if normalized != arg.value.value:
                        arg.value = nl = Ps1StringLiteral(offset=arg.value.offset, value=normalized, raw=normalized)
                        nl.parent = arg
                return
            if isinstance(arg, Ps1StringLiteral):
                normalized = self._normalize_type_name(arg.value)
                if normalized != arg.value:
                    nl = Ps1StringLiteral(offset=arg.offset, value=normalized, raw=normalized)
                    idx = node.arguments.index(arg)
                    node.arguments[idx] = nl
                    nl.parent = node
                return
