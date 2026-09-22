"""
PowerShell syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, set_value
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.commands import CommandKind, Ps1CommandModel
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.separator import coerced_text_at
from refinery.lib.scripts.ps1.ast import get_command_name, has_wildcard
from refinery.lib.scripts.ps1.data import (
    ALL_PARAMETER_NAMES,
    KNOWN_PS_OPERATORS,
    KNOWN_PS_SWITCHES,
    PS1_KNOWN_VARIABLES,
    SIMPLE_IDENTIFIER,
    TYPE_ARG_COMMANDS,
    abbreviated_parameter,
)
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    is_bare_command_name,
    make_string_literal,
)
from refinery.lib.scripts.ps1.deobfuscation.substitution import substitute_field, substitute_list
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
    Ps1Script,
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


class Ps1Simplifications(Transformer):

    def __init__(self):
        super().__init__()
        self._commands: Ps1CommandModel | None = None
        self._flow: Ps1VariableFlow | None = None
        self._entry = False

    def visit(self, node: Node):
        """
        The models are captured once at the root and dropped when the walk ends, for the reason
        `refinery.lib.scripts.ps1.deobfuscation.typecast.Ps1TypeCasts.visit` gives.
        """
        if self._entry or not isinstance(node, Ps1Script):
            return super().visit(node)
        self._entry = True
        try:
            cache = model_cache(self, node)
            self._commands = cache.commands
            self._flow = cache.variable_flow
            return super().visit(node)
        finally:
            self._entry = False
            self._commands = None
            self._flow = None

    def visit_Ps1Variable(self, node: Ps1Variable):
        self.generic_visit(node)
        if '`' in node.name:
            set_value(node, 'name', _strip_backtick_noop(node.name))
            self.mark_changed()
        if node.braced and SIMPLE_IDENTIFIER.match(node.name):
            set_value(node, 'braced', False)
            self.mark_changed()
        canonical = PS1_KNOWN_VARIABLES.get(node.name.lower())
        if canonical is not None and canonical != node.name:
            set_value(node, 'name', canonical)
            self.mark_changed()
        if node.scope == Ps1ScopeModifier.ENV:
            canonical = _KNOWN_ENV_NAMES.get(node.name.lower())
            if canonical is not None and canonical != node.name:
                set_value(node, 'name', canonical)
                self.mark_changed()
        return None

    def visit_Ps1FunctionDefinition(self, node: Ps1FunctionDefinition):
        self.generic_visit(node)
        if '`' in node.name:
            set_value(node, 'name', _strip_backtick_noop(node.name))
            self.mark_changed()
        return None

    def visit_Ps1ClassDefinition(self, node: Ps1ClassDefinition):
        self.generic_visit(node)
        if '`' in node.name:
            set_value(node, 'name', _strip_backtick_noop(node.name))
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
        """
        An expandable string every part of which is a constant, written as the plain string it
        produces.

        What a subexpression contributes is what the value it holds *renders* to and not the way it
        was written — measured, `"$(0xFF)"` is `255` and `"$([char]65)"` is `A` — which is the same
        question `refinery.lib.scripts.ps1.deobfuscation.constants` answers for a variable
        substituted into one of these. A collection contributes its elements separated by `$OFS`,
        which is why the question is asked at the string rather than of the value alone.
        """
        self.generic_visit(node)
        if self._flow is None:
            return None
        parts: list[str] = []
        for p in node.parts:
            if isinstance(p, Ps1StringLiteral):
                parts.append(p.value)
                continue
            if isinstance(p, Ps1SubExpression) and len(p.body) == 1:
                stmt = p.body[0]
                if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                    sv = coerced_text_at(stmt.expression, node, self._flow)
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
            set_value(node, 'member', name)
            self.mark_changed()

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        normalized = KNOWN_PS_OPERATORS.get(node.operator.lower(), node.operator)
        if normalized != node.operator:
            set_value(node, 'operator', normalized)
            self.mark_changed()
        return None

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        self.generic_visit(node)
        normalized = KNOWN_PS_OPERATORS.get(node.operator.lower(), node.operator)
        if normalized != node.operator:
            set_value(node, 'operator', normalized)
            self.mark_changed()
        return None

    def visit_Ps1CommandArgument(self, node: Ps1CommandArgument):
        self.generic_visit(node)
        if node.kind in (Ps1CommandArgumentKind.SWITCH, Ps1CommandArgumentKind.NAMED):
            if '`' in node.name:
                set_value(node, 'name', _strip_backtick_noop(node.name))
                self.mark_changed()
            if self._binds_parameters_by_name(node):
                name_lower = node.name.lower()
                # The command's own record answers first: an exact spelling can be the alias of
                # a longer parameter on this cmdlet — `Add-Member -Type` names `MemberType` —
                # and the union tables below would read that spelling as the full name of a
                # different command's parameter.
                normalized = self._expanded_abbreviation(node)
                if normalized is None:
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
                    set_value(node, 'name', normalized)
                    self.mark_changed()
        return None

    def _expanded_abbreviation(self, node: Ps1CommandArgument) -> str | None:
        """
        The full spelling of an abbreviated parameter *node* writes, or `None` where the command it
        is written against is not a cmdlet the collected surface carries.

        An abbreviated parameter binds only where the command it names resolves to that cmdlet, so
        the gate is the denotation's resolved target and not the spelling: an alias invocation
        expands through the alias, and a script function — which binds prefixes just the same,
        measured — is left, because the collected surface carries no function parameters. A
        function defined by the script also beats the cmdlet of the same name in resolution, so a
        `function Remove-Item { param($EA) }` cannot be mis-expanded. The rewrite spells the full
        name with the casing the record carries; a value a colon-form parameter holds is a field
        the parser has already split, so this touches the name alone.
        """
        command = node.parent
        if self._commands is None or not isinstance(command, Ps1CommandInvocation):
            return None
        denotation = self._commands.denotation(command)
        if denotation.kind not in (CommandKind.CMDLET, CommandKind.ALIAS):
            return None
        target = denotation.target
        if target is None:
            return None
        expanded = abbreviated_parameter(target, node.name)
        return None if expanded is None else F'-{expanded}'

    def _binds_parameters_by_name(self, argument: Ps1CommandArgument) -> bool:
        """
        Whether the command `argument` is written against completes and case-normalizes parameter
        names the way this rewrite assumes. A cmdlet, function or alias binds an argument name
        case-insensitively and by unambiguous prefix, so respelling `-noprofile` to `-NoProfile`
        leaves the run unchanged. A native program receives every argument as text — `openssl -in`
        reaches it as `-in` — so a spelling nothing may rewrite. The model refusing the name a
        concrete command (`Denotation.is_a_name` is false for the unknown and unresolved names an
        external executable reads as, and for one that denotes nothing) forbids the rewrite, and no
        command model at all is the same refusal.
        """
        command = argument.parent
        if self._commands is None or not isinstance(command, Ps1CommandInvocation):
            return False
        return self._commands.denotation(command).is_a_name

    def visit_Ps1TypeExpression(self, node: Ps1TypeExpression):
        self._normalize_type_field(node, 'name')
        return None

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        self._normalize_type_field(node, 'type_name')
        return None

    def _normalize_type_field(self, node: Node, attr: str) -> None:
        spelled = getattr(node, attr)
        normalized = self._normalize_type_name(spelled)
        if normalized != spelled:
            set_value(node, attr, normalized)

    def _normalize_type_name(self, name: str) -> str:
        canonical = canonical_type_name(name)
        if canonical is not None and canonical != name:
            self.mark_changed()
            return canonical
        return name

    def _operator_is_noise(self, node: Ps1CommandInvocation) -> bool:
        """
        Whether dropping the invocation operator from `node` leaves the same program. `&` always
        does: it only forces command position. `.` does not — it runs the target in the *caller's*
        scope, so a script file or a function dot-sourced this way writes its definitions, variables
        and type-system changes here rather than into a child scope. A compiled cmdlet has no such
        body and cannot tell the two apart, so the dot may be dropped only from a name the command
        model resolves to a cmdlet — never from one a `function`/`filter`, a `function:`/`alias:`
        assignment, or an unresolved `Set-Alias` has taken over, each of which the model reports as
        something other than a cmdlet.

        The world reads the surviving dot as its evidence that off-tree code runs
        (`refinery.lib.scripts.ps1.analysis.world.runs_another_script_file`), so dropping it from
        `. helper` would not merely change scope: the world, rebuilt from the stripped tree, would
        read closed and every grant in the script would fire.
        """
        if node.invocation_operator == '&':
            return True
        if self._commands is None:
            return False
        return self._commands.denotation(node).kind is CommandKind.CMDLET

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        old_name = node.name
        if isinstance(node.name, Ps1ParenExpression) and node.name.expression is not None:
            inner = node.name.expression
            if isinstance(inner, Ps1StringLiteral):
                substitute_field(node, 'name', inner)
            elif isinstance(inner, Ps1CommandInvocation):
                c = get_command_name(inner)
                if c is not None and c.lower() in ('gcm', 'get-command'):
                    if len(inner.arguments) == 1:
                        arg = inner.arguments[0]
                        if isinstance(arg, Ps1CommandArgument):
                            arg = arg.value
                        if isinstance(arg, Ps1ParenExpression):
                            arg = arg.expression
                        # Only resolve a concrete command name; a wildcard pattern such as
                        # `gcm i*e-e*` must not be substituted verbatim as the command name.
                        if isinstance(arg, Ps1StringLiteral) and not has_wildcard(arg.value):
                            substitute_field(node, 'name', arg)
        if node.name is not old_name:
            self.mark_changed()
        if node.name and isinstance(node.name, Ps1StringLiteral):
            if '`' in node.name.value:
                stripped = _strip_backtick_noop(node.name.value)
                substitute_field(node, 'name', Ps1StringLiteral(
                    offset=node.name.offset,
                    value=stripped,
                    raw=stripped,
                ))
                self.mark_changed()
            if is_bare_command_name(node.name.value) and node.name.raw != node.name.value:
                substitute_field(node, 'name', Ps1StringLiteral(
                    offset=node.name.offset,
                    value=node.name.value,
                    raw=node.name.value,
                ))
                self.mark_changed()
        if node.invocation_operator in ('&', '.'):
            if isinstance(node.name, Ps1StringLiteral):
                name_val = node.name.value
                if (
                    (SIMPLE_IDENTIFIER.match(name_val) or '-' in name_val)
                    and is_bare_command_name(name_val)
                    and not has_wildcard(name_val)
                    and self._operator_is_noise(node)
                ):
                    substitute_field(node, 'name', Ps1StringLiteral(
                        offset=node.name.offset,
                        value=name_val,
                        raw=name_val,
                    ))
                    set_value(node, 'invocation_operator', '')
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
                            substitute_field(arg, 'value', Ps1StringLiteral(
                                offset=arg.value.offset, value=normalized, raw=normalized))
                    continue
                if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                    continue
                if isinstance(arg.value, Ps1StringLiteral):
                    normalized = self._normalize_type_name(arg.value.value)
                    if normalized != arg.value.value:
                        substitute_field(arg, 'value', Ps1StringLiteral(
                            offset=arg.value.offset, value=normalized, raw=normalized))
                return
            if isinstance(arg, Ps1StringLiteral):
                normalized = self._normalize_type_name(arg.value)
                if normalized != arg.value:
                    arguments = list(node.arguments)
                    arguments[arguments.index(arg)] = Ps1StringLiteral(
                        offset=arg.offset, value=normalized, raw=normalized)
                    substitute_list(node, 'arguments', arguments)
                return
