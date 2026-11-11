"""
The listing folds: each replaces a lookup of the session by the one name it yields, where the
session lists exactly that one name wherever the lookup runs. Three listings are read:

1. The command table, through `Get-Command` and the lookups of `$ExecutionContext.InvokeCommand`:
   `(Get-Command ???t?).Name` is `'write'`, and `& (Get-Command 'wr?te')` runs `write`.
2. The members of a value, through `Get-Member` and its `psobject`:
   `([string] | Get-Member -Static | ? { $_.Name -like 'Conc?t' }).Name` is `'Concat'`.
3. The variable table, through `Get-Variable` and the `Variable:` drive:
   `(Get-Item Variable:E*t).Value` is `$ExecutionContext`, and `Set-Variable x 5` is `$x = 5`.

What each listing holds, how its lookups read a name, and what must hold at a lookup for the
collected surface to be what the session lists there is
`refinery.lib.scripts.ps1.analysis.listing`'s to say; this module decides where a lookup's result
can stand in for its name. A lookup hands back objects — a `CmdletInfo`, a `MemberDefinition`, a
`PSVariable` — so it is replaced by a name only where its result is used as one: its `.Name` is
read, a call operator runs it, another lookup is handed it, or a `GetCommandName` list is unrolled
by the statement it stands in. A narrowed `Get-Command` keeps its object and loses the filter.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, owning_field
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.environment import takes_a_read_the_environment_owns
from refinery.lib.scripts.ps1.analysis.listing import (
    command_listing_holds_at,
    get_command_selection,
    listed_command,
    listed_member,
    listed_variable,
    lookup_selection,
    member_selection,
    name_narrowing,
    variable_listing_holds_at,
)
from refinery.lib.scripts.ps1.analysis.values import make_string_literal, resolve_expression_type
from refinery.lib.scripts.ps1.ast import (
    argument_text,
    binds_parameter,
    bound_argument_value,
    free_positional_values,
    get_command_name,
    get_member_name,
    resolve_command_name,
    string_value,
    switch_setting,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import OUT_VARIABLE_PARAMETERS, SESSION_VARIABLES, is_type
from refinery.lib.scripts.ps1.deobfuscation.substitution import substitute_field, substituted
from refinery.lib.scripts.ps1.deobfuscation.typenames import VariableTypeAwareTransformer
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AssignmentExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScopeModifier,
    Ps1StringLiteral,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.patterns import is_wildcard_pattern, literal_name

_GET_COMMAND = 'get-command'
_GET_ITEM_COMMANDS = frozenset({'get-item', 'get-childitem'})
_GET_VARIABLE = 'get-variable'
_SET_ITEM = 'set-item'
_SET_VARIABLE = 'set-variable'
_WHERE_OBJECT = 'where-object'
_VARIABLE_DRIVE = 'variable:'

#: The type whose methods look a command up by a name or a pattern: what `InvokeCommand` holds.
_COMMAND_LOOKUP_TYPE = 'System.Management.Automation.CommandInvocationIntrinsics'

#: The members of a lookup's result a fold may read the name off: the result's name.
_NAME_MEMBER = 'name'

#: The `-Scope` arguments a variable reference can express, mapped to the qualifier that expresses
#: them. `Local` needs none, since an unqualified reference means the scope it stands in. Every
#: other spelling — `-Scope 1`, which names the *caller's* scope, an unrecognised word, a computed
#: expression — names a scope no qualifier reaches, and the rewrite is declined rather than
#: approximated.
_EXPRESSIBLE_SCOPES: dict[str, Ps1ScopeModifier] = {
    'global': Ps1ScopeModifier.GLOBAL,
    'local': Ps1ScopeModifier.NONE,
    'private': Ps1ScopeModifier.PRIVATE,
    'script': Ps1ScopeModifier.SCRIPT,
}

#: Parameters whose effect a reference or an assignment cannot carry, so binding one declines the
#: rewrite.
#:
#: Measured: after `New-Variable x -Option ReadOnly` a later `$x = …` raises
#: `SessionStateUnauthorizedAccessException`, where after `$x = …` it succeeds — so the option is
#: not decoration, it decides what every later store in the script does. `-PassThru` makes the
#: command emit the variable object, which an assignment does not emit, and `-Force` is what lets a
#: write land on a name an option protects. `-Include`, `-Exclude` and `-Filter` filter the result
#: by name: measured, `$x = 1; (Get-Variable x -Exclude x).Value` is `$null`, not `1`.
#:
#: `-Description` is deliberately absent: it is metadata no read or write observes. Anything not
#: listed is *allowed*, which is the wrong polarity for a corruption and the right one for a
#: rewrite — see `refinery.lib.scripts.ps1.analysis.naming` on why the two tables differ. The
#: common parameters that fill a variable of their own, `-OutVariable` among them, are refused
#: beside these: a reference fills none.
_INEXPRESSIBLE_PARAMETERS = (
    'exclude',
    'filter',
    'force',
    'include',
    'option',
    'passthru',
    'visibility',
    *sorted(OUT_VARIABLE_PARAMETERS),
)

#: The qualifiers a variable command reads off the front of the name it is handed, mapped to the
#: qualifier a reference spells them with: `Set-Variable global:y 1` writes `$global:y`.
_NAME_QUALIFIERS: dict[str, Ps1ScopeModifier] = {
    'global': Ps1ScopeModifier.GLOBAL,
    'local': Ps1ScopeModifier.LOCAL,
    'private': Ps1ScopeModifier.PRIVATE,
    'script': Ps1ScopeModifier.SCRIPT,
}


def _expresses_every_effect(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether a variable reference or an assignment carries everything *cmd* does, or drops an
    effect on the floor.
    """
    for argument in cmd.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            continue
        if any(binds_parameter(argument.name, name) for name in _INEXPRESSIBLE_PARAMETERS):
            return False
    return True


def _subject_argument_value(
    cmd: Ps1CommandInvocation,
    command: str,
    parameter: str,
) -> str | None:
    """
    The literal name *cmd* is about, written either as `-Name x` / `-Path x` or as the first
    argument it binds by position, or `None` when it is not a literal this can read. The same
    reading `refinery.lib.scripts.ps1.analysis.naming` takes, down to
    `refinery.lib.scripts.ps1.ast.argument_text`, so the two layers agree on which argument a
    variable command names *and* on what it is called.
    """
    explicit = bound_argument_value(cmd, parameter)
    if explicit is not None:
        return argument_text(explicit)
    for value in free_positional_values(cmd, command):
        return argument_text(value)
    return None


def _expressible_reference(
    node: Ps1CommandInvocation,
    var_name: str,
) -> tuple[str, Ps1ScopeModifier | None] | None:
    """
    The bare name of the variable *node* is about and the qualifier a reference replacing it must
    carry, the qualifier being `None` where no reference can name the scope. A qualifier written
    into the name, as `global:y`, is the reference's own and is not part of its name; it is
    declined beside a `-Scope` argument, since the two would have to be rendered one inside the
    other. A prefix no qualifier spells, as `env:y`, names no variable this can reference at all.
    """
    declared = bound_argument_value(node, 'scope')
    qualifier, separator, bare = var_name.rpartition(':')
    if separator:
        scope = _NAME_QUALIFIERS.get(qualifier.lower())
        if scope is None or not bare:
            return None
        return bare, None if declared is not None else scope
    if declared is None:
        return var_name, Ps1ScopeModifier.NONE
    written = string_value(declared)
    if written is None:
        return var_name, None
    return var_name, _EXPRESSIBLE_SCOPES.get(written.lower())


def _session_spelling(name: str) -> str:
    """
    The name a variable lookup of the literal *name* reports: the session's own spelling where the
    session starts with such a variable, the name as written otherwise.
    """
    folded = name.casefold()
    return next((known for known in SESSION_VARIABLES if known.casefold() == folded), name)


def _value_carrier(node: Node) -> Node:
    """
    The node that stands where *node*'s value is used: *node* itself, or the parenthesis around it.
    """
    while isinstance(node.parent, Ps1ParenExpression):
        node = node.parent
    return node


def _stands_as_a_statement(node: Node) -> bool:
    """
    Whether the value of *node* is written to the output by the statement it stands in, with
    nothing between them: the expression of a statement, or the one stage of a pipeline that a
    statement list holds rather than a value slot.
    """
    parent = node.parent
    if isinstance(parent, Ps1ExpressionStatement):
        return parent.expression is node and owning_field(parent) is None
    if isinstance(parent, Ps1PipelineElement) and not parent.redirections:
        pipeline = parent.parent
        return (
            isinstance(pipeline, Ps1Pipeline)
            and len(pipeline.elements) == 1
            and owning_field(pipeline) is None
        )
    return False


class Ps1WildcardResolution(VariableTypeAwareTransformer):

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self.generic_visit(node)
        replacement = (
            self._try_resolve_variable_value(node)
            or self._try_resolve_listed_name(node)
        )
        return substituted(
            node,
            replacement,
            flow=self._flow,
            options=self.options,
        )

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self.generic_visit(node)
        return substituted(
            node,
            self._try_resolve_lookup_used_as_a_name(node),
            flow=self._flow,
            options=self.options,
        )

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        self.generic_visit(node)
        return substituted(
            node,
            self._try_resolve_narrowed_command_listing(node),
            flow=self._flow,
            options=self.options,
        )

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        self._try_resolve_command_run_by_a_lookup(node)
        replacement = self._try_resolve_get_variable_value_only(node)
        if replacement is not None:
            return substituted(node, replacement, flow=self._flow, options=self.options)
        return substituted(node, self._try_resolve_set_variable(node))

    def _callee_is_trusted(self, invocation: Ps1CommandInvocation) -> bool:
        """
        Whether the command *invocation* spells still runs the command it names: trusted under both
        the written spelling and the canonical name it resolves to, because a `function` taking the
        canonical name over captures every alias that resolves to it while the written spelling of
        such a call shadows nothing.
        """
        written = get_command_name(invocation)
        resolved = resolve_command_name(invocation)
        if written is None or resolved is None:
            return False
        reach = model_cache(self, invocation).world_reach
        return (
            reach.may_trust_command_name_at(written, invocation)
            and reach.may_trust_command_name_at(resolved, invocation)
        )

    def _command_listed_by(
        self,
        invocation: Ps1CommandInvocation,
        narrowed_by: Node | None = None,
    ) -> str | None:
        """
        The one command name the `Get-Command` *invocation*, narrowed by the `Where-Object` stage
        *narrowed_by* where one is given, lists at the place it stands, or `None`.
        """
        if resolve_command_name(invocation) != _GET_COMMAND:
            return None
        selection = get_command_selection(invocation)
        if selection is None:
            return None
        narrowing = None
        if narrowed_by is not None:
            narrowing = name_narrowing(narrowed_by)
            where = narrowed_by.expression if isinstance(narrowed_by, Ps1PipelineElement) else narrowed_by
            if narrowing is None or not isinstance(where, Ps1CommandInvocation):
                return None
            if not self._callee_is_trusted(where):
                return None
        name = listed_command(selection, narrowing)
        if name is None:
            return None
        patterns = [pattern for pattern in (selection.name, narrowing and narrowing.pattern) if pattern]
        if not command_listing_holds_at(invocation, patterns, model_cache(self, invocation)):
            return None
        return name

    def _try_resolve_narrowed_command_listing(self, node: Ps1Pipeline) -> Expression | None:
        """
        `Get-Command [S] | ? { $_.Name -like P }` → `Get-Command 'N'`, where `N` is the one command
        the narrowed listing holds: the same object, without the filter.
        """
        if len(node.elements) != 2:
            return None
        source, narrowing = node.elements
        if source.redirections or narrowing.redirections:
            return None
        invocation = source.expression
        if not isinstance(invocation, Ps1CommandInvocation):
            return None
        name = self._command_listed_by(invocation, narrowing)
        if name is None:
            return None
        return Ps1Pipeline(offset=node.offset, elements=[Ps1PipelineElement(
            offset=node.offset,
            expression=Ps1CommandInvocation(
                offset=invocation.offset,
                name=Ps1StringLiteral(offset=invocation.offset, value='Get-Command', raw='Get-Command'),
                arguments=[Ps1CommandArgument(
                    offset=invocation.offset,
                    kind=Ps1CommandArgumentKind.POSITIONAL,
                    value=make_string_literal(name),
                )],
            ),
        )])

    def _try_resolve_command_run_by_a_lookup(self, node: Ps1CommandInvocation) -> None:
        """
        `& (Get-Command S) …` → `& 'N' …`: a call operator runs the command a lookup hands it, and
        that command is the one the lookup lists. A lookup that lists none raises at the call as it
        does at the lookup, but not with the same error, so it stays.
        """
        if node.invocation_operator not in ('&', '.'):
            return
        name = node.name
        if not isinstance(name, Ps1ParenExpression):
            return
        inner = name.expression
        if isinstance(inner, Ps1Pipeline) and len(inner.elements) == 1 and not inner.elements[0].redirections:
            inner = inner.elements[0].expression
        if not isinstance(inner, Ps1CommandInvocation):
            return
        listed = self._command_listed_by(inner)
        if listed is None:
            return
        if substitute_field(node, 'name', make_string_literal(listed)):
            self.mark_changed()

    def _looks_up_commands(self, call: Ps1InvokeMember) -> bool:
        """
        Whether *call* is a method of the engine's `CommandInvocationIntrinsics`, as
        `$ExecutionContext.InvokeCommand` holds them, called directly or through its `Invoke`.
        """
        receiver = call.object
        member = get_member_name(call.member)
        if member is not None and member.lower() == 'invoke':
            if not isinstance(receiver, Ps1MemberAccess):
                return False
            receiver = receiver.object
        if receiver is None:
            return False
        found = resolve_expression_type(receiver, self._type_of_variable)
        return found is not None and is_type(str(found), _COMMAND_LOOKUP_TYPE)

    def _command_looked_up_by(self, call: Ps1InvokeMember) -> str | None:
        """
        The one command name the intrinsic lookup *call* lists at the place it stands, or `None`.
        """
        if not self._looks_up_commands(call):
            return None
        selection = lookup_selection(call)
        if selection is None or selection.name is None:
            return None
        name = listed_command(selection)
        if name is None:
            return None
        if not command_listing_holds_at(call, [selection.name], model_cache(self, call)):
            return None
        return name

    def _try_resolve_lookup_used_as_a_name(self, node: Ps1InvokeMember) -> Expression | None:
        """
        An intrinsic lookup whose result is used as its name: run by a call operator, handed to
        another lookup as the name it looks up, or a `GetCommandName` standing as a statement,
        whose one-name list the output unrolls into that name.
        """
        carrier = _value_carrier(node)
        parent = carrier.parent
        runs = (
            isinstance(parent, Ps1CommandInvocation)
            and parent.name is carrier
            and parent.invocation_operator in ('&', '.')
        )
        named = (
            isinstance(parent, Ps1InvokeMember)
            and bool(parent.arguments)
            and parent.arguments[0] is carrier
            and self._looks_up_commands(parent)
        )
        unrolled = False
        if not runs and not named:
            selection = lookup_selection(node)
            unrolled = (
                selection is not None
                and not selection.cmdlets_only
                and selection.pattern
                and _stands_as_a_statement(carrier)
                and (get_member_name(node.member) or '').lower() == 'getcommandname'
            )
        if not runs and not named and not unrolled:
            return None
        name = self._command_looked_up_by(node)
        if name is None:
            return None
        return make_string_literal(name)

    def _try_resolve_listed_name(self, node: Ps1MemberAccess) -> Expression | None:
        """
        The `.Name` of a lookup's result, where the lookup lists one name: a `Get-Command`, an
        intrinsic lookup, or a narrowed listing of a value's members.
        """
        member = get_member_name(node.member)
        if member is None or member.lower() != _NAME_MEMBER or node.object is None:
            return None
        inner = unwrap_parens(node.object)
        if isinstance(inner, Ps1Pipeline) and len(inner.elements) == 1 and not inner.elements[0].redirections:
            inner = inner.elements[0].expression
        name: str | None = None
        if isinstance(inner, Ps1CommandInvocation):
            name = self._command_listed_by(inner)
        elif isinstance(inner, Ps1InvokeMember):
            name = self._command_looked_up_by(inner)
        elif isinstance(inner, Ps1Pipeline):
            name = self._member_listed_by(inner)
        return None if name is None else make_string_literal(name)

    def _member_listed_by(self, pipeline: Ps1Pipeline) -> str | None:
        """
        The one member name the pipeline lists, where it pipes a listing of a value's members into
        a `Where-Object` filter on the name.
        """
        if len(pipeline.elements) < 2 or any(element.redirections for element in pipeline.elements):
            return None
        *stages, last = pipeline.elements
        narrowing = name_narrowing(last)
        where = last.expression
        if narrowing is None or not isinstance(where, Ps1CommandInvocation):
            return None
        if not self._callee_is_trusted(where):
            return None
        if not model_cache(self, pipeline).world_reach.closed_at(pipeline):
            return None
        selection = member_selection(stages, self._type_of_variable)
        if selection is None:
            return None
        return listed_member(selection, narrowing)

    def _variable_named_by(
        self,
        written: str,
        site: Node,
    ) -> str | None:
        """
        The name of the variable the lookup at *site* of the name or pattern *written* addresses:
        the one variable a pattern lists there, or the name a literal spells, in the session's
        spelling where it is one of the session's variables.
        """
        if is_wildcard_pattern(written):
            listed = listed_variable(written)
            if listed is None or not variable_listing_holds_at(written, site, model_cache(self, site)):
                return None
            return listed
        literal = literal_name(written)
        return None if literal is None else _session_spelling(literal)

    def _try_resolve_variable_value(
        self,
        node: Ps1MemberAccess,
    ) -> Expression | None:
        """
        Resolve property access on `Get-Item Variable:X` or `Get-Variable X`:

        - `.Value` resolves to `$X` (the variable's value)
        - `.Name` resolves to `'X'` as a string literal (the variable's name)

        `Get-Item Variable:X` and `Get-Variable X` return a `PSVariable` wrapper object whose
        `.Value` property gives the actual variable content and `.Name` property gives its name.
        """
        member_name = get_member_name(node.member)
        if member_name is None:
            return None
        member_lower = member_name.lower()
        if member_lower not in ('value', 'name'):
            return None
        if node.object is None:
            return None
        found = self._resolve_get_variable_pattern(node.object)
        if found is None:
            return None
        resolved, scope = found
        if member_lower == 'value':
            if scope is None:
                return None
            return Ps1Variable(
                offset=node.offset,
                name=resolved,
                scope=scope,
            )
        return make_string_literal(resolved)

    def _resolve_get_variable_pattern(
        self,
        expr: Expression,
    ) -> tuple[str, Ps1ScopeModifier | None] | None:
        """
        Given the object expression of a member access, check if it is a `Get-Item Variable:X` or
        `Get-Variable X` invocation and resolve the variable name (supporting wildcards) together
        with the qualifier a reference replacing it must carry.

        The qualifier is `None` for a `-Scope` no reference can name, which only the `.Value`
        rewrite has to decline: the name a command is about is that name whichever scope it reads.
        """
        inner = unwrap_parens(expr)
        if not isinstance(inner, Ps1CommandInvocation) or not _expresses_every_effect(inner):
            return None
        command = resolve_command_name(inner)
        if command is None:
            return None
        if command in _GET_ITEM_COMMANDS:
            arg_value = _subject_argument_value(inner, command, 'path')
            if arg_value is None or not arg_value.lower().startswith(_VARIABLE_DRIVE):
                return None
            pattern = arg_value[len(_VARIABLE_DRIVE):].lstrip('/\\')
        elif command == _GET_VARIABLE:
            pattern = _subject_argument_value(inner, command, 'name')
            if pattern is None:
                return None
        else:
            return None
        resolved = self._variable_named_by(pattern, inner)
        if resolved is None:
            return None
        return _expressible_reference(inner, resolved)

    def _try_resolve_get_variable_value_only(
        self,
        node: Ps1CommandInvocation,
    ) -> Expression | None:
        """
        Resolve `Get-Variable X -ValueOnly` to `$X`.
        """
        command = resolve_command_name(node)
        if command != _GET_VARIABLE:
            return None
        if switch_setting(node, 'valueonly') is not True or not _expresses_every_effect(node):
            return None
        arg_value = _subject_argument_value(node, command, 'name')
        if arg_value is None:
            return None
        resolved = self._variable_named_by(arg_value, node)
        if resolved is None:
            return None
        reference = _expressible_reference(node, resolved)
        if reference is None:
            return None
        name, scope = reference
        if scope is None:
            return None
        return Ps1Variable(
            offset=node.offset,
            name=name,
            scope=scope,
        )

    def _try_resolve_set_variable(
        self,
        node: Ps1CommandInvocation,
    ) -> Expression | None:
        """
        Resolve Set-Item Variable:X value or Set-Variable X value to $X = value.
        """
        command = resolve_command_name(node)
        if command == _SET_ITEM:
            return self._handle_set_item_variable(node, command)
        if command == _SET_VARIABLE:
            return self._handle_set_variable(node, command)
        return None

    def _keeps_every_read_the_environment_owns(
        self,
        node: Ps1CommandInvocation,
        carried: Expression,
    ) -> bool:
        """
        Whether rewriting *node* as an assignment keeps every read of an `$env:` name the script
        stores that its arguments hold: the expression an assignment is built from is carried
        into it, while a parameter an assignment has no spelling for is dropped together with the
        read bound to it.
        """
        for argument in node.arguments:
            if not isinstance(argument, Ps1CommandArgument):
                continue
            value = argument.value
            if value is None or value is carried:
                continue
            if takes_a_read_the_environment_owns(value, self._flow, self.options):
                return False
        return True

    @staticmethod
    def _assigned_value(
        node: Ps1CommandInvocation,
        positionals: list[Expression],
    ) -> Expression | None:
        """
        The one value a variable write *node* assigns: the `-Value` it binds, or the one free
        argument left for it. A second free argument is a call the binder rejects, which
        `refinery.lib.scripts.ps1.deobfuscation.substitution` refuses to fold away.
        """
        named = bound_argument_value(node, 'value')
        if named is not None:
            return named
        if len(positionals) != 1:
            return None
        return positionals[0]

    def _handle_set_item_variable(
        self,
        node: Ps1CommandInvocation,
        command: str,
    ) -> Expression | None:
        """
        Set-Item Variable:/X val → $X = val

        `-Path` and `-Value` name the same two arguments the positional spelling does, and a command
        binding either of them by name leaves nothing free for the positional reading to find.
        """
        positionals = free_positional_values(node, command)
        path_expr = bound_argument_value(node, 'path')
        if path_expr is None:
            if not positionals:
                return None
            path_expr, positionals = positionals[0], positionals[1:]
        value = self._assigned_value(node, positionals)
        if value is None:
            return None
        path_str = string_value(path_expr)
        if path_str is None or not path_str.lower().startswith(_VARIABLE_DRIVE):
            return None
        written = path_str[len(_VARIABLE_DRIVE):].lstrip('/\\')
        if is_wildcard_pattern(written):
            return None
        var_name = literal_name(written)
        if var_name is None:
            return None
        if not self._keeps_every_read_the_environment_owns(node, value):
            return None
        return self._build_assignment(node.offset, _session_spelling(var_name), value, Ps1ScopeModifier.NONE)

    def _handle_set_variable(
        self,
        node: Ps1CommandInvocation,
        command: str,
    ) -> Expression | None:
        """
        Set-Variable X val or Set-Variable -Name X -Value val → $X = val
        """
        if not _expresses_every_effect(node):
            return None
        positionals = free_positional_values(node, command)
        name_expr = bound_argument_value(node, 'name')
        if name_expr is not None:
            written = argument_text(name_expr)
        elif positionals:
            written = argument_text(positionals[0])
            positionals = positionals[1:]
        else:
            return None
        if written is None or is_wildcard_pattern(written):
            return None
        var_name = literal_name(written)
        if var_name is None:
            return None
        reference = _expressible_reference(node, _session_spelling(var_name))
        if reference is None:
            return None
        resolved, scope = reference
        if scope is None:
            return None
        value = self._assigned_value(node, positionals)
        if value is None:
            return None
        if not self._keeps_every_read_the_environment_owns(node, value):
            return None
        return self._build_assignment(node.offset, resolved, value, scope)

    @staticmethod
    def _build_assignment(
        offset: int,
        var_name: str,
        value: Expression,
        scope: Ps1ScopeModifier,
    ) -> Ps1AssignmentExpression:
        target = Ps1Variable(
            offset=offset,
            name=var_name,
            scope=scope,
        )
        return Ps1AssignmentExpression(
            offset=offset,
            target=target,
            operator='=',
            value=value,
        )
