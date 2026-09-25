"""
The names a script addresses as *strings* rather than as variables.

`Set-Variable X 'v'` writes `$X`, `Get-Variable X` reads it, `Remove-Variable X` unbinds it, and
`Get-Process -OutVariable p` fills `$p` — none of which contains a `Ps1Variable` occurrence of the
name at all. Every layer above reasons about a name through its occurrences, so a name only ever
addressed this way has no binding, no reads and no writes, and a value is folded straight across the
command that changed it.

This module recognises those commands and reports what each does to which name, so the semantic model
can create the binding and file the occurrence. It is therefore a *definition source* consulted while
the model is built, not a decoration applied afterwards: there is nowhere to hang a decoration when
`Get-Process -OutVariable x` is the only mention of `x` in the script.

The session state's `PSVariable` addresses names the same way from a method call:
`$ExecutionContext.SessionState.PSVariable.Set('x', 'v')` writes `$x`. And several of these hand out
the *variable itself* rather than its value — `Get-Variable x` without `-ValueOnly` does — which a
store into its `Value` rebinds later, wherever the variable has been handed by then.

A command spelling this cannot resolve is not a command this may declare harmless — it is one whose
effect is unknown, and the conservative answer is to record that the enclosing scope writes a name
nobody can read. That is the opposite polarity from a grant table
such as `refinery.lib.scripts.ps1.analysis.effects`'s purity allow-list, and the two must not be
confused: an allow-list that misses an entry withholds a rewrite, and a deny-list that misses one
performs a corruption.

Roles come from `refinery.lib.scripts.ps1.analysis.model.Ps1OccurrenceRole`, the same vocabulary a
variable occurrence uses, so a consumer asks one question of both kinds of reference.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.ast import (
    argument_text,
    binds_parameter,
    bound_argument_value,
    free_positional_values,
    get_member_name,
    has_wildcard,
    resolve_command_name,
    resolved_command_names,
    string_value,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
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
    Ps1SubExpression,
    Ps1UnaryExpression,
    Ps1Variable,
)


class Ps1NameRole(enum.Enum):
    """
    What a command does to the name it addresses.

    Kept apart from `refinery.lib.scripts.ps1.analysis.model.Ps1OccurrenceRole` by one member:
    `UNBINDS` has no counterpart among variable occurrences, because no syntax removes a variable.
    A consumer that only tracks values may read it as a replacing write — the value afterwards is
    not the value before — but one that reasons about whether the name exists needs it apart.
    """
    READS      = enum.auto()  # noqa
    WRITES     = enum.auto()  # noqa
    APPENDS    = enum.auto()  # noqa
    UNBINDS    = enum.auto()  # noqa


class Ps1NameTarget(enum.Enum):
    """
    Which scope the addressed name resolves in.

    `LOCAL` is the scope the command itself is written in — measured, and the default: a bare
    `Set-Variable x 'v'` inside a function writes that function's scope and leaves the caller's
    binding alone. `SCRIPT` covers the explicitly script- or global-qualified forms. `UNREADABLE`
    is every form this cannot place, of which `-Scope 1` is the one that matters: it writes the
    *caller's* scope, which is not a lexical ancestor and which the scope chain cannot name.
    """
    LOCAL      = enum.auto()  # noqa
    SCRIPT     = enum.auto()  # noqa
    UNREADABLE = enum.auto()  # noqa


@dataclass(frozen=True)
class Ps1NamedReference:
    """
    One command's reference to one name. `key` is keyed as
    `refinery.lib.scripts.ps1.ast.binding_key` keys a variable occurrence, so a name reached both
    ways lands on one binding. `node` is the command or the call performing it.
    """
    key: str
    role: Ps1NameRole
    target: Ps1NameTarget
    node: Node
    #: Whether the reference also hands out the variable itself, and to something other than a
    #: read of its `Value` where it stands. A store into that `Value` rebinds the name later, from
    #: wherever the variable has been handed: measured, `$v = Get-Variable b; $v.Value = 'b'`
    #: leaves `$b` holding `b`. Which binding of the name the variable is depends on the scopes
    #: that stand around the reference when it runs.
    hands_out: bool = False


#: Commands whose first argument is the *name* of a variable, mapped to what they do to it. Resolved
#: through `refinery.lib.scripts.ps1.ast.resolved_command_names`, so aliases (`sv`, `gv`, `rv`),
#: case variants and the bare noun `variable` all arrive here already canonical.
_VARIABLE_COMMANDS: dict[str, Ps1NameRole] = {
    'clear-variable': Ps1NameRole.WRITES,
    'get-variable': Ps1NameRole.READS,
    'new-variable': Ps1NameRole.WRITES,
    'remove-variable': Ps1NameRole.UNBINDS,
    'set-variable': Ps1NameRole.WRITES,
}

#: Commands whose first argument is a *provider path*, which addresses a variable when it names the
#: `Variable:` or `Env:` drive. `Remove-Item Variable:x` is how `del variable:x` arrives.
_ITEM_COMMANDS: dict[str, Ps1NameRole] = {
    'clear-item': Ps1NameRole.WRITES,
    'get-childitem': Ps1NameRole.READS,
    'get-item': Ps1NameRole.READS,
    'new-item': Ps1NameRole.WRITES,
    'remove-item': Ps1NameRole.UNBINDS,
    'set-item': Ps1NameRole.WRITES,
}

#: The commands that write out the variable they address, on the `Variable:` drive for the item
#: commands, unless `Get-Variable` is told `-ValueOnly`.
_HANDING_OUT_COMMANDS = frozenset({
    'get-childitem',
    'get-item',
    'get-variable',
    'new-item',
})

#: The commands that write out the variable they address when told `-PassThru`.
_HANDING_OUT_WITH_PASSTHRU = frozenset({
    'clear-variable',
    'new-variable',
    'set-item',
    'set-variable',
})

#: The automatic variables whose `SessionState` holds the variable table of the scope that reads it.
_SESSION_STATE_HOLDERS = frozenset({
    'executioncontext',
    'pscmdlet',
})

#: The members of the holders that reach a variable table, lowercased: the session state, and
#: `InvokeProvider`, which reaches the `Variable:` drive.
_HOLDER_MEMBERS_WITH_VARIABLES = frozenset({
    'invokeprovider',
    'sessionstate',
})

#: The members of the session state that reach no variable, lowercased. Every other member may:
#: `PSVariable` addresses them by name, `InvokeProvider` reaches the `Variable:` drive, and `Module`
#: holds a session state of its own.
_SESSION_STATE_MEMBERS_WITHOUT_VARIABLES = frozenset({
    'applications',
    'drive',
    'languagemode',
    'path',
    'provider',
    'scripts',
    'usefulllanguagemodeindebugger',
})

#: What each method of the session state's `PSVariable` does to the name it is handed first.
_VARIABLE_INTRINSIC_METHODS: dict[str, Ps1NameRole] = {
    'get': Ps1NameRole.READS,
    'getvalue': Ps1NameRole.READS,
    'remove': Ps1NameRole.UNBINDS,
    'set': Ps1NameRole.WRITES,
}

#: Provider drives whose items are the names this reasons about, mapped to the prefix the key takes.
_NAME_DRIVES: dict[str, str] = {
    'env': 'env:',
    'variable': '',
}

#: Scope arguments that place the write somewhere the lexical chain can name. Anything else —
#: a number, an expression, a spelling not listed — is `Ps1NameTarget.UNREADABLE`.
_SCOPE_TARGETS: dict[str, Ps1NameTarget] = {
    'global': Ps1NameTarget.SCRIPT,
    'local': Ps1NameTarget.LOCAL,
    'private': Ps1NameTarget.LOCAL,
    'script': Ps1NameTarget.SCRIPT,
}

#: Name qualifiers written into the name string itself — `Set-Variable global:x` — which say the
#: same thing the `-Scope` argument does.
_QUALIFIER_TARGETS: dict[str, Ps1NameTarget] = {
    Ps1ScopeModifier.GLOBAL.value: Ps1NameTarget.SCRIPT,
    Ps1ScopeModifier.LOCAL.value: Ps1NameTarget.LOCAL,
    Ps1ScopeModifier.PRIVATE.value: Ps1NameTarget.LOCAL,
    Ps1ScopeModifier.SCRIPT.value: Ps1NameTarget.SCRIPT,
}


def named_references(node: Node) -> list[Ps1NamedReference]:
    """
    Every reference *node* makes to a name addressed as a string, or an empty list when it makes
    none. A single command may make several: `Get-Variable x -OutVariable y` reads one and writes
    another. A call of the session state's `PSVariable` makes one.

    Both names a call may run are asked about, because `variable x` and `item variable:x` reach
    `Get-Variable` and `Get-Item` through the implicit `Get-` retry and a table keyed on the bare
    spelling misses them. At most one of the two is in either table, and reading a name a `function
    variable` would have taken back only over-reports a read, which withholds a removal.
    """
    if isinstance(node, Ps1InvokeMember):
        return list(_intrinsic_references(node))
    if not isinstance(node, Ps1CommandInvocation):
        return []
    found: list[Ps1NamedReference] = []
    for command in resolved_command_names(node):
        found.extend(_subject_references(node, command))
    found.extend(_out_variable_references(node))
    return found


def unreadable_name_target(node: Node) -> Ps1NameTarget | None:
    """
    Where *node* writes a variable whose name this cannot read, or `None` when it writes no such
    name. The name is unknown, so *every* binding in the scope it lands in is in doubt, which is a
    fact about that scope rather than about any one binding.

    - `Set-Variable $n 'v'` computes the name, and `Remove-Variable x*` names every variable the
      pattern matches; either lands where the command's `-Scope` says.
    - `$ExecutionContext.SessionState.PSVariable.Set($n, 'v')` computes the name, and `Set($v)` is
      handed a variable whose name is its own; either lands in the scope the call runs in.
    - A variable handed out by a command that reads names nobody can attribute — `$v =
      Get-Variable` — may be one of any scope the command could see, and a store into its `Value`
      lands there later. So may a store through the session state itself, handed anywhere but to
      one of the methods of its `PSVariable`. These are `Ps1NameTarget.UNREADABLE`.

    A `Set-Item` whose path is computed might address the `Variable:` drive and might equally be
    writing a file, and answering for every one of them would put most scripts permanently in doubt;
    that is left as a known hole rather than paid for everywhere. A command that only reads is not
    reported: not knowing which name was read changes no value.

    The implicit `Get-` retry needs no reading here, unlike in `named_references`: it prefixes
    `Get-`, so the only commands it can reach are readers, and a reader hands out a variable of a
    name this cannot read only where the table names it.
    """
    if isinstance(node, Ps1Variable):
        return Ps1NameTarget.UNREADABLE if _leaks_the_variable_table(node) else None
    if isinstance(node, Ps1InvokeMember):
        return _intrinsic_unreadable_target(node)
    if not isinstance(node, Ps1CommandInvocation):
        return None
    command = resolve_command_name(node)
    if command is None:
        return None
    role = _VARIABLE_COMMANDS.get(command)
    if role is not None:
        if _subject_name(node, command, 'name') is not None and not _is_a_pattern(node, command):
            return None
    else:
        role = _ITEM_COMMANDS.get(command)
        if role is None or not _addresses_unreadable_variables(node, command):
            return None
    if role is not Ps1NameRole.READS:
        return _declared_target(node)
    if _hands_out(node, command):
        return Ps1NameTarget.UNREADABLE
    return None


def reads_unreadable_name(node: Node) -> bool:
    """
    Whether *node* reads a variable whose name this cannot read: `Get-Variable` with no name, with
    a pattern or with a name it computes, `Get-ChildItem variable:` and its patterns, a `GetValue`
    or a `Get` of the session state's `PSVariable` handed a name it computes, and the session state
    handed anywhere but to one of the methods of its `PSVariable`. Such a read may observe every
    name, so no store is dead for want of a read of it.
    """
    if isinstance(node, Ps1Variable):
        return _leaks_the_variable_table(node)
    if isinstance(node, Ps1InvokeMember):
        method = _intrinsic_method(node)
        if method is None:
            return False
        role = _VARIABLE_INTRINSIC_METHODS.get(method)
        if role is None:
            return True
        if role is not Ps1NameRole.READS or _intrinsic_name(node) is not None:
            return False
        return method != 'get' or _left_by(node) is not _Left.NAMES
    if not isinstance(node, Ps1CommandInvocation):
        return False
    for command in resolved_command_names(node):
        if _VARIABLE_COMMANDS.get(command) is Ps1NameRole.READS:
            if _subject_name(node, command, 'name') is not None:
                if not _is_a_pattern(node, command):
                    continue
        elif _ITEM_COMMANDS.get(command) is not Ps1NameRole.READS:
            continue
        elif not _addresses_unreadable_variables(node, command):
            continue
        if _reads_values(node, command):
            return True
    return False


def addresses_unreadable_name(cmd: Node) -> bool:
    """
    Whether *cmd* writes a variable whose name this cannot read. `unreadable_name_target` says
    where.
    """
    return unreadable_name_target(cmd) is not None


def _subject_references(
    cmd: Ps1CommandInvocation, command: str,
) -> Iterator[Ps1NamedReference]:
    """
    The reference a variable or item command makes to the name it is *about*.
    """
    role = _VARIABLE_COMMANDS.get(command)
    if role is not None:
        written = _subject_name(cmd, command, 'name')
        if written is not None and not has_wildcard(written):
            yield from _resolve(
                cmd, written, role, _declared_target(cmd), _hands_out(cmd, command))
        return
    role = _ITEM_COMMANDS.get(command)
    if role is None:
        return
    written = _subject_name(cmd, command, 'path')
    if written is None:
        return
    drive, _, rest = written.partition(':')
    prefix = _NAME_DRIVES.get(drive.lower())
    if prefix is None or not rest or has_wildcard(rest):
        return
    yield Ps1NamedReference(
        key=F'{prefix}{rest.lower()}',
        role=role,
        target=Ps1NameTarget.SCRIPT if prefix else _declared_target(cmd),
        node=cmd,
        hands_out=not prefix and _hands_out(cmd, command),
    )


def _out_variable_references(cmd: Ps1CommandInvocation) -> Iterator[Ps1NamedReference]:
    """
    The references a command's out-variable parameters make. `-OutVariable p` replaces `$p`;
    `-OutVariable +p` keeps what was there and appends, which reads the name as well as writing it.
    """
    for parameter in data.OUT_VARIABLE_PARAMETERS:
        value = bound_argument_value(cmd, parameter)
        if value is None:
            continue
        written = string_value(value)
        if written is None:
            continue
        role = Ps1NameRole.WRITES
        if written.startswith('+'):
            role = Ps1NameRole.APPENDS
            written = written[1:]
        if written:
            yield from _resolve(cmd, written, role, Ps1NameTarget.LOCAL)


def _subject_name(cmd: Ps1CommandInvocation, command: str, parameter: str) -> str | None:
    """
    The literal name a command is about, written either as `-Name x` or as the first positional
    argument, or `None` when it is not a literal this can read.

    The positional fallback skips the arguments a preceding value-taking switch consumed, which is
    what tells `Set-Variable -Scope Global x 5` — where the name is `x` — from a reading of the
    argument list that would call it `Global`.

    A name written as a number is a literal like any other and is read through
    `refinery.lib.scripts.ps1.ast.argument_text`. Reading it with `string_value` answers `None`,
    which says the name is *computed* and puts every binding in the enclosing scope in doubt over a
    name that is sitting in the source.
    """
    explicit = bound_argument_value(cmd, parameter)
    if explicit is not None:
        return argument_text(explicit)
    for value in free_positional_values(cmd, command):
        return argument_text(value)
    return None


def _declared_target(cmd: Ps1CommandInvocation) -> Ps1NameTarget:
    """
    The scope a command's `-Scope` argument names, `Ps1NameTarget.LOCAL` when it has none — the
    measured default — and `Ps1NameTarget.UNREADABLE` for a spelling the lexical chain cannot place,
    of which `-Scope 1` is the one that occurs.
    """
    declared = bound_argument_value(cmd, 'scope')
    if declared is None:
        return Ps1NameTarget.LOCAL
    written = string_value(declared)
    if written is None:
        return Ps1NameTarget.UNREADABLE
    return _SCOPE_TARGETS.get(written.lower(), Ps1NameTarget.UNREADABLE)


def _resolve(
    node: Node,
    written: str,
    role: Ps1NameRole,
    target: Ps1NameTarget,
    hands_out: bool = False,
) -> Iterator[Ps1NamedReference]:
    """
    One reference, with a qualifier written into the name string resolved against *target*.
    """
    qualifier, _, rest = written.partition(':')
    if rest:
        lowered = qualifier.lower()
        prefix = _NAME_DRIVES.get(lowered)
        if prefix is not None:
            yield Ps1NamedReference(
                key=F'{prefix}{rest.lower()}',
                role=role,
                target=Ps1NameTarget.SCRIPT if prefix else target,
                node=node,
                hands_out=hands_out and not prefix,
            )
            return
        placed = _QUALIFIER_TARGETS.get(lowered)
        if placed is None:
            return
        yield Ps1NamedReference(
            key=rest.lower(), role=role, target=placed, node=node, hands_out=hands_out)
        return
    yield Ps1NamedReference(
        key=written.lower(), role=role, target=target, node=node, hands_out=hands_out)


def _is_a_pattern(cmd: Ps1CommandInvocation, command: str) -> bool:
    """
    Whether the name a variable command is about is a wildcard pattern, which addresses every
    variable it matches rather than one.
    """
    written = _subject_name(cmd, command, 'name')
    return written is not None and has_wildcard(written)


def _addresses_unreadable_variables(cmd: Ps1CommandInvocation, command: str) -> bool:
    """
    Whether an item command addresses variables on the `Variable:` drive whose names this cannot
    read: the whole drive, as `Get-ChildItem variable:` lists it, or a pattern over it.
    """
    written = _subject_name(cmd, command, 'path')
    if written is None:
        return False
    drive, _, rest = written.partition(':')
    if drive.lower() != 'variable':
        return False
    return not rest or has_wildcard(rest)


class _Left(enum.Enum):
    """
    What is used of the variables a command or a call writes out, where it stands.
    """
    #: Only their names are read, as `(Get-Variable '*mdr*').Name` reads them: no value is
    #: observed and no variable is handed on.
    NAMES = enum.auto()
    #: Only their values are read, as `(Get-Variable b).Value` reads it.
    VALUES = enum.auto()
    #: The variables themselves leave: kept, piped, handed on, stored into or asked a method.
    VARIABLES = enum.auto()


def _left_by(node: Node) -> _Left:
    """
    What is used of the variables *node* writes out, where it stands. Only a property read where
    the node stands is anything less than the variables leaving; a store into `Value` rebinds the
    name, and a method of the variable is code this does not read.
    """
    cursor: Node = node
    parent = cursor.parent
    if isinstance(parent, Ps1PipelineElement):
        pipeline = parent.parent
        if parent.redirections or not isinstance(pipeline, Ps1Pipeline):
            return _Left.VARIABLES
        if len(pipeline.elements) != 1:
            return _Left.VARIABLES
        cursor, parent = pipeline, pipeline.parent
    if isinstance(parent, Ps1ExpressionStatement):
        holder = parent.parent
        if not isinstance(holder, Ps1SubExpression) or len(holder.body) != 1:
            return _Left.VARIABLES
        cursor, parent = holder, holder.parent
    while isinstance(parent, Ps1ParenExpression):
        cursor, parent = parent, parent.parent
    if not isinstance(parent, Ps1MemberAccess) or parent.object is not cursor:
        return _Left.VARIABLES
    if parent.access is not Ps1AccessKind.INSTANCE or _is_stored_into(parent):
        return _Left.VARIABLES
    name = get_member_name(parent.member)
    if name is None:
        return _Left.VARIABLES
    return {'name': _Left.NAMES, 'value': _Left.VALUES}.get(name.lower(), _Left.VARIABLES)


def _writes_out_variables(cmd: Ps1CommandInvocation, command: str) -> bool:
    """
    Whether *cmd* writes out the variables it addresses rather than their values or nothing.
    """
    if command in _HANDING_OUT_COMMANDS:
        return command != 'get-variable' or not _binds_switch(cmd, 'valueonly')
    return command in _HANDING_OUT_WITH_PASSTHRU and _binds_switch(cmd, 'passthru')


def _hands_out(cmd: Ps1CommandInvocation, command: str) -> bool:
    """
    Whether *cmd* hands the variables it addresses to something other than a read of a property
    where it stands.
    """
    return _writes_out_variables(cmd, command) and _left_by(cmd) is _Left.VARIABLES


def _reads_values(cmd: Ps1CommandInvocation, command: str) -> bool:
    """
    Whether what *cmd* writes out may be used for the values of the variables it addresses: always
    for values, and for the variables themselves unless only their names are read.
    """
    return not _writes_out_variables(cmd, command) or _left_by(cmd) is not _Left.NAMES


def _binds_switch(cmd: Ps1CommandInvocation, parameter: str) -> bool:
    return any(
        isinstance(argument, Ps1CommandArgument)
        and argument.kind is not Ps1CommandArgumentKind.POSITIONAL
        and binds_parameter(argument.name, parameter)
        for argument in cmd.arguments
    )


def _is_stored_into(node: Node) -> bool:
    """
    Whether *node* is, through parentheses, what an assignment or an increment stores into.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, Ps1ParenExpression):
        cursor, parent = parent, parent.parent
    if isinstance(parent, Ps1AssignmentExpression):
        return parent.target is cursor
    if isinstance(parent, Ps1UnaryExpression) and parent.operator in ('++', '--'):
        return parent.operand is cursor
    return False


def _is_a_session_state_holder(node: Node | None) -> bool:
    return (
        isinstance(node, Ps1Variable)
        and node.scope is Ps1ScopeModifier.NONE
        and node.name.lower() in _SESSION_STATE_HOLDERS
    )


def _member_of(node: Node | None, name: str) -> Node | None:
    """
    What *node* reads the instance member *name* off, through parentheses, or `None` where it is no
    such member access.
    """
    if node is None:
        return None
    node = unwrap_parens(node)
    if not isinstance(node, Ps1MemberAccess) or node.access is not Ps1AccessKind.INSTANCE:
        return None
    spelled = get_member_name(node.member)
    if spelled is None or spelled.lower() != name or node.object is None:
        return None
    return unwrap_parens(node.object)


def _intrinsic_method(call: Ps1InvokeMember) -> str | None:
    """
    The lowercased method *call* runs on `$ExecutionContext.SessionState.PSVariable`, or on the
    same reached from `$PSCmdlet`, the empty string for one whose name the source does not spell,
    and `None` where *call* is no call of it. `$PSCmdlet.GetVariableValue` reads a variable by name
    the way `GetValue` does and is answered as `getvalue`.
    """
    if call.access is not Ps1AccessKind.INSTANCE:
        return None
    name = get_member_name(call.member)
    table = _member_of(_member_of(call.object, 'psvariable'), 'sessionstate')
    if _is_a_session_state_holder(table):
        return '' if name is None else name.lower()
    holder = unwrap_parens(call.object) if call.object is not None else None
    if (
        name is not None
        and name.lower() == 'getvariablevalue'
        and _is_a_session_state_holder(holder)
        and isinstance(holder, Ps1Variable)
        and holder.name.lower() == 'pscmdlet'
    ):
        return 'getvalue'
    return None


def _intrinsic_name(call: Ps1InvokeMember) -> str | None:
    """
    The name a call of the session state's `PSVariable` is handed, where the source spells it.
    `Set` and `Remove` handed a single argument other than a name are handed the variable itself.
    """
    if not call.arguments:
        return None
    return string_value(call.arguments[0])


def _intrinsic_references(call: Ps1InvokeMember) -> Iterator[Ps1NamedReference]:
    """
    The reference a call of the session state's `PSVariable` makes to the name it is handed, which
    it resolves the way the commands do: in the scope the call runs in unless the name is qualified.
    `Get` hands out the variable itself.
    """
    method = _intrinsic_method(call)
    if not method:
        return
    role = _VARIABLE_INTRINSIC_METHODS.get(method)
    written = _intrinsic_name(call)
    if role is None or written is None or has_wildcard(written):
        return
    hands_out = method == 'get' and _left_by(call) is _Left.VARIABLES
    yield from _resolve(call, written, role, Ps1NameTarget.LOCAL, hands_out)


def _intrinsic_unreadable_target(call: Ps1InvokeMember) -> Ps1NameTarget | None:
    """
    Where a call of the session state's `PSVariable` writes a variable whose name this cannot read:
    in the scope it runs in for a `Set` or a `Remove` handed no name it spells, and in any scope for
    a `Get` whose variable leaves or a method this cannot name.
    """
    method = _intrinsic_method(call)
    if method is None:
        return None
    role = _VARIABLE_INTRINSIC_METHODS.get(method)
    if role is None:
        return Ps1NameTarget.UNREADABLE
    written = _intrinsic_name(call)
    if written is not None and not has_wildcard(written):
        return None
    if role is not Ps1NameRole.READS:
        return Ps1NameTarget.LOCAL
    if method == 'get' and _left_by(call) is _Left.VARIABLES:
        return Ps1NameTarget.UNREADABLE
    return None


def _leaks_the_variable_table(var: Ps1Variable) -> bool:
    """
    Whether *var* is `$ExecutionContext` or `$PSCmdlet` used in a way that may reach a variable by a
    name this cannot read. A member that reaches no variable — `$ExecutionContext.InvokeCommand`,
    `$ExecutionContext.SessionState.Path` — leaks nothing, and neither does a call of one of the
    methods of the session state's `PSVariable`, which `named_references` reads. Anything else —
    the holder or its session state kept, handed on or asked for a member whose name the source
    does not spell — is the whole variable table.
    """
    if not _is_a_session_state_holder(var):
        return False
    state = _next_member(var)
    if state is None:
        return True
    access, name = state
    if name is None:
        return True
    if isinstance(access, Ps1InvokeMember) or name not in _HOLDER_MEMBERS_WITH_VARIABLES:
        return False
    if name == 'invokeprovider':
        return True
    table = _next_member(access)
    if table is None:
        return True
    access, name = table
    if name is None:
        return True
    if name in _SESSION_STATE_MEMBERS_WITHOUT_VARIABLES:
        return isinstance(access, Ps1InvokeMember)
    if name != 'psvariable' or isinstance(access, Ps1InvokeMember):
        return True
    call = access.parent
    return not isinstance(call, Ps1InvokeMember) or call.object is not access


def _next_member(node: Node) -> tuple[Ps1MemberAccess | Ps1InvokeMember, str | None] | None:
    """
    The member access or call made on *node*, through parentheses, with the lowercased name of its
    member, or `None` where *node* is not the object of one.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, Ps1ParenExpression):
        cursor, parent = parent, parent.parent
    if not isinstance(parent, (Ps1MemberAccess, Ps1InvokeMember)) or parent.object is not cursor:
        return None
    if parent.access is not Ps1AccessKind.INSTANCE:
        return None
    name = get_member_name(parent.member)
    return parent, None if name is None else name.lower()
