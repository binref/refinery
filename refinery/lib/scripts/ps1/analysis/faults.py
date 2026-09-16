"""
Where a terminating error raised at a point in a PowerShell script goes.

The routing itself is already in the control-flow graph:
`refinery.lib.scripts.ps1.analysis.cfg` joins every statement of a guarded region to the handler
that may be offered its errors, chains `catch` clauses and `trap` sets in the order the engine
consults them, and edges to the body exit where the error gets past all of them. What is here is
the reading of that graph — which handlers a point reaches, whether the error may leave the body,
and the transpose, which points a handler is reachable from.

This module answers three questions. *Does an error
raised here reach a handler that acts* is a property of a **position**, and it is what a pass asks
before it empties a guarded body. *Would deleting this statement change which handler runs* is a
property of a **statement**, and it additionally needs to know whether the statement can raise at
all — `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` asks that one, because the
predicate that answers it lives there. *Is this handler still reachable from anything that raises*
is the **transpose**, and it is what a pass asks before deleting a `trap`, where the statement being
removed cannot itself raise and every error it re-routes belongs to something else.

A body boundary is where this stops. The graphs are per body, so an error that leaves a function
reaches whatever guards the *call*, and no graph here holds both. `leaves_the_body` reports that
rather than guessing, and a caller reads it as *unknown* wherever a caller might be guarding.
"""
from __future__ import annotations

from typing import Callable, Iterator, NamedTuple

from refinery.lib.scripts import Node, tree_root
from refinery.lib.scripts.analysis.cfg import (
    CfgEdge,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    normal_reach,
)
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.ast import (
    STATEMENT_LIST_EXPRESSIONS,
    argument_text,
    assignment_target_variables,
    binding_key,
    binds_parameter,
    bound_argument_value,
    fault_operand,
    free_positional_values,
    get_member_name,
    is_soft_error_source,
    raises_a_caught_terminating_error,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.analysis.naming import Ps1NameRole, named_references
from refinery.lib.scripts.ps1.data import COMMON_PARAMETERS
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1RealLiteral,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1Variable,
)

#: The names the `-ErrorAction` parameter answers to, lowercased and without the dash: the parameter
#: itself and every alias the collected command data records for it. The alias is subscripted rather
#: than defaulted, so that a collected surface which stops carrying this parameter fails the load
#: rather than silently dropping the spelling, as `refinery.lib.scripts.ps1.data` does for its own
#: derived sets.
_ERROR_ACTION_NAME = 'erroraction'
_ERROR_ACTION = frozenset((_ERROR_ACTION_NAME, *COMMON_PARAMETERS[_ERROR_ACTION_NAME]))

#: Every name a *common* parameter answers to, so that an abbreviation of one can be told from an
#: abbreviation that reaches several. A command carrying `-ErrorAction` carries the whole set of
#: them — that is what makes a command advanced — so a prefix reaching another member of this set
#: reaches it on the very commands the question is about.
_COMMON_SURFACES = frozenset(
    surface
    for parameter, aliases in COMMON_PARAMETERS.items()
    for surface in (parameter, *aliases)
)

#: The `ActionPreference` member that makes an error terminating, and the number that member is.
#: `Stop` and `1` are the two spellings the corpus measures directly.
#:
#: Neither is read literally. The ordinal is read as a *number* rather than as a numeral, because
#: what selects the member is its value and `0x1`, `01` and `1` all denote it. The name is read by
#: prefix, because 5.1 resolves `-ErrorAction St` to `Stop`.
#:
#: An **ambiguous** member prefix is a third thing, and the reading costs recall rather than
#: correctness. `-ErrorAction S` reaches `SilentlyContinue`, `Stop` and `Suspend`, and 5.1 answers
#: it with a `ParameterBindingException` — `CannotConvertArgumentNoMessage`, measured — so the
#: command never runs at all and the error it reports instead is statement-terminating: the script
#: carries on. Reading the prefix as `Stop` keeps a handler over that, which is the safe direction
#: and is what `TestPs1AnAmbiguousActionPrefixKeepsTheTrapOverIt` records.
_STOP = 'stop'
_STOP_ORDINAL = 1

#: The automatic variable that decides what a command does with an error it reports. Set to `Stop`
#: it makes every one of them terminating — a failing cast included, which is otherwise reported
#: and stepped over.
_ERROR_ACTION_PREFERENCE = 'erroractionpreference'

#: The automatic variable that binds a default argument into every command that takes the parameter.
#: A `Stop` written under a key that names `-ErrorAction` — `*:ErrorAction` for every command, or
#: `Get-Item:ErrorAction` for one — makes that command's reported error terminating, but a failing
#: cast is not a command and is left stepped over. That is why an arming written here reaches the
#: per-command terminating path rather than the whole-script `_stops_on_every_error` gate.
_DEFAULT_PARAMETER_VALUES = 'psdefaultparametervalues'

#: The members that mutate a hashtable in place, so that a `Stop` written through one of them arms
#: the default table as an index-assignment does. Spelled as `resolve` sees a member — lowercased
#: — and read as a set so `.Add` and its accessor alias `.set_Item` are one question.
_HASHTABLE_MUTATORS = frozenset({'add', 'set_item'})


class Ps1FaultRouting(NamedTuple):
    """
    Where a terminating error raised at one point may go: the handlers it may be offered to, in no
    particular order, and whether it may get past all of them and leave the body.

    `handlers` holds `Ps1CatchClause` and `Ps1TrapStatement` nodes and is a *may* set — a type
    filter is matched by inheritance at run time, so a clause that cannot be shown to miss is
    reported alongside the one after it.

    The two fields answer different questions and a caller reads both. A handler that acts makes the
    error observable however the rest of the routing looks; `leaves_the_body` beside a `trap` is the
    escalation that ends the body, and beside nothing at all it is the ordinary unhandled error that
    5.1 reports and steps over.
    """
    handlers: tuple[Ps1CatchClause | Ps1TrapStatement, ...]
    leaves_the_body: bool


#: What the graphs place nothing for, and therefore claim nothing about. Every query answers `None`
#: for a node it cannot place, and every caller reads that as *the error may go anywhere*.
UNPLACED = None


def _binds_the_error_action(written: str) -> bool:
    """
    Whether the parameter name *written* at a call site binds `-ErrorAction` and nothing else.

    5.1 binds a parameter by any prefix of its name that no other parameter of the command answers
    to, which `refinery.lib.scripts.ps1.ast.binds_parameter` reads. What it cannot read on its own
    is the *ambiguity*, and here that is decidable: every command carrying `-ErrorAction` carries
    every common parameter, so a prefix reaching a second common name reaches it on exactly the
    commands this asks about. `-e`, `-er` and `-erro` all reach `-ErrorVariable` as well and are
    measured not to stop; `-errora` reaches this one alone and is measured to stop.

    Refusing an ambiguous prefix is also what keeps a native command out: `powershell.exe -e <b64>`
    hands `-e` to a program rather than to a parameter binder, and reading it as an error action
    pins every handler in the script around the commonest shape in this project's corpus.
    """
    reached = {surface for surface in _COMMON_SURFACES if binds_parameter(written, surface)}
    return bool(reached) and reached <= _ERROR_ACTION


def _rethrows(handler: Ps1TrapStatement) -> bool:
    """
    Whether *handler* disposes of an error by re-raising it, which a `trap` spells as an unlabelled
    `break` — measured: `& { trap { break }; [int]'a' }` ends the script where the same block
    without the handler reports the cast and carries on.

    A `break` written inside a loop of the trap's own body leaves that loop instead and is read here
    as a rethrow all the same, because the statement list is read rather than the control flow. That
    keeps a handler rather than dropping one, and the exact reading is the builder's
    `refinery.lib.scripts.ps1.analysis.cfg` already makes for the block the `trap` is written in.
    """
    body = handler.body.body if handler.body is not None else ()
    return any(
        isinstance(statement, Ps1BreakStatement) and statement.label is None
        for statement in body
    )


def _selects_stop(value: Node | None) -> bool:
    """
    Whether *value* selects `Stop`, as the argument of `-ErrorAction` or as what a write to
    `$ErrorActionPreference` stores. A value this cannot read is read as selecting it: the question
    decides whether a handler is load bearing, and a value computed at run time may be anything.

    A numeral is read for the number it denotes rather than for the text it is written as, because
    what selects the member is the ordinal and `0x1`, `01` and `1` all denote it.
    `refinery.lib.scripts.ps1.ast.argument_text` deliberately answers a numeral's spelling, which
    is the right reading where a bare word names something and the wrong one here. A name is
    matched by prefix, for the same reason a parameter name is.
    """
    if isinstance(value, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return value.value == _STOP_ORDINAL
    text = argument_text(value)
    if text is None:
        return True
    text = text.strip().lower()
    return bool(text) and (text == str(_STOP_ORDINAL) or _STOP.startswith(text))


def _stops_on_error(command: Ps1CommandInvocation) -> bool:
    """
    Whether *command* carries `-ErrorAction Stop`, which turns every error it reports into one that
    ends the script wherever nothing handles it.

    The parameter and its argument are two arguments rather than one: 5.1 binds a bare `-Name value`
    pair by position and only the `-Name:value` spelling arrives as a single named argument, so both
    shapes are read here. A parameter written last with nothing after it binds no value at all,
    which 5.1 rejects, and is read as `Stop` for the same reason an unreadable value is.

    Every occurrence is read rather than the first, so that a name bound by a prefix 5.1 would in
    fact reject cannot hide the parameter written after it — reading such a name as this one is
    then the over-approximation the name set claims it is, rather than a verdict on the command. A
    command carrying a splat is read as carrying the parameter for the same reason: the names it
    binds are in a table this cannot see into.
    """
    arguments = [
        argument for argument in command.arguments
        if isinstance(argument, Ps1CommandArgument)
    ]
    for index, argument in enumerate(arguments):
        value = argument.value
        if isinstance(value, Ps1Variable) and value.splatted:
            return True
        if not _binds_the_error_action(argument.name):
            continue
        if argument.kind is not Ps1CommandArgumentKind.NAMED:
            following = arguments[index + 1] if index + 1 < len(arguments) else None
            value = None
            if following is not None and following.kind is Ps1CommandArgumentKind.POSITIONAL:
                value = following.value
        if _selects_stop(value):
            return True
    return False


def _writes_stop_to_the_preference(node: Node) -> bool:
    """
    Whether *node* writes `$ErrorActionPreference` a value that may be `Stop`, which makes every
    error terminating — the failing cast included, which is otherwise reported and stepped over.

    Two shapes write the variable and both are read. An assignment names it through
    `refinery.lib.scripts.ps1.ast.assignment_target_variables`, so that a type-constrained,
    parenthesized or multi-assignment target is the same write as a bare one, and is keyed through
    `refinery.lib.scripts.ps1.ast.binding_key`, so that the unrelated process-global
    `$env:ErrorActionPreference` is not read as this variable. A cmdlet writes it by name —
    `New-Variable`/`Set-Variable ErrorActionPreference Stop`, or the provider form
    `Set-Item Variable:ErrorActionPreference Stop` — which `_cmdlet_writes_stop_to_the_preference`
    reads through the same name authority the model builds bindings from.
    """
    if isinstance(node, Ps1AssignmentExpression):
        return any(
            binding_key(variable) == _ERROR_ACTION_PREFERENCE
            for variable in assignment_target_variables(node.target)
        ) and _selects_stop(node.value)
    if isinstance(node, Ps1CommandInvocation):
        return _cmdlet_writes_stop_to_the_preference(node)
    return False


def _cmdlet_writes_stop_to_the_preference(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether *cmd* writes `Stop` to `$ErrorActionPreference` by naming the variable as a string —
    `Set-Variable ErrorActionPreference Stop`, `New-Variable ErrorActionPreference Stop -Force`, or
    `Set-Item Variable:ErrorActionPreference Stop`.

    Whether the command writes the variable at all is
    `refinery.lib.scripts.ps1.analysis.naming.named_references`' answer, the one authority for what
    a command does to a name it addresses as a string; it reports the write for every alias, casing
    and scope-qualified spelling of these commands. What it does not report is the *value* written,
    which is read here so the negative controls are decidable: `_written_variable_value` reads the
    named `-Value`, else the positional value the command binds after the name — the `-Name` written
    explicitly moves the value to the first free positional, exactly as it moves the name off it.

    A write that binds no value at all stores `$null` and arms nothing: `Clear-Variable` and a
    `-OutVariable` that happens to name the preference both reach here as writes with no value node,
    and are read as not arming. A value present but not statically readable is read as `Stop`, the
    `_selects_stop(None)` over-approximation that keeps a handler rather than dropping one.
    """
    if not any(
        reference.role is Ps1NameRole.WRITES
        and reference.key == _ERROR_ACTION_PREFERENCE
        for reference in named_references(cmd)
    ):
        return False
    value = _written_variable_value(cmd)
    return value is not None and _selects_stop(value)


def _written_variable_value(cmd: Ps1CommandInvocation) -> Node | None:
    """
    The value a variable- or item-writing command stores, or `None` when it binds no value.

    Read as the named `-Value` where one is written, else the positional value the command binds
    after its subject: the name or path takes the first free positional unless an explicit `-Name`
    or `-Path` moves it off, so the value is the free positional at index one when the subject is
    positional and at index zero when it is not — the same reading
    `refinery.lib.scripts.ps1.analysis.naming` makes for the name, one place along.
    """
    value = bound_argument_value(cmd, 'value')
    if value is not None:
        return value
    command = resolve_command_name(cmd)
    if command is None:
        return None
    subject_is_positional = (
        bound_argument_value(cmd, 'name') is None
        and bound_argument_value(cmd, 'path') is None
    )
    index = 1 if subject_is_positional else 0
    positional = free_positional_values(cmd, command)
    return positional[index] if len(positional) > index else None


def _names_the_default_table(node: Node | None) -> bool:
    """
    Whether *node* is the `$PSDefaultParameterValues` variable itself, keyed the way every other
    occurrence of it is so an aliased copy under another name is not read as it — that copy is the
    completeness hole tracked as an xfail, not a write this sees.
    """
    return isinstance(node, Ps1Variable) and binding_key(node) == _DEFAULT_PARAMETER_VALUES


def _names_the_error_action(key: str | None) -> bool:
    """
    Whether a `$PSDefaultParameterValues` key *key* binds `-ErrorAction`: its parameter half — what
    stands after the `command:` scope — being the action's own name or its `ea` alias. 5.1 matches
    that half against the parameter's name and aliases exactly rather than by prefix, so `ea` and
    `erroraction` bind it where an abbreviation like `errora` does not — the `_ERROR_ACTION` set
    the call-site reader already answers from. A key this cannot read as a literal is read as
    binding it, the direction that keeps a handler.
    """
    if key is None:
        return True
    _scope, separator, parameter = key.strip().lower().rpartition(':')
    return bool(separator) and parameter in _ERROR_ACTION


def _writes_stop_to_the_default_table(node: Node) -> bool:
    """
    Whether *node* writes `Stop` under an `-ErrorAction` key of `$PSDefaultParameterValues`, which
    makes every command that binds the key report a terminating error.

    Three spellings write the table statically and all are read: the index-assignment
    `$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'`, the member-assignment
    `$PSDefaultParameterValues.'*:ErrorAction' = 'Stop'` that sets the same key through the
    hashtable adapter, and the in-place mutation `$PSDefaultParameterValues.Add('*:ErrorAction',
    'Stop')` or its `.set_Item` accessor. The key is read through `_names_the_error_action`, and the
    value through the same `_selects_stop` a preference write reads, so `Continue` written here arms
    nothing. A whole-table replacement `$PSDefaultParameterValues = @{ ... }`, a splat, and an
    aliased copy are the completeness holes tracked as xfails: their target is not this index or the
    member.
    """
    if isinstance(node, Ps1AssignmentExpression):
        target = node.target
        if isinstance(target, Ps1IndexExpression):
            return (
                _names_the_default_table(target.object)
                and _names_the_error_action(argument_text(target.index))
                and _selects_stop(node.value)
            )
        if isinstance(target, Ps1MemberAccess):
            return (
                _names_the_default_table(target.object)
                and _names_the_error_action(get_member_name(target.member))
                and _selects_stop(node.value)
            )
        return False
    if isinstance(node, Ps1InvokeMember):
        member = node.member.lower() if isinstance(node.member, str) else ''
        return (
            _names_the_default_table(node.object)
            and member in _HASHTABLE_MUTATORS
            and len(node.arguments) >= 2
            and _names_the_error_action(argument_text(node.arguments[0]))
            and _selects_stop(node.arguments[1])
        )
    return False


#: The commands that arm strict mode, in the spelling `resolve_command_name` answers with. Two
#: rather than one, because two commands write the same engine slot: `Set-StrictMode -Version`
#: writes the scope it stands in and `Set-PSDebug -Strict` writes the global scope, and 5.1
#: documents the second as the first at version 1. Neither carries an alias in the collected
#: surface, and every other way of arming either arrives as a string these are matched inside.
_STRICT_MODE_COMMANDS = frozenset({
    'set-psdebug',
    'set-strictmode',
})


def _arms_strict_mode(node: Node) -> bool:
    """
    Whether *node* may turn a read of a variable that was never set into an error.

    A command is the spelling that matters, resolved the deny-list way through
    `refinery.lib.scripts.ps1.ast.resolve_command_name`, so that a module- or scope-qualified
    spelling of one arms strict mode as the bare word does. The argument is not read: a
    `Set-StrictMode -Off` and a `Set-PSDebug -Trace 1` are armings here like every other spelling,
    and what that costs is the recall of a script that names either command for another purpose.

    A string value need only *contain* a name, which is the asymmetry
    `refinery.lib.scripts.ps1.analysis.worldflow._names_own_path` makes and that
    `a_stop_may_be_in_force` makes beside it. `Invoke-Expression 'Set-StrictMode -Version 1'`
    arms it as surely as writing the command does, and a script that spells either name anywhere is
    read as arming it — the direction that refuses a removal rather than granting one.
    """
    if (
        isinstance(node, Ps1CommandInvocation)
        and resolve_command_name(node) in _STRICT_MODE_COMMANDS
    ):
        return True
    written = string_value(node)
    if written is None:
        return False
    written = written.lower()
    return any(command in written for command in _STRICT_MODE_COMMANDS)


def _arms_strict_mode_v2(node: Node) -> bool:
    """
    Whether *node* may arm strict mode at version 2 or above, under which the object adapter's
    faked `Count` and `Length` on a scalar or `$null` become terminating errors rather than a
    value. This is narrower than `_arms_strict_mode`: `Set-PSDebug -Strict` is documented as
    `Set-StrictMode -Version 1`, where those fakes still read, so only `Set-StrictMode` can arm the
    version this asks about.

    The argument *is* read here, unlike in `_arms_strict_mode`, because version 1 and version 2 are
    the two cases this distinguishes. Only a `-Version` that is provably the integer `1` is read as
    not arming version 2; every other spelling — a higher or non-constant version, `Latest`, `-Off`,
    or no readable value — is read as arming it, the direction that refuses a fold rather than
    granting one. A string value need only *contain* the command name, the way
    `_arms_strict_mode` reads one, since the version inside it cannot be told apart.
    """
    if isinstance(node, Ps1CommandInvocation):
        if resolve_command_name(node) != 'set-strictmode':
            return False
        version = bound_argument_value(node, 'version')
        return not (isinstance(version, Ps1IntegerLiteral) and version.value == 1)
    written = string_value(node)
    if written is None or 'set-strictmode' not in written.lower():
        return False
    parent = node.parent
    if isinstance(parent, Ps1CommandInvocation) and parent.name is node:
        # A bareword command name parses as a string literal too, so a genuine `Set-StrictMode`
        # invocation reaches this the way a concealed one does. Its version is read on the
        # invocation above; reading the version-less name here would refuse every `-Version 1`.
        return False
    return True


#: The automatic variables through which a `Stop` can be armed for commands that did not ask for
#: one: the preference itself, and the table that binds `-ErrorAction` into every command that takes
#: it. Spelled as names rather than as assignment shapes because `a_stop_may_be_in_force` asks
#: whether either is *touched* at all, however it is spelled.
_STOP_BEARING_NAMES = frozenset({
    _ERROR_ACTION_PREFERENCE,
    _DEFAULT_PARAMETER_VALUES,
})


def a_stop_may_be_in_force(root: Node) -> bool:
    """
    Whether anything in *root* may make an error a command reports into a terminating one — the
    strict counterpart of the whole-script question `Ps1FaultReach` asks itself, and a different
    question from it.

    That one reads a `Stop` written to `$ErrorActionPreference` — by assignment or by a cmdlet that
    names the variable — and a `Stop` written under an `-ErrorAction` key of
    `$PSDefaultParameterValues` by index-assignment or `.Add`, and reads them *laxly* on purpose: it
    decides whether a handler may be removed, where a missed arming keeps a handler that could have
    gone and costs recall on junk. The spellings it still misses arm the table through a shape whose
    target is not that index — a whole-table replacement `$PSDefaultParameterValues = @{ ... }`, a
    splatted `Set-Variable`, and an aliased copy of the table under another name — each tracked as
    an expected failure.

    A caller asking whether a *statement completed* cannot inherit those. Reading a script as arming
    nothing where it does says a command that in fact raised ran to its end, and a value it was going
    to establish is then resolved through at every use below it — which rewrites calls a run never
    makes. So this asks the wider question: does the script touch either name at all, in any way,
    including naming one in a string that a command could set it through. What that costs is the
    recall of every script that so much as mentions the preference, which is a shape worth refusing.

    A variable occurrence must carry the name exactly; a string value need only *contain* one,
    which is the same asymmetry `refinery.lib.scripts.ps1.analysis.worldflow._names_own_path`
    makes, and for the same reason. A provider path spells the name inside a larger word, and
    `Set-Item Variable:ErrorActionPreference Stop` arms it as surely as the assignment does — as
    does a payload handed to `Invoke-Expression`. Matching the whole literal instead reads a script
    that really arms `Stop` as arming nothing, which is the one direction that rewrites a call the
    run does not make.
    """
    for node in root.walk():
        if isinstance(node, Ps1Variable) and binding_key(node) in _STOP_BEARING_NAMES:
            return True
        written = string_value(node)
        if written is not None and any(
            name in written.lower() for name in _STOP_BEARING_NAMES
        ):
            return True
    return False


def ends_the_script(element: Node, stop_default: bool = False) -> bool:
    """
    Whether an error raised at *element* stops the script, rather than being reported and stepped
    over, where no handler takes it.

    PowerShell has two kinds of error a `trap` sees, and they are disposed of differently where
    there is no `trap`. A **statement-terminating** error ends the statement it was raised in and
    the next statement runs: a failing cast, a division by zero, a member access on `$null`, an
    exception out of a .NET method, an unresolved command name. A **terminating** error ends the
    script, and only `throw` and a command told to stop raise one. Both halves are measured.

    *stop_default* is whether the script binds `Stop` into every command through
    `$PSDefaultParameterValues`, which makes any command a subtree runs report a terminating error
    the way `-ErrorAction Stop` on the command does — and only a command, since the default table
    binds a parameter and a failing cast takes none. A subtree that runs no command is unchanged by
    it, so a cast stays the stepped-over error it is; the caller reads the whole-script fact off
    `Ps1FaultReach._a_stop_default_is_in_force` and every subtree is judged against it.

    `exit` is neither, and is deliberately absent: it ends the script by an exception no `trap`
    catches, so a handler over one disposes of nothing and reading `exit` as a raise would keep a
    handler no run reaches. `trap { 'T' }; exit 3` writes neither `T` nor anything else, which the
    executable corpus cannot hold as a row because a snippet that exits takes the measuring host
    with it.

    The whole subtree is read, because a construct raises wherever its parts do:

        1..2 | ForEach-Object { throw }

    ends the script although the `throw` stands in a body of its own. That reaches into a `function`
    definition written inside the statement as well, whose `throw` runs only once something calls
    it — an over-approximation, and one that keeps a handler rather than dropping it.

    A `trap` inside the subtree that re-raises is read the same way, because it *converts*: an error
    a nested block would have reported and stepped over ends the script once such a handler takes
    it. See `_rethrows`.
    """
    for node in element.walk():
        if isinstance(node, Ps1ThrowStatement):
            return True
        if isinstance(node, Ps1TrapStatement) and _rethrows(node):
            return True
        if isinstance(node, Ps1CommandInvocation) and (stop_default or _stops_on_error(node)):
            return True
    return False


def handler_acts(handler: Ps1CatchClause | Ps1TrapStatement) -> bool:
    """
    Whether running *handler* changes what the script does.

    An empty `catch { }` swallows the error and lets execution resume after the construct, so a
    script that never raises reaches the same next statement — which is why an obfuscator writes one
    and why removing what it guards costs nothing. A `trap` is the same rule with one more spelling:
    a body holding only an unlabelled `break` or `continue` decides how the error is disposed of and
    emits nothing, while a body holding anything else — a call, an assignment, or a bare value the
    engine writes to the output stream — is a handler whose running is observable.
    """
    body = handler.body.body if handler.body is not None else ()
    if isinstance(handler, Ps1CatchClause):
        return bool(body)
    for statement in body:
        if isinstance(statement, (Ps1BreakStatement, Ps1ContinueStatement)):
            if statement.label is not None:
                return True
            continue
        return True
    return False


def _handled_in_the_body(routing: Ps1FaultRouting) -> bool:
    """
    Whether a handler of the body the error was raised in disposes of it in a way a run can see: a
    `catch` or `trap` that acts, or a `trap` set the error may get past, which 5.1 answers by ending
    the body rather than by reporting the error and stepping over it.

    A `catch` that misses does not end the body, but a `trap` the error gets past does, so the
    escalation reading is keyed to the `trap` and not to the escape.
    """
    if any(handler_acts(handler) for handler in routing.handlers):
        return True
    return routing.leaves_the_body and any(
        isinstance(handler, Ps1TrapStatement) for handler in routing.handlers
    )


def _escapes(routing: Ps1FaultRouting) -> bool:
    """
    Whether an error routed like *routing* gets past every handler of the body it was raised in. A
    handler set it cannot leave settles it there; an empty set settles nothing, which the graphs
    spell as no handlers and no exceptional edge out of the body.
    """
    return not routing.handlers or routing.leaves_the_body


def _normal_successors(graph: ControlFlowGraph, node: CfgNode) -> frozenset[CfgNode]:
    """
    The nodes control reaches from *node* along a plain fall-through edge — where a soft error at
    *node* steps over to, which is the same node its value flows to when it does not fail.
    """
    return frozenset(
        successor for successor in node.successors
        if graph.edge_kind(node, successor) == CfgEdge.NORMAL
    )


def _enclosing_trap_body(node: Node) -> Ps1TrapStatement | None:
    """
    The `trap` whose body *node* stands in, or `None` where *node* is in no trap body. Assumes
    *node* is a body statement — a `trap`'s own type filter is not one, and the veto that reaches
    here has already restricted itself to a statement with a `fault_operand`.

    The walk stops at the first `Ps1ScriptBlock` because a `trap` reached only across a function or a
    stored scriptblock boundary does not guard the scope *node* runs in: a raise there ends the inner
    scope, and whatever the outer `trap` does is a question about the call, not about deleting the
    raise. The bodies of `if`/`while`/`for`/`switch`/`try` and of a named block (`begin`/`process`/
    `end`) are a `Block` rather than a `Ps1ScriptBlock`, so a raise nested in one still finds the
    `trap` it shares a scope with.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, Ps1TrapStatement):
            return cursor
        if isinstance(cursor, Ps1ScriptBlock):
            return None
        cursor = cursor.parent
    return None


def _resumption_slot(graph: ControlFlowGraph, node: CfgNode) -> CfgNode | None:
    """
    The slot a resuming handler carries *node*'s error to — the `CfgEdge.RESUMPTION_FORWARD`
    successor — or `None` where nothing resumes this node.
    """
    for successor in node.successors:
        if graph.edge_kind(node, successor) & CfgEdge.RESUMPTION_FORWARD:
            return successor
    return None


class Ps1SoftStepOver(NamedTuple):
    """
    One soft raiser a resuming `trap` catches whose local step-over lands off where the trap resumes,
    paired with the region the trap therefore skips and the continuation past it.

    `skipped` are the statements that run on the untrapped fall-through from the raiser's local
    step-over up to the reconvergence point — what a resuming `trap` abandons. `continuation` are the
    ids of the nodes that run forward from the reconvergence point, shared by the trapped and
    untrapped runs; a skipped write is observable exactly when one of them reads it. Both are read off
    `CfgEdge.NORMAL` edges alone: the plain control flow, never the error edges, which would route the
    walk back through the handler into the very block it stepped out of. This is the graph shape the
    step-over is decided over; whether a skipped statement is *observable* is a fact of the semantic
    model and is decided by the reader the transpose is handed, not here.
    """
    graph: ControlFlowGraph
    raiser: Node
    skipped: tuple[Node, ...]
    continuation: frozenset[int]


class Ps1FaultReach:
    """
    The fault routing of one script, read off its control-flow graphs.

    Built over `refinery.lib.scripts.analysis.cfg.ControlFlowModel`: where an error goes is decided
    by the graph the builder already wired, so this needs no semantic model, no call graph and no
    world. It is a view rather than a solver — every answer is one walk over the exceptional edges,
    memoized per node for the life of the model, and the model itself is discarded whenever the tree
    moves. The graph it reads is the sub-statement one
    `refinery.lib.scripts.ps1.analysis.cfg.build_control_flow_model` draws with `descend`, so that a
    soft error stepping over inside a `$( )` or `@( )` — and a `trap` written among those inner
    statements — is a point it places rather than detail hidden in the one node the coarse graph
    gives the whole statement. It draws that itself from its own root on first demand, so no caller
    can hand it a graph too coarse to see the step-over and remove a load-bearing trap.
    """

    def __init__(self, control_flow: ControlFlowModel):
        self._given = control_flow
        self._model: ControlFlowModel | None = None
        self._forward: dict[int, Ps1FaultRouting] = {}
        self._divergences: dict[int, list[Ps1SoftStepOver]] = {}
        self._reaching: dict[int, tuple[CfgNode, ...]] = {}
        self._handled: set[int] | None = None
        self._ending: dict[int, bool] = {}
        self._stopping: bool | None = None
        self._stop_default: bool | None = None
        self._strict: bool | None = None
        self._strict_v2: bool | None = None

    @property
    def _control_flow(self) -> ControlFlowModel:
        """
        The one graph every question is read off, descended so that a `$( )` or `@( )` shows its
        inner statements as points of their own. Built once from this reader's own root — the tree
        the model passed to the constructor was drawn over — and only where the script writes such a
        bracket at all: a script that writes none draws an identical graph under `descend`, which
        expands only those constructs, so the passed model is the descended one already and is reused
        unchanged. The empty model a caller may construct owns no root and is likewise returned as it
        is.
        """
        if self._model is None:
            root = self._script
            self._model = self._given
            if isinstance(root, Ps1Script) and any(
                isinstance(node, STATEMENT_LIST_EXPRESSIONS) for node in root.walk()
            ):
                self._model = build_control_flow_model(root, descend=True)
        return self._model

    def routing_at(self, node: Node) -> Ps1FaultRouting | None:
        """
        Where an error raised at *node* may go, or `None` when the graphs place *node* nowhere —
        a body they do not descend into, or an expression evaluated at no point they model.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return UNPLACED
        return self._routing(*located)

    def points_in(self, node: Node) -> Iterator[Node]:
        """
        The points inside *node* at which the graphs say something is evaluated, *node* itself
        included where it is one.

        Deleting a construct deletes everything it holds, so the errors it stops raising are its
        body's as well as its own — and each is at a position of its own, since a `try` nested in it
        routes its body's errors to its own `catch`. What the graphs place is exactly the list of
        such positions, which is why it is read off them rather than guessed from the node types: a
        `for` loop is three points and a body, an `if` is one point per test, and neither construct
        has a node standing for the statement as a whole.

        A construct that yields nothing at all is one the graphs model nowhere, and a caller reads
        that as a subtree it cannot judge rather than as one that raises nothing.
        """
        for inner in node.walk():
            if self._control_flow.node_of(inner) is not None:
                yield inner

    def escapes_the_body(self, node: Node) -> bool:
        """
        Whether an error raised at *node* gets past every handler written in the body *node* stands
        in, so that where it goes next is decided by whatever ran that body and not by anything the
        body itself says.

        A position the graphs place nowhere settles nothing and escapes nothing; `False` is the
        answer that leaves such a node to the position question, which reads an unplaced node as
        observed.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return False
        routing = self._routing(*located)
        return not _handled_in_the_body(routing) and _escapes(routing)

    def observed_at(self, node: Node) -> bool:
        """
        Whether an error raised at *node* changes which code runs: some handler it reaches acts, a
        `trap` set may decline it and end the body, or the graphs place *node* nowhere.

        This is the question about the **position** and not about the statement standing there —
        it answers the same for a statement that cannot raise at all, which is what a caller
        weighing whether a guarded body may be emptied wants to know.

        What the body itself decides is `_handled_in_the_body`; what is left over once the error
        gets past it is this.

        **An error that gets past a function's own handlers is the caller's**, and no graph here
        holds both ends of a call. Measured: the same function whose error is reported and stepped
        over when called at script scope abandons its remaining statements and runs the `catch` of a
        `try` written around the *call*, however many bodies deep the raise is. So a raise in a body
        something may call is refused wherever the script holds a handler that acts — and granted
        where it holds none, since a `catch` that is not written cannot be the one guarding the
        call.

        **A terminating error that escapes the script scope ends the run**, so deleting its raise
        would start the tail that never ran. `_reading_is_observed` reads a raise escaping to the
        script owner as unobserved — right for the statement-terminating errors 5.1 reports and steps
        over, wrong for the terminating ones. So when the error gets past the body unhandled and
        `_terminates` names the raise fatal, it is observed. This is the forward reading of the same
        termination the transpose `_removal_matters` already weighs.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return True
        graph, start = located
        routing = self._routing(graph, start)
        if self._reading_is_observed(graph, routing):
            return True
        return _escapes(routing) and self._terminates(node)

    def _reading_is_observed(self, graph: ControlFlowGraph, routing: Ps1FaultRouting) -> bool:
        """
        Whether an error routed like *routing* out of *graph* changes what runs. The one reading of
        a routing there is, so that the position question, the arrival question `_observed_from`
        asks of a fallback, and anything later that reads a routing cannot answer it three ways.
        """
        if _handled_in_the_body(routing):
            return True
        if not _escapes(routing):
            return False
        return not isinstance(graph.owner, Ps1Script) and self._handled_elsewhere(graph)

    def _handled_elsewhere(self, body: ControlFlowGraph) -> bool:
        """
        Whether this script writes a handler that acts in some body other than *body*. What guards
        a call is unknowable from the called body's graph, and this is what settles it in the
        direction of a grant: a handler written in the very body that raises is one the error has
        already got past, and a script with none anywhere else has no call site the raise could
        matter at.

        A named block is not a body of its own here, which is why the comparison is per graph: a
        `trap` in `begin` and a raise in `process` share one script block, and neither guards the
        other.
        """
        if self._handled is None:
            self._handled = {
                id(graph)
                for graph in self._control_flow.graphs.values()
                if any(
                    isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement))
                    and handler_acts(node.element)
                    for node in graph.nodes
                )
            }
        return bool(self._handled - {id(body)})

    def guarded_by_a_resuming_trap(self, node: Node) -> bool:
        """
        Whether a `trap` set that *resumes* guards *node* — one that, after taking a terminating
        error, carries execution on at the statement after the one that raised, rather than
        re-raising it (`trap { break }`) or letting it leave the body.

        The control-flow builder draws a `RESUMPTION_FORWARD` edge out of a guarded statement only
        where its block's trap set resumes — a `trap { continue }`, or a trap whose body runs off its
        end — and draws none for a re-raising set, so the mere existence of that edge answers the
        question. This is why a splice into such a body is load bearing: the edge lands on the next
        statement of the block, and splicing more statements after a raiser moves what that next
        statement is.

        Read off the descended graph the reader already holds. A `for` loop and a `try` are keyed to
        no node of their own — the builder gives each of their parts a node and names the statement
        after none of them — so `locate` places the construct itself nowhere, where an `if`, a
        `switch` and a `while` are each keyed to their head. The resumption of the block still reaches
        those parts: every point the construct owns that sits at the block's level draws the same edge
        to the same slot, so where the construct itself is placed nowhere, a point inside it that
        resumes answers for it. A construct the graph places nothing of, parts included, is guarded by
        nothing here.
        """
        located = self._control_flow.locate(node)
        if located is not None:
            return _resumption_slot(*located) is not None
        for inner in self.points_in(node):
            placed = self._control_flow.locate(inner)
            if placed is not None and _resumption_slot(*placed) is not None:
                return True
        return False

    def leaves_the_body(self, node: Node) -> bool:
        """
        Whether an error raised at *node* may get past every handler of the body it is in, so that
        where it goes next is a question about the caller. `True` for a node the graphs cannot
        place, which is the same answer for the same reason.
        """
        routing = self.routing_at(node)
        return routing is None or routing.leaves_the_body

    def an_empty_catch_skips_a_live_tail(self, node: Node) -> bool:
        """
        Whether a fault raised at *node* is taken by an **empty** `catch` that resumes past a live
        statement still standing after *node* in its own block — the position fact behind the
        body-tail keep.

        A position question and nothing more: it says where a fault at *node* would go and what the
        fault path skips, never whether *node* can raise. The caller pairs it with the raise
        predicate, the way every removal site pairs a position with a fault of its own.

        An empty `catch` is the only handler that matters here. One that *acts* already makes the
        fault observable through `observed_at`, so pairing this with it would only re-derive that
        keep. Emptiness is read from the body directly rather than through `handler_acts`, so the
        answer is a property of where the handler sits and not of a predicate a caller may be
        mutating. The tail is live exactly when *node*'s fall-through successor is not the slot the
        empty `catch` resumes to: equal successors mean the fault steps over to where the code went
        anyway (the raiser is last in the block, or stands at script scope with no catch at all), and
        deleting it changes nothing.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return False
        graph, start = located
        normal = _normal_successors(graph, start)
        if not normal:
            return False
        routing = self._routing(graph, start)
        for handler in routing.handlers:
            if not isinstance(handler, Ps1CatchClause):
                continue
            if handler.body is not None and handler.body.body:
                continue
            placed = self._control_flow.locate(handler)
            if placed is None:
                continue
            if normal != _normal_successors(placed[0], placed[1]):
                return True
        return False

    def fault_the_try_catches(self, operand: Node) -> bool:
        """
        Whether evaluating *operand* may raise a terminating error a `try` catches. A cast, a
        fallible operator and a method call raise one whatever the error preferences say; a command
        raises one only where the script makes its error terminating, which `error_is_terminating`
        reads from `Stop`. The default command error is non-terminating — reported and stepped over —
        so the `try` does not catch it and a statement after it still runs.

        It is the fault model's rather than the effect layer's because its command arm reads the
        script's error preferences, a judgment `error_is_terminating` already owns here; the
        expression arm is the pure `raises_a_caught_terminating_error` shape from `ast`.
        """
        if raises_a_caught_terminating_error(operand):
            return True
        return is_soft_error_source(operand) and self.error_is_terminating(operand)

    def _fires_a_trap(self, raiser: Node) -> bool:
        """
        Whether *raiser* provably fires the `trap` its block is guarded by — a statement-terminating
        or terminating error, the only errors a `trap` runs on. A cast, a fallible operator, a method
        call or a command a `Stop` makes terminating is read through `fault_the_try_catches` over the
        raiser's `fault_operand`; a bare `throw` or a global `Stop` is read through
        `error_is_terminating`.

        This under-approximates on purpose. It is the dual of the transpose's over-approximation: the
        transpose keeps a `trap` when *anything* its block holds may raise, so a plain command counts
        there; this decides whether to *delete* a body raise the `trap` would let end the scope, and a
        plain command whose default error is non-terminating does not fire the `trap`, so counting it
        would keep the junk body raise the deletion pass is written to drop. Excluding the plain
        command is therefore the price of that removal.
        """
        operand = fault_operand(raiser)
        if operand is not None and self.fault_the_try_catches(operand):
            return True
        return self.error_is_terminating(raiser)

    def escapes_a_firing_trap_body(self, node: Node) -> bool:
        """
        Whether *node* is a raise in the body of a `trap` that fires, whose error therefore leaves
        the body and ends the scope the `trap` belongs to. A `trap` does not guard its own body, so a
        raise among its statements is not offered back to it: it ends the script at script scope, or
        the function where the `trap` is written inside one. Deleting such a raise runs the remainder
        of the body — and the scope past it — that the original abandoned, which is why it is the
        position half of a keep.

        Three things have to hold. The raise stands in a `trap` body (`_enclosing_trap_body`, which
        stops at a function/scriptblock boundary). Its error actually leaves that body rather than
        being taken by a handler nested inside it (`escapes_the_body`). And the `trap` fires: some
        statement its block guards raises a firing error (`_fires_a_trap` over the trap node's
        raisers). A `trap` the graph places nowhere fires for nothing and is refused.
        """
        trap = _enclosing_trap_body(node)
        if trap is None or not self.escapes_the_body(node):
            return False
        located = self._control_flow.locate(trap)
        if located is None:
            return False
        return any(self._fires_a_trap(raiser) for raiser in self._raisers(*located))

    def deleting_the_raise_resurrects_a_continuation(self, node: Node) -> bool:
        """
        Whether a live continuation runs only because a raise at *node* pre-empts it, so deleting the
        raise starts that continuation. The one position predicate the removal veto pairs with the
        raise half `fault_the_try_catches`. Two mechanisms resurrect a continuation and both are the
        same observable: an empty `catch` resumes past the tail of a `try` body
        (`an_empty_catch_skips_a_live_tail`), and a firing `trap` body raise ends the scope the tail
        would otherwise have kept running in (`escapes_a_firing_trap_body`). A future mechanism — a
        `finally` that abandons — is a third disjunct here, not a fourth copy of the conjunction the
        veto pairs it into.
        """
        return (
            self.an_empty_catch_skips_a_live_tail(node)
            or self.escapes_a_firing_trap_body(node)
        )

    def error_is_terminating(self, node: Node) -> bool:
        """
        Whether a fault raised at *node* is terminating rather than reported and stepped over — the
        script writes `Stop` to `$ErrorActionPreference`, or the raise is one of the terminating
        shapes `ends_the_script` names: a command with `-ErrorAction Stop`, and any command at all
        where `$PSDefaultParameterValues` binds `Stop` into it. It is what makes a command's error
        one a `try` catches, and it is `_terminates` under a name a caller outside the module may
        read.
        """
        return self._terminates(node)

    def removing_a_handler_is_observed(
        self,
        handler: Node,
        may_raise: Callable[[Node], bool],
        soft_step_over_observed: Callable[[Node], bool] = lambda _handler: True,
    ) -> bool:
        """
        Whether deleting *handler* may change which code runs — the transpose, and the question
        asked before a `trap` is deleted.

        A `trap` cannot itself raise, so the forward question answers nothing about removing one:
        what changes is where the errors of *other* statements go. Three things have to be true for
        that to matter, and asking fewer gets it wrong in some direction.

        **Something that may actually raise has to still reach it.** Walking the exceptional edges
        backwards from the handler's own node finds the statements whose errors it may be offered,
        and *may_raise* keeps only those that can raise a terminating error at all — a `trap` beside
        a bare constant guards nothing, and one left behind by the removal of the only raise in its
        block becomes removable in turn. That predicate is injected rather than computed here,
        because whether an expression can fault is a fact of the semantic model this module holds
        none of; the caller reads it off
        `refinery.lib.scripts.ps1.analysis.effects.statement_can_raise`, the same
        `expression_cannot_fault` the forward question asks. The walk crosses other handlers,
        because a `catch` that misses hands the error on and the statement that raised it is behind
        that clause rather than at it.

        **A handler that acts and is reached by a raiser is load bearing.** A body that writes runs
        exactly when the handler is offered an error, so `trap { 'h' }` beside a raise puts `h` on
        the output stream where an unhandled error writes only its record. `handler_acts` of the
        handler under test decides it, and the precise raisers are what keep this from over-holding
        a `trap` beside a constant that cannot raise — the injected-noise shape
        `refinery.lib.scripts.ps1.deobfuscation.deadcode` drops is one whose block offers the
        handler no statement that may raise, so it is removed by the raiser test before this one is
        reached.

        **And what it would fall back to has to act.** Deleting a handler sends its errors to
        whatever the graph records as its fallback, so the question is asked again there: an empty
        `catch` beside it swallows exactly as it did, and a `trap` at script scope with nothing
        outside it lets an error be reported and stepped over, which is what an unhandled error
        already did. A fallback the graph does not record is refused, because a handler whose
        counterfactual is unknown is one whose removal cannot be judged.

        **A `trap` set that may decline is load bearing for declining**, not only for handling. It
        is what turns an error 5.1 would report and step over into one that ends the body, so
        deleting it starts running everything written after the raise:

            trap [System.IO.IOException] { }

        guards nothing yet is still why the script stops where it does.

        **And a resuming `trap` is load bearing when the region it skips is observable.** A soft
        error caught by a resuming `trap` would, untrapped, step over to the next statement in its
        own block and carry on; the trap abandons that block and lands past it. Whether the abandoned
        region does anything a run can see — writes the output stream, or a name a later statement
        reads — is a fact of the semantic model, so it is injected as *soft_step_over_observed* over
        the `soft_step_over_divergences` this reader reports; it defaults to always-observed so a
        caller that cannot judge it keeps the trap.
        """
        located = self._control_flow.locate(handler)
        if located is None:
            return True
        graph, start = located
        if start.element is not handler:
            # The climb left the handler behind, so the node this would answer about stands for the
            # statement around it and every question below reads the wrong element.
            return True
        return self._removal_matters(graph, start, may_raise, soft_step_over_observed)

    def _removal_matters(
        self,
        graph: ControlFlowGraph,
        start: CfgNode,
        may_raise: Callable[[Node], bool],
        soft_step_over_observed: Callable[[Node], bool],
    ) -> bool:
        raisers = [raiser for raiser in self._raisers(graph, start) if may_raise(raiser)]
        if not raisers:
            return False
        if any(self._terminates(raiser) for raiser in raisers):
            return True
        element = start.element
        if isinstance(element, Ps1TrapStatement) and handler_acts(element):
            return True
        routing = self._routing(graph, start)
        if isinstance(element, Ps1TrapStatement) and routing.leaves_the_body:
            return True
        if any(handler_acts(handler) for handler in routing.handlers):
            return True
        if isinstance(element, Ps1TrapStatement) and soft_step_over_observed(element):
            return True
        fallback = graph.fallback_of(start)
        if fallback is None:
            return True
        return self._observed_from(graph, fallback)

    def soft_step_over_divergences(self, handler: Node) -> list[Ps1SoftStepOver]:
        """
        The soft raisers a resuming *handler* catches whose local step-over lands off where the trap
        resumes, each paired with the region the trap therefore skips and the continuation past it —
        the graph shape a reader weighs to decide whether deleting the trap changes what runs.

        Empty for a handler the graph places nowhere, one the climb left behind, and one no soft
        raiser diverges under: a soft error at statement level steps over to the same slot the trap
        resumes at, so its skipped region is empty and it reports nothing. Read off `CfgEdge.NORMAL`
        edges alone — the region skipped is `normal_reach` from the raiser's local step-over up to the
        reconvergence, the continuation is `normal_reach` from the reconvergence — so no error edge
        routes the walk back through the handler into the block it stepped out of.

        Remembered per handler for the life of this model, because it reads only the graph — the same
        lifetime and reasoning as the routing this reader memoizes.
        """
        remembered = self._divergences.get(id(handler))
        if remembered is None:
            remembered = self._divergences[id(handler)] = self._soft_step_over_divergences(handler)
        return remembered

    def _soft_step_over_divergences(self, handler: Node) -> list[Ps1SoftStepOver]:
        located = self._control_flow.locate(handler)
        if located is None or located[1].element is not handler:
            return []
        graph, start = located
        by_id = {id(node): node for node in graph.nodes}
        result: list[Ps1SoftStepOver] = []
        for raiser in self._reaching_raise_nodes(graph, start):
            element = raiser.element
            if element is None or not is_soft_error_source(element):
                continue
            local = _normal_successors(graph, raiser)
            slot = _resumption_slot(graph, raiser)
            resumed = _normal_successors(graph, slot) if slot is not None else frozenset()
            if not resumed or local == resumed:
                continue
            skipped: list[Node] = []
            for node_id in normal_reach(local, barrier=resumed):
                skipped_element = by_id[node_id].element
                if skipped_element is not None and skipped_element is not element:
                    skipped.append(skipped_element)
            result.append(Ps1SoftStepOver(graph, element, tuple(skipped), normal_reach(resumed)))
        return result

    def _observed_from(self, graph: ControlFlowGraph, arrival: CfgNode) -> bool:
        """
        Whether an error arriving at *arrival* changes what runs: *arrival* is a handler that acts,
        or the routing onward from it is one `_reading_is_observed` calls observable — including the
        body boundary, because an error that gets past *arrival* is the caller's exactly as one
        raised at a position is.
        """
        element = arrival.element
        if isinstance(element, (Ps1CatchClause, Ps1TrapStatement)) and handler_acts(element):
            return True
        return self._reading_is_observed(graph, self._routing(graph, arrival))

    def _routing(self, graph: ControlFlowGraph, start: CfgNode) -> Ps1FaultRouting:
        """
        The routing out of *start*, remembered for the life of this model. Every reader goes through
        here so that a node's closure is walked once however many questions are asked about it.
        """
        remembered = self._forward.get(id(start))
        if remembered is None:
            remembered = self._forward[id(start)] = self._route(graph, start)
        return remembered

    def _route(self, graph: ControlFlowGraph, start: CfgNode) -> Ps1FaultRouting:
        handlers: list[Ps1CatchClause | Ps1TrapStatement] = []
        leaves = False
        for node in self._exceptional_closure(graph, start, forward=True):
            if node is graph.exit:
                leaves = True
            elif isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement)):
                handlers.append(node.element)
        return Ps1FaultRouting(tuple(handlers), leaves)

    def _reaching_raise_nodes(
        self, graph: ControlFlowGraph, start: CfgNode,
    ) -> tuple[CfgNode, ...]:
        """
        The graph nodes whose errors *start* may be offered — the backward walk over the exceptional
        edges — remembered for the life of this model. The raiser list the transpose reads and the
        soft-step-over divergences both flood backward from the same handler node, so the flood is
        walked once however many of them ask; the two differ only in which of these nodes they keep.
        """
        remembered = self._reaching.get(id(start))
        if remembered is None:
            remembered = self._reaching[id(start)] = tuple(
                self._exceptional_closure(graph, start, forward=False))
        return remembered

    def _raisers(self, graph: ControlFlowGraph, start: CfgNode) -> list[Node]:
        """
        The statements whose errors *start* may be offered, which is the backward walk over the
        exceptional edges. They are reported rather than counted, because what would become of an
        error if this handler were gone is a question about the statement that raises it.
        """
        return [
            node.element
            for node in self._reaching_raise_nodes(graph, start)
            if node.element is not None
            and not isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement))
        ]

    def _ends_the_script(self, element: Node) -> bool:
        """
        `ends_the_script` for *element*, remembered for the life of this model. Every handler judged
        against the same block is offered the same statements, so the subtree behind each one is
        read once however many removals ask about it. A `Stop` bound through
        `$PSDefaultParameterValues` is a whole-script fact folded in here rather than at each call
        site, so the same subtree is not re-scanned for it per element.
        """
        remembered = self._ending.get(id(element))
        if remembered is None:
            remembered = self._ending[id(element)] = ends_the_script(
                element, self._a_stop_default_is_in_force())
        return remembered

    def _terminates(self, element: Node) -> bool:
        """
        Whether an error raised at *element* ends the run rather than being reported and stepped
        over: the script writes `Stop` to `$ErrorActionPreference` anywhere, or the raise is one of
        the terminating shapes `_ends_the_script` names — a `throw`, a rethrowing `trap`, a command
        told to stop, or any command at all where `$PSDefaultParameterValues` binds `Stop` into it.
        The one predicate the position question and the transpose both read, so a raise the
        trap-removal side reads as script-ending is read the same way on the path that weighs
        deleting the raise itself.
        """
        return self._stops_on_every_error() or self._ends_the_script(element)

    @property
    def _script(self) -> Node | None:
        """
        The tree the graphs were built over, read off the passed model's owner rather than taken as
        an argument: a graph owner is a node of that tree, and a whole-script fact has to be asked of
        the whole script rather than of the statements the graphs happen to place. It reads the model
        the constructor was handed, not the descended one `_control_flow` derives, so the root the
        descended build needs is available without asking the build for it.
        """
        for graph in self._given.graphs.values():
            return tree_root(graph.owner)
        return None

    def _stops_on_every_error(self) -> bool:
        """
        Whether this script writes `Stop` to `$ErrorActionPreference` anywhere at all, which makes
        every error terminating — a failing cast, a division by zero and a member access on `$null`
        among them, not only what a command reports. The write is read through
        `_writes_stop_to_the_preference`, which counts an assignment and a cmdlet that writes the
        variable by name alike.

        This is the wider of the two whole-script arming gates. `$PSDefaultParameterValues` binds an
        action into commands and reaches no cast, so it is read on the per-command path
        `_a_stop_default_is_in_force` feeds rather than here.

        Position is deliberately not asked. The preference is a variable of the session rather than
        of a block, so a write in one body governs a raise in another and a write inside a branch
        governs everything that runs after it; a script that arms it at all is therefore read as
        arming it throughout. That direction keeps handlers, and what it costs — junk `trap` beside
        a script that arms `Stop` — is a shape an obfuscator has no reason to emit.

        The tree is read rather than the graphs. What the graphs place is statements, and their
        elements nest, so a walk per placed element reads an inner subtree once per level of
        nesting around it and still misses what stands at no point they model — a `param` block
        default among it.
        """
        if self._stopping is None:
            root = self._script
            self._stopping = root is not None and any(
                _writes_stop_to_the_preference(node) for node in root.walk()
            )
        return self._stopping

    def _a_stop_default_is_in_force(self) -> bool:
        """
        Whether this script binds `Stop` into every command through `$PSDefaultParameterValues`,
        which makes any command's reported error terminating while leaving a failing cast the
        stepped-over error it is. This is why it is read on the per-command terminating path
        `_ends_the_script` follows rather than in `_stops_on_every_error`: that gate escalates every
        error, casts included, and the default table does not reach a cast.

        Position is not asked, for the reason `_stops_on_every_error` gives: the table is a variable
        of the session, so a write in one body governs a command in another, and a script that arms
        it at all is read as arming it throughout. The tree is read rather than the graphs, so a
        write standing at a point no graph models is not missed.
        """
        if self._stop_default is None:
            root = self._script
            self._stop_default = root is not None and any(
                _writes_stop_to_the_default_table(node) for node in root.walk()
            )
        return self._stop_default

    def strict_mode_may_be_in_force(self) -> bool:
        """
        Whether this script may arm strict mode anywhere at all, which makes reading a variable that
        was never set an error instead of a `$null`.

        Two consumers, both reading it as the one model of whether the script arms strict mode.
        `refinery.lib.scripts.ps1.analysis.effects.expression_cannot_fault` is the single place
        deciding whether a bare variable read can raise before a removal site deletes it;
        `refinery.lib.scripts.ps1.deobfuscation.constants.Ps1NullVariableInlining` stands its whole
        pass down where this holds, because a never-assigned read it would rewrite to `$null` is a
        terminating error under strict mode and the value would decide a branch the script never
        reaches. Measured on 5.1: under the default semantics `$unset | ForEach-Object { [void]$_ }`
        writes nothing and the script runs on, so removing it is invisible; under
        `Set-StrictMode -Version 1` the same line raises a statement-terminating error that a
        `catch` and a `trap` both take, so removing it is exactly what
        `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` exists to refuse.

        Position is not asked, and the reason is not the one `_stops_on_every_error` gives. Which
        scopes an arming covers is not one rule: `Set-StrictMode` writes the scope it stands in and
        `Set-PSDebug -Strict` writes the global one, so the first arms nothing outside the function
        it is written in and the second arms everything that runs anywhere afterwards. Reading the
        whole script is what covers both without deciding which was meant. `Set-StrictMode -Off` is
        not distinguished from an arming either, since reading the argument buys back only the
        recall of a script that turns strict mode off again.

        **What this cannot see is an arming that is not in the script.** Strict mode is resolved by
        walking the scope chain to the global scope, so a script dot-sourced from a session that
        armed it — a profile, a stage-1 loader, an analyst's console — runs strict while spelling
        nothing. Nothing readable says whether that happened, so the grant this feeds assumes the
        entry scope runs the default semantics, the way
        `refinery.lib.scripts.ps1.analysis.worldflow` assumes a leak does not re-run the statements
        above it. A fragment carved out of a larger script is the case where the assumption is worth
        doubting.

        Where the graphs place no script this refuses rather than reading as the lax default.
        `_stops_on_every_error` answers `False` there safely, because a missed arming only keeps a
        handler; this one grants a *removal*, so a script the graphs hold nothing of has to refuse it
        rather than read as running under the lax default.
        """
        if self._strict is None:
            root = self._script
            self._strict = root is None or any(
                _arms_strict_mode(node) for node in root.walk()
            )
        return self._strict

    def strict_mode_v2_may_be_in_force(self) -> bool:
        """
        Whether this script may arm strict mode at version 2 or above, under which the `Count` and
        `Length` the object adapter fakes onto a scalar or `$null` raise `PropertyNotFoundStrict`
        rather than answering. Folding one of those to its value would stand a number where the
        script terminated and decide a branch it never reaches, so the fold in
        `refinery.lib.scripts.ps1.deobfuscation.folding` stands down where this holds and keeps the
        real members — a `String`'s own `Length`, an array's own `Count` — that read on regardless.

        This is the version-sensitive sibling of `strict_mode_may_be_in_force`: that one refuses a
        removal wherever any strict mode is armed, because reading an unset variable raises under
        version 1 too, and so treats `Set-PSDebug -Strict` and every `-Version` alike. The fake
        adapter members survive version 1, so this asks the narrower question, and everything the
        two share — position not asked, an arming outside the script not seen, an empty script
        refusing — is shared for the reasons written there.
        """
        if self._strict_v2 is None:
            root = self._script
            self._strict_v2 = root is None or any(
                _arms_strict_mode_v2(node) for node in root.walk()
            )
        return self._strict_v2

    @staticmethod
    def _exceptional_closure(
        graph: ControlFlowGraph, start: CfgNode, *, forward: bool,
    ) -> Iterator[CfgNode]:
        """
        The nodes reachable from *start* over exceptional edges alone, in either direction, without
        *start* itself. One sweep rather than a walk per edge kind: the graph marks an edge by the
        pair of nodes it joins, so the direction decides only which end of the pair the walk holds.
        """
        seen = {id(start)}
        stack = [start]
        while stack:
            current = stack.pop()
            adjacent = current.successors if forward else current.predecessors
            for node in adjacent:
                edge = (current, node) if forward else (node, current)
                if not graph.is_exceptional(*edge) or id(node) in seen:
                    continue
                seen.add(id(node))
                yield node
                stack.append(node)


def build_fault_reach(control_flow: ControlFlowModel) -> Ps1FaultReach:
    """
    The `Ps1FaultReach` over one script. The reader reads its own root off *control_flow* and draws
    the sub-statement graph it answers from there, so the coarse model is passed only to locate the
    root — and reused unchanged for a script that writes no `$( )` or `@( )`, whose graph is the same
    under `descend`.
    """
    return Ps1FaultReach(control_flow)
