"""
What a PowerShell script may set in its session that changes what an error or a command does: the
error preference, the table of default parameter values, and the seed of the random generator.

Each is a variable or a state of the session rather than of a block, so a write in one body governs
a raise or a call in another, and a script that sets one anywhere is read as setting it throughout.
Position is never asked here, and nothing here needs a graph: the control-flow builder reads these
answers while it builds, and the fault and value layers read them afterwards, so that all of them
read one answer.

Two readings of a write are made, and which one a question takes is a matter of which way a missed
write errs. Where missing a write keeps code or a handler, the write is read as it is spelled:
`writes_stop_to_the_preference` reads an assignment or a command that names the variable.
Where missing a write deletes code that runs, any mention of the name counts, in a variable, inside
a string that may run as code or name a provider path, or as the name of a variable written by a
name nobody can read: `Ps1Session` holds those answers.
"""
from __future__ import annotations

import typing

from weakref import WeakKeyDictionary

from refinery.lib.scripts import Node, tree_root, tree_version
from refinery.lib.scripts.ps1.analysis.model import Ps1OccurrenceRole, occurrence_role
from refinery.lib.scripts.ps1.analysis.naming import (
    Ps1NamedReference,
    Ps1NameRole,
    named_references,
    unreadable_name_target,
)
from refinery.lib.scripts.ps1.analysis.values import ordinal_of, read
from refinery.lib.scripts.ps1.ast import (
    argument_text,
    assignment_of,
    assignment_target_variables,
    binding_key,
    binds_parameter,
    bound_argument_value,
    free_positional_values,
    get_member_name,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.data import COMMON_PARAMETERS
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1RealLiteral,
    Ps1Variable,
)

#: The names the `-ErrorAction` parameter answers to, lowercased and without the dash: the parameter
#: itself and every alias the collected command data records for it. The alias is subscripted rather
#: than defaulted, so that a collected surface which stops carrying this parameter fails the load
#: rather than silently dropping the spelling, as `refinery.lib.scripts.ps1.data` does for its own
#: derived sets.
_ERROR_ACTION_NAME = 'erroraction'
_ERROR_ACTION = frozenset((_ERROR_ACTION_NAME, *COMMON_PARAMETERS[_ERROR_ACTION_NAME]))

#: The names the `-InformationAction` parameter answers to, read as `_ERROR_ACTION` is: bound to
#: `Stop` it makes `Write-Host` in the command it is bound on fail after writing, as a `Stop` stored
#: into `$InformationPreference` does.
_INFORMATION_ACTION_NAME = 'informationaction'
_INFORMATION_ACTION = frozenset((
    _INFORMATION_ACTION_NAME,
    *COMMON_PARAMETERS[_INFORMATION_ACTION_NAME],
))

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


def _binds_only(written: str, surfaces: frozenset[str]) -> bool:
    """
    Whether the parameter name *written* at a call site binds the common parameter whose names are
    *surfaces* and nothing else.

    5.1 binds a parameter by any prefix of its name that no other parameter of the command answers
    to, which `refinery.lib.scripts.ps1.ast.binds_parameter` reads. What it cannot read on its own
    is the *ambiguity*, and here that is decidable: every command carrying a common parameter
    carries every one of them, so a prefix reaching a second common name reaches it on exactly the
    commands this asks about. `-e`, `-er` and `-erro` all reach `-ErrorVariable` as well as
    `-ErrorAction` and are measured not to stop; `-errora` reaches `-ErrorAction` alone and is
    measured to stop.

    Refusing an ambiguous prefix is also what keeps a native command out: `powershell.exe -e <b64>`
    hands `-e` to a program rather than to a parameter binder, and reading it as an error action
    pins every handler in the script around the commonest shape in this project's corpus.
    """
    reached = {surface for surface in _COMMON_SURFACES if binds_parameter(written, surface)}
    return bool(reached) and reached <= surfaces


def selects_stop(value: Node | None) -> bool:
    """
    Whether *value* selects `Stop`, as the argument of `-ErrorAction` or as what a write to
    `$ErrorActionPreference` stores. A value this cannot read is read as selecting it: the question
    decides whether a handler is load bearing, and a value computed at run time may be anything.

    A numeral is read for the number it denotes rather than for the text it is written as, because
    what selects the member is the ordinal and `0x1`, `01` and `1` all denote it.
    `refinery.lib.scripts.ps1.ast.argument_text` deliberately answers a numeral's spelling, which
    is the right reading where a bare word names something and the wrong one here. A name is
    matched by prefix, for the same reason a parameter name is.

    A value the domain reads as an enum member — the spelling an inlined preference variable
    arrives in — selects `Stop` by its ordinal whatever enum it is a member of, because 5.1
    converts one enum to another by ordinal: `-ErrorAction ([ConfirmImpact]::Low)` is `Stop`.
    """
    return _selects_a_member(value, _STOP_MEMBER)


class _ActionMembers(typing.NamedTuple):
    """
    Members of `ActionPreference`, by the ordinals they are and the names they answer to.
    """
    ordinals: frozenset[int]
    names: tuple[str, ...]


_STOP_MEMBER = _ActionMembers(frozenset({_STOP_ORDINAL}), (_STOP,))
_SILENT_MEMBERS = _ActionMembers(frozenset({0, 4}), ('silentlycontinue', 'ignore'))


def _selects_a_member(value: Node | None, members: _ActionMembers) -> bool:
    """
    Whether *value* selects one of *members*, read as `selects_stop` reads `Stop`: a numeral by the
    number it denotes, an enum member by its ordinal, a name by prefix, and a value this cannot read
    as selecting one.
    """
    if isinstance(value, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return value.value in members.ordinals
    ordinal = ordinal_of(read(value))
    if ordinal is not None:
        return ordinal in members.ordinals
    text = argument_text(value)
    if text is None:
        return True
    text = text.strip().lower()
    return bool(text) and (
        text in {str(ordinal) for ordinal in members.ordinals}
        or any(name.startswith(text) for name in members.names)
    )


def selects_silence(value: Node | None) -> bool:
    """
    Whether *value* selects `SilentlyContinue` or `Ignore`, the two members under which an error is
    neither reported nor stops anything, read the way `selects_stop` reads `Stop`: a value this
    cannot read selects them.
    """
    return _selects_a_member(value, _SILENT_MEMBERS)


def _binds_an_action(
    command: Ps1CommandInvocation,
    selects: typing.Callable[[Node | None], bool],
    surfaces: frozenset[str] = _ERROR_ACTION,
) -> bool:
    """
    Whether *command* binds the action parameter whose names are *surfaces*, `-ErrorAction` unless
    given, to a value *selects* answers for, or carries a splat, whose table this cannot see into.
    Read as `stops_on_error` describes.
    """
    arguments = [
        argument for argument in command.arguments
        if isinstance(argument, Ps1CommandArgument)
    ]
    for index, argument in enumerate(arguments):
        value = argument.value
        if isinstance(value, Ps1Variable) and value.splatted:
            return True
        if not _binds_only(argument.name, surfaces):
            continue
        if argument.kind is not Ps1CommandArgumentKind.NAMED:
            following = arguments[index + 1] if index + 1 < len(arguments) else None
            value = None
            if following is not None and following.kind is Ps1CommandArgumentKind.POSITIONAL:
                value = following.value
        if selects(value):
            return True
    return False


def _resolved_as_a_reference(node: Node, key: str) -> bool:
    """
    Whether the string *node* is a name the command or call holding it addresses, so that what it
    does to the name is read off its reference rather than off the string.
    """
    cursor = node.parent
    while cursor is not None and not isinstance(cursor, (Ps1CommandInvocation, Ps1InvokeMember)):
        cursor = cursor.parent
    return cursor is not None and any(
        reference.key == key for reference in named_references(cursor)
    )


def _value_written_by(reference_node: Node) -> Node | None:
    """
    The value a command or a `PSVariable` call writes to the name it addresses, or `None` where
    it binds none or this cannot tell which argument it is.
    """
    if isinstance(reference_node, Ps1CommandInvocation):
        return _written_variable_value(reference_node)
    if isinstance(reference_node, Ps1InvokeMember) and len(reference_node.arguments) >= 2:
        return reference_node.arguments[1]
    return None


class _Names(typing.NamedTuple):
    """
    What one node does to names addressed other than as a variable: the references it makes to
    names spelled as strings, and whether it writes a variable by a name nobody can read. Read once
    per node, for every session variable asked about.
    """
    references: list[Ps1NamedReference]
    unreadable: bool


def _names_of(node: Node) -> _Names:
    return _Names(named_references(node), unreadable_name_target(node) is not None)


def _may_write(
    node: Node,
    names: _Names,
    key: str,
    harmless: typing.Callable[[Node], bool],
) -> bool:
    """
    Whether *node*, which does to names what *names* says, may leave the session variable named by
    *key* holding a value *harmless* does not clear, read the wide way: a read and a plain
    assignment of a value *harmless* clears are the only occurrences of the variable that pass; a
    write by name passes where it binds such a value; a variable written by a name nobody can read,
    and a string that holds the name anywhere else, never pass.
    """
    if isinstance(node, Ps1Variable) and binding_key(node) == key:
        role = occurrence_role(node)
        if not role.stores:
            return False
        assignment = assignment_of(node)
        return not (
            role is Ps1OccurrenceRole.WRITE_REPLACING
            and assignment is not None
            and assignment.operator == '='
            and assignment.value is not None
            and harmless(assignment.value)
        )
    if names.unreadable:
        return True
    for reference in names.references:
        if reference.key != key or reference.role is Ps1NameRole.READS:
            continue
        value = _value_written_by(reference.node)
        if value is None or not harmless(value):
            return True
    written = string_value(node)
    return written is not None and key in written.lower() and not _resolved_as_a_reference(node, key)


def _mentions(node: Node, names: _Names, key: str) -> bool:
    """
    Whether *node*, which does to names what *names* says, names the session variable *key* at all,
    as a variable, inside a string, or possibly as a variable written by a name nobody can read.
    """
    if isinstance(node, Ps1Variable):
        return binding_key(node) == key
    if names.unreadable:
        return True
    if any(reference.key == key for reference in names.references):
        return True
    written = string_value(node)
    return written is not None and key in written.lower()


#: The parameter of `Get-Random` that seeds the generator every later call reads, lowercased.
_SET_SEED = 'setseed'


def _may_seed(node: Node) -> bool:
    """
    Whether *node* may seed the random generator: a command that binds a splat or a parameter name
    `-SetSeed` answers to, or a string that holds the parameter's name. Any command counts, whatever
    its name: the name a script calls `Get-Random` by may be one it defines as an alias, or one 5.1
    reaches through the implicit `Get-` retry, and asking which is a question about the script this
    does not read.
    """
    if isinstance(node, Ps1CommandInvocation):
        for argument in node.arguments:
            if not isinstance(argument, Ps1CommandArgument):
                continue
            value = argument.value
            if isinstance(value, Ps1Variable) and value.splatted:
                return True
            if argument.name and binds_parameter(argument.name, _SET_SEED):
                return True
        return False
    written = string_value(node)
    return written is not None and _SET_SEED in written.lower()


def stops_on_error(command: Ps1CommandInvocation) -> bool:
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
    return _binds_an_action(command, selects_stop)


def writes_stop_to_the_preference(node: Node) -> bool:
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
        ) and selects_stop(node.value)
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
    `selects_stop(None)` over-approximation that keeps a handler rather than dropping one.
    """
    if not any(
        reference.role is Ps1NameRole.WRITES
        and reference.key == _ERROR_ACTION_PREFERENCE
        for reference in named_references(cmd)
    ):
        return False
    value = _written_variable_value(cmd)
    return value is not None and selects_stop(value)


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


def writes_stop_to_the_default_table(node: Node) -> bool:
    """
    Whether *node* writes `Stop` under an `-ErrorAction` key of `$PSDefaultParameterValues`, which
    makes every command that binds the key report a terminating error.

    Three spellings write the table statically and all are read: the index-assignment
    `$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'`, the member-assignment
    `$PSDefaultParameterValues.'*:ErrorAction' = 'Stop'` that sets the same key through the
    hashtable adapter, and the in-place mutation `$PSDefaultParameterValues.Add('*:ErrorAction',
    'Stop')` or its `.set_Item` accessor. The key is read through `_names_the_error_action`, and the
    value through the same `selects_stop` a preference write reads, so `Continue` written here arms
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
                and selects_stop(node.value)
            )
        if isinstance(target, Ps1MemberAccess):
            return (
                _names_the_default_table(target.object)
                and _names_the_error_action(get_member_name(target.member))
                and selects_stop(node.value)
            )
        return False
    if isinstance(node, Ps1InvokeMember):
        member = node.member.lower() if isinstance(node.member, str) else ''
        return (
            _names_the_default_table(node.object)
            and member in _HASHTABLE_MUTATORS
            and len(node.arguments) >= 2
            and _names_the_error_action(argument_text(node.arguments[0]))
            and selects_stop(node.arguments[1])
        )
    return False


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
    nothing where it does says a command that in fact raised ran to its end, and a value it was
    going to establish is then resolved through at every use below it — which rewrites calls a run
    never makes. So this asks the wider question: does the script touch either name at all, in any
    way, including naming one in a string that a command could set it through. What that costs is
    the recall of every script that so much as mentions the preference, which is a shape worth
    refusing.

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


class Ps1Session(typing.NamedTuple):
    """
    What one script may set in its session, each read the wide way, because each answers a question
    where a missed write deletes code that runs.

    `silenced` is whether `$ErrorActionPreference` may hold `SilentlyContinue` or `Ignore` anywhere,
    so that a `throw` may be reported and stepped over in every body. `silenced_by_a_call` is
    whether a call may be handed a silent `-ErrorAction` or the default table may hand one, which
    sets the preference in the body called and in every body that body runs: every body but the
    script's own. `defaults` is whether `$PSDefaultParameterValues` may bind a value into any
    command, which changes what the command does without a word at the call. `seeded` is whether the
    random generator may be seeded, after which every call of `Get-Random` changes what the next one
    hands back.
    """
    silenced: bool
    silenced_by_a_call: bool
    defaults: bool
    seeded: bool
    informs: bool = False


def _keeps_reporting(value: Node) -> bool:
    return not selects_silence(value)


def _session(root: Node) -> Ps1Session:
    silenced = silenced_by_a_call = defaults = seeded = informs = False
    for node in root.walk():
        if not (silenced and defaults and informs):
            names = _names_of(node)
            if not silenced:
                silenced = _may_write(node, names, _ERROR_ACTION_PREFERENCE, _keeps_reporting)
            if not defaults:
                defaults = _mentions(node, names, _DEFAULT_PARAMETER_VALUES)
            if not informs:
                informs = _mentions(node, names, 'informationpreference')
        if not silenced_by_a_call and isinstance(node, Ps1CommandInvocation):
            silenced_by_a_call = _binds_an_action(node, selects_silence)
        if not informs and isinstance(node, Ps1CommandInvocation):
            informs = _binds_an_action(node, selects_stop, _INFORMATION_ACTION)
        if not seeded:
            seeded = _may_seed(node)
    return Ps1Session(
        silenced,
        silenced_by_a_call or defaults,
        defaults,
        seeded or defaults,
        informs or defaults,
    )


def session_of(node: Node) -> Ps1Session:
    """
    The `Ps1Session` of the script holding *node*, remembered until that script changes, the way
    `refinery.lib.scripts.modelcache.ModelCacheBase` remembers a model: by the version its root
    stood at, so that a change to some other tree keeps it.
    """
    root = tree_root(node)
    version = tree_version(root)
    found = _SESSIONS.get(root)
    if found is None or found[0] != version:
        found = _SESSIONS[root] = version, _session(root)
    return found[1]


_SESSIONS: WeakKeyDictionary[Node, tuple[int, Ps1Session]] = WeakKeyDictionary()
