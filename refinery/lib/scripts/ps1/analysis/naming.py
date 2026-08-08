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

**The recognition is deny-side.** A command spelling this cannot resolve is not a command this may
declare harmless — it is one whose effect is unknown, and the conservative answer is to record that
the enclosing scope writes a name nobody can read. That is the opposite polarity from a grant table
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

from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.ast import (
    argument_text,
    bound_argument_value,
    free_positional_values,
    resolve_command_name,
    resolved_command_names,
    string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CommandInvocation,
    Ps1ScopeModifier,
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
    ways lands on one binding. `node` is the command performing it.
    """
    key: str
    role: Ps1NameRole
    target: Ps1NameTarget
    node: Ps1CommandInvocation


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
    'get-item': Ps1NameRole.READS,
    'new-item': Ps1NameRole.WRITES,
    'remove-item': Ps1NameRole.UNBINDS,
    'set-item': Ps1NameRole.WRITES,
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


def named_references(cmd: Ps1CommandInvocation) -> list[Ps1NamedReference]:
    """
    Every reference *cmd* makes to a name addressed as a string, or an empty list when it makes
    none. A single command may make several: `Get-Variable x -OutVariable y` reads one and writes
    another.

    Both names a call may run are asked about, because `variable x` and `item variable:x` reach
    `Get-Variable` and `Get-Item` through the implicit `Get-` retry and a table keyed on the bare
    spelling misses them. At most one of the two is in either table, and reading a name a `function
    variable` would have taken back only over-reports a read, which withholds a removal.
    """
    found: list[Ps1NamedReference] = []
    for command in resolved_command_names(cmd):
        found.extend(_subject_references(cmd, command))
    found.extend(_out_variable_references(cmd))
    return found


def unreadable_name_target(cmd: Ps1CommandInvocation) -> Ps1NameTarget | None:
    """
    Where *cmd* writes a variable whose name this cannot read — `Set-Variable $n 'v'`, where the
    name is computed — or `None` when it writes no such name. The name is unknown, so *every*
    binding in the scope it lands in is in doubt, which is a fact about that scope rather than
    about any one binding.

    Only the variable commands are reported. A `Set-Item` whose path is computed might address the
    `Variable:` drive and might equally be writing a file, and answering for every one of them would
    put most scripts permanently in doubt; that is left as a known hole rather than paid for
    everywhere. A reading command is not reported either: not knowing which name was read costs
    nothing, since a read changes no value.

    The implicit `Get-` retry needs no reading here, unlike in `named_references`: it prefixes
    `Get-`, so the only commands it can reach are readers, and a reader is not reported.
    """
    command = resolve_command_name(cmd)
    if command is None:
        return None
    role = _VARIABLE_COMMANDS.get(command)
    if role is None or role is Ps1NameRole.READS:
        return None
    if _subject_name(cmd, command, 'name') is not None:
        return None
    return _declared_target(cmd)


def addresses_unreadable_name(cmd: Ps1CommandInvocation) -> bool:
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
        if written is not None:
            yield from _resolve(cmd, written, role, _declared_target(cmd))
        return
    role = _ITEM_COMMANDS.get(command)
    if role is None:
        return
    written = _subject_name(cmd, command, 'path')
    if written is None:
        return
    drive, _, rest = written.partition(':')
    prefix = _NAME_DRIVES.get(drive.lower())
    if prefix is None or not rest:
        return
    yield Ps1NamedReference(
        key=F'{prefix}{rest.lower()}',
        role=role,
        target=Ps1NameTarget.SCRIPT if prefix else _declared_target(cmd),
        node=cmd,
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
    cmd: Ps1CommandInvocation,
    written: str,
    role: Ps1NameRole,
    target: Ps1NameTarget,
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
                node=cmd,
            )
            return
        placed = _QUALIFIER_TARGETS.get(lowered)
        if placed is None:
            return
        yield Ps1NamedReference(key=rest.lower(), role=role, target=placed, node=cmd)
        return
    yield Ps1NamedReference(key=written.lower(), role=role, target=target, node=cmd)
