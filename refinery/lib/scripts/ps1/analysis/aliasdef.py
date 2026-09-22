"""
The reading of one `Set-Alias`/`New-Alias` invocation as the binding it spells: which name it takes
over and which command it names. It is the one reader of that shape, so the command model that
resolves the script's aliases (`refinery.lib.scripts.ps1.analysis.commands`) and the closed-world
model that asks which name a surviving binding rebinds (`refinery.lib.scripts.ps1.analysis.world`)
cannot disagree about what a definition binds. It sits below both: the command model is built over
the shadow set the world model produces, so a reader either of them owned would be out of the
other's reach.

Nothing here resolves. Whether a binding reaches a use, whether the name it takes was writable, and
what the statement does to the world are the questions the two models above answer, each over the
binding read here.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts.ps1.ast import (
    consumes_a_value,
    get_command_name,
    has_wildcard,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
)

#: The command names that define an alias. `sal` and `nal` are themselves default aliases of
#: `Set-Alias` and `New-Alias`; they are matched by spelling here because a script that has not
#: redefined them means exactly what they say, and one that has is caught as a collision when the
#: redefined name is later used.
ALIAS_DEFINING_COMMANDS = frozenset({'set-alias', 'sal', 'new-alias', 'nal'})

#: The defining command that raises rather than rebinding when the name it is given already has a
#: binding, so that the *first* definition of a name is the one a later use runs. See
#: `AliasDefinition.throws_if_bound`.
_BINDS_ONLY_WHEN_UNBOUND = frozenset({'new-alias'})

#: The parameters of `Set-Alias`/`New-Alias` that carry the alias name and its target, written out
#: with every prefix PowerShell binds them under: a parameter may be abbreviated to any prefix that
#: names one of the cmdlet's own parameters, and `Set-Alias -N zzq -V Write-Output` binds both
#: (measured — `-V` is not read as `-Verbose`, since a cmdlet's own parameters win over the common
#: ones). No prefix of `Description` is here: `Set-Alias` has no `-Definition`, so a spelling that
#: starts with `d` names a parameter this does not consume.
_NAME_PARAMS = frozenset({'n', 'na', 'nam', 'name'})
_VALUE_PARAMS = frozenset({'v', 'va', 'val', 'valu', 'value'})


class AliasDefinition(NamedTuple):
    """
    One `Set-Alias`/`New-Alias` invocation read as a binding: the lowercased alias `name`, the
    `target` command it names (or `None` when the target is not a literal), the defining `node`, and
    three reasons the binding may not be resolvable. `refuse` marks a definition the model will not
    act on — `-Force`/`-Option`, or an unreadable target — and `wildcard` marks a target that
    matches no single command, so the alias denotes nothing.

    `throws_if_bound` marks `New-Alias`, which raises `AliasAlreadyExists` rather than rebinding, so
    it takes effect only where nothing bound the name before it. That is the opposite of the
    nearest-definition-wins rule the rest of the resolution runs on, and it is what makes `New-Alias
    zzq Write-Output; New-Alias zzq Write-Host; zzq` run the *first* one — measured on 5.1.
    """
    name: str
    target: str | None
    node: Ps1CommandInvocation
    refuse: bool
    wildcard: bool
    throws_if_bound: bool


def extract_alias_definition(cmd: Ps1CommandInvocation) -> AliasDefinition | None:
    """
    Read `cmd` as an alias definition, or `None` when it is not one or this could not tell which of
    its arguments is the name. Positional (`sal x y`), named (`Set-Alias -Name x -Value y`) and
    mixed forms are all handled, in whichever order they are written; a wildcard target is noted as
    denoting nothing, and everything else this could not account for is a reason to refuse. A
    parameter written where the one before it is still waiting for its value is one of those:
    `Set-Alias -Value -Name zzq Write-Output` binds nothing on a 5.1 host, because `-Value` is left
    without an argument, so reading the words as the binding they spell reports a name the script
    never bound and lets the statement that reports it be deleted.

    **A parameter that is not the name or the value makes the binding unreadable, not merely
    uninteresting.** `-PassThru` writes the alias object to the output stream, `-Scope` binds it
    somewhere the reaching-definition question was never asked about, `-Option` and `-Force` decide
    a rebind this model does not resolve, and `-WhatIf` means no alias is created at all. Each is
    refused. More than that, the parser hands over a value-taking parameter as a switch followed by
    a bare word, and which of the two it is cannot be told apart here — `Set-Alias -Description d
    zzq Write-Output` binds `zzq`, because `-Description` took the `d` (measured). So an
    unrecognized switch does not merely add a reason to refuse: it ends the positional reading,
    and a name that had not been found by then is not found at all. Reading on regardless is how
    that same script came to be read as binding `d` to `zzq`.

    **Which switches those are is asked of the command's own parameter metadata**, through
    `refinery.lib.scripts.ps1.ast.consumes_a_value`, rather than assumed of every switch. A genuine
    switch takes no argument, so `Set-Alias -Force ls Get-Content` binds `ls` exactly where
    `Set-Alias ls Get-Content -Force` does; reading the two differently loses the binding for the
    one form `-Force` exists for — rebinding a `ReadOnly` default alias — and a name the model
    holds no definition for resolves through the built-in table instead, so `ls` was rewritten to
    `Get-ChildItem` in a script that had just made it `Get-Content`.
    """
    name = get_command_name(cmd)
    if name is None or name.lower() not in ALIAS_DEFINING_COMMANDS:
        return None
    command = resolve_command_name(cmd) or name.lower()
    alias_name: str | None = None
    target: str | None = None
    target_seen = False
    refuse = False
    reading_positionals = True
    awaiting: frozenset[str] | None = None
    positional: list[str | None] = []
    for arg in cmd.arguments:
        if (
            isinstance(arg, Ps1CommandArgument)
            and arg.kind is not Ps1CommandArgumentKind.POSITIONAL
        ):
            if awaiting is not None:
                refuse = True
                awaiting = None
            parameter = arg.name.lstrip('-').lower()
            wanted = (
                _NAME_PARAMS if parameter in _NAME_PARAMS else
                _VALUE_PARAMS if parameter in _VALUE_PARAMS else None)
            if wanted is None:
                refuse = True
                if (
                    arg.kind is Ps1CommandArgumentKind.SWITCH
                    and consumes_a_value(command, arg.name)
                ):
                    reading_positionals = False
            elif arg.kind is Ps1CommandArgumentKind.SWITCH:
                awaiting = wanted
            elif wanted is _NAME_PARAMS:
                alias_name = string_value(arg.value) if arg.value is not None else None
            else:
                target = string_value(arg.value) if arg.value is not None else None
                target_seen = True
            continue
        value = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        written = string_value(value) if value is not None else None
        if awaiting is _NAME_PARAMS:
            alias_name, awaiting = written, None
        elif awaiting is _VALUE_PARAMS:
            target, target_seen, awaiting = written, True, None
        elif reading_positionals:
            positional.append(written)
    if alias_name is None and positional:
        alias_name = positional.pop(0)
    if not target_seen and positional:
        target, target_seen = positional.pop(0), True
    if positional:
        refuse = True
    if alias_name is None:
        return None
    throws_if_bound = command in _BINDS_ONLY_WHEN_UNBOUND
    if not target_seen or target is None:
        return AliasDefinition(alias_name.lower(), None, cmd, True, False, throws_if_bound)
    return AliasDefinition(
        alias_name.lower(), target, cmd, refuse, has_wildcard(target), throws_if_bound)
