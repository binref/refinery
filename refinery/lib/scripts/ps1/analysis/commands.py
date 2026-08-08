"""
What command a name denotes at a point in one PowerShell script.

Command resolution is a language fact several passes each held half of: two of them split the alias
relation, a third folded a call to a user function without asking whether an alias of the same name
shadowed it, and none of them knew that a name used before its definition, or defined in a scope the
use is not in, denotes no command at all. This model answers the whole question once, so a caller
rewrites a name only where 5.1 would resolve it the same way.

Three outcomes, kept apart because a caller does different things with each:

- **a name** — the invocation resolves to a concrete command, reached through zero or more aliases
  (`CommandKind.ALIAS`), or named directly as a script function (`CommandKind.FUNCTION`) or a known
  cmdlet (`CommandKind.CMDLET`). `Denotation.target` carries the canonical command name.
- **nothing** (`CommandKind.NOTHING`) — the name denotes no command at this point, so 5.1 raises
  `CommandNotFoundException` and rewriting it is not meaning-preserving. It arises from an alias
  cycle, a wildcard alias target, a use its definition does not reach, or a definition in a scope the
  use is not in. The faithful output is the script exactly as written.
- **unknown** (`CommandKind.UNKNOWN`) — the model cannot decide: a computed name, an alias whose
  target is not a literal, a `Set-Alias` carrying `-Force`/`-Option` whose writability outcome is not
  static, or a definition that collides with a name the running host already binds. A caller refuses.

**Precedence is measured, not assumed.** On a 5.1 host `Get-Command` returns an alias over a function
of the same name and a function over a cmdlet, so this model resolves an alias before a function and a
function before a cmdlet. A default alias therefore wins over a script `function` of its name, which
is why `function echo { }; echo` runs `Write-Output` and not the body.

The precedence covers the names a script takes over through the `function:`/`alias:` variable
namespace (`${function:Get-ChildItem} = { ... }`), not only `function`/`filter` keyword definitions.
Such an assignment redefines command identity under a spelling this model cannot follow to a body, so
when no alias wins the name denotes *unknown* rather than the cmdlet the metadata would otherwise
report — the caller keeps it as written. The set of taken-over names is the world's
(`refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld.shadowed_names`), so this model and the closed-
world model cannot disagree about which names the script has shadowed.

**Writability is handled by refusal, not by a rebind table.** Nearly every default alias is
`ReadOnly` or `AllScope`, and a plain `Set-Alias` rebinds neither — measured on 5.1 as
`AliasNotWritable` for the first and `AliasAllScopeOptionCannotBeRemoved` for the second — so a
script `Set-Alias` naming an existing builtin alias almost never takes effect. Which aliases the
handful of exceptions are is deliberately not written down here: it is a property of the host's
table rather than of the language, it cannot be measured without reading the state of a machine, and
nothing below depends on it. Rather than ship the per-alias `Options` that would say which outcome a
collision had, the model treats every such collision — and any `-Force`/`-Option` definition — as
unknown and keeps the name as written, which is faithful whichever way the rebind went. Precise
builtin-rebind resolution waits on that metadata.

**A scope qualifier is part of an alias name, unlike a command name.** `Set-Alias global:foo X`
creates an alias called `global:foo`, which no later `foo` runs, so a definition is keyed by the
literal name it writes and `normalize_command_name` is not applied to it. That is the opposite of
what the same qualifier means on a `function` definition, where `function global:Get-Date` is what a
later bare `Get-Date` runs.

**What a command does to the world is asked here too**, through `Ps1CommandModel.world_role`, and for
the same reason the rest is: `refinery.lib.scripts.ps1.analysis.world` follows a name one hop through
the built-in alias table and cannot follow the script's own, so `Set-Alias e iex` hides a leak from
it. It cannot be fixed there — this model is built over the shadow set that one produces, so a world
consulting this one would be a cycle — and the deny-lists themselves stay there, where the argument
for what belongs on them is written. What is added here is the resolution, not a second list.

**Whether a definition is still doing anything is asked here too.** A pass that has rewritten every
use it could would otherwise have to work out which definitions the uses it left behind still resolve
through, and that is this model's own resolution run backwards. `implicated_definitions` reports it
forwards instead — from the use — and `binding_only_definition`, `introspected_names` and
`reads_command_success` answer the three other things a definition's absence could change: what its
statement does besides bind, who reads the name back out of the alias table rather than using it, and
whether the engine state a statement writes is read. What to do with those answers is not decided
here; see `refinery.lib.scripts.ps1.deobfuscation.aliases`.

**Position and scope come from dominance**, which is why Phase 1a precedes this. A `Set-Alias` binds a
use only where its statement strictly dominates the use — it is guaranteed to have run — and the
per-script-block control-flow graphs put a definition in a function body and a use outside it in
different graphs, so the body's definition cannot reach the outer use. The reaching-definition
selection is `refinery.lib.scripts.analysis.reaching.ReachabilityQuery.reaching_definition`, the same
one variable flow uses: an alias name's `Set-Alias` statements are its writes and an invocation is a
read.
"""
from __future__ import annotations

import enum

from typing import NamedTuple, Sequence

from refinery.lib.scripts.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockModel, Ps1BlockReach
from refinery.lib.scripts.ps1.analysis.world import (
    WorldRole,
    command_role,
    runs_another_script_file,
    touches_identity_provider,
)
from refinery.lib.scripts.ps1.ast import (
    get_command_name,
    is_opaque_dispatch,
    normalize_command_name,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.data import KNOWN_ALIAS, KNOWN_CMDLETS
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1Variable,
)

#: The command names that define an alias. `sal` and `nal` are themselves default aliases of
#: `Set-Alias` and `New-Alias`; they are matched by spelling here because a script that has not
#: redefined them means exactly what they say, and one that has is caught as a collision when the
#: redefined name is later used.
_ALIAS_DEFINING_COMMANDS = frozenset({'set-alias', 'sal', 'new-alias', 'nal'})

#: The parameters of `Set-Alias`/`New-Alias` that carry the alias name and its target, written out
#: with every prefix PowerShell binds them under: a parameter may be abbreviated to any prefix that
#: names one of the cmdlet's own parameters, and `Set-Alias -N zzq -V Write-Output` binds both
#: (measured — `-V` is not read as `-Verbose`, since a cmdlet's own parameters win over the common
#: ones). No prefix of `Description` is here: `Set-Alias` has no `-Definition`, so a spelling that
#: starts with `d` names a parameter this does not consume.
_NAME_PARAMS = frozenset({'n', 'na', 'nam', 'name'})
_VALUE_PARAMS = frozenset({'v', 'va', 'val', 'valu', 'value'})


def _has_wildcard(name: str) -> bool:
    return any(character in name for character in '*?[')


class CommandKind(enum.Enum):
    """
    What kind of command a name denotes. `ALIAS`, `FUNCTION` and `CMDLET` are the three ways it names
    a concrete command — the "a name" outcome — and `NOTHING` and `UNKNOWN` are the other two.
    """
    ALIAS = enum.auto()
    FUNCTION = enum.auto()
    CMDLET = enum.auto()
    NOTHING = enum.auto()
    UNKNOWN = enum.auto()


class Denotation(NamedTuple):
    """
    What an invocation's command name denotes: the `CommandKind` and, when it names a concrete
    command, its canonical spelling in `target`. `target` is `None` for `NOTHING` and `UNKNOWN`.
    """
    kind: CommandKind
    target: str | None

    @property
    def is_a_name(self) -> bool:
        """
        Whether the name denotes a concrete command, so `target` is set.
        """
        return self.kind in (CommandKind.ALIAS, CommandKind.FUNCTION, CommandKind.CMDLET)


class AliasDefinition(NamedTuple):
    """
    One `Set-Alias`/`New-Alias` invocation read as a binding: the lowercased alias `name`, the
    `target` command it names (or `None` when the target is not a literal), the defining `node`, and
    two reasons the binding may not be resolvable. `refuse` marks a definition the model will not act
    on — `-Force`/`-Option`, or an unreadable target — and `wildcard` marks a target that matches no
    single command, so the alias denotes nothing.
    """
    name: str
    target: str | None
    node: Ps1CommandInvocation
    refuse: bool
    wildcard: bool


#: The command that reads the whole alias table however it is asked, so that any of its arguments may
#: name an alias. `Export-Alias` writes every alias when no `-Name` selects one and its first
#: positional argument is a path rather than a name; `Trace-Command` names trace sources, and what it
#: reports about a traced command is not bounded by them. Neither is worth binding parameters for
#: when the sound answer is that every name is read.
_TABLE_READING_COMMANDS = frozenset({'export-alias', 'trace-command'})

#: The commands that report on one named command, so that the name they are given is the only one
#: they read. A form that names none reads the whole table and is treated as one of the above.
_NAME_READING_COMMANDS = frozenset({'get-alias', 'get-command', 'get-help'})

#: The parameters under which the commands above take the name they report on. A bare `n` is not
#: among them although it is a prefix of `Name`: `Get-Command` also has `-Noun`, so `-N` names
#: neither on its own, and reading it as the name would record one name for a form that reports on
#: every command carrying a noun.
_READ_NAME_PARAMS = frozenset({'na', 'nam', 'name'})

#: The automatic variable holding whether the last command succeeded. A statement that runs sets it,
#: so removing one is visible to any read of it.
_SUCCESS_VARIABLE = '?'

#: The command a definition must denote for its removal to be nothing but the unbinding of a name.
_SET_ALIAS = 'set-alias'


def _read_name_argument(cmd: Ps1CommandInvocation) -> str | None:
    """
    The literal command name `cmd` reports on, or `None` when it names none, names it with something
    this cannot read, or selects what to report by anything other than a name. The first positional
    argument carries it, or `-Name`.

    Any other parameter answers `None` rather than being passed over. `Get-Alias -Definition
    Write-Output` reports every alias of a command, `-Exclude` reports everything but a pattern, and
    a parameter this does not know may have taken the very argument that would otherwise have read
    as the name — the same ambiguity `extract_alias_definition` describes, in the direction where
    reading on means reporting one name for a form that reports on many.
    """
    for argument in cmd.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            return string_value(argument)
        if argument.kind is not Ps1CommandArgumentKind.POSITIONAL:
            if argument.name.lstrip('-').lower() not in _READ_NAME_PARAMS:
                return None
            if argument.kind is Ps1CommandArgumentKind.SWITCH:
                continue
        return string_value(argument.value) if argument.value is not None else None
    return None


class _Resolution(NamedTuple):
    """
    What `Ps1CommandModel._resolve` found: the `Denotation`, the definitions it consulted on the way,
    and whether the script itself is why it names no command.

    The consulted definitions are what makes a definition's removal decidable. A caller that has
    rewritten every use it could cannot tell from the tree which definitions the uses it left behind
    still need — a use may reach one through three hops, or be refused *because* of one, or denote
    nothing precisely because one exists somewhere it cannot reach. All three are recorded, because
    all three are reasons the definition is doing something.

    The second is not a shade of the first — it separates two outcomes `CommandKind.UNKNOWN` and
    `CommandKind.NOTHING` each cover both of. A name the collected metadata simply does not describe
    is the host's business and nothing the script did: the world model's deny-list stance applies,
    an unrecognized command is not treated as a mutator, and `Ps1CommandModel.world_role` answers
    `WorldRole.NONE`. A name the script bound to something this model could not read through — a
    `-Force` rebind, a `function:` takeover, a definition that does not statically reach — is a
    refusal reached *with* evidence, and answering that it leaves the world as it found it would be
    this model contradicting its own denotation.
    """
    denotation: Denotation
    implicated: tuple[AliasDefinition, ...]
    unread_binding: bool


def extract_alias_definition(cmd: Ps1CommandInvocation) -> AliasDefinition | None:
    """
    Read `cmd` as an alias definition, or `None` when it is not one or this could not tell which of
    its arguments is the name. Positional (`sal x y`), named (`Set-Alias -Name x -Value y`) and
    mixed forms are all handled, in whichever order they are written; a wildcard target is noted as
    denoting nothing, and everything else this could not account for is a reason to refuse.

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
    """
    name = get_command_name(cmd)
    if name is None or name.lower() not in _ALIAS_DEFINING_COMMANDS:
        return None
    alias_name: str | None = None
    target: str | None = None
    target_seen = False
    refuse = False
    reading_positionals = True
    awaiting: frozenset[str] | None = None
    positional: list[str | None] = []
    for arg in cmd.arguments:
        parameter = arg.name.lstrip('-').lower() if (
            isinstance(arg, Ps1CommandArgument)
            and arg.kind is not Ps1CommandArgumentKind.POSITIONAL
        ) else None
        if parameter is not None:
            assert isinstance(arg, Ps1CommandArgument)
            wanted = (
                _NAME_PARAMS if parameter in _NAME_PARAMS else
                _VALUE_PARAMS if parameter in _VALUE_PARAMS else None)
            if wanted is None:
                refuse = True
                if arg.kind is Ps1CommandArgumentKind.SWITCH:
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
    if not target_seen or target is None:
        return AliasDefinition(alias_name.lower(), None, cmd, True, False)
    return AliasDefinition(alias_name.lower(), target, cmd, refuse, _has_wildcard(target))


class Ps1CommandModel:
    """
    What each command invocation of one script denotes. Build it through `build_command_model`; every
    query is `denotation`.
    """

    def __init__(
        self,
        root: Ps1Script,
        control_flow: ControlFlowModel,
        reach: ReachabilityQuery,
        blocks: Ps1BlockModel,
        functions: frozenset[str],
        shadowed: frozenset[str],
    ):
        self._root = root
        self._flow = control_flow
        self._reach = reach
        self._blocks = blocks
        self._functions = functions
        self._shadowed = shadowed
        self._alias_defs: dict[str, list[AliasDefinition]] = {}
        for node in root.walk_in_order():
            if not isinstance(node, Ps1CommandInvocation):
                continue
            definition = extract_alias_definition(node)
            if definition is not None:
                self._alias_defs.setdefault(definition.name, []).append(definition)
        self._memo: dict[int, _Resolution] = {}
        self._roles: dict[int, WorldRole] = {}
        self._introspected: frozenset[str] | None = None
        self._introspected_known = False

    def denotation(self, invocation: Ps1CommandInvocation) -> Denotation:
        """
        What `invocation`'s command name denotes at its position — see this module's own
        documentation for the three outcomes. Memoized for as long as the tree is unchanged.
        """
        return self._resolution(invocation).denotation

    def _resolution(self, invocation: Ps1CommandInvocation) -> _Resolution:
        found = self._memo.get(id(invocation))
        if found is None:
            found = self._memo[id(invocation)] = self._resolve(invocation)
        return found

    def alias_definitions(self, name: str) -> Sequence[AliasDefinition]:
        """
        Every alias definition the script writes for `name`, in source order, wherever it sits.

        The key is the literal name the definition writes, lowercased and nothing more, because a
        scope qualifier is part of an alias name — see this module's own documentation.
        """
        return self._alias_defs.get(name.lower(), ())

    def every_alias_definition(self) -> Sequence[AliasDefinition]:
        """
        Every alias definition the script writes, for any name, grouped by name and in source order
        within each group.

        This is what the script's alias definitions *are* as far as this model is concerned, and a
        caller that must account for all of them reads it rather than enumerating names it thought
        of. It is not the same as every command that defines an alias: a definition this could not
        read — a computed name, a defining command reached under another name — is not here, and a
        caller that needs that guarantee asks `world_role` of every invocation instead.
        """
        return [definition for group in self._alias_defs.values() for definition in group]

    def implicated_definitions(self, invocation: Ps1CommandInvocation) -> Sequence[AliasDefinition]:
        """
        The alias definitions whose presence decides what `invocation` denotes: every one the
        resolution read on the way to its answer — see `_Resolution`. Empty when the name resolves
        without consulting any, which is what makes a definition removable.

        This is the question "is this definition still needed", asked from the use rather than from
        the definition. Asking it the other way round means predicting which uses *would* resolve
        through a definition that is no longer there, and that is the resolution run backwards.
        """
        return self._resolution(invocation).implicated

    def binding_only_definition(self, definition: AliasDefinition) -> bool:
        """
        Whether `definition` does nothing but bind its name — so that a script from which it is
        absent differs only in that the name is unbound.

        Every clause is a way for the statement to do something else besides:

        - It must **denote the `Set-Alias` cmdlet**, asked of the model rather than read off the
          spelling. The kind is checked as well as the target, because a script defining
          `function Set-Alias { <payload> }` denotes `FUNCTION` under a target that is the
          function's own spelling — reading only the target there says the statement binds a name
          when what it does is run the payload, and taking it out deletes a call that ran.
          `New-Alias` is refused although it binds: it throws when the name already has a binding,
          and the error it writes is an effect of its own.
        - Its name must not be one the **host already binds**. Nearly every default alias refuses a
          plain rebind, so the statement's whole observable effect is the error it raises; which
          error it is depends on host metadata this model does not carry, and it writes one either
          way.
        - Its target must not be a **wildcard**, which binds a name that resolves to no command, so
          removing it turns a `CommandNotFoundException` into whatever the name means without it.
        - Its name must carry **no scope qualifier**. `Set-Alias global:foo X` binds an alias called
          `global:foo` — measured on 5.1 — and this model keys definitions by the literal name, so
          the reaching-definition question that decides whether a use needs one was never asked of
          such a name.
        - It must carry **no argument** beyond the name and the value, and both must be **literal**.
          `extract_alias_definition` reports this as a refusal, because a parameter it does not
          consume is one it cannot be sure did not consume the name.
        """
        node = definition.node
        denotation = self.denotation(node)
        if denotation.kind not in (CommandKind.ALIAS, CommandKind.CMDLET):
            return False
        if denotation.target is None:
            return False
        if normalize_command_name(denotation.target) != _SET_ALIAS:
            return False
        if definition.refuse or definition.wildcard or definition.target is None:
            return False
        if definition.name in KNOWN_ALIAS:
            return False
        return normalize_command_name(definition.name) == definition.name

    def introspected_names(self) -> frozenset[str] | None:
        """
        The lowercased command names the script reads out of the alias table, or `None` when it
        reads names this cannot enumerate — which stands for *every* name.

        A rewrite reaches the uses of an alias, not the mentions of it. `Get-Alias foo` names the
        alias in an argument and reports what it is bound to, so a definition the uses no longer
        need is still what that answer is about, and `${alias:foo}` reads it through the variable
        namespace instead. The reader is identified through `denotation`, so `alias foo` and a
        script's own `Set-Alias g Get-Alias; g foo` are both recognized and neither is matched by
        spelling.

        `None` is the top element rather than an error: a reader given a computed name
        (`Get-Alias $n`), a wildcard, or no name at all reports on names this cannot list, and a set
        that quietly omitted them would answer `False` for exactly the definitions most likely to be
        in it. Every caller must read `None` as "every name is read".

        A command this model cannot identify is *not* read as a reader. That is the stance
        `refinery.lib.scripts.ps1.analysis.world` takes on mutation, taken here for the same reason —
        the collected metadata omits hundreds of host commands, and reading every one of them as a
        possible reader would make this answer `None` for almost any script — and it carries the same
        residual. `alias`, the built-in name of `Get-Alias`, being absent from the collected alias
        table was therefore a soundness bug rather than a recall one.
        """
        if not self._introspected_known:
            self._introspected = self._collect_introspected_names()
            self._introspected_known = True
        return self._introspected

    def _collect_introspected_names(self) -> frozenset[str] | None:
        names: set[str] = set()
        for node in self._root.walk():
            if isinstance(node, Ps1Variable):
                if node.scope is Ps1ScopeModifier.ALIAS:
                    names.add(node.name.lower())
                continue
            if not isinstance(node, Ps1CommandInvocation):
                continue
            target = self.denotation(node).target
            if target is None:
                continue
            reader = normalize_command_name(target)
            if reader in _TABLE_READING_COMMANDS:
                return None
            if reader not in _NAME_READING_COMMANDS:
                continue
            name = _read_name_argument(node)
            if name is None or _has_wildcard(name):
                return None
            names.add(name.lower())
        return frozenset(names)

    def reads_command_success(self) -> bool:
        """
        Whether the script reads `$?`, the automatic variable holding whether the last command
        succeeded.

        Every statement that runs a command writes it, so removing one is observable to a later read
        even when the statement's own output is not: a `Set-Alias` that succeeds sets `$?` to true,
        and taking it out lets the failure before it through to the read. The variable is not the
        only engine state a removal disturbs, but it is the one a script can read back, and this is
        the fact a pass needs to decline the removal rather than reason about it.
        """
        return any(
            isinstance(node, Ps1Variable)
            and node.scope is Ps1ScopeModifier.NONE
            and node.name == _SUCCESS_VARIABLE
            for node in self._root.walk()
        )

    def world_role(self, invocation: Ps1CommandInvocation) -> WorldRole:
        """
        What `invocation` does to the type world and the command table, with the script's own
        aliases followed — the question
        `refinery.lib.scripts.ps1.analysis.world.build_closed_world` asks of every node, re-asked
        where command identity is known. Memoized for as long as the tree is unchanged.

        The world model reads a name one hop through the built-in alias table and no further, so
        `Set-Alias e iex` followed by `e $payload` reads there as an ordinary command and the world
        reads closed over a script that runs whatever `$payload` says. It cannot read further: this
        model is built over the shadow set that one produces, so a world that consulted this one
        would be a cycle. The refinement therefore belongs here, and it is a refinement rather than
        a second opinion — the name as written is classified first, so this can only ever name a
        role where the world named one, or name one where the world named none.

        A command the collected metadata does not describe reads as `WorldRole.NONE`, which is the
        world model's stance and not a weaker one: mutation is a deny-list there, an unrecognized
        command is not treated as a mutator, and that residual is the declared soundness gap its own
        documentation names. Answering `UNKNOWN` for every command outside the metadata would make
        this a different, vacuous question.

        `UNKNOWN` is for the two ways nothing static bounds what runs: dispatch that is open by
        construction, which is the axis the world model runs as an allow-list, and a name the script
        itself bound to something this model could not read through — see `_Resolution`. The second
        is why not naming a command is not on its own an answer of `NONE`: `Set-Alias e iex -Force`
        and `${function:Get-Date} = $x` each leave this model unable to say what a later use runs,
        and it knows exactly why.
        """
        found = self._roles.get(id(invocation))
        if found is None:
            found = self._roles[id(invocation)] = self._resolve_world_role(invocation)
        return found

    def _resolve_world_role(self, invocation: Ps1CommandInvocation) -> WorldRole:
        if is_opaque_dispatch(invocation):
            return WorldRole.UNKNOWN
        if runs_another_script_file(invocation):
            return WorldRole.LEAK
        written = resolve_command_name(invocation)
        if written is not None and (role := command_role(written)) is not WorldRole.NONE:
            return role
        resolution = self._resolution(invocation)
        target = resolution.denotation.target
        if target is not None and (role := command_role(target)) is not WorldRole.NONE:
            return role
        if touches_identity_provider(invocation):
            return WorldRole.IDENTITY
        if target is None and resolution.unread_binding:
            return WorldRole.UNKNOWN
        return WorldRole.NONE

    def _resolve(self, invocation: Ps1CommandInvocation) -> _Resolution:
        """
        Resolve `invocation`, recording the alias definitions it consults and, at every exit that
        names no command, whether the script's own definitions are the reason — see `_Resolution`.

        A definition is recorded wherever the resolution *read* it, not only where it followed one.
        Refusing because of a definition and denoting nothing because one exists out of reach are
        both uses of it: delete it and this invocation resolves to something else. Recording only
        the followed hops is the shape that reports `Set-Alias foo Get-*` and `Set-Alias foo *` as
        needed by nobody, and a differential cannot catch either — 5.1 raises
        `CommandNotFoundException` before and after, and the two errors differ only in a field the
        oracle drops.

        An inline scriptblock (`&{ ... }`) is not an unread binding: its body stands in the tree, so
        the whole-tree walk reads whatever it does. The unlocatable node is, defensively — a node in
        no control-flow graph is one this model knows nothing about, including whether the script
        bound the name it carries.
        """
        implicated: list[AliasDefinition] = []

        def resolved(kind: CommandKind, target: str | None, unread: bool = False) -> _Resolution:
            return _Resolution(Denotation(kind, target), tuple(implicated), unread)

        name = get_command_name(invocation)
        if name is None:
            return resolved(CommandKind.UNKNOWN, None)
        if self._flow.locate(invocation) is None:
            return resolved(CommandKind.UNKNOWN, None, True)
        visited: set[str] = set()
        current = normalize_command_name(name)
        spelling = name
        hops = 0
        while True:
            if current in visited:
                return resolved(CommandKind.NOTHING, None)
            reaching = self._reaching_alias_def(current, invocation)
            if reaching is not None:
                implicated.append(reaching)
                if current in KNOWN_ALIAS or reaching.refuse:
                    return resolved(CommandKind.UNKNOWN, None, True)
                if reaching.wildcard or reaching.target is None:
                    return resolved(CommandKind.NOTHING, None)
                visited.add(current)
                spelling = reaching.target
                current = normalize_command_name(reaching.target)
                hops += 1
                continue
            if current in self._alias_defs:
                implicated.extend(self._alias_defs[current])
                return resolved(CommandKind.NOTHING, None, True)
            builtin = KNOWN_ALIAS.get(current)
            if builtin is not None:
                visited.add(current)
                spelling = builtin
                current = normalize_command_name(builtin)
                hops += 1
                continue
            break
        if hops > 0:
            return resolved(CommandKind.ALIAS, KNOWN_CMDLETS.get(current, spelling))
        if current in self._functions:
            return resolved(CommandKind.FUNCTION, spelling)
        if current in self._shadowed:
            return resolved(CommandKind.UNKNOWN, None, True)
        if current in KNOWN_CMDLETS:
            return resolved(CommandKind.CMDLET, KNOWN_CMDLETS[current])
        return resolved(CommandKind.UNKNOWN, None)

    def _reaching_alias_def(
        self,
        name: str,
        invocation: Ps1CommandInvocation,
    ) -> AliasDefinition | None:
        """
        The one alias definition of `name` whose binding reaches the use at `invocation`, or `None`
        when none does or more than one might.

        An alias is session-wide: a `Set-Alias` in one scope is visible in the scopes nested inside
        it, so a definition at the top level reaches a use inside a `ForEach-Object` block. The use
        is therefore projected outward — onto the site where each enclosing block runs — and a
        definition sought in that scope, climbing until one is found or a body is reached that does
        not run when its site does (a function body, a stored block), which a definition inside does
        not escape. This is the projection `refinery.lib.scripts.ps1.analysis.dataflow` performs for
        a variable read; the nearest enclosing scope with a reaching definition wins, so a
        block-local rebinding shadows an outer one. A definition strictly dominates the projected
        use, so it is guaranteed to have run before it.
        """
        definitions = self._alias_defs.get(name, ())
        if not definitions:
            return None
        located = self._flow.locate(invocation)
        while located is not None:
            graph, use = located
            candidates = [
                (definition, placed[1])
                for definition in definitions
                if (placed := self._flow.locate(definition.node)) is not None
                and placed[0] is graph
            ]
            if candidates:
                reaching = self._reach.reaching_definition(graph, use, candidates)
                if reaching is not None:
                    return reaching
            owner = graph.owner
            if not isinstance(owner, Ps1ScriptBlock):
                return None
            facts = self._blocks.facts(owner)
            if facts.reach is not Ps1BlockReach.IMMEDIATE or facts.site is None:
                return None
            located = self._flow.locate(facts.site)
        return None


def build_command_model(
    root: Ps1Script,
    control_flow: ControlFlowModel,
    dominance: DominatorModel,
    blocks: Ps1BlockModel,
    functions: frozenset[str],
    shadowed: frozenset[str],
) -> Ps1CommandModel:
    """
    Build the `Ps1CommandModel` for a script from its control-flow model, its dominators, the block
    model that says where each script block runs, the set of command names it defines as `function`
    or `filter`, and the wider set of names it takes over by any means — the latter from
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld.shadowed_names`.
    """
    return Ps1CommandModel(
        root, control_flow, ReachabilityQuery(dominance), blocks, functions, shadowed)
