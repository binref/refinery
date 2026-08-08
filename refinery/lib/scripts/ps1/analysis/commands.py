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

**Writability is handled by refusal, not by a rebind table.** Every default alias but `sls` is
`ReadOnly` or `AllScope`, and a plain `Set-Alias` rebinds neither (measured: `AliasNotWritable` /
`AliasAllScopeOptionCannotBeRemoved`), so a script `Set-Alias` naming an existing builtin alias almost
never takes effect. Rather than ship the per-alias `Options` that would say which of the two happened,
the model treats such a collision — and any `-Force`/`-Option` definition — as unknown and keeps the
name as written, which is faithful whichever way the rebind went. Precise builtin-rebind resolution
waits on that metadata.

**What a command does to the world is asked here too**, through `Ps1CommandModel.world_role`, and for
the same reason the rest is: `refinery.lib.scripts.ps1.analysis.world` follows a name one hop through
the built-in alias table and cannot follow the script's own, so `Set-Alias e iex` hides a leak from
it. It cannot be fixed there — this model is built over the shadow set that one produces, so a world
consulting this one would be a cycle — and the deny-lists themselves stay there, where the argument
for what belongs on them is written. What is added here is the resolution, not a second list.

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
    Ps1Script,
    Ps1ScriptBlock,
)

#: The command names that define an alias. `sal` and `nal` are themselves default aliases of
#: `Set-Alias` and `New-Alias`; they are matched by spelling here because a script that has not
#: redefined them means exactly what they say, and one that has is caught as a collision when the
#: redefined name is later used.
_ALIAS_DEFINING_COMMANDS = frozenset({'set-alias', 'sal', 'new-alias', 'nal'})

#: The named parameters of `Set-Alias`/`New-Alias` that carry the alias name and its target.
_NAME_PARAMS = frozenset({'name', 'n'})
_VALUE_PARAMS = frozenset({'value', 'v', 'definition', 'd'})


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


class _Resolution(NamedTuple):
    """
    What `Ps1CommandModel._resolve` found: the `Denotation`, and whether the script itself is why it
    names no command.

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
    unread_binding: bool


def extract_alias_definition(cmd: Ps1CommandInvocation) -> AliasDefinition | None:
    """
    Read `cmd` as an alias definition, or `None` when it is not one or its alias name is not a
    literal. Positional (`sal x y`), named (`Set-Alias -Name x -Value y`) and mixed forms are all
    handled, `-Force` and `-Option` are noted as reasons to refuse the binding, and a wildcard target
    is noted as denoting nothing.
    """
    name = get_command_name(cmd)
    if name is None or name.lower() not in _ALIAS_DEFINING_COMMANDS:
        return None
    alias_name: str | None = None
    target: str | None = None
    target_seen = False
    refuse = False
    positional: list[str | None] = []
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument):
            if arg.kind == Ps1CommandArgumentKind.SWITCH:
                switch = arg.name.lstrip('-').lower()
                if switch == 'force' or switch.startswith('opt'):
                    refuse = True
                continue
            if arg.kind == Ps1CommandArgumentKind.NAMED:
                param = arg.name.lstrip('-').lower()
                value = string_value(arg.value) if arg.value is not None else None
                if param in _NAME_PARAMS:
                    alias_name = value
                elif param in _VALUE_PARAMS:
                    target, target_seen = value, True
                elif param.startswith('opt'):
                    refuse = True
                continue
            positional.append(string_value(arg.value) if arg.value is not None else None)
        else:
            positional.append(string_value(arg))
    if alias_name is None and positional:
        alias_name = positional.pop(0)
    if not target_seen and positional:
        target, target_seen = positional.pop(0), True
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
        self._flow = control_flow
        self._reach = reach
        self._blocks = blocks
        self._functions = functions
        self._shadowed = shadowed
        self._alias_defs: dict[str, list[AliasDefinition]] = {}
        for node in root.walk():
            if not isinstance(node, Ps1CommandInvocation):
                continue
            definition = extract_alias_definition(node)
            if definition is not None:
                self._alias_defs.setdefault(definition.name, []).append(definition)
        self._memo: dict[int, _Resolution] = {}
        self._roles: dict[int, WorldRole] = {}

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
        """
        return self._alias_defs.get(name.lower(), ())

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
        Resolve `invocation`, recording at every exit that names no command whether the script's own
        definitions are the reason — see `_Resolution`.

        An inline scriptblock (`&{ ... }`) is not one of them: its body stands in the tree, so the
        whole-tree walk reads whatever it does. The unlocatable node is, defensively — a node in no
        control-flow graph is one this model knows nothing about, including whether the script bound
        the name it carries.
        """
        name = get_command_name(invocation)
        if name is None:
            return _Resolution(Denotation(CommandKind.UNKNOWN, None), False)
        if self._flow.locate(invocation) is None:
            return _Resolution(Denotation(CommandKind.UNKNOWN, None), True)
        visited: set[str] = set()
        current = normalize_command_name(name)
        spelling = name
        hops = 0
        while True:
            if current in visited:
                return _Resolution(Denotation(CommandKind.NOTHING, None), False)
            reaching = self._reaching_alias_def(current, invocation)
            if reaching is not None:
                if current in KNOWN_ALIAS or reaching.refuse:
                    return _Resolution(Denotation(CommandKind.UNKNOWN, None), True)
                if reaching.wildcard or reaching.target is None:
                    return _Resolution(Denotation(CommandKind.NOTHING, None), False)
                visited.add(current)
                spelling = reaching.target
                current = normalize_command_name(reaching.target)
                hops += 1
                continue
            if current in self._alias_defs:
                return _Resolution(Denotation(CommandKind.NOTHING, None), True)
            builtin = KNOWN_ALIAS.get(current)
            if builtin is not None:
                visited.add(current)
                spelling = builtin
                current = normalize_command_name(builtin)
                hops += 1
                continue
            break
        if hops > 0:
            return _Resolution(
                Denotation(CommandKind.ALIAS, KNOWN_CMDLETS.get(current, spelling)), False)
        if current in self._functions:
            return _Resolution(Denotation(CommandKind.FUNCTION, spelling), False)
        if current in self._shadowed:
            return _Resolution(Denotation(CommandKind.UNKNOWN, None), True)
        if current in KNOWN_CMDLETS:
            return _Resolution(Denotation(CommandKind.CMDLET, KNOWN_CMDLETS[current]), False)
        return _Resolution(Denotation(CommandKind.UNKNOWN, None), False)

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
