"""
The closed-world model of the PowerShell analysis substrate: whether the script leaves the .NET type
system and the command table intact, so that a present-member purity grant in
`refinery.lib.scripts.ps1.analysis.effects` can be trusted. A member read the metadata proves inert
(`String.Length` is a plain property) still runs code when the script has re-pointed that member
through the Extended Type System (`Update-TypeData -Force`), and a resolved type name still
constructs a different type when the script has remapped its accelerator — both confirmed possible
on Windows PowerShell. The gate therefore grants a present-member read only where the world is
*closed*: no code the script runs can have performed such a mutation.

The predicate opens the world on two axes with opposite defaults. **Dispatch** is an allow-list: a
command is inert only when its name is statically known, so any `& $x` / `. $x` / computed-name
call opens the world, closing the open-ended escape of runtime-constructed code without a list to
forget.
**Mutation** is a curated, documented deny-list — a pure allow-list would be vacuous, since the
collected metadata omits hundreds of host cmdlets and every one would then read as a possible
mutator. The deny-list is enumerated here rather than left silent, and its residual — an exotic
aliasing spelling, a `using module` statement, a computed provider path — is a *soundness* gap, not a
recall gap: a mutator the list misses leaves the world reading closed, which fires the grants and
deletes the reads that mutator makes effectful. Every name added to it buys correctness, not recall.

This is a leaf value model — a one-shot whole-script verdict plus the shadow set — cached in
`refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache`. Whether the world is closed at *one*
particular read, which depends on where that read sits relative to the leaks that reach it, is a
graph question and does not live here: `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach`
answers it, layered on this model and on the control-flow graph. `measure_world` produces the
verdict and the opener positions the flow gate floods from in one walk, so the two cannot disagree
about what an opener is.
"""
from __future__ import annotations

import enum

from typing import NamedTuple

from refinery.lib.scripts import Node, tree_version
from refinery.lib.scripts.ps1.ast import (
    assignment_target_variables,
    get_member_name,
    is_execution_context_invoke,
    is_opaque_dispatch,
    is_scriptblock_create,
    is_scriptblock_invoke,
    normalize_command_name,
    normalize_dotnet_type_name,
    resolve_command_name,
    string_value,
    unwrap_assignment_target,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import KNOWN_ALIAS
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1ClassDefinition,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1EnumDefinition,
    Ps1FunctionDefinition,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.options import eval_is_trusted


class WorldRole(enum.Enum):
    """
    What a command does to the type world and the command table. The three opening roles are kept
    apart rather than collapsed into one boolean because a caller acts differently on each: a pass
    deleting an alias definition has to know that the invocation blocking it is another alias
    definition, which it may yet be able to delete too, and not a leak, which it never can.

    `NONE` and `UNKNOWN` are the two ways of not naming a role, and they are as far apart as they
    are in `refinery.lib.scripts.ps1.analysis.commands.CommandKind`: `NONE` says the command leaves
    the world as it found it, `UNKNOWN` says nothing static bounds what it runs.
    """
    #: Runs code supplied as data, so what it does to the world is whatever that data says.
    LEAK = enum.auto()
    #: Mutates the .NET type system, after which reflection no longer describes a type's members.
    MUTATION = enum.auto()
    #: Redefines command identity, after which a bareword no longer names what the metadata says.
    IDENTITY = enum.auto()
    #: Leaves both intact.
    NONE = enum.auto()
    #: Dispatches to whatever an expression yields, so it may be any of the above.
    UNKNOWN = enum.auto()


#: Commands that execute arbitrary code supplied as data. `Invoke-Expression` is the canonical one;
#: the opaque dispatch and scriptblock-execution forms are recognized syntactically instead. The job
#: and remoting cmdlets belong here rather than beside the mutators: each takes a scriptblock the
#: walk cannot read when it is written as a variable, and the type-system effects such a block
#: performs are runspace-global, so a child scope does not contain them.
_LEAK_CMDLETS = frozenset({
    'invoke-command',
    'invoke-expression',
    'start-job',
    'start-threadjob',
})

#: The subset of the above that runs its code in the scope that called it, so that a command or
#: variable the code writes lands in this script's own tables. See `runs_code_in_the_calling_scope`.
_CALLER_SCOPE_LEAKS = frozenset({'invoke-expression'})

#: Commands that mutate the .NET type system, so reflection can no longer be trusted to describe a
#: type's members. Curated and documented rather than derived — the module docstring says why a
#: mutation allow-list would be vacuous. Names are compared after alias resolution.
_MUTATION_CMDLETS = frozenset({
    'add-member',
    'add-type',
    'import-module',
    'new-module',
    'update-typedata',
})

#: The subset of the mutators that also loads commands into the session, so a bareword after one may
#: name a command this tree never spells. `Import-Module` imports a module's exported commands and
#: `New-Module` runs a scriptblock whose functions become callable; the rest of `_MUTATION_CMDLETS`
#: touch only the type system and leave the command table as they found it. See
#: `_opens_command_namespace`.
_MODULE_LOADER_CMDLETS = frozenset({
    'import-module',
    'new-module',
})

#: Commands that redefine command identity, after which a later bareword can no longer be trusted to
#: name what the metadata says — including a mutator hidden behind the new name. A static
#: single-definition alias is inlined away before this runs, so a *surviving* one is an alias the
#: inliner could not resolve.
_ALIAS_CMDLETS = frozenset({
    'import-alias',
    'new-alias',
    'remove-alias',
    'set-alias',
})

#: The subset of the above that binds one name to one command, written out in the script, and
#: nothing else — the only alias definition a pass is in a position to take out. See
#: `Ps1TypeWorld.closed_but_for_alias_bindings`.
_ALIAS_BINDING_COMMANDS = frozenset({'set-alias'})

#: The file extension of a PowerShell script. Invoking one runs its definitions and whatever type
#: mutations it performs into this session, whichever operator carries the call.
_SCRIPT_FILE_SUFFIX = '.ps1'

#: The variable namespaces that name a command rather than a value: assigning into either redefines
#: command identity the way `_ALIAS_CMDLETS` do.
_IDENTITY_SCOPES = frozenset({
    Ps1ScopeModifier.ALIAS,
    Ps1ScopeModifier.FUNCTION,
})

#: The provider names that address command identity, written as a path argument to an item cmdlet
#: (`Set-Item alias:x ...`). Matched by name rather than by enumerating every aliasing cmdlet, which
#: is the family the mutation deny-list cannot close by name.
_IDENTITY_PROVIDERS = ('alias', 'function')

#: The cmdlets whose subject is a provider path, so that one they are given as an expression may be
#: a path into an identity provider however it is spelled. See `may_touch_identity_provider`.
_ITEM_CMDLETS = frozenset({
    'clear-item',
    'copy-item',
    'move-item',
    'new-item',
    'remove-item',
    'rename-item',
    'set-item',
})

#: The keywords that define a command under a name given as an argument rather than as a definition
#: node. `workflow NAME { ... }` and `configuration NAME { ... }` each introduce a command named NAME
#: that shadows a same-named cmdlet under 5.1's Function-over-Cmdlet precedence, but the parser emits
#: both as a plain invocation whose name is the keyword, so the name they take over is read off the
#: arguments the way an item cmdlet's provider path is.
_COMMAND_DEFINITION_KEYWORDS = frozenset({'workflow', 'configuration'})


def command_role(name: str) -> WorldRole:
    """
    What the command `name` does to the world, or `WorldRole.NONE` when no deny-list holds it. Never
    `WorldRole.UNKNOWN`: a name is by construction something this can look up, and not knowing what
    an invocation runs is a fact about the invocation rather than about any name.

    The lookup key is the *deny-list* reading `refinery.lib.scripts.ps1.ast.resolve_command_name`
    describes, taken here rather than owed by the caller: the module and scope qualifiers dropped
    and one hop through the built-in alias table, so that neither `Microsoft.PowerShell.Utility\\iex`
    nor `global:iex` nor plain `iex` can dodge a table the bare `Invoke-Expression` matches. Eight
    of the entries below are reachable only through that hop, so a caller handing over a name it
    had not resolved would otherwise read a deny-list answer of `NONE` — the one direction a
    deny-list must never fail in. Taking the key here is what makes that impossible to get wrong at
    a call site. It is idempotent: no built-in alias names what another one resolves to.

    This is the one place the three tables are read. `refinery.lib.scripts.ps1.analysis.commands`
    asks the same question of a name it reached by following the script's own aliases — which this
    module cannot follow, since the command model is built over the shadow set this one produces —
    and a second reading of the tables there would be a second deny-list to keep in step.
    """
    key = normalize_command_name(name.rpartition('\\')[2])
    key = KNOWN_ALIAS.get(key, key).lower()
    if key in _LEAK_CMDLETS:
        return WorldRole.LEAK
    if key in _MUTATION_CMDLETS:
        return WorldRole.MUTATION
    if key in _ALIAS_CMDLETS:
        return WorldRole.IDENTITY
    return WorldRole.NONE


def _opens_type_system(role: WorldRole) -> bool:
    """
    Whether an opener `_opens_world` gave `role` leaves the .NET type system in a state reflection
    no longer describes — the axis a present-member purity grant reads.

    `WorldRole.MUTATION` is the plain-sight change to it, and `LEAK` and `UNKNOWN` open it by
    running code that can perform one. `WorldRole.IDENTITY` does not: rebinding a command name
    through `Set-Alias` or the `function:`/`alias:` namespace touches no type and no member. The
    command that identity binds may itself mutate the type system when it later runs, but that is a
    fact about the *call* to the rebound name — the command axis — not about the binding itself.
    """
    return role in (WorldRole.LEAK, WorldRole.MUTATION, WorldRole.UNKNOWN)


def _opens_command_namespace(node, role: WorldRole) -> bool:
    """
    Whether the opener `node`, which `_opens_world` gave `role`, leaves a bareword able to name a
    command this tree never spells — the axis `refinery.lib.scripts.ps1.analysis.callgraph` reads.

    A `WorldRole.MUTATION` opens the type system but binds no command name — a `class` or `Add-Type`
    puts a *type* into the session, `Update-TypeData` and `Add-Member` re-point a type's *members* —
    so none of them says a later call runs something other than what the metadata names. The two
    module loaders are the exception the type-system deny-list folds in for its own reasons: an
    `Import-Module` imports commands and a `New-Module` runs a body whose functions become callable,
    so each does open the command namespace. `LEAK`, `IDENTITY` and `UNKNOWN` open it by running
    unreadable code, rebinding a name, or dispatching opaquely.

    Every opener opens at least one of the two axes, so `_opens_type_system` and this one together
    reproduce `closed_for_the_whole_run` as their conjunction — no opener is invisible to both.
    """
    if role in (WorldRole.LEAK, WorldRole.IDENTITY, WorldRole.UNKNOWN):
        return True
    if role is WorldRole.MUTATION and isinstance(node, Ps1CommandInvocation):
        return (resolve_command_name(node) or '') in _MODULE_LOADER_CMDLETS
    return False


class Ps1ShadowSite(NamedTuple):
    """
    One statement that takes a command name over: the `name` it rebinds, keyed through
    `refinery.lib.scripts.ps1.ast.normalize_command_name` like the shadow set, and the `site` node
    performing the redefinition. `refinery.lib.scripts.ps1.analysis.worldflow.build_world_reach`
    floods forward from these the way it floods from the openers, so a call no redefinition of its
    name can precede still means the built-in the metadata describes.
    """
    name: str
    site: Node


class Ps1WorldMeasurement(NamedTuple):
    """
    One walk's reading of *root*: the whole-run `world` verdict, the `openers` that produced it and
    the `shadow_sites` where a command name is taken over, each in walk order, and the `root` and
    `build_version` they were measured over. All come from the same walk, so
    `world.closed_for_the_whole_run` and `not openers` are the same fact, and the names of
    `shadow_sites` are exactly `world.shadowed_names` — a node one counts and the other misses
    cannot exist. Held in a `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot;
    `build_world_reach` floods from `openers` and `shadow_sites` and stamps `build_version` onto
    the reach model so a held one notices the tree change.

    The opener and site nodes are live tree references, which is why this is a cache record rather
    than a field of the leaf `Ps1TypeWorld`: a slot is dropped whole on the next version bump, so
    its node references are never read against a tree they no longer belong to.
    """
    world: Ps1TypeWorld
    openers: tuple[Node, ...]
    shadow_sites: tuple[Ps1ShadowSite, ...]
    root: Ps1Script
    build_version: int


#: The commands that write the command table with a binding written down beside them. `Import-Alias`
#: is the aliasing cmdlet that is not one: it takes its names from a file no analysis here sees, so
#: what it does to the table is unreadable in exactly the sense an `Invoke-Expression` payload is. A
#: command outside this set that merely mentions a provider path — `Get-ChildItem alias:`,
#: `Test-Path 'function:more'` — is read as an identity opener by `touches_identity_provider`, which
#: cannot tell a read from a write, and binds nothing at all.
_NAME_BINDING_COMMANDS = (_ALIAS_CMDLETS - {'import-alias'}) | _ITEM_CMDLETS

#: The parameter spellings that carry the binding such a command performs, each a prefix of `-Name`
#: or `-Value` because PowerShell binds a parameter by any unambiguous prefix of its name. Every
#: other named parameter — `-Force`, `-Scope`, `-Option`, `-Description` — steers the binding
#: without saying what it is, and reading one as part of the binding would let a `-Force:$true` make
#: a fully written-out rebinding look unreadable.
_BINDING_PARAMETERS = frozenset({
    'n',
    'na',
    'nam',
    'name',
    'v',
    'va',
    'val',
    'valu',
    'value',
})


def _runs_unreadable_code(node, role: WorldRole) -> bool:
    """
    Whether the danger `role` names at `node` is that code this analysis cannot read will run — now,
    for `WorldRole.LEAK` and `WorldRole.UNKNOWN`, or under a name a later statement invokes, for
    `WorldRole.IDENTITY`. These are the openers
    `refinery.lib.scripts.ps1.options.Ps1DeobfuscationOptions.trust_eval` excuses.

    `WorldRole.MUTATION` is never one: it is a change the script performs in plain sight, and
    excusing it would mean disbelieving a statement the walk can read. Neither is a command that
    writes the command table with the whole binding spelled out beside it — `New-Alias Get-Date
    Stop-Process`, `Set-Item alias:Out-Null Write-Host`, `Set-Item function:Get-Date { ... }`. That
    is the same plain-sight change to command identity, and it is the one opener nothing else
    covers: `_identity_redefinitions` classifies a `function` statement and a
    `function:`/`alias:` variable write, so a name an aliasing or item cmdlet takes over never
    reaches the shadow set, and the verdict is all that stands between such a statement and a later
    call to the name it rebound.

    A binding with an unreadable half is excused, name or target either way, which is where the
    trade the option buys actually sits: `Set-Alias Copy-Item $t` says which name it takes over but
    not what that name will run, and refusing it would keep every script whose payload dispatcher is
    reached through an alias. The residual is stated rather than left silent — such a name is
    trusted afterwards, and closing that needs the shadow set to record what an aliasing cmdlet
    binds, which is a reading no walk here performs.
    """
    if role is WorldRole.MUTATION or role is WorldRole.NONE:
        return False
    if role is not WorldRole.IDENTITY or not isinstance(node, Ps1CommandInvocation):
        return True
    if normalize_command_name(resolve_command_name(node) or '') not in _NAME_BINDING_COMMANDS:
        return True
    return _binds_what_the_walk_cannot_read(node)


def _binds_what_the_walk_cannot_read(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether any argument of `cmd` that carries the binding hides what it holds.

    A parameter and the value written after it reach the tree as two arguments — a switch naming the
    parameter, then a positional holding the value — so the two are paired here. A value written
    after `-Name` or `-Value`, and a positional that follows no parameter at all, carry the binding;
    a value written after any other parameter steers it without saying what it is, and reading one
    as part of the binding lets a `-Scope 1` make a fully written-out rebinding look unreadable.
    """
    pending: str | None = None
    for argument in cmd.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            if not _is_written_out(argument):
                return True
            continue
        name = argument.name.lstrip('-').lower()
        if argument.kind is Ps1CommandArgumentKind.SWITCH:
            pending = name
            continue
        if argument.kind is Ps1CommandArgumentKind.NAMED:
            carries = name in _BINDING_PARAMETERS
        else:
            carries = pending is None or pending in _BINDING_PARAMETERS
        pending = None
        if carries and not _is_written_out(argument.value):
            return True
    return False


def _is_written_out(value) -> bool:
    """
    Whether `value` stands in the tree as something this walk reads whole: a static string, a
    scriptblock whose body is written out, a list of such values, or the absent value of a switch.
    Anything else — a variable, the result of a call — hides what the command holding it binds.
    """
    if value is None:
        return True
    value = unwrap_parens(value)
    if isinstance(value, Ps1ScriptBlock):
        return True
    if isinstance(value, Ps1ArrayLiteral):
        return all(_is_written_out(element) for element in value.elements)
    return string_value(value) is not None


def measure_world(root: Ps1Script, options: object | None = None) -> Ps1WorldMeasurement:
    """
    Walk the whole tree once, computing the world verdict and every position together: whether any
    node opens the type system (`_opens_type_system`) and whether any opens the command table
    (`_opens_command_namespace`) — the two independent axes the world carries apart — the set of
    command names the script redefines and the site of each redefinition, and every opener node in
    walk order. A single opener anywhere is global and retroactive, so it closes off the axis it
    opens. The walk cannot short-circuit on the first opener because the shadow set needs every
    redefinition, wherever it sits, and the floods need every position.

    An opener is yielded as the node itself, not its role. The class or enum definition among them
    opens the world at no position — the engine compiles it before the first statement runs — and is
    recognized by `build_world_reach`, which must fail closed on it.

    Under `refinery.lib.scripts.ps1.options.Ps1DeobfuscationOptions.trust_eval` an opener
    `_runs_unreadable_code` answers for is not recorded at all, so it neither opens the whole-run
    verdict nor floods a position. The shadow set is untouched by the option: every site in it is a
    redefinition this walk *did* read, so nothing about it rests on what unreadable code does.
    """
    trusting = eval_is_trusted(options)
    type_system_closed = True
    command_table_closed = True
    closed_but_for_alias_bindings = True
    shadowed: set[str] = set()
    openers: list[Node] = []
    shadow_sites: list[Ps1ShadowSite] = []
    for node in root.walk():
        redefined = _identity_redefinitions(node)
        shadowed.update(record.name for record in redefined)
        shadow_sites.extend(Ps1ShadowSite(record.name, node) for record in redefined)
        role = _opens_world(node, redefined)
        if role is WorldRole.NONE or (trusting and _runs_unreadable_code(node, role)):
            continue
        openers.append(node)
        if _opens_type_system(role):
            type_system_closed = False
        if _opens_command_namespace(node, role):
            command_table_closed = False
        if not _opens_world_only_by_binding_an_alias(node):
            closed_but_for_alias_bindings = False
    world = Ps1TypeWorld(
        type_system_closed,
        frozenset(shadowed),
        closed_but_for_alias_bindings,
        command_table_closed,
    )
    return Ps1WorldMeasurement(
        world, tuple(openers), tuple(shadow_sites), root, tree_version(root))


class Ps1TypeWorld:
    """
    The verdict of `build_closed_world`: whether the running script leaves the .NET type system and
    the command table intact. These are two independent axes with two independent openers — a
    `class` mutates the type system without binding a command name, a `Set-Alias` the reverse — so
    the world carries them apart, `type_system_closed` and `command_table_closed`, and the combined
    whole-run verdict `closed_for_the_whole_run` is their conjunction rather than a third stored
    flag that could drift from them. Callers read the axis they need: the call graph reads the
    command axis, the present-member purity gate reads the combined verdict. Alongside them sit the
    set of command names the script redefines (`command_shadowed`) and the one question asked of the
    verdict-and-set pair (`may_trust_command_name`). Held in a
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot and passed to the effect layer.

    A world nothing was measured over is spelled `Ps1TypeWorld(False, frozenset())` — open on both
    axes, trusting no name — rather than by an absent object, so that "we did not look" and "we
    looked and it is open" cannot become two verdicts a caller distinguishes.
    """

    def __init__(
        self,
        type_system_closed: bool,
        shadowed: frozenset[str],
        closed_but_for_alias_bindings: bool | None = None,
        command_table_closed: bool | None = None,
    ):
        """
        A verdict left unstated for `closed_but_for_alias_bindings` or `command_table_closed` takes
        the value of `type_system_closed`, which is the answer for a world that has no opener at all
        and the conservative one for a world stated by a single closed/open verdict — a hand-built
        world that does not distinguish the axes.
        """
        self._type_system_closed = type_system_closed
        self._closed_but_for_alias_bindings = (
            type_system_closed
            if closed_but_for_alias_bindings is None else closed_but_for_alias_bindings)
        self._command_table_closed = (
            type_system_closed if command_table_closed is None else command_table_closed)
        self._shadowed = shadowed

    @property
    def closed_but_for_alias_bindings(self) -> bool:
        """
        Whether the only thing keeping this world open is that the script binds aliases — so that a
        pass which deleted every `Set-Alias` would leave it closed.

        A pass cannot work this out from `closed_for_the_whole_run` and its own list of what it is
        about to remove, because a verdict of *open* names no reason: it would have to re-walk the
        tree for every other way the world opens, which is the whole of this model restated in a
        transform.
        Asking here instead is one walk, and the two answers cannot disagree about what an opener is.

        Only `Set-Alias` is set aside, not every command that redefines identity. `New-Alias` throws
        on a name that is already bound, `Import-Alias` reads a file this analysis cannot see, and a
        provider path such as `Set-Item alias:x` is not a binding this model reads at all — none of
        them is something a caller is in a position to delete, so a script containing one is one
        whose world stays open however many `Set-Alias` statements go.
        """
        return self._closed_but_for_alias_bindings

    @property
    def type_system_closed(self) -> bool:
        """
        Whether nothing the script runs leaves the .NET type system in a state reflection no longer
        describes: the type-system half of the world. A pure command-table opener — a `Set-Alias`,
        an `Import-Alias`, a `function:`/`alias:` binding — leaves this closed while opening
        `command_table_closed`, the mirror of a `class` opening this one alone. See
        `_opens_type_system`.
        """
        return self._type_system_closed

    @property
    def closed_for_the_whole_run(self) -> bool:
        """
        Whether the world is closed on *both* axes *anywhere* the script runs: no node opens the
        type system and none opens the command table, so a present-member grant holds everywhere.
        This is the whole-script verdict, position free by construction — a question about the run
        entire, not about one read within it. It is the conjunction of the two axes, not a stored
        flag: a world open on either axis is not closed for the whole run.

        The flow-sensitive successor to this — whether the world is closed at one particular read,
        which depends on where that read sits relative to the leaks that reach it — is not a fact
        about this value object. It needs the control-flow graph, so it lives in
        `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach`, layered on this the way
        `refinery.lib.scripts.ps1.analysis.commands.Ps1CommandModel` is layered on `shadowed_names`.
        A verdict of closed here means that model grants at every position; only when this is open
        does the position start to matter.
        """
        return self._type_system_closed and self._command_table_closed

    @property
    def command_table_closed(self) -> bool:
        """
        Whether nothing the script runs can leave a bareword naming a command this tree never
        spells: the command-table half of the world, read by
        `refinery.lib.scripts.ps1.analysis.callgraph` where `closed_for_the_whole_run` is the wider
        type-system-and-command verdict the member-trust gate reads.

        A pure type-system mutation — a `class`, `Add-Type`, `Update-TypeData`, `Add-Member`, a
        type-accelerator remap, a PSObject member mutation — opens `closed_for_the_whole_run` but
        not this: it changes what a *type* name denotes, never what a *command* name runs. So
        `closed_for_the_whole_run` implies this, and the converse fails for exactly those mutations.
        See `_opens_command_namespace` for what does open it.
        """
        return self._command_table_closed

    def command_shadowed(self, name: str) -> bool:
        """
        Whether `name` is a command the script redefines with a script-local `function`/`filter`
        or a `function:`/`alias:`-scope assignment, so the collected metadata no longer describes
        what the name runs. The analysis must not trust such a name for typing or purity. The set is
        whole-script and conservative — an inner-scope redefinition distrusts the name everywhere,
        which only keeps more — mirroring `closed_for_the_whole_run`'s whole-script granularity.

        The query is normalized the way the set was built, so the spelling a caller happens to hold
        cannot answer `False` for a name the walk recorded under its canonical key.
        """
        return normalize_command_name(name) in self._shadowed

    def may_trust_command_name(self, name: str) -> bool:
        """
        Whether the collected metadata still describes what the command `name` runs, so a site may
        act on the name — for typing or for purity. Two things stop it describing it, and both are
        this model's to answer: the script redefines the name where the walk can classify the
        redefinition, or the world is open anywhere the run reaches, in which case a dot-sourced
        file, an imported module, an `iex`, an item cmdlet writing the `function:` provider or an
        opaque dispatch can bind *any* name to code this tree does not contain. Reading the shadow
        set alone would trust every name in exactly the scripts able to rebind them, and that set
        holds only the two spellings the classifier sees.

        This is the whole-run verdict, position free by construction. Whether the name may be
        trusted at *one particular node* — which depends on where that node sits relative to the
        openers and to the redefinitions of this very name — is
        `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach.may_trust_command_name_at`,
        layered on this verdict the way `closed_at` is layered on `closed_for_the_whole_run`. A
        verdict of trusted here means that model grants at every position; only when this refuses
        does the position start to matter. That short-circuit is the whole of what reads this in
        the package today — every pass asks the positional query — and it is why the verdict stays
        here rather than moving into the layer above it: the wider question is answered by
        narrowing this one, so this one has to exist first.

        Named for the question a caller actually has rather than for the shadow set, because the
        answer is wider than the set: a reader who takes this for "is it redefined?" and narrows it
        back to that would reopen a hole that deletes code, and no `_grant` sits in the path to
        catch it.

        The verdict read is the combined `closed_for_the_whole_run`, which a pure type-system
        mutation opens. That is safe over-refusal, not a requirement: a `class` or `Add-Type` cannot
        change what a *command* name runs, so this could read `command_table_closed` and trust the
        name over such a mutation. Tightening it that way is a separate increment, since it would
        move member-grant behaviour on every script that mutates a type beside a trusted command.
        """
        return self.closed_for_the_whole_run and not self.command_shadowed(name)

    @property
    def shadowed_names(self) -> frozenset[str]:
        """
        Every command name the script redefines, keyed through
        `refinery.lib.scripts.ps1.ast.normalize_command_name`. Exposed so a transform that must not
        rewrite a name the script has taken over reads the one set the whole-tree walk built,
        instead of keeping a narrower private one that sees only `function` definitions.
        """
        return self._shadowed


def build_closed_world(root: Ps1Script) -> Ps1TypeWorld:
    """
    The whole-run verdict alone, for a caller that wants the leaf value without a cache and not the
    opener positions `refinery.lib.scripts.ps1.analysis.worldflow.build_world_reach` floods from —
    the tests that assert the verdict. A projection of `measure_world`, so a verdict read this way
    and one the flow gate floods from are never two different answers. The cache reaches that same
    projection through `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache.world_measurement`,
    not through here.
    """
    return measure_world(root).world


def runs_code_supplied_as_data(measurement: Ps1WorldMeasurement) -> bool:
    """
    Whether any opener the measurement recorded runs code this analysis cannot read — the
    `WorldRole.LEAK` and `WorldRole.UNKNOWN` openers, the ones that can write script state out of
    data the tree does not contain. A driver asked to read a name no binding claims may answer
    `$null` only where this says no such site exists, because an `Invoke-Expression` payload writing
    that name is state no collection in the tree sees.
    """
    return any(
        _opens_world(node, _identity_redefinitions(node)) in (WorldRole.LEAK, WorldRole.UNKNOWN)
        for node in measurement.openers
    )


def _opens_world_only_by_binding_an_alias(node) -> bool:
    """
    Whether the sole reason `node` opens the world is that it is a `Set-Alias` — see
    `Ps1TypeWorld.closed_but_for_alias_bindings`. Every other reason the same node might open it is
    excluded here rather than assumed away, because a `Set-Alias` that also dispatches opaquely or
    addresses a provider path is still each of those things.
    """
    if not isinstance(node, Ps1CommandInvocation):
        return False
    if is_opaque_dispatch(node) or runs_another_script_file(node):
        return False
    if touches_identity_provider(node):
        return False
    return resolve_command_name(node) in _ALIAS_BINDING_COMMANDS


class _IdentityBody(enum.Enum):
    """
    What a command redefinition binds the name to, which is what decides whether the redefinition
    also opens the type world. An enum rather than a boolean because the two ways of *not* being a
    visible block are unrelated — one hides a body inside a value, the other names another command
    entirely — and collapsing them would make the world rule read as if it had one reason.
    """
    #: A scriptblock literal standing in the tree, so the whole-tree walk reads its statements and
    #: catches a mutation inside it by presence. The only kind that leaves the world closed.
    VISIBLE_BLOCK = enum.auto()
    #: A value the walk cannot see through — a variable, a call's result, or a compound assignment
    #: folding in whatever the name held before.
    OPAQUE_VALUE = enum.auto()
    #: Another command, named rather than defined. Its body is not in this script at all.
    EXTERNAL_COMMAND = enum.auto()


class _IdentityRedefinition(NamedTuple):
    name: str
    body: _IdentityBody


def _identity_redefinitions(node) -> tuple[_IdentityRedefinition, ...]:
    """
    The command names `node` redefines, each normalized to the key a call resolves under and paired
    with what it binds, or an empty tuple. A `function`/`filter` definition names one command
    directly; an assignment into the `function:`/`alias:` variable namespace names one per slot it
    writes, so the multi-assignment `${function:Get-Date}, $y = { ... }, 2` records `get-date` where
    matching one target shape against one variable would miss it; an item cmdlet writing a
    `function:`/`alias:` provider path names the item that path addresses; a `workflow`/`configuration`
    statement names the command its first argument spells.

    Normalizing is what makes the name usable: `function global:Get-Date` defines exactly what a
    later unqualified `Get-Date` runs, and a shadow set holding the qualified spelling answers `False`
    to every consumer that asks about the unqualified one.

    Only a plain `=` onto a single target reports `VISIBLE_BLOCK`. A multi-assignment could be
    paired up with the values on its right, but the target list drops non-variable slots, so the
    position a variable came from is already lost — and the shape is rare enough that reading
    every slot of one as opaque costs nothing.
    """
    if isinstance(node, Ps1FunctionDefinition):
        return (_IdentityRedefinition(
            normalize_command_name(node.name), _IdentityBody.VISIBLE_BLOCK),)
    if isinstance(node, Ps1CommandInvocation):
        keyword = _command_definition_keyword_redefinition(node)
        return (keyword,) if keyword is not None else _provider_path_redefinitions(node)
    if not isinstance(node, Ps1AssignmentExpression):
        return ()
    targets = assignment_target_variables(node.target)
    single = len(targets) == 1 and not isinstance(
        unwrap_assignment_target(node.target), Ps1ArrayLiteral)
    return tuple(
        _IdentityRedefinition(
            normalize_command_name(variable.name),
            _assigned_identity_body(node, variable, single),
        )
        for variable in targets
        if variable.scope in _IDENTITY_SCOPES
    )


def _assigned_identity_body(
    node: Ps1AssignmentExpression, variable: Ps1Variable, single: bool,
) -> _IdentityBody:
    """
    What an identity-scope assignment binds its name to. The `alias:` namespace always names another
    command; the `function:` namespace binds a scriptblock, which is readable only when written out
    as a literal and this assignment plainly rebinds one target.
    """
    if variable.scope is Ps1ScopeModifier.ALIAS:
        return _IdentityBody.EXTERNAL_COMMAND
    if not single or node.operator != '=' or node.value is None:
        return _IdentityBody.OPAQUE_VALUE
    if isinstance(unwrap_parens(node.value), Ps1ScriptBlock):
        return _IdentityBody.VISIBLE_BLOCK
    return _IdentityBody.OPAQUE_VALUE


def _provider_path_redefinitions(cmd: Ps1CommandInvocation) -> tuple[_IdentityRedefinition, ...]:
    """
    The command names an item cmdlet takes over by writing a `function:`/`alias:` provider path —
    `Set-Item function:ForEach-Object { ... }` rebinds `ForEach-Object` exactly as
    `function ForEach-Object { ... }` does, but through a path this reads out of the argument rather
    than off the statement keyword. Only the item cmdlets are read this way: `Get-ChildItem alias:`
    and `Test-Path 'function:x'` name the same provider and bind nothing, so a command outside
    `_ITEM_CMDLETS` yields no name however it spells a provider.

    The bound body is `OPAQUE_VALUE`: what a path write installs is not a scriptblock standing where
    the name is declared, and the world opens on the command through `_command_opens_world` as it
    always has. A computed path (`Set-Item $p { ... }`) spells no name here; it leaves the world
    closed, since `touches_identity_provider` cannot read `$p` either, and catching that shape is
    the `may_touch_identity_provider` residual the command model carries, not this walk.

    A name an item cmdlet binds outside a provider-path string is not read: a `-Name`/`-NewName`
    operand, a positional new-name (`Rename-Item function:t X`), an array element
    (`Set-Item a,b { ... }`), or a path behind a `/` this does not canonicalize. A pipeline over
    such a rebound iterator still folds. Measured on 5.1 and pinned in `test_aliases.py`; closing
    it is the extraction-completeness increment.
    """
    if normalize_command_name(resolve_command_name(cmd) or '') not in _ITEM_CMDLETS:
        return ()
    redefinitions: list[_IdentityRedefinition] = []
    for argument in cmd.arguments:
        value = argument.value if isinstance(argument, Ps1CommandArgument) else argument
        text = string_value(value)
        if text is None:
            continue
        item = _identity_provider_item_name(text)
        if item is not None:
            redefinitions.append(_IdentityRedefinition(
                normalize_command_name(item), _IdentityBody.OPAQUE_VALUE))
    return tuple(redefinitions)


def _identity_provider_item_name(path: str) -> str | None:
    """
    The command name a `function:`/`alias:` provider path addresses — `ForEach-Object` for
    `function:ForEach-Object`, `x` for `Alias:\\x`, `Get-Date` for
    `Microsoft.PowerShell.Core\\Function::Get-Date` — or `None` for a path naming no identity
    provider or no item under one. The drive is read in both spellings `touches_identity_provider`
    reads it, and the item is what follows the provider's colon, cleared of the `:` a qualified path
    doubles and the `\\` a drive-rooted one leads with.
    """
    for spelling in (path, path.rpartition('\\')[2]):
        drive, separator, item = spelling.partition(':')
        if separator and drive.lower() in _IDENTITY_PROVIDERS:
            item = item.lstrip('\\:')
            if item:
                return item
    return None


def command_definition_keyword_binding(
    cmd: Ps1CommandInvocation,
) -> tuple[str, Ps1ScriptBlock] | None:
    """
    The command a `workflow`/`configuration` statement defines and the scriptblock body it binds to
    that name, or `None` when `cmd` is not one. The defined name is the statement's first positional
    argument and the body is a scriptblock standing among the arguments; a form carrying no
    scriptblock defines nothing and is left alone, and one whose name is not a static literal names no
    command this can read. It is the one recognizer of these keywords, shared with
    `refinery.lib.scripts.ps1.analysis.callgraph` so that the shadow set and the call graph cannot
    disagree on what a `workflow` defines.
    """
    if resolve_command_name(cmd) not in _COMMAND_DEFINITION_KEYWORDS:
        return None
    positionals = [
        argument.value
        for argument in cmd.arguments
        if isinstance(argument, Ps1CommandArgument)
        and argument.kind is Ps1CommandArgumentKind.POSITIONAL
    ]
    body = next((value for value in positionals if isinstance(value, Ps1ScriptBlock)), None)
    if body is None:
        return None
    name = string_value(positionals[0]) if positionals else None
    if name is None:
        return None
    return normalize_command_name(name), body


def _command_definition_keyword_redefinition(
    cmd: Ps1CommandInvocation,
) -> _IdentityRedefinition | None:
    """
    The identity redefinition a `workflow`/`configuration` statement performs, or `None` when `cmd`
    is not one. The body is a `VISIBLE_BLOCK` for the same reason `function NAME { ... }` is — it
    stands in the tree, so a mutation inside it is caught by presence and the redefinition leaves the
    world closed.
    """
    binding = command_definition_keyword_binding(cmd)
    if binding is None:
        return None
    name, _ = binding
    return _IdentityRedefinition(name, _IdentityBody.VISIBLE_BLOCK)


def _opens_world(node, redefined: tuple[_IdentityRedefinition, ...]) -> WorldRole:
    """
    The role by which `node` leaves the type system or the command table in a state the collected
    metadata no longer describes, or `WorldRole.NONE` for a node that leaves both as it found them.
    `redefined` is the identity classification of the same node, so an assignment into the identity
    namespaces is recognized once, not by two functions that can drift apart.

    The role rather than a boolean, because `measure_world` has a caller that acts differently on
    each: `refinery.lib.scripts.ps1.options.Ps1DeobfuscationOptions.trust_eval` excuses an opener
    that runs code nobody can read and never one that mutates the world in plain sight.

    A redefinition binding a visible scriptblock does *not* open the world. Its body stands in the
    tree, so a mutation inside it is caught by presence like any other statement, and the same
    construct spelled `function X { }` has always left the world closed. Opening on it would kill
    every member grant in the script over a name the shadow set already distrusts.

    A `class` or `enum` definition does open it, for the reason `Add-Type` does: it puts a type into
    the session under a name the collected metadata never described, and a name it *did* describe is
    exactly the interesting case — `class Math { static [int] Abs([int]$x) { <payload> } }` makes
    `[Math]::Abs(1)` run that body while `resolve_type` still vouches for `System.Math`. The
    definition standing in the tree does not help, because the grant is keyed on the type name
    rather than on the presence of a body.
    """
    if isinstance(node, (Ps1ClassDefinition, Ps1EnumDefinition)):
        return WorldRole.MUTATION
    if isinstance(node, Ps1CommandInvocation):
        return _command_opens_world(node)
    if isinstance(node, Ps1InvokeMember):
        if (
            is_scriptblock_create(node)
            or is_scriptblock_invoke(node)
            or is_execution_context_invoke(node)
        ):
            return WorldRole.LEAK
        if _is_type_accelerator_mutation(node) or _is_psobject_member_mutation(node):
            return WorldRole.MUTATION
        return WorldRole.NONE
    if isinstance(node, Ps1AssignmentExpression):
        if any(record.body is not _IdentityBody.VISIBLE_BLOCK for record in redefined):
            return WorldRole.IDENTITY
        return WorldRole.NONE
    return WorldRole.NONE


def _command_opens_world(cmd: Ps1CommandInvocation) -> WorldRole:
    """
    The deny-list is read before the opaque-file test, so that a command the tables name keeps the
    role they give it however it is invoked. Both spellings open the world either way, but the role
    is what decides whether `_runs_unreadable_code` may excuse the node, and a dot-invoked
    `Add-Type` mutates the type system in plain sight rather than running a file nobody can read.
    """
    if is_opaque_dispatch(cmd):
        return WorldRole.UNKNOWN
    name = resolve_command_name(cmd)
    if name is not None and (role := command_role(name)) is not WorldRole.NONE:
        return role
    if runs_another_script_file(cmd):
        return WorldRole.LEAK
    if name is None:
        return WorldRole.NONE
    return WorldRole.IDENTITY if touches_identity_provider(cmd) else WorldRole.NONE


def runs_another_script_file(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether `cmd` runs a `.ps1` file that is not part of this tree, so the analysis cannot see what
    it defines or mutates. Dot-sourcing is the spelling that matters most — it runs the file's
    definitions into the current scope — but the operator is not what makes the file opaque: a
    `& '.\\stage2.ps1'` or a bareword `stage2.ps1` runs the same code, and the Extended Type System
    and accelerator mutations it may perform are runspace-global rather than scope-local, so the
    child scope a call operator opens does not contain them.

    A dot-sourced inline block (`.{ ... }`) runs only its visible body, which the walk covers, and
    `. $x` is already opaque dispatch.
    """
    if not isinstance(cmd.name, Ps1StringLiteral):
        return False
    return (
        cmd.invocation_operator == '.'
        or cmd.name.value.lower().endswith(_SCRIPT_FILE_SUFFIX)
    )


def touches_identity_provider(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether any argument is a literal path into the `alias:` or `function:` provider, the vector
    that escapes a name-keyed deny-list because `Set-Item alias:x Update-TypeData` mutates identity
    without `Set-Item` being an aliasing cmdlet. Recognized by the provider the path names, not by
    resolving the aliased target, so an obfuscated or dynamic target cannot slip through.

    The provider is read both as written and after the module qualifier `resolve_command_name`
    strips from a command name, because a path addresses the identical namespace through either
    and the separator between them is the same character:
    `Microsoft.PowerShell.Core\\Function::Get-Date` is what `function:Get-Date` is short for and is
    only found after the strip, while `Alias:\\x` — which is what `Get-ChildItem Alias:` completes
    to, and what a provider path most often looks like — is only found before it. Reading either
    spelling alone leaves the other looking like an ordinary file path, which is the direction a
    deny-list must never fail in.

    **The colon is what makes it a path.** A drive qualifier is a name followed by `:`, so a bare
    `alias` is an ordinary word and `Write-Output 'alias'` addresses nothing. Reading the part before
    the separator without checking that there was one answers `True` for every argument that happens
    to spell a provider's name, which opened the world over a string.
    """
    for arg in cmd.arguments:
        value = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        text = string_value(value)
        if text is None:
            continue
        for spelling in (text, text.rpartition('\\')[2]):
            drive, separator, _ = spelling.partition(':')
            if separator and drive.lower() in _IDENTITY_PROVIDERS:
                return True
    return False


def runs_code_in_the_calling_scope(cmd: Ps1CommandInvocation, resolved: str | None) -> bool:
    """
    Whether `cmd` runs code this analysis cannot read *in the scope it is written in*, so a command
    table that code writes is this script's own. `resolved` is the command name after the caller has
    followed the script's own aliases, since `Set-Alias e iex` puts one behind any spelling.

    `WorldRole.LEAK` is not this question, and the difference is the scope rather than the leak.
    `Invoke-Expression` and dot-sourcing run their code where they stand — measured on 5.1,
    `Invoke-Expression 'Set-Alias zzq Get-Date'` leaves `zzq` bound to `Get-Date` afterwards — so
    what they run may rebind any name. `Start-Job` and `Start-ThreadJob` run in another runspace,
    `Invoke-Command` opens a child scope, and a script file invoked with `&` or as a bareword gets a
    child scope too: a binding any of them performs is gone before the next statement here.

    The dot-source test is the operator rather than the file, which is the opposite of
    `runs_another_script_file`'s reason for existing: there the file is opaque however it is called,
    here the operator is what decides whose tables the file writes. An inline `.{ ... }` is excluded
    with the same test that excludes it there — its body stands in the tree, so whatever it binds is
    read like any other statement.
    """
    if isinstance(cmd.name, Ps1StringLiteral) and cmd.invocation_operator == '.':
        return True
    if resolved is None:
        return False
    return normalize_command_name(resolved.rpartition('\\')[2]) in _CALLER_SCOPE_LEAKS


def may_touch_identity_provider(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether `cmd` may address the `alias:` or `function:` provider — `touches_identity_provider`
    widened to the item cmdlets carrying a path this cannot read.

    `Set-Item $p Write-Host` addresses whatever `$p` spells, and a script that computes the drive
    qualifier (`('Ali' + 'as:') + $n`) addresses it through a spelling no literal reading finds. The
    item cmdlets are named because the provider path is what they take: widening every command this
    way would say that any call with a variable argument may rebind a name.

    Held apart from `touches_identity_provider` rather than replacing it, because the two answer
    different questions and pay differently for being wrong. Opening the *type world* on this would
    cost every member-read grant in a script that merely deletes a file by variable, and the
    mutation deny-list this belongs to is documented as carrying a computed-path residual. Refusing
    an *alias resolution* on it costs only the names that script also binds, which is the claim
    `refinery.lib.scripts.ps1.analysis.commands` is making complete.
    """
    if touches_identity_provider(cmd):
        return True
    if normalize_command_name(resolve_command_name(cmd) or '') not in _ITEM_CMDLETS:
        return False
    return any(
        string_value(arg.value if isinstance(arg, Ps1CommandArgument) else arg) is None
        for arg in cmd.arguments
    )


def assigns_an_alias_name(node) -> bool:
    """
    Whether `node` binds a command name by writing the `alias:` variable namespace — `${alias:x} =
    'Write-Host'`, which rebinds `x` without any command being invoked at all.

    This is the one binding form that is not an invocation, so a caller asking what a script does to
    the alias table through `refinery.lib.scripts.ps1.analysis.commands.Ps1CommandModel.world_role`
    alone never sees it. It is stated here beside the rest of the identity rules rather than in the
    command model, which reads the tables and does not own them.
    """
    if not isinstance(node, Ps1AssignmentExpression):
        return False
    return any(
        variable.scope is Ps1ScopeModifier.ALIAS
        for variable in assignment_target_variables(node.target)
    )


def _is_type_accelerator_mutation(node: Ps1InvokeMember) -> bool:
    """
    Whether `node` adds or removes a type accelerator through
    `[…PSObject+TypeAccelerators]::Add/Remove`, which remaps what a type name resolves to.
    """
    obj = node.object
    return (
        node.access is Ps1AccessKind.STATIC
        and isinstance(obj, Ps1TypeExpression)
        and 'typeaccelerators' in normalize_dotnet_type_name(obj.name)
        and isinstance(node.member, str)
        and node.member.lower() in ('add', 'remove')
    )


def _is_psobject_member_mutation(node: Ps1InvokeMember) -> bool:
    """
    Whether `node` adds or removes a member through the reflective
    `$obj.PSObject.Members.Add/Remove` chain, the Extended Type System mutation that is not a cmdlet
    call and so escapes the name-keyed deny-list.
    """
    if node.access is not Ps1AccessKind.INSTANCE:
        return False
    if not (isinstance(node.member, str) and node.member.lower() in ('add', 'remove')):
        return False
    members = node.object
    if not isinstance(members, Ps1MemberAccess):
        return False
    members_name = get_member_name(members.member)
    if members_name is None or members_name.lower() != 'members':
        return False
    psobject = members.object
    if not isinstance(psobject, Ps1MemberAccess):
        return False
    psobject_name = get_member_name(psobject.member)
    return psobject_name is not None and psobject_name.lower() == 'psobject'
