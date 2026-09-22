"""
The flow-sensitive reading of the closed-world model: whether the type world is closed at *one*
particular read, rather than anywhere the script runs. `refinery.lib.scripts.ps1.analysis.world`
answers the whole-run question over a bare tree walk and stays a leaf value object; this layer adds
the position, which is a control-flow question, the way
`refinery.lib.scripts.ps1.analysis.commands` layers command identity on the same model's shadow set.

A member read the metadata proves inert still runs code once a leak has re-pointed that member
through the Extended Type System or remapped its type accelerator. A read *no such leak has run
before* observes what it always would have, so it is inert like any other — and the whole-run model
cannot tell the two apart, keeping every read in a file that leaks once anywhere. This model floods
forward through the control-flow graph from every opener and grants a read only where the flood does
not reach it: no code that could have mutated the world runs on any path to that read.

Command identity is the model's second axis. A discarded pure call is junk only while its bareword
still names the built-in the metadata describes, and two families of statements can change that: an
opener — a leak, an aliasing cmdlet, an opaque dispatch can each rebind *any* name — and the
script's own classified redefinitions (a `function` statement, a `function:`/`alias:` write), which
rebind exactly the name they spell and may open no world at all.
`Ps1WorldReach.may_trust_command_name_at` floods forward from both: from every opener, and per name
from that name's definition sites, granting a call only where neither flood reaches it.
`refinery.lib.scripts.ps1.analysis.commands` also layers positions over command identity, but its
`Ps1CommandModel` answers *resolution* — which of the bindings written in this tree a name denotes
at a point. This model answers *trust*: whether anything, including code no tree contains, could
have made the name run something the metadata does not describe. Resolution picks among known
meanings; trust bounds the unknown ones.

A wrong grant deletes code that had an effect; a refusal only costs recall, so every uncertainty
fails toward *open*:

- A `class` or `enum` definition opens the world at no position: the engine compiles it before the
  first statement runs, so it stands before every read. Its presence anywhere returns the whole-run
  verdict for the whole file.
- A root `process` block re-runs once per pipeline input, which the per-body graph models as
  straight-line with no back edge, so a leak late in it precedes a read early in it on the next
  item. Its presence returns the whole-run verdict.
- An opener the graph cannot place — a parameter default, a node in no body's graph — poisons
  nothing a flood could reach, so it too returns the whole-run verdict.

An opener written inside a scriptblock or function body is *lifted* to the root-graph statement that
runs that body — the value where the block is written, the `function` statement that defines it —
and floods from there, because a stored block cannot execute before the statement that creates it
and a function cannot be called before its definition runs.

A read inside such a body is lifted only where the body provably runs *where it is written*, which
`refinery.lib.scripts.ps1.analysis.blocks` decides: `& { }`, `. { }` and the block a
`ForEach-Object` or `Where-Object` runs are evaluated by one statement of the enclosing body and by
nothing else, so a read inside them observes exactly what that statement observes. Everything else
is refused, because a body may be entered again by a later call, and a read written after a leak in
source can then run before it at runtime — an edge the intraprocedural graph does not carry. The
lift through a *command* is worth only as much as the command name: a script that redefines
`ForEach-Object` may hand the block to something that stores it, so every name climbed through has
to be trustworthy at the statement the climb lands on, or the whole climb is refused.

The gate rests on one assumption the graph cannot enforce: that the code a leak runs does not
re-execute this script's own earlier statements. A script that dot-sources or invokes its own file
(`. $PSCommandPath`) runs its statements a second time, after the first run's leaks, and a read
granted on the first pass then runs after them — a control-flow edge no per-body graph carries.
The portable spellings of such a re-run all pass through the names PowerShell reveals a script's
own path or text under — `$PSCommandPath`, `$MyInvocation`, `$PSScriptRoot`, the call stack, the
process arguments — so a script that spells any of them anywhere is refused whole, the same
fallback the placeless openers take. What remains is a script that hits its own file without
naming it: through a leak's opaque payload, or through a hard-coded path that happens to be its
own location, which an analysis that never learns where the script lies cannot recognize. Both
stay out of contract — refusing every leaking script for what an unseen payload might do is the
whole-run verdict this model exists to replace — and are stated rather than left silent.
"""
from __future__ import annotations

from typing import Callable, Mapping

from refinery.lib.scripts import Node, tree_version
from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    reachable_forward_from_any,
)
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockReach, classify_block
from refinery.lib.scripts.ps1.analysis.world import (
    Ps1ShadowSite,
    Ps1TypeWorld,
    Ps1WorldMeasurement,
    opens_command_table_only_by_binding,
)
from refinery.lib.scripts.ps1.ast import normalize_command_name, resolve_command_name
from refinery.lib.scripts.ps1.model import (
    Ps1ClassDefinition,
    Ps1CommandInvocation,
    Ps1EnumDefinition,
    Ps1HereString,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1Variable,
)


class Ps1WorldReach:
    """
    The world as the purity gate reads it at a position: the whole-run facts of a
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld`, plus the two positional queries —
    `closed_at`, which asks whether the type world is closed at one read rather than anywhere, and
    `may_trust_command_name_at`, which asks the same of a command name's identity. Held in a
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot and threaded through
    `refinery.lib.scripts.ps1.analysis.effects` in place of the leaf world. It answers the two
    positional questions, `closed_for_the_whole_run`, and `shadowed_names` — the whole-run shadow
    set, mirrored here because the values layer that reads it holds this wrapper and not the leaf.
    Every other leaf fact is read straight off `Ps1ModelCache.closed_world`, which no staleness can
    touch because the cache rebuilds it, so mirroring one with no reader would be an answer nobody
    asks for. The whole-run `Ps1TypeWorld.may_trust_command_name` is one of those, and no pass reads
    it: it is the verdict `may_trust_command_name_at` short-circuits on, which is a fact about the
    leaf model and stays with it.

    Built without flow context — `Ps1WorldReach(world)` — it answers each positional query with
    the whole-run verdict at every position, which is what a caller that did not build the graphs,
    or that holds a world nothing was measured over, gets. "We looked and it is open here" and "we
    did not look" are the same refusal, deliberately, since both keep the read.

    Every answer is bound to the tree the model was built over: `build_world_reach` stamps that
    tree's version onto the wrapper, and once the tree changes under it all three questions read
    `False`. A transform reading this through the fresh
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot never sees a stale one, since the
    cache rebuilds it on the same version bump. A pass that instead captures the wrapper and holds
    it across its own edits reads `False` from the first edit on: it loses recall until the next
    pass rebuilds against the changed tree, never soundness. A rootless synthetic wrapper
    carries no stamp and so never goes stale — it has no tree to change under it.
    """

    def __init__(
        self,
        world: Ps1TypeWorld,
        *,
        root: Ps1Script | None = None,
        control_flow: ControlFlowModel | None = None,
        poisoned: frozenset[int] = frozenset(),
        shadow_poisoned: Mapping[str, frozenset[int]] | None = None,
        refuse: bool = False,
        build_version: int = 0,
    ):
        self._world = world
        self._root = root
        self._control_flow = control_flow
        self._poisoned = poisoned
        self._shadow_poisoned = shadow_poisoned or {}
        self._refuse = refuse
        self._build_version = build_version

    @property
    def _stale(self) -> bool:
        """
        Whether the tree has changed since this reach model was built, so its every answer is about
        a script that no longer stands. A wrapper carrying a `root` — one `build_world_reach` made —
        notices; a rootless one built around a synthetic world cannot, and answers from the leaf
        forever, which is what a caller that never named a tree wants.
        """
        return self._root is not None and tree_version(self._root) != self._build_version

    @property
    def closed_for_the_whole_run(self) -> bool:
        return not self._stale and self._world.closed_for_the_whole_run

    @property
    def shadowed_names(self) -> frozenset[str]:
        """
        The whole-run set of command names the script takes over, off the leaf model — the fact
        `refinery.lib.scripts.ps1.analysis.values.candidate_types` reads to decide whether a
        `ForEach-Object` still binds `$_` in the body handed to it.

        The leaf set is returned as measured, without the `_stale` guard the positional queries
        apply, because a *smaller* set is the unsound direction here: it lets a redefined iterator
        read as intact, so a wrapper that has fallen behind an edit must never be the one asked.
        The sole reader takes this off `Ps1ModelCache.world_reach`, which the cache rebuilds on the
        same version bump, so it is fresh by construction and no stale wrapper reaches this
        property; a pass must not capture one and read it across its own edits.
        """
        return self._world.shadowed_names

    def may_trust_command_name_at(self, name: str, node) -> bool:
        """
        Whether the collected metadata still describes what the command `name` runs at `node`: no
        statement that could rebind it — an opener, which can rebind any name, or a classified
        redefinition of this very name — can have run on any path that reaches the statement
        evaluating `node`. The positional successor of `Ps1TypeWorld.may_trust_command_name`, which
        lives on the leaf model and not on this one: a name the whole run trusts is trusted at every
        position, and one it refuses is refused wherever either flood reaches, plus everywhere the
        graphs cannot place.

        The opener check deliberately overlaps the `closed_at` that a purity verdict also routes
        through `refinery.lib.scripts.ps1.analysis.effects._grant`: at the discard-sink
        recognizers no grant guards the terminating invocation, so this query may not lean on its
        callers for the opener half of the answer.

        A shadowed name missing from the shadow floods is refused everywhere, never read as an
        empty poison set: the missing entry is `build_world_reach` reporting a definition site the
        graphs could not place, and trusting over it would delete a call that site can rebind.
        """
        if self._stale:
            return False
        if self._world.may_trust_command_name(name):
            return True
        position = self._position_in_root(node)
        return position is not None and self._trusted_at(name, position)

    def _climb_is_trusted(self, climbed: list[str], position: CfgNode) -> bool:
        """
        Whether every command name `_position_in_root` climbed through still denotes what the
        metadata says at *position*. A name the script may have taken over is a name that may hand
        the block to something that keeps it, and then the body no longer runs where it is written.
        """
        return all(self._trusted_at(name, position) for name in climbed)

    def _trusted_at(self, name: str, position: CfgNode) -> bool:
        """
        `may_trust_command_name_at` once the position is known, which is also the question
        `_position_in_root` asks of every command name it climbs through. Kept apart from the query
        so that the climb does not have to re-enter the query it is answering.
        """
        if self._world.may_trust_command_name(name):
            return True
        if id(position) in self._poisoned:
            return False
        if not self._world.command_shadowed(name):
            return True
        shadow = self._shadow_poisoned.get(normalize_command_name(name))
        return shadow is not None and id(position) not in shadow

    def closed_at(self, node) -> bool:
        """
        Whether the type world is closed at `node`: no opener can have run on any path that reaches
        the statement evaluating it. A closed-for-the-whole-run world answers `True` everywhere,
        since it has no opener to reach anything; otherwise the answer is `False` unless `node`
        locates into the root graph outside the poisoned region.

        Staleness is read first, before the whole-run shortcut: a wrapper built over a tree that has
        since changed answers `False` even where its stale verdict is closed, because an edit could
        have opened a world the old walk read shut. The shortcut in turn precedes the
        `_position_in_root` refusals, because a wrapper can be built refused for the identity
        floods' sake while the type axis, with no opener anywhere, still holds at every position.
        """
        if self._stale:
            return False
        if self.closed_for_the_whole_run:
            return True
        position = self._position_in_root(node)
        return position is not None and id(position) not in self._poisoned

    def _position_in_root(self, node) -> CfgNode | None:
        """
        The root-graph control-flow node that evaluates `node`, or `None` when no positional answer
        may be given: the wrapper was built refused or without a graph, or the graphs cannot place
        the node in the root body. Each `None` is the fail-closed direction both positional queries
        share: a wrong grant deletes an effect, a refusal keeps a statement.

        A node inside a scriptblock locates into that block's own graph, and the climb out of it is
        sound exactly where the block runs where it is written — `_runs_in_place`. Anything else is
        refused, because a later call can run the body again after a statement the intraprocedural
        graphs do not order it against.

        A block reaches an iterating command under a *name*, and the name is what makes the climb
        true: `function ForEach-Object { $args }` hands the block to something that may store it
        rather than run it. Every name climbed through is therefore checked at the landing, and one
        the landing cannot trust refuses the whole climb. Checking at the landing rather than at the
        site is the same answer, since the site is nested inside the statement the landing stands
        for, and it keeps this off the query it is part of answering.
        """
        if self._refuse or self._control_flow is None or self._root is None:
            return None
        climbed: list[str] = []
        while True:
            located = self._control_flow.locate(node)
            if located is None:
                return None
            graph, position = located
            if graph.owner is self._root:
                return position if self._climb_is_trusted(climbed, position) else None
            site = _runs_in_place(graph.owner)
            if site is None:
                return None
            if site.name is not graph.owner:
                name = resolve_command_name(site)
                if name is None:
                    return None
                climbed.append(name)
            node = site


def _runs_in_place(owner: Node) -> Ps1CommandInvocation | None:
    """
    The invocation whose evaluation runs *owner*, when *owner* is a script block that runs where it
    is written and nowhere else, else `None`. A function body, a stored block and a block handed to
    a command that may keep it all answer `None`: when they run is not a question the enclosing
    body's control-flow graph orders.
    """
    if not isinstance(owner, Ps1ScriptBlock):
        return None
    facts = classify_block(owner)
    if facts.reach is not Ps1BlockReach.IMMEDIATE:
        return None
    return facts.site if isinstance(facts.site, Ps1CommandInvocation) else None


def build_world_reach(
    measurement: Ps1WorldMeasurement,
    control_flow_of: Callable[[], ControlFlowModel],
) -> Ps1WorldReach:
    """
    The flow-sensitive world for `measurement.root`, over its whole-run verdict, its opener
    positions, and its command-redefinition sites. A world closed for the whole run in a script
    that redefines no command carries no position at all, so it is wrapped with no graph, and
    `control_flow_of` is never called: a clean script never pays for a control-flow build it would
    not read. Otherwise every opener is lifted into the root graph and the poisoned region is the
    forward flood from all of them, and every redefinition site is lifted and flooded the same way
    per name (`_flood_shadow_sites`).

    The verdict falls back to the whole-run answer at every position — a `Ps1WorldReach` built with
    `refuse` — whenever a position-less opener is present (a `class`/`enum` definition, a root
    `process` block that re-runs), an opener cannot be placed in the root graph, or the script names
    its own path (`_names_own_path`), through which a leak could re-run the statements before it.
    Each is the fail-closed direction the module docstring states: the floods cannot bound where
    such an opener ran, so no read and no name is granted over it.

    An opener that binds one command name the tree never invokes — a `Set-Alias` of a name no
    statement calls, which `opens_command_table_only_by_binding` names — is left out of the flood
    and never asked for a position. It runs nothing and rebinds nothing any call reaches, so no
    position observes it. A script whose every opener is such a binding floods from nothing and
    grants every position the graphs place: on the command axis because no call reaches a rebound
    name, on the type axis because a binding touches no type. The whole-run verdict stays open, so
    the grant is positional and the call graph still reads the command table as open.

    Every wrapper — closed, refused, or measured — is stamped with the root and the version the
    measurement was taken at, so each notices the tree changing under a pass that holds it. A
    measurement already stale against the current tree is refused whole: its opener list may miss a
    leak an edit introduced, and stamping the stale version makes the wrapper read stale at once, so
    no answer is trusted.
    """
    world = measurement.world
    root = measurement.root
    version = measurement.build_version
    if tree_version(root) != version:
        return Ps1WorldReach(world, root=root, refuse=True, build_version=version)
    if world.closed_for_the_whole_run and not measurement.shadow_sites:
        return Ps1WorldReach(world, root=root, build_version=version)
    if root.process_block is not None or _names_own_path(root):
        return Ps1WorldReach(world, root=root, refuse=True, build_version=version)
    control_flow = control_flow_of()
    root_graph = control_flow.graph_of(root)
    if root_graph is None:
        return Ps1WorldReach(world, root=root, refuse=True, build_version=version)
    refuse = False
    sources: list[CfgNode] = []
    for opener in measurement.openers:
        if isinstance(opener, (Ps1ClassDefinition, Ps1EnumDefinition)):
            refuse = True
            continue
        bound = opens_command_table_only_by_binding(opener)
        if bound is not None and bound not in measurement.invoked_command_names:
            continue
        landing = _lift_to_root(control_flow, opener, root_graph)
        if landing is None:
            refuse = True
            continue
        sources.append(landing)
    if refuse:
        return Ps1WorldReach(world, root=root, refuse=True, build_version=version)
    return Ps1WorldReach(
        world,
        root=root,
        control_flow=control_flow,
        poisoned=reachable_forward_from_any(root_graph, sources),
        shadow_poisoned=_flood_shadow_sites(measurement.shadow_sites, control_flow, root_graph),
        build_version=version,
    )


def _flood_shadow_sites(
    sites: tuple[Ps1ShadowSite, ...],
    control_flow: ControlFlowModel,
    root_graph: ControlFlowGraph,
) -> dict[str, frozenset[int]]:
    """
    The forward flood from every placed redefinition of each command name, keyed the way the shadow
    set is keyed. Forward in the strict sense `reachable_forward_from_any` gives it: a name rebound
    inside a `trap`-guarded block does not thereby become untrustworthy at the statements written
    above the rebinding, which is what following the resumption hub would claim.

    A name any of whose sites cannot be lifted into the root graph gets no entry at all
    rather than the flood of the sites that could:
    `Ps1WorldReach.may_trust_command_name_at` reads a missing entry as a refusal everywhere, which
    is the only sound reading — the unplaced site may rebind the name at a position no flood
    bounds, and a union of the placed ones would vouch for exactly the positions it fails to
    poison.
    """
    landings: dict[str, list[CfgNode]] = {}
    unplaceable: set[str] = set()
    for name, site in sites:
        if name in unplaceable:
            continue
        landing = _lift_to_root(control_flow, site, root_graph)
        if landing is None:
            unplaceable.add(name)
            landings.pop(name, None)
            continue
        landings.setdefault(name, []).append(landing)
    return {
        name: reachable_forward_from_any(root_graph, nodes)
        for name, nodes in landings.items()
    }


def _lift_to_root(
    control_flow: ControlFlowModel,
    opener: Node,
    root_graph: ControlFlowGraph,
) -> CfgNode | None:
    """
    The root-graph control-flow node from which *opener* poisons forward, climbing out of every
    nested body it sits in, or `None` when it cannot be placed at all.

    An opener in the root graph is its own statement's node. One inside a scriptblock or function
    body locates into that body's own graph; the block or definition is a value written at a point
    in the body around it, so the climb re-locates that owner and repeats until it lands in the root
    graph. The landing is sound as a flood source: a stored block cannot run before the statement
    that creates it, and a function cannot be called before its definition executes, so poisoning
    from that statement forward reaches every point the opener's effect could. A `None` climb — a
    parameter default the graphs place nowhere — is the caller's signal to fall back to the
    whole-run verdict.
    """
    node: Node = opener
    while True:
        located = control_flow.locate(node)
        if located is None:
            return None
        graph, cfg_node = located
        if graph is root_graph:
            return cfg_node
        node = graph.owner


#: The names under which PowerShell reveals a running script's own path or text: the automatic
#: variables, the call-stack cmdlet, and the process-arguments member. Lowercase, because the
#: language matches none of them case-sensitively.
_SELF_PATH_NAMES = frozenset({
    'pscommandpath',
    'myinvocation',
    'psscriptroot',
    'pscallstack',
    'getcommandlineargs',
})


def _names_own_path(root: Ps1Script) -> bool:
    """
    Whether *root* spells, anywhere, one of the names through which a running script reaches its
    own path or text. The flood poisons forward only, so a statement that re-runs the script's file
    puts every leak before every read; the portable spellings of such a re-run all pass through one
    of these names, and which statement would perform it — under an `if` guard, inside a payload —
    is not decidable from here, so the whole script is refused instead.

    A variable or member name must match one exactly; a string value need only contain one, so that
    a bareword argument (`Get-Variable MyInvocation`) and a quoted payload (`'. $PSCommandPath'`)
    trip the guard as surely as the bare variable read does.
    """
    for node in root.walk():
        if isinstance(node, Ps1Variable):
            if node.name.lower() in _SELF_PATH_NAMES:
                return True
            continue
        if isinstance(node, (Ps1StringLiteral, Ps1HereString)):
            value = node.value.lower()
            if any(name in value for name in _SELF_PATH_NAMES):
                return True
            continue
        if isinstance(node, (Ps1MemberAccess, Ps1InvokeMember)):
            member = node.member
            if isinstance(member, str) and member.lower() in _SELF_PATH_NAMES:
                return True
    return False
