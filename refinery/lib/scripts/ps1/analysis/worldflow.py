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

- A `class` or `enum` definition opens the type axis at no position: the engine compiles it
  before the first statement runs, so it stands before every read. Its presence anywhere returns
  the whole-run verdict for that axis alone — the command axis it never touches, so a
  command-table read is still answered positionally beside it.
- A root `process` block re-runs once per pipeline input, which the per-body graph models as
  straight-line with no back edge, so a leak late in it precedes a read early in it on the next
  item. Its presence returns the whole-run verdict.
- An opener the graph cannot place — a parameter default, a node in no body's graph — poisons
  nothing a flood could reach, so it returns the whole-run verdict on each axis it opens: one
  that opens both refuses both, while a `Set-Alias` nothing can place refuses the command axis
  and leaves the type axis, which it never opened, answering positionally.

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

from types import MappingProxyType
from typing import Callable, Collection, Mapping, NamedTuple

from refinery.lib.scripts import Node, tree_version
from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    LabelledReach,
    Projection,
    reachable_forward_from_any,
    reachable_forward_labels,
    require_sources_in,
)
from refinery.lib.scripts.ps1.analysis.aliasdef import extract_alias_definition
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockReach, classify_block
from refinery.lib.scripts.ps1.analysis.world import (
    Ps1ShadowSite,
    Ps1TypeWorld,
    Ps1WorldMeasurement,
    opens_command_table_only_by_binding,
)
from refinery.lib.scripts.ps1.ast import (
    get_command_name,
    normalize_command_name,
    resolve_command_name,
    resolve_command_spelling,
)
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
from refinery.lib.scripts.ps1.patterns import wildcard_regex


class Ps1Flood(NamedTuple):
    """
    What one positional query of `Ps1WorldReach` reads: the root-graph positions its sources
    `poisoned`, keyed by identity; for a source statement no other source and no way back reaches,
    the sources standing on it directly, which argument order may excuse (`only_by`); whether a
    source the graphs could not place `refuse`s every position; whether the query had anything to
    flood from at all (`sourced`); and the command names of the sources that bind one name and do
    nothing else (`named`), which the query asks about by name rather than flooding from.
    """
    poisoned: frozenset[int] = frozenset()
    only_by: Mapping[int, tuple[Node, ...]] = MappingProxyType({})
    refuse: bool = False
    sourced: bool = False
    named: frozenset[str] = frozenset()

    def spares(self, node: Node, position: CfgNode) -> bool:
        """
        Whether *node*, which *position* evaluates, is evaluated before every source of this flood
        that may have run: its position is not poisoned, or it stands in the arguments of every
        source its own statement holds.
        """
        if id(position) not in self.poisoned:
            return True
        sources = self.only_by.get(id(position))
        return sources is not None and all(_evaluated_before(node, source) for source in sources)


class Ps1CommandShadows:
    """
    The forward floods from the placed redefinition sites of every command name a script takes over,
    keyed by the normalized name: a name spares a position when no redefinition of it can have run
    before that position. A name missing from *landings* has a site no flood can bound, so it spares
    no position. The floods are walked as one, and only on the first question: most builds of a
    world reach are never asked about a name at all.
    """

    def __init__(self, graph: ControlFlowGraph, landings: Mapping[str, list[CfgNode]]):
        for nodes in landings.values():
            require_sources_in(graph, nodes)
        self._graph = graph
        self._landings = landings
        self._floods: LabelledReach[str] | None = None

    def spares(self, name: str, position: CfgNode) -> bool:
        """
        Whether no redefinition of *name* can have run before *position*.
        """
        if name not in self._landings:
            return False
        if self._floods is None:
            self._floods = reachable_forward_labels(self._graph, self._landings)
        return not self._floods.reaches(name, position)


class Ps1WorldReach:
    """
    The world as the purity gate reads it at a position: the whole-run facts of a
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld`, plus the three positional queries —
    `closed_at`, which asks whether the type world is closed at one read rather than anywhere,
    `may_trust_command_name_at`, which asks the same of a command name's identity, and
    `may_read_the_command_table_at`, which asks it of a lookup over the command vocabulary. Held
    in a `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot and threaded through
    `refinery.lib.scripts.ps1.analysis.effects` in place of the leaf world. It answers the three
    positional questions, `closed_for_the_whole_run`, and `shadowed_names` — the whole-run shadow
    set, mirrored here because the values layer that reads it holds this wrapper and not the leaf.
    Every other leaf fact is read straight off `Ps1ModelCache.closed_world`, which no staleness can
    touch because the cache rebuilds it, so mirroring one with no reader would be an answer nobody
    asks for. The whole-run `Ps1TypeWorld.may_trust_command_name` is one of those, and no pass reads
    it: it is the verdict `may_trust_command_name_at` short-circuits on, which is a fact about the
    leaf model and stays with it.

    The queries read one flood record each (`Ps1Flood`). The type flood and the trust flood
    are flooded from every opener, whichever axis it opened, and differ only in what refuses them
    outright: a position-less opener of the type axis refuses `closed_at`, one of the command axis
    refuses `may_trust_command_name_at`. The command flood, which `may_trust_invocation` reads, is
    flooded from the command openers alone and refused like the trust flood. The table flood is
    flooded from the command openers and from the table writers of the measurement — the writes
    nobody can read that may add a command a listing shows without opening either axis — so a
    read of the session's command names is granted beside a type-only opener that ran before it
    and refused after a file copy by variable, where trust in a command name holds on. `refuse`
    breaks statement ordering itself and refuses every positional query.

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
        type_flood: Ps1Flood | None = None,
        trust_flood: Ps1Flood | None = None,
        command_flood: Ps1Flood | None = None,
        table_flood: Ps1Flood | None = None,
        shadow_poisoned: Ps1CommandShadows | None = None,
        refuse: bool = False,
        build_version: int = 0,
    ):
        self._world = world
        self._root = root
        self._control_flow = control_flow
        self._type = type_flood or Ps1Flood()
        self._trust = trust_flood or Ps1Flood()
        self._command = command_flood or Ps1Flood()
        self._table = table_flood or Ps1Flood(sourced=not world.command_table_closed)
        self._shadow_poisoned = shadow_poisoned
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

        A call standing in what an opener is handed is evaluated before the opener runs, which is
        `closed_at`'s rule and holds here for the same reason: `& (gcm 'wr?te') 'a'` dispatches on
        a value only once `gcm` has run, so the dispatch cannot have taken `gcm` over.
        """
        if self._stale:
            return False
        if self._world.may_trust_command_name(name):
            return True
        if self._trust.refuse:
            return False
        position = self._position_in_root(node)
        return position is not None and self._trusted_at(name, position, node)

    def may_trust_invocation(self, invocation: Ps1CommandInvocation) -> bool:
        """
        Whether *invocation* still runs the command it names where it stands: neither the spelling
        it is written in nor the canonical name that spelling resolves to can have been taken over
        before it, because a `function` taking the canonical name over captures every alias
        resolving to it, while the written spelling of such a call shadows nothing.

        The positional successor of `Ps1TypeWorld.runs_the_command_it_names`, and like it the
        command axis alone: it reads the command flood, which floods from the openers of the command
        table and not from those of the type system. An `Add-Type` changes what a type name denotes
        and never what a command name runs, where `may_trust_command_name_at` answers for the
        metadata of a command as a whole and is refused after one.
        """
        if self._stale:
            return False
        written = get_command_name(invocation)
        resolved = resolve_command_name(invocation)
        if written is None or resolved is None:
            return False
        names = (written, resolved)
        if all(self._world.runs_the_command_it_names(name) for name in names):
            return True
        if self._command.refuse:
            return False
        position = self._position_in_root(invocation)
        return position is not None and all(
            self._world.runs_the_command_it_names(name)
            or self._unshadowed_where_spared(name, position, invocation, self._command)
            for name in names
        )

    def _climb_is_trusted(self, climbed: list[str], position: CfgNode) -> bool:
        """
        Whether every command name `_position_in_root` climbed through still denotes what the
        metadata says at *position*. A name the script may have taken over is a name that may hand
        the block to something that keeps it, and then the body no longer runs where it is written.
        """
        return all(self._trusted_at(name, position) for name in climbed)

    def _trusted_at(self, name: str, position: CfgNode, node: Node | None = None) -> bool:
        """
        `may_trust_command_name_at` once the position is known, which is also the question
        `_position_in_root` asks of every command name it climbs through. Kept apart from the query
        so that the climb does not have to re-enter the query it is answering. The *node* the
        position evaluates, where one is given, may stand in what the openers of its statement are
        handed; a climb has no such node and is refused at a poisoned position.
        """
        if self._world.may_trust_command_name(name):
            return True
        return self._unshadowed_where_spared(name, position, node, self._trust)

    def _unshadowed_where_spared(
        self,
        name: str,
        position: CfgNode,
        node: Node | None,
        flood: Ps1Flood,
    ) -> bool:
        """
        Whether *flood* spares *position*, and with it *node* where one is given, and no
        redefinition of the command *name* can have run before it.
        """
        if node is None:
            if id(position) in flood.poisoned:
                return False
        elif not flood.spares(node, position):
            return False
        if not self._world.command_shadowed(name):
            return True
        shadows = self._shadow_poisoned
        return shadows is not None and shadows.spares(normalize_command_name(name), position)

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
        The `refuse` check of the type flood takes the same side of the shortcut: a position-less
        type opener — a `class`, a default the graphs place nowhere — cannot be ordered against any
        read, so no position is closed over it.

        **An opener's own arguments run before it.** The statement holding an opener is poisoned
        from the opener on, and what the opener is handed is evaluated before it runs: the `Join`
        of `iex ([string]::Join(' ', $b))` runs in a world nothing has opened yet. So a node
        standing in the arguments of every opener its statement holds, and in no block one of them
        runs, is closed where nothing else poisons that statement — no opener before it, and no way
        back into it for its own openers, which a statement control returns to has.
        """
        if self._stale:
            return False
        if self.closed_for_the_whole_run:
            return True
        if self._type.refuse:
            return False
        position = self._position_in_root(node)
        if position is None:
            return False
        return self._type.spares(node, position)

    def may_read_the_command_table_at(self, node, patterns: Collection[str]) -> bool:
        """
        Whether the session's commands matching any of *patterns* are, at `node`, exactly the ones
        the collected vocabulary lists — the claim a listing fold makes when it replaces a lookup
        with the one name it yields. What breaks it is an opener of the command axis, which can bind
        a command the vocabulary does not list, a table writer, which may add one without opening
        the axis, and a redefinition of a name matching a pattern, each run before the read.

        The patterns are taken, not a precomputed shadow subset: the matcher inside decides what a
        takeover must match, so a caller with a divergent or case-sensitive matcher hands in a
        subset the query then under-matches and grants over vacuously. A pattern 5.1 rejects lists
        nothing a fold could name, and is refused.

        The whole-run fast path — nothing the table flood floods from, and no shadowed name —
        grants at every position, and soundly over a wrapper built refused: the type axis, a
        `class`, a root `process` block — none of them adds a command where no command opener and
        no table writer stands anywhere. The flood takes no binding skip, unlike the trust flood,
        because a listing read sees aliases no statement invokes. Callee trust is not this query's
        job: a takeover of the lookup command itself matches no pattern and is invisible to shadow
        matching, so the folds ask `may_trust_invocation` of the invocation separately.
        """
        if self._stale:
            return False
        if not self._table.sourced and not self._world.shadowed_names:
            return True
        if self._table.refuse:
            return False
        position = self._position_in_root(node)
        if position is None or not self._table.spares(node, position):
            return False
        regexes = [wildcard_regex(pattern) for pattern in patterns]
        for name in self._world.shadowed_names.union(self._table.named):
            if not any(regex is None or regex.match(name) for regex in regexes):
                continue
            if self._shadow_poisoned is None or not self._shadow_poisoned.spares(name, position):
                return False
        return True

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
    that redefines no command and holds no table writer carries no position at all, so it is
    wrapped with no graph, and
    `control_flow_of` is never called: a clean script never pays for a control-flow build it would
    not read. Otherwise every opener is lifted into the root graph and the poisoned region is the
    forward flood from all of them, and every redefinition site is lifted and flooded the same way
    per name (`_flood_shadow_sites`).

    The verdict falls back to the whole-run answer at every position — a `Ps1WorldReach` built
    with `refuse` — whenever a root `process` block that re-runs is present, the script names its
    own path (`_names_own_path`), through which a leak could re-run the statements before it, or
    the root graph cannot be built. Each breaks statement ordering itself, so no query — type,
    command, or identity — may read a position under it. The position-less openers refuse per axis
    instead: a `class`/`enum` definition and a type opener that cannot be placed in the root graph
    refuse the type flood, a command opener that cannot be placed refuses the trust and the table
    floods, and one that opens both refuses all three; a table writer that cannot be placed refuses
    the table flood alone. Each is the fail-closed direction the module docstring states: the
    floods cannot bound where such an opener ran, so no read on an axis it opens is granted over
    it, while the other axis — which it never touched — still answers positionally.

    An opener that binds one command name the tree never invokes — a `Set-Alias` of a name no
    statement calls, which `opens_command_table_only_by_binding` names — is left out of the
    trust flood and never asked for a position. It runs nothing and rebinds nothing any call
    reaches, so no position observes it on the trust axis. The table flood takes no such skip: a
    listing read sees aliases no statement invokes — `Set-Alias wrnte Get-Date` before a lookup
    matching `wrnte` — so every command opener floods it whatever it binds, and so does every
    table writer of the measurement. A script whose every opener is an uninvoked binding floods the
    trust axis from nothing and grants every position the graphs place there, while the table
    refuses the position after the binding. The whole-run verdict stays open, so both answers are
    positional and the call graph still reads the command table as open.

    Every wrapper — closed, refused, or measured — is stamped with the root and the version the
    measurement was taken at, so each notices the tree changing under a pass that holds it. A
    measurement already stale against the current tree is refused whole: its opener list may miss a
    leak an edit introduced, and stamping the stale version makes the wrapper read stale at once, so
    no answer is trusted.
    """
    world = measurement.world
    root = measurement.root
    version = measurement.build_version
    table_sourced = bool(measurement.command_openers or measurement.table_writers)
    unordered = Ps1Flood(sourced=table_sourced)
    if tree_version(root) != version:
        return Ps1WorldReach(world, root=root, table_flood=unordered, refuse=True, build_version=version)
    if world.closed_for_the_whole_run and not measurement.shadow_sites and not table_sourced:
        return Ps1WorldReach(world, root=root, build_version=version)
    if root.process_block is not None or _names_own_path(root):
        return Ps1WorldReach(world, root=root, table_flood=unordered, refuse=True, build_version=version)
    control_flow = control_flow_of()
    root_graph = control_flow.graph_of(root)
    if root_graph is None:
        return Ps1WorldReach(world, root=root, table_flood=unordered, refuse=True, build_version=version)
    type_refuse = False
    command_refuse = False
    table_refuse = False
    opens_type = frozenset(id(opener) for opener in measurement.type_openers)
    opens_command = frozenset(id(opener) for opener in measurement.command_openers)
    sources: list[CfgNode] = []
    standing: dict[int, list[Node | None]] = {}
    command_sources: list[CfgNode] = []
    command_standing: dict[int, list[Node | None]] = {}
    table_sources: list[CfgNode] = []
    table_standing: dict[int, list[Node | None]] = {}
    binding_sites: list[Ps1ShadowSite] = []

    def place(node: Node, landing: CfgNode, on: list[CfgNode], stand: dict[int, list[Node | None]]):
        located = control_flow.locate(node)
        direct = located is not None and located[1] is landing
        on.append(landing)
        stand.setdefault(id(landing), []).append(node if direct else None)

    for opener in measurement.openers:
        if isinstance(opener, (Ps1ClassDefinition, Ps1EnumDefinition)):
            type_refuse = True
            continue
        bound = opens_command_table_only_by_binding(opener)
        skipped = bound is not None and bound not in measurement.invoked_command_names
        landing = _lift_to_root(control_flow, opener, root_graph)
        if landing is None:
            if id(opener) in opens_type:
                type_refuse = True
            if id(opener) in opens_command:
                command_refuse = True
                table_refuse = True
            continue
        if not skipped:
            place(opener, landing, sources, standing)
        if id(opener) not in opens_command:
            continue
        if not skipped:
            place(opener, landing, command_sources, command_standing)
        listed = _names_a_binding_lists(opener)
        if listed:
            binding_sites.extend(Ps1ShadowSite(name, opener) for name in listed)
        else:
            place(opener, landing, table_sources, table_standing)
    for writer in measurement.table_writers:
        landing = _lift_to_root(control_flow, writer, root_graph)
        if landing is None:
            table_refuse = True
            continue
        place(writer, landing, table_sources, table_standing)
    poisoned, only_by = _flood_positions(root_graph, sources, standing)
    command_poisoned, command_only_by = _flood_positions(root_graph, command_sources, command_standing)
    table_poisoned, table_only_by = _flood_positions(root_graph, table_sources, table_standing)
    named = frozenset(site.name for site in binding_sites)
    return Ps1WorldReach(
        world,
        root=root,
        control_flow=control_flow,
        type_flood=Ps1Flood(poisoned, only_by, type_refuse, bool(sources)),
        trust_flood=Ps1Flood(poisoned, only_by, command_refuse, bool(sources)),
        command_flood=Ps1Flood(command_poisoned, command_only_by, command_refuse, bool(command_sources)),
        table_flood=Ps1Flood(table_poisoned, table_only_by, table_refuse, table_sourced, named),
        shadow_poisoned=_flood_shadow_sites(
            (*measurement.shadow_sites, *binding_sites), control_flow, root_graph),
        build_version=version,
    )


def _names_a_binding_lists(opener: Node) -> tuple[str, ...]:
    """
    The command names a listing of the command table may show for the opener *opener*, where
    binding one name is the whole of what it does: the alias it binds under its own name, and the
    name that spelling resolves to, read the deny-list way so that a match is never missed. Empty
    for an opener that does anything else, which floods instead.
    """
    if opens_command_table_only_by_binding(opener) is None or not isinstance(opener, Ps1CommandInvocation):
        return ()
    alias = extract_alias_definition(opener)
    if alias is None:
        return ()
    return tuple(dict.fromkeys((
        normalize_command_name(alias.name),
        resolve_command_spelling(alias.name),
    )))


def _flood_positions(
    root_graph: ControlFlowGraph,
    sources: list[CfgNode],
    standing: Mapping[int, list[Node | None]],
) -> tuple[frozenset[int], dict[int, tuple[Node, ...]]]:
    """
    The poisoned region of one axis' flood with its only-by refinement: the forward flood from
    every source, and for each source statement its own successors do not return to — neither
    through the resumption hub nor by standing in the region after the other sources — the openers
    placed on it directly, keyed by the statement's identity. A poisoned position whose statement
    holds no entry is poisoned by openers argument order cannot excuse, and `_evaluated_before` is
    the only thing that lifts it.
    """
    after = reachable_forward_from_any(root_graph, [
        successor for source in sources for successor in Projection.FORWARD.successors(source)])
    poisoned_only_by: dict[int, tuple[Node, ...]] = {}
    for source in sources:
        openers = standing[id(source)]
        if id(source) in after or id(source) in root_graph.hub_bound or None in openers:
            continue
        poisoned_only_by[id(source)] = tuple(opener for opener in openers if opener is not None)
    return reachable_forward_from_any(root_graph, sources), poisoned_only_by


def _evaluated_before(node: Node, opener: Node) -> bool:
    """
    Whether *node* is evaluated to produce what *opener* is handed, and so before *opener* runs: it
    stands inside *opener* and in no block *opener* runs or holds.
    """
    cursor = node.parent
    while cursor is not None:
        if cursor is opener:
            return True
        if isinstance(cursor, Ps1ScriptBlock):
            return False
        cursor = cursor.parent
    return False


def _flood_shadow_sites(
    sites: tuple[Ps1ShadowSite, ...],
    control_flow: ControlFlowModel,
    root_graph: ControlFlowGraph,
) -> Ps1CommandShadows:
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
    return Ps1CommandShadows(root_graph, landings)


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
