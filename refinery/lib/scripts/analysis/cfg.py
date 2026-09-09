"""
Per-body control-flow graphs, derived from an AST and independent of the language it came from.

Each function — and the script itself — gets one `ControlFlowGraph`: a graph whose nodes wrap the
statements and loop-head expressions the body evaluates, connected by the order in which control may
pass between them. Sequential flow, the branches of a conditional, loop back-edges, the non-local
jumps a `break`/`continue`/`return` performs, and *exceptional* edges from any point inside a guarded
block to the handler that would catch a throw.

The graph is keyed to AST node identity (`node_of`) and is a disposable, per-body view — the tree
stays the spine. It is *conservative by construction*: where modelling control flow precisely would
be intricate (the order of evaluation inside an expression, the exact point a statement throws, a
finalizer on an exceptional path) the graph adds edges rather than omits them, so an analysis reading
it sees at least every path the program can take. Nested function bodies are not descended into; each
has its own graph.

**What a language supplies is the dispatch, not the shapes.** `CfgBuilder` holds the frontier
threading, the jump-target stack, the handler stack and one method per control-flow *shape* —
`branch_on`, `loop_head_tested`, `loop_tail_tested`, `loop_counted`, `dispatch`, `guarded`,
`labelled`, `jump_out`, `jump_back`, `terminate`. A subclass implements `statement`, recognises its
own node types, pulls the parts out of them, and calls the shape that matches. No method here reads a
field a language declares, which is what lets two languages whose `for` loops share nothing but their
meaning share this code.

The shapes are parameterised where languages genuinely differ rather than being duplicated: what an
arm of a `dispatch` reaches when control runs off its end is an `ArmFlow`, and each of its members
is some language's answer to the same construct.
"""
from __future__ import annotations

import enum

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import AbstractSet as Set, Callable, Iterable, Iterator, Sequence

from refinery.lib.scripts import Node


class CfgEdge(enum.Flag):
    """
    What an edge says about the run that takes it, beyond the two nodes it joins.

    `NORMAL` — control simply passed on, the source having done whatever it does.

    `ERROR_CARRYING` — the source threw and the error travels here: the edge into the handler that
    is offered it, and onward from a handler set that may decline. A definition the source makes is
    not guaranteed to have happened along one of these.

    `RESUMPTION_HUB`, `RESUMPTION_FORWARD` — the two projections of a handler that *resumes* the
    block it guards rather than ending it. The engine carries on at the statement after the one that
    threw, and no graph knows which statement that was, so the shape is carried twice: the hub is
    the over-approximation, joining every resumption point to every statement of the block, and the
    forward edges are the precise half, joining each statement to the one it would resume at.

    The two are *not* interchangeable, and reading one where the other is meant is how this goes
    wrong. Every run the forward edges draw the hub draws too; the hub draws more, and what it adds
    is the claim that a resumption point reaches the statements written *above* it — which is the
    claim the forward half exists to drop. An analysis asking whether *any* resumption path exists
    reads the hub, since dropping a path there would let it call a live statement unreachable; one
    asking what a point reaches *going forward* reads the forward edges and skips the hub, since
    keeping the backward reach there would poison a whole trap-guarded script from one leak — see
    `reachable_forward_from_any`.

    The distinction the resumption kinds force is that `ERROR_CARRYING` conflates two bits which
    coincide nowhere else: *taken only when the source threw*, and *the error object travels here*.
    A resumption edge is the first that is the former and not the latter — the handler swallowed the
    error — so a consumer reasoning about whether the source completed must read `RAISE_TAKEN`, and
    only one reasoning about where an error went may read `ERROR_CARRYING` alone.

    Which edges of the hub carry the kind follows from that and is not symmetric. The edges *out*
    of a hub do: their target is reached only because something threw. The edge *into* one does
    not, and is plain — its source is the handler body running to its end, which is a statement
    that completed, and a store it makes did happen. Reading the way in as raise-taken says no read
    below a `trap` can ever observe a store the handler made.
    """
    NORMAL = 0
    ERROR_CARRYING = enum.auto()
    RESUMPTION_HUB = enum.auto()
    RESUMPTION_FORWARD = enum.auto()


#: The kinds an edge is taken along only on runs where its source threw rather than completing. A
#: store the source makes may not have happened at the other end of one, whichever of the three it
#: is, which is the one question every flow-sensitive consumer asks of the kind.
RAISE_TAKEN = CfgEdge.ERROR_CARRYING | CfgEdge.RESUMPTION_HUB | CfgEdge.RESUMPTION_FORWARD

#: The raw bit masks the two hot edge-kind predicates test. `enum.Flag.__and__` rebuilds a member on
#: every call — its `_get_value`/`__call__`/`__new__` cost dominates a graph flood, which asks these
#: of millions of edges — so the predicates read the stored member's `.value` and mask it as a plain
#: integer. The result is identical; only the construction of a throwaway member is skipped.
_ERROR_CARRYING_MASK = CfgEdge.ERROR_CARRYING.value
_RAISE_TAKEN_MASK = RAISE_TAKEN.value


class Projection(enum.Enum):
    """
    Which reading of a resuming handler a walk over a control-flow graph is asked for — the two
    halves `CfgEdge` describes, named so that a walk states which one it means.

    `MAY` — every path the graph draws, the resumption hub among them. A resumption point is taken
    to reach every statement of its block, the ones written above it included. This is the reading a
    caller asking whether something *can* happen has to have: dropping a path there would let it
    call a live statement unreachable, or a store that is read dead.

    `FORWARD` — the paths a run takes going forward. The hub is declined, so a resumption reaches
    only the statement control would resume at and what follows it. This is the reading a flood
    needs: under `MAY` one leak anywhere in a trap-guarded block poisons the whole of it, the
    statements above the leak included.

    Neither is the safe one. `MAY` claims runs that cannot happen and `FORWARD` drops the fact that a
    handler body carries on somewhere the forward edges do not name, so which of them fails closed
    depends on what is asked. That is why every walk here names one rather than taking a default.

    The hub is declined as a *node*, and in both directions. Filtering the edges instead would let a
    walk cross a hub the moment some other edge joined the same pair, and would strand a backward
    walk inside a hub it can never leave.

    **The forward reading is sound by excision.** Take any run: the segment where it is inside a
    resuming handler body is exactly the part the forward edges do not draw, and cutting that segment
    out leaves a path over the guarded statements that the forward edges do draw — the statement that
    threw, then the one after it. So every ordering the forward projection reports holds of the real
    run, over a subset of the nodes the run visited. What it does *not* report is where a statement
    of the handler body itself leads, which is why a source inside one is walked under `MAY` instead
    (`CfgNode.is_hub_bound`).
    """
    MAY = enum.auto()
    FORWARD = enum.auto()

    def successors(self, node: CfgNode) -> list[CfgNode]:
        """
        The nodes control may pass to from *node* under this reading.
        """
        if self is Projection.MAY:
            return node.successors
        if node.is_resumption_hub:
            return []
        return [target for target in node.successors if not target.is_resumption_hub]

    def predecessors(self, node: CfgNode) -> list[CfgNode]:
        """
        The nodes control may arrive at *node* from under this reading.
        """
        if self is Projection.MAY:
            return node.predecessors
        if node.is_resumption_hub:
            return []
        return [source for source in node.predecessors if not source.is_resumption_hub]

    @property
    def declines_the_hub(self) -> bool:
        """
        Whether a walk under this reading refuses to stand at a resumption hub, which is the whole of
        what the two readings disagree about and the form a walk over millions of edges can afford to
        ask it in. `successors` and `predecessors` say the same thing by building a list, which is
        what a caller wanting an adjacency it can iterate twice wants and what a single depth-first
        sweep must not pay per node.
        """
        return self is Projection.FORWARD


class ArmFlow(enum.Enum):
    """
    What an arm of a multi-way branch may reach when control runs off its end.

    The three members are three languages' answers to the same construct, and reading one as another
    either invents paths that cannot be taken or drops paths that can — the second of which is the
    direction that lets an analysis call live code unreachable.

    `EXCLUSIVE` — at most one arm ever runs, so an arm's exits leave the construct.
    `SEQUENTIAL` — an arm that runs off its end enters the *next* arm's body unconditionally, which
    is C-style fallthrough and what JavaScript's `switch` does.
    `CUMULATIVE` — every arm is tested in turn and every matching one runs, so an arm's exits may
    reach *any* later arm, not only the next. PowerShell's `switch` is this: it does not fall
    through, it keeps matching, and a `break` is what stops it.
    """
    EXCLUSIVE  = enum.auto()  # noqa
    SEQUENTIAL = enum.auto()  # noqa
    CUMULATIVE = enum.auto()  # noqa


@dataclass(eq=False, repr=False)
class CfgNode:
    """
    One vertex of a control-flow graph. `element` is the AST node it stands for — a statement, or a
    loop-head expression whose reads and writes occur at this point — or `None` for the synthetic
    entry and exit. `successors` lists the nodes control may pass to next. `graph` is the body this
    vertex belongs to, which is what makes the questions below answerable of a node alone.

    `is_resumption_hub` marks the synthetic fan-out standing for the over-approximate half of a
    resuming handler — see `CfgEdge`. A walk that wants only the paths going forward declines to
    enter one, and declines to leave one, which makes it a *projection* of the graph rather than a
    filter on its edges. It is a fact about the node and not about the edges into it, because an
    edge kind is keyed by the pair of nodes it joins and `CfgBuilder.add_edge` builds a multigraph:
    two edges between the same pair collapse to one entry, so a plain edge drawn beside a hub edge
    would make the pair read as pure hub and a walk keyed on the kind would decline the plain path
    too. No pair of edges can disagree about what the node is.

    `is_hub_bound` marks a node the precise, forward-only projection does not reach: it sits inside a
    handler body that resumes the block around it. That block's forward edges join each *guarded*
    statement to the one it resumes at; a statement of the handler itself is on neither end of one,
    and everything it may reach afterwards hangs off the hub. A forward edge it does carry belongs to
    a block further out — one whose own resuming set guards the statement this handler is written
    inside — and stands for that block's resumption, not this one, so it says nothing about where
    this handler carries on. A forward-only walk seeded here would stop dead where the real run
    carries on, which for a flood is the unsound direction; `reachable_forward_from_any` reads this
    and falls back to the hub for such a source.

    Both are fields rather than questions asked of *graph*, and that is a matter of what a walk can
    afford as much as of where the fact lives. Every layer that had to ask them of a graph it was
    separately handed could be handed the wrong one — a node lifted from a nested body reads as
    neither against the graph around it, and the walk that asked takes the wrong branch without
    anything failing — and one depth-first sweep over a large script asks tens of millions of times.
    `graph` remains because a caller naming which body it means is a contract worth checking, and
    because `ControlFlowGraph.hub_bound` answers the same question for a caller holding ids.

    `eq=False` because every map in every layer above is keyed by `id(node)`, and two structurally
    equal statements are two distinct points in the program.

    `repr=False` because a generated repr expands `successors` and `predecessors`, and the guard
    against recursion only covers the node currently being formatted, so a graph re-expands at every
    join: a chain of five hundred nodes — a script of five hundred statements — exhausts the
    interpreter's stack, and a handful of branches produces megabytes. A debugger, a failing
    assertion, or `pytest --showlocals` would print one.
    """
    graph: ControlFlowGraph
    element: Node | None
    successors: list[CfgNode] = field(default_factory=list)
    predecessors: list[CfgNode] = field(default_factory=list)
    is_resumption_hub: bool = False
    is_hub_bound: bool = False


def flood(
    sources: Iterable[CfgNode], *, forward: bool, projection: Projection,
) -> set[int]:
    """
    The ids of the nodes reachable from *any* of *sources*, each source included: over successor
    edges when *forward* and over predecessor edges otherwise, and over the projection that declines
    the resumption hub when *projected*.

    The one walk every reachability question over these graphs is asked through, so that a caller
    choosing a direction or a projection chooses it by naming an argument rather than by writing a
    fourth copy of the sweep that quietly disagrees with the other three about what an edge means.
    Neither dimension has a default: `forward` decides whether the answer is *what this reaches* or
    *what reaches this*, and `projection` decides how a resumption is read. A caller that did not
    think about either asked the wrong question.

    **The hub-bound fallback is a property of a source, so it is applied here.** A forward walk
    under `Projection.FORWARD` seeded at a node the graph calls `CfgNode.is_hub_bound` is walked
    with the hub followed instead, because the forward edges carry nothing for such a source and the
    precise walk would stop dead at the resumption point — the fail-open direction, and the one a
    flood cannot afford. It is applied to the *sources* and never to a node the walk merely met,
    which would follow the hub out of any handler body the sweep happened to pass through. The two
    sweeps share one `seen`, so the second never re-walks what the first already reached.

    Walked as one depth-first sweep seeded with every source rather than a union of per-source
    walks: the union grows the same answer at the cost of one full walk per source, where a single
    sweep visits each node once however many sources reach it. The result is a fresh set the caller
    owns, so it may intersect or discard it in place.

    A graph none of whose handlers resume draws no hub, so the two readings walk it identically and
    the screen is dropped before the sweep begins. That is nearly every script, and this is the one
    walk every layer above reaches the graphs through — asking a projection per node instead costs
    the whole run more than the resumption edges do.
    """
    seen: set[int] = set()
    stack: list[CfgNode] = []
    for source in sources:
        if id(source) not in seen:
            seen.add(id(source))
            stack.append(source)
    declines = projection.declines_the_hub and any(
        node.graph.carries_resumption for node in stack)
    if declines and forward:
        coarse = [node for node in stack if node.is_hub_bound]
        if coarse:
            _sweep(coarse, seen, forward=True, declines=False)
            stack = [node for node in stack if not node.is_hub_bound]
    _sweep(stack, seen, forward=forward, declines=declines)
    return seen


def _sweep(
    stack: list[CfgNode], seen: set[int], *, forward: bool, declines: bool,
) -> None:
    """
    One depth-first sweep of `flood`, growing *seen* in place and consuming *stack*.

    *declines* is the `Projection.declines_the_hub` screen, hoisted out of the loop because it is
    the same for every edge of one sweep. It is asked of the node the walk stands at as well as of
    each neighbour, which is what makes this the same projection `Projection.successors` and
    `Projection.predecessors` build a list for: a hub is declined as a *node*, so a walk seeded at
    one leaves it by no edge at all.
    """
    while stack:
        node = stack.pop()
        if declines and node.is_resumption_hub:
            continue
        for neighbour in (node.successors if forward else node.predecessors):
            if id(neighbour) in seen:
                continue
            if declines and neighbour.is_resumption_hub:
                continue
            seen.add(id(neighbour))
            stack.append(neighbour)


def reachable_from_any(sources: Iterable[CfgNode]) -> frozenset[int]:
    """
    The ids of the nodes forward-reachable from *any* of *sources*, each source included — every
    path the graph draws, whatever an edge means.

    A flood over a graph that may carry resumption edges wants `reachable_forward_from_any` instead:
    this walk follows the resumption hub, which claims a statement is reached from every later one
    of its block, so one leak anywhere in a trap-guarded script poisons the whole of it.
    """
    return frozenset(flood(sources, forward=True, projection=Projection.MAY))


def normal_reach(
    sources: Iterable[CfgNode], *, barrier: Iterable[CfgNode] = (),
) -> frozenset[int]:
    """
    The ids of the nodes forward-reachable from *any* of *sources* over `CfgEdge.NORMAL` edges only,
    each source included, never expanding *through* a node of *barrier*.

    This is the plain-control-flow reach — where a run carries on when nothing throws — as opposed to
    `flood`/`Projection`, which read a resuming handler and follow the error edges beside the plain
    ones. The two questions the resuming-trap step-over asks both want this reading and neither wants
    the error edges: the region a resumed trap *skips* is what runs on the fall-through from the soft
    error's local step-over up to the reconvergence point (seed *sources* at the step-over, put the
    reconvergence nodes in *barrier*), and the continuation a skipped write is read on is what runs
    forward from the reconvergence point (seed *sources* there, no barrier). Following an error edge
    would route either walk back through a handler into the very block it stepped out of, reading a
    read that the continuation never performs.

    *barrier* is seeded into the visited set, so a walk never enters one and the returned set excludes
    it: the cut is `reach(sources) \\ through(barrier)`, not the unsound difference
    `reach(sources) - reach(barrier)`, which would drop a node the barrier merely *also* reaches by a
    back-edge around it.
    """
    barrier_ids = {id(node) for node in barrier}
    seen: set[int] = set(barrier_ids)
    stack: list[CfgNode] = []
    for source in sources:
        if id(source) not in seen:
            seen.add(id(source))
            stack.append(source)
    while stack:
        node = stack.pop()
        for target in node.successors:
            if id(target) in seen:
                continue
            if node.graph.edge_kind(node, target) is not CfgEdge.NORMAL:
                continue
            seen.add(id(target))
            stack.append(target)
    return frozenset(seen - barrier_ids)


class ControlFlowGraph:
    """
    The control-flow graph of one function or script body. `entry` and `exit` are synthetic; every
    other node wraps an AST element reachable through `node_of`.
    """

    def __init__(self, owner: Node):
        self.owner = owner
        self._node_of: dict[int, CfgNode] = {}
        self._edge_kinds: dict[tuple[int, int], CfgEdge] = {}
        self._hub_bound: set[int] = set()
        self._resuming = False
        self._fallback: dict[int, CfgNode] = {}
        self.entry = CfgNode(self, None)
        self.exit = CfgNode(self, None)
        self.nodes: list[CfgNode] = [self.entry, self.exit]

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The graph node standing for *element*, or `None` if *element* is not part of this body, or is
        a node the graph does not represent on its own such as a plain expression inside a statement.
        """
        return self._node_of.get(id(element))

    def fallback_of(self, handler: CfgNode) -> CfgNode | None:
        """
        Where a throw offered to *handler* goes if *handler* does not take it, or `None` when
        *handler* is not a handler entry of this graph.

        This is recorded rather than read off the edges because the two are not the same claim. The
        edge is drawn only where some run may decline — a clause with a type filter, a `trap` set
        that may fail to match — and a handler certain to take the throw has none, which is what
        makes it shield whatever guards the construct. The fact holds either way, and it is what
        answers the *counterfactual*: not where the throw goes, but where it would go if this
        handler were not written at all, which is the question asked before one is deleted.
        """
        return self._fallback.get(id(handler))

    def edge_kind(self, source: CfgNode, target: CfgNode) -> CfgEdge:
        """
        What the edge from *source* to *target* says about the run that takes it — see `CfgEdge`.
        An edge the builder recorded nothing for is `CfgEdge.NORMAL`, which is what an unrelated
        pair of nodes reads as too.
        """
        return self._edge_kinds.get((id(source), id(target)), CfgEdge.NORMAL)

    def is_exceptional(self, source: CfgNode, target: CfgNode) -> bool:
        """
        Whether the error travels along the edge from *source* to *target*: the edge into a handler
        offered the throw, or outward from a set that declined it. This is the question `faults`
        asks — where an error goes — and it is *narrower* than `raise_taken`, because a handler that
        resumes swallows the error and carries on along an edge no error travels.
        """
        return bool(self.edge_kind(source, target).value & _ERROR_CARRYING_MASK)

    def raise_taken(self, source: CfgNode, target: CfgNode) -> bool:
        """
        Whether the edge from *source* to *target* is taken only when *source* throws rather than
        completing normally. A definition *source* makes is not guaranteed to have happened along
        such an edge, so a flow-sensitive analysis must not treat it as a kill there.

        This is the question about *completion*, and it is the one nearly every consumer means. A
        resumption edge answers it although no error travels along it: the statement that resumed
        the block is precisely the one that did not finish.
        """
        return bool(self.edge_kind(source, target).value & _RAISE_TAKEN_MASK)

    @property
    def hub_bound(self) -> Set[int]:
        """
        The ids of the nodes `CfgNode.is_hub_bound` is set on, for a caller holding node *ids*
        rather than nodes. Written beside the field by `CfgBuilder.mark_hub_bound`, which is the one
        place either is recorded. `refinery.lib.scripts.analysis.reaching.ReachabilityQuery` is one: its
        candidate sets are ids because the layers above memoize them that way, and turning them back
        into nodes to ask each one is what those caches exist to avoid.
        """
        return self._hub_bound

    @property
    def carries_resumption(self) -> bool:
        """
        Whether any handler of this body resumes the block it guards, which is the only shape over
        which the two projections of `CfgEdge` differ. A body with none — every script that writes
        no `trap`, and every one whose traps rethrow — draws no resumption edge and marks no node
        hub-bound, so a forward walk over it answers exactly what `reachable_from_any` does and may
        be answered by the cheaper one.
        """
        return self._resuming


def reachable_forward_from_any(
    graph: ControlFlowGraph,
    sources: Iterable[CfgNode],
) -> frozenset[int]:
    """
    `reachable_from_any` restricted to the paths a run takes *going forward* from each source: the
    resumption hub is not followed, so a source does not reach the statements standing before it in
    its own block merely because some later statement of that block may throw and resume.

    The hub claims every resumption point reaches every statement of the guarded block, earlier ones
    included. That is the reading a *may* query wants and the ruin of a flood: one leak anywhere in
    a trap-guarded script poisons the whole of it. The `CfgEdge.RESUMPTION_FORWARD` edges carry
    every run that goes forward — each statement joined to the one control would resume at — so
    declining the hub drops no path that goes forward, only the backward reach the hub adds.

    A source the graph reports `is_hub_bound` for is flooded with the hub followed instead, because
    the forward edges carry nothing for such a source and the precise walk would stop at the
    resumption point: an opener written inside a `trap` body would then vouch for the very
    statements the handler resumes into. Its flood is the over-approximate one, which is the
    fail-closed direction. `flood` performs that fallback, so every door onto the forward reading
    inherits it rather than only this one.

    Every source must be a node of *graph*, which is what this adds over naming the projection at
    `flood` directly. Both facts the walk reads — `is_hub_bound` and `edge_kind` — are keyed by
    node identity in that graph alone, so a node lifted from a nested body's graph reads as neither
    hub-bound nor kinded and takes the precise walk over what the graph calls plain flow, which is
    the fail-open direction.
    """
    sources = list(sources)
    for source in sources:
        if source.graph is not graph:
            raise ValueError(
                'a source of a forward flood belongs to another body: the two facts this walk '
                'reads are recorded per graph, so such a source reads as neither a hub nor '
                'hub-bound and takes the precise walk over what this graph calls plain flow'
            )
    return frozenset(flood(sources, forward=True, projection=Projection.FORWARD))


class ElementLocator:
    """
    Locates an AST node among the per-body control-flow graphs of one script. Built once from the
    graph set, it maps an element to the graph and node that evaluate it — directly for an element a
    graph node stands for (`node_of`), or by climbing to the enclosing statement for one nested
    inside an expression (`locate`). Every flow-sensitive layer built on the graphs shares it, so the
    AST-to-graph mapping and its parent-climb live in one place.
    """

    def __init__(self, graphs: dict[int, ControlFlowGraph]):
        self._element_graph: dict[int, ControlFlowGraph] = {}
        self._owners = {id(graph.owner) for graph in graphs.values()}
        for graph in graphs.values():
            for node in graph.nodes:
                if node.element is not None:
                    self._element_graph[id(node.element)] = graph

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node standing for *element* in whichever graph owns it, or `None` when
        *element* is not itself a node the graphs represent.
        """
        graph = self._element_graph.get(id(element))
        return graph.node_of(element) if graph is not None else None

    def locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The graph and node that evaluate *element*, climbing out of any expression it is nested in to
        the enclosing statement or loop head, or `None` when it has no enclosing graph node.

        The climb stops at the body *element* is written in rather than continuing into the body
        around it. Something inside a body that no node of that body's graph stands for — the default
        of a parameter, an attribute on the body itself — is evaluated when that body is invoked, and
        the enclosing body's statement that mentions it is not that point. Answering with that
        statement orders the element against code the invocation may never run beside, which is the
        false claim the per-body split exists to avoid; `None` says the graphs do not place it, and a
        caller reads that as unknown.

        The body *element* is itself is not its own boundary: a block is a value written at a point
        in the body around it, so locating one climbs out to the statement that mentions it.
        """
        cursor: Node | None = element
        while cursor is not None:
            graph = self._element_graph.get(id(cursor))
            if graph is not None:
                node = graph.node_of(cursor)
                if node is not None:
                    return graph, node
            if cursor is not element and id(cursor) in self._owners:
                return None
            cursor = cursor.parent
        return None


@dataclass
class _Target:
    """
    A jump destination active while a breakable or continuable construct is being built. `breaks`
    collects the nodes that leave it early, wired to whatever follows once that is known;
    `continue_to` is the node a back-jump reaches, or `None` for a construct only a break can leave.

    `continues` collects the back-jumps of a loop whose `continue_to` is not yet known — a counted
    loop with neither a test nor an update jumps back to its body's own entry, and that entry only
    exists once the body has been built. Wiring them to the exit instead would drop the back-edge
    the loop is made of.
    """
    label: str | None
    breaks: list[CfgNode]
    continue_to: CfgNode | None
    is_continuable: bool
    is_breakable: bool
    continues: list[CfgNode] = field(default_factory=list)


@dataclass(eq=False)
class Resumption:
    """
    One statement block being built whose handler set *resumes* it rather than ending it, and the two
    synthetic nodes that carry the two projections of `CfgEdge` for it.

    `hub` is the over-approximate half: every point the block may resume from joins it, and it joins
    every node the block owns. `slot` is the precise half for the statement being built right now —
    the point control resumes at when that statement throws, which is the statement after it — and is
    created on the first node that needs one, because a statement building no node of its own resumes
    at the same place the one before it does.

    A frame owns only the nodes built while it is the *innermost* one. A nested resumable block opens
    a frame of its own and takes the nodes below it; what joins the two is one edge from the outer hub
    to the inner, and the tail of the inner block's forward chain arriving in the frontier the outer
    block threads on. Both are edges per nesting *pair*, where naming each node from each enclosing
    level is edges per node per level, and a script nested sixty-four deep costs twelve thousand
    edges rather than nine hundred.
    """
    hub: CfgNode
    slot: CfgNode | None = None


def distinct(nodes: Iterable[CfgNode]) -> list[CfgNode]:
    """
    *nodes* with every repetition dropped, compared by identity and in first-seen order.

    A frontier carried from one arm of a construct into the next must not accumulate duplicates. An
    arm that creates no node of its own hands its incoming frontier straight back, so concatenating
    the two doubles the list on every such arm: a `switch` with thirty empty clause bodies would
    build 2**30 edges, every one of them a repetition of an edge already there.
    """
    seen: set[int] = set()
    result: list[CfgNode] = []
    for node in nodes:
        if id(node) in seen:
            continue
        seen.add(id(node))
        result.append(node)
    return result


class CfgBuilder:
    """
    Single-pass construction of one `ControlFlowGraph` by structural recursion over a body, threading
    a *frontier* — the set of nodes from which normal control currently falls through — into each
    statement and out the other side.

    A language subclasses this and implements `statement` and `body_blocks`. Everything else is
    shared, and the shape methods below take the parts of a construct rather than the construct, so
    that no code here has to know what a language calls the pieces of its `for` loop.
    """

    def __init__(self, owner: Node):
        self.cfg = ControlFlowGraph(owner)
        self._handlers: list[CfgNode] = []
        self._targets: list[_Target] = []
        self._resumptions: list[Resumption] = []
        self._pending_label: str | None = None

    def build(self) -> ControlFlowGraph:
        frontier = [self.cfg.entry]
        for statements in self.body_blocks(self.cfg.owner):
            frontier = self.block(statements, frontier)
        self.link(frontier, self.cfg.exit)
        return self.cfg

    def body_blocks(self, owner: Node) -> Sequence[Sequence[Node]]:
        """
        The statement blocks *owner* runs, in the order it runs them. A language whose body may be a
        single unbraced statement resolves that here, and one that splits a body across several
        named blocks reports them apart rather than joined, because a construct scoped to a block
        cannot be modelled from a body that has forgotten where its blocks ended.
        """
        raise NotImplementedError

    def block(self, statements: Sequence[Node], frontier: list[CfgNode]) -> list[CfgNode]:
        """
        One statement block. The statements in order, which is all a block is to a language whose
        blocks carry nothing of their own; a language whose blocks scope a handler installs it here
        and calls this for every block it builds.
        """
        return self.sequence(statements, frontier)

    def statement(self, statement: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        Add *statement* to the graph and report the frontier that follows it. A language recognises
        its own node types here and calls the shape method that matches; anything it does not
        recognise goes to `opaque`, which is the conservative answer.
        """
        raise NotImplementedError

    def node(self, element: Node) -> CfgNode:
        """
        A graph node for *element*, joined to the innermost active handler if one is open.

        The handler edge is added here rather than at each site that creates a node, because *any*
        statement inside a guarded block may throw and the whole point of the edge is that it does
        not depend on which statement it is.
        """
        node = self.detached_node(element)
        if self._handlers:
            self.exceptional_edge(node, self._handlers[-1])
        return node

    def synthetic_node(self) -> CfgNode:
        """
        A graph node standing for no element: a join or fan-out point the graph needs and the
        program does not name. It locates into no query and generates no dataflow fact, which is
        what lets one stand in for a set of edges between real nodes without an analysis reading it
        as a statement.
        """
        node = CfgNode(self.cfg, None)
        self.cfg.nodes.append(node)
        return node

    def detached_node(self, element: Node) -> CfgNode:
        """
        A graph node for *element* that the enclosing handler does not guard.

        A handler's own entry is one: it stands for the point at which a throw is *offered* to a
        clause, which is not a point inside the region that clause guards. The edge outward from
        there says the clause did not take the throw, and whether any run says that is a property of
        the whole handler set, which `guarded` reads once.

        This is the one place an element gets a node, which is why the resumption edges are drawn
        here rather than by the caller that knows a block resumes. A block's own statements, the
        arms of a construct nested in it, and the entries of a handler set written inside it are
        built by three different methods that share nothing but this one, and a level that had to
        name its nodes afterwards would have to name the ones its nested levels built as well.
        """
        node = CfgNode(self.cfg, element)
        self.cfg.nodes.append(node)
        self.cfg._node_of[id(element)] = node
        if self._resumptions:
            self.join_resumption(node)
        return node

    @staticmethod
    def add_edge(source: CfgNode, target: CfgNode) -> None:
        source.successors.append(target)
        target.predecessors.append(source)

    def kind_edge(self, source: CfgNode, target: CfgNode, kind: CfgEdge) -> None:
        """
        An edge carrying *kind*, which every edge but a plain one is drawn through so that the
        adjacency lists and the kind map are never written apart.

        A pair drawn for the first time is stored rather than merged. `enum.Flag.__or__` builds a
        member through the class constructor and costs an order of magnitude more than the dict
        write around it, and every kinded edge in a script wrapped in resuming traps passes here.
        """
        self.add_edge(source, target)
        kinds = self.cfg._edge_kinds
        key = (id(source), id(target))
        carried = kinds.get(key)
        kinds[key] = kind if carried is None else carried | kind

    def exceptional_edge(self, source: CfgNode, target: CfgNode) -> None:
        self.kind_edge(source, target, CfgEdge.ERROR_CARRYING)

    def resumption_hub(self) -> CfgNode:
        """
        A fresh synthetic node standing for the over-approximate half of a resuming handler: every
        point the block may resume from joins it, and it joins every point the block may resume at.
        Recorded as a hub so that `CfgNode.is_resumption_hub` answers for it, which is what a
        forward-only walk declines to enter.
        """
        node = self.synthetic_node()
        node.is_resumption_hub = True
        self.cfg._resuming = True
        return node

    def resumption_hub_edge(self, source: CfgNode, target: CfgNode) -> None:
        """
        An edge *out* of a resumption hub — see `CfgEdge`. The way in is drawn plain, because the
        handler body reaching it completed.
        """
        self.cfg._resuming = True
        self.kind_edge(source, target, CfgEdge.RESUMPTION_HUB)

    def resumption_forward_edge(self, source: CfgNode, target: CfgNode) -> None:
        """
        An edge of the precise, forward-only half of a resuming handler — see `CfgEdge`.
        """
        self.cfg._resuming = True
        self.kind_edge(source, target, CfgEdge.RESUMPTION_FORWARD)

    def mark_hub_bound(self, nodes: Iterable[CfgNode]) -> None:
        """
        Record that the forward-only projection of resumption does not reach *nodes* — see
        `CfgNode.is_hub_bound`.

        A hub among *nodes* is passed over. A caller naming a handler body names whatever the
        level it walked appended, and a resumable block written inside that body contributes its
        own hub — a node the forward reading declines to stand at, not one it fails to reach.
        Marking it both would leave one node routed to the over-approximate walk as a *source* and
        refused as a *neighbour* in the same query, and `ControlFlowGraph.hub_bound` would report a
        fan-out as a statement.
        """
        self.cfg._resuming = True
        for node in nodes:
            if node.is_resumption_hub:
                continue
            node.is_hub_bound = True
            self.cfg._hub_bound.add(id(node))

    @contextmanager
    def resumption(self, resumes: Iterable[CfgNode]) -> Iterator[None]:
        """
        Build the enclosed block as one whose handler set resumes it from *resumes*, taking
        ownership of every node built inside it — see `Resumption`.

        The hub is wired on the way in, before the block is walked, because `detached_node` draws
        the edge out of it as each node appears. Where a resumable block is opened inside one, the
        outer hub reaches the inner rather than reaching the inner block's nodes one by one: a hub
        reaches exactly the nodes its block owns and everything those nodes lead to, and an inner
        hub is one of them.

        Ownership ends on every way out, which is why this is a block and not a pair of calls. A
        build abandoned part-way through a guarded statement would otherwise leave the frame open,
        and every node built afterwards would draw both halves of resumption against a handler set
        that does not guard it.
        """
        hub = self.resumption_hub()
        self.resumption_hub_edge(hub, self.cfg.exit)
        if self._resumptions:
            self.resumption_hub_edge(self._resumptions[-1].hub, hub)
        for resume in resumes:
            self.add_edge(resume, hub)
        self._resumptions.append(Resumption(hub))
        try:
            yield
        finally:
            self._resumptions.pop()

    def resume_past(self, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        *frontier* extended by the point control resumes at when the statement just built throws,
        with the innermost open block left ready for the statement after it.

        `join_resumption` claims the slot for the first node the statement builds and joins every
        later one to it, so there is one here exactly when the statement built a node of its own. A
        statement that built none claims nothing — a `trap` declaration is one, and so is an empty
        nested block — and the slot of the statement before it stays in the frontier and carries
        on to the next, which is where control really resumes.

        Claiming and clearing the slot are one step here so that no caller holds the frame or has to
        remember to reset it between statements. `distinct` is what keeps a statement that hands its
        incoming frontier straight back from drawing the same edge once per statement that passed it
        on.
        """
        frame = self._resumptions[-1]
        slot, frame.slot = frame.slot, None
        if slot is None:
            return frontier
        return distinct([*frontier, slot])

    def join_resumption(self, node: CfgNode) -> None:
        """
        Draw both projections of resumption for *node* against the innermost open block: the hub
        reaches it, and it resumes at the slot standing for the statement being built.

        One edge each. A node reached from the hub of the level above it is reached from this one
        too, through the edge between the two hubs, and a node resuming at this level's slot carries
        on to the level above through the frontier the inner block hands back — so neither half loses
        a path by naming only the innermost level, and both stop costing an edge per level.
        """
        frame = self._resumptions[-1]
        if frame.slot is None:
            frame.slot = self.synthetic_node()
        self.resumption_forward_edge(node, frame.slot)
        self.resumption_hub_edge(frame.hub, node)

    def close_handler_set(self, entries: Sequence[CfgNode], *, escapes: bool) -> None:
        """
        Finish a chain of handler entries: record where a throw goes when none of them takes it,
        and draw the edge there when some run may leave one of them to.

        Called once the set's bodies are built and the set itself is off the handler stack, so that
        `unwinding` names what guards the *construct* rather than the set being closed.

        A member that is not the last one falls back to the member after it and not to what guards
        the construct, because the engine consults the set in order: a throw the first clause
        declines is offered to the second, which is also where it would go if the first were not
        written. Recording the construct's fallback for every member reads one clause's
        counterfactual off another's, and a set whose later member acts then looks deletable.
        """
        outward = self.unwinding()
        for index, entry in enumerate(entries):
            following = entries[index + 1] if index + 1 < len(entries) else outward
            self.cfg._fallback[id(entry)] = following
        if escapes and entries:
            self.exceptional_edge(entries[-1], outward)

    def unwinding(self) -> CfgNode:
        """
        Where a throw goes when nothing open here takes it: the innermost active handler, or the
        body's exit, which is how the graph says the throw leaves the body.
        """
        return self._handlers[-1] if self._handlers else self.cfg.exit

    def link(self, frontier: Iterable[CfgNode], target: CfgNode) -> None:
        for node in frontier:
            self.add_edge(node, target)

    def sequence(self, statements: Sequence[Node], frontier: list[CfgNode]) -> list[CfgNode]:
        for statement in statements:
            frontier = self.statement(statement, frontier)
        return frontier

    def opaque(self, element: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        A statement whose internal control flow this does not model: one node, entered from the
        frontier and falling through. The default for anything a language does not recognise.
        """
        node = self.node(element)
        self.link(frontier, node)
        return [node]

    def _body(self, body: Node | None, frontier: list[CfgNode]) -> list[CfgNode]:
        return self.statement(body, list(frontier)) if body is not None else list(frontier)

    def _branch(self, body: Node | None, head: CfgNode) -> list[CfgNode]:
        return self._body(body, [head])

    def _capture_body(
        self, body: Node | None, frontier: list[CfgNode],
    ) -> tuple[CfgNode | None, list[CfgNode]]:
        """
        Build *body* and return its entry node — the node control reaches first — alongside its exit
        frontier. Used where a back-edge must target the body's own entry, which the plain frontier
        threading does not expose.

        The entry is the first successor the incoming *frontier* gains while *body* is built, not the
        first node created. A body that opens with a guarded block builds its handler or finalizer
        node before any guarded statement, so creation order would return that handler — a node with
        no edge back into the body — and the loop's back-edge would be wired to it, hiding the real
        body head from a backward reachability walk. The frontier instead links to the first guarded
        statement, which is the node control actually enters.
        """
        before = [(node, len(node.successors)) for node in frontier]
        exits = self._body(body, frontier)
        for node, count in before:
            if len(node.successors) > count:
                return node.successors[count], exits
        return None, exits

    def park_label(self, label: str | None) -> None:
        """
        Park *label* for the construct about to be built, for `take_label` to consume.

        `labelled` calls this for a language whose label is a statement wrapping the construct. A
        language whose label is a field *of* the construct calls it directly, because there is no
        wrapping statement to recognise — and a construct built without it carries no label, so
        every jump naming it misses and leaves the body instead.
        """
        self._pending_label = label

    def take_label(self) -> str | None:
        """
        The label parked for the construct about to be built, consumed once.
        """
        label = self._pending_label
        self._pending_label = None
        return label

    def branch_on(
        self,
        element: Node,
        arms: Sequence[Node | None],
        frontier: list[CfgNode],
        *,
        exhaustive: bool = False,
    ) -> list[CfgNode]:
        """
        A conditional: one head node the frontier enters, and one arm per branch. When the arms do
        not cover every case — an `if` with no `else` — the head itself is an exit, because control
        may pass the whole construct without entering any arm. `exhaustive` says the arms do cover
        it, which is what an `if`/`else` pair reports.
        """
        head = self.node(element)
        self.link(frontier, head)
        exits: list[CfgNode] = []
        for arm in arms:
            exits += self._branch(arm, head)
        if not exhaustive:
            exits.append(head)
        return exits

    def loop_head_tested(
        self, element: Node, body: Node | None, frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A loop whose condition is evaluated before the body, so the head is both the entry and an
        exit: `while`, and every `foreach` whose iteration may run zero times.
        """
        head = self.node(element)
        self.link(frontier, head)
        target = _Target(self.take_label(), [], head, is_continuable=True, is_breakable=True)
        self._targets.append(target)
        body_exits = self._branch(body, head)
        self._targets.pop()
        self.link(body_exits, head)
        return [head] + target.breaks

    def loop_tail_tested(
        self, element: Node, body: Node | None, frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A loop whose condition is evaluated after the body, so the body always runs once and the
        back-edge targets the body's own entry rather than the test.
        """
        test = self.node(element)
        target = _Target(self.take_label(), [], test, is_continuable=True, is_breakable=True)
        self._targets.append(target)
        entry, body_exits = self._capture_body(body, frontier)
        self._targets.pop()
        self.link(body_exits, test)
        self.add_edge(test, entry if entry is not None else test)
        return [test] + target.breaks

    def loop_counted(
        self,
        initializer: Node | None,
        test: Node | None,
        update: Node | None,
        body: Node | None,
        frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A loop with a separate initializer, test and update, each evaluated at its own point and so
        each given its own node. Any of the three may be absent; a loop with no test has no exit
        other than the jumps out of it, and its back-edge targets the body entry.
        """
        label = self.take_label()
        if initializer is not None:
            start = self.node(initializer)
            self.link(frontier, start)
            frontier = [start]
        head = self.node(test) if test is not None else None
        if head is not None:
            self.link(frontier, head)
            body_frontier: list[CfgNode] = [head]
        else:
            body_frontier = list(frontier)
        step = self.node(update) if update is not None else None
        target = _Target(label, [], step or head, is_continuable=True, is_breakable=True)
        self._targets.append(target)
        entry, body_exits = self._capture_body(body, body_frontier)
        self._targets.pop()
        latch = body_exits
        if step is not None:
            self.link(body_exits, step)
            latch = [step]
        back_to = head if head is not None else entry
        if back_to is not None:
            self.link(latch, back_to)
        self.link(target.continues, back_to if back_to is not None else self.cfg.exit)
        exits = list(target.breaks)
        if head is not None:
            exits.append(head)
        return exits

    def branch_chain(
        self,
        clauses: Sequence[tuple[Node, Node | None]],
        otherwise: Node | None,
        frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A chain of guarded arms, each tested only when every earlier test failed: `if`/`elseif`/`else`
        where the whole chain is one node rather than a nest of two-armed conditionals.

        Each test gets its own node, because the tests run at different points and an analysis that
        collapsed them could not order two of them. A test's node flows into its own arm and on to
        the next test; the last test flows into `otherwise` when there is one, and out of the
        construct when there is not.
        """
        exits: list[CfgNode] = []
        current = frontier
        for test, body in clauses:
            head = self.node(test)
            self.link(current, head)
            exits += self._branch(body, head)
            current = [head]
        if otherwise is not None:
            return distinct(exits + self._body(otherwise, current))
        return distinct(exits + current)

    def dispatch(
        self,
        element: Node,
        arms: Sequence[Sequence[Node]],
        frontier: list[CfgNode],
        *,
        arm_flow: ArmFlow,
        exhaustive: bool,
        iterated: bool = False,
    ) -> list[CfgNode]:
        """
        A multi-way branch: one head the frontier enters and one arm per clause, each arm a statement
        sequence the head may jump into. `arm_flow` says what an arm reaches when it runs off its
        end; see `ArmFlow`, which is where the languages differ.

        `exhaustive` says some arm always runs — a default clause — so the head is not itself an
        exit.

        `iterated` says the construct runs its arms once per element of an input, so it is a loop:
        a back-jump inside an arm re-enters the head rather than resolving to an enclosing loop, and
        an arm that simply runs off its end re-enters it too, for the next element. Without that
        second edge the arms lie on no cycle and an analysis reads a store inside one as happening
        once, which is what lets a self-referential assignment be folded to its first value.
        PowerShell's `switch` is this; JavaScript's is not, and reading one as the other both invents
        a back-edge to a loop the jump never reaches and drops the one it does.

        A jump *out* takes no back-edge: it leaves the construct rather than advancing it, which is
        the whole difference between the two spellings.
        """
        head = self.node(element)
        self.link(frontier, head)
        target = _Target(
            self.take_label(),
            [],
            head if iterated else None,
            is_continuable=iterated,
            is_breakable=True,
        )
        self._targets.append(target)
        carried: list[CfgNode] = []
        completed: list[CfgNode] = []
        for arm in arms:
            reached = self.sequence(list(arm), distinct([head, *carried]))
            if arm_flow is ArmFlow.SEQUENTIAL:
                carried = reached
            elif arm_flow is ArmFlow.CUMULATIVE:
                carried = distinct([*carried, *reached])
            else:
                completed += reached
        self._targets.pop()
        completed = distinct(completed + carried)
        if iterated:
            self.link(completed, head)
        exits = completed + target.breaks
        if not exhaustive:
            exits.append(head)
        return distinct(exits)

    def guarded(
        self,
        block: Node | None,
        handlers: Sequence[tuple[Node, Node | None]],
        finalizer: Node | None,
        finalizer_body: Sequence[Node],
        frontier: list[CfgNode],
        *,
        escapes: bool,
    ) -> list[CfgNode]:
        """
        A guarded block with any number of handlers and an optional finalizer.

        The handler nodes are created *before* the guarded block is built and the first is pushed on
        the handler stack, so that `node` joins every statement created inside the block to it. That
        ordering is the whole mechanism: it is why no statement inside the block has to know it is
        guarded.

        Several handlers are chained from the first, because which one runs depends on the type of
        the exception and none of them is guaranteed — a language with one handler passes a
        one-element sequence and the chain degenerates. The chain edge is *exceptional*: control
        takes it exactly when the earlier handler did not match, so nothing that handler's node
        stands for has run and its kill must not apply along it.

        `escapes` says the set of handlers may fail to take a throw the block makes, which is what a
        language whose clauses carry a type filter reports and what one whose single clause takes
        everything denies. It decides one edge — from the last handler to whatever guards this
        construct, or to the body exit when nothing does, which is how the graph says a throw leaves
        the body with no handler having taken it. Denying the edge is the difference between a
        clause that swallows and one that passes the throw on, so it is asked of every language
        rather than defaulted: the safe answer invents a path the program cannot take, and the
        other drops one it can.

        The finalizer is entered from the block's normal exits and from every handler's, and itself
        carries an exceptional edge outward, because a finalizer runs on the exceptional path too and
        control leaves the construct from it either way.
        """
        handlers = list(handlers)
        entries = [self.detached_node(handler) for handler, _ in handlers]
        finalizer_entry = self.detached_node(finalizer) if finalizer is not None else None
        guard = entries[0] if entries else finalizer_entry
        if guard is not None:
            self._handlers.append(guard)
        block_exits = self.statement(block, frontier) if block is not None else list(frontier)
        if guard is not None:
            self._handlers.pop()
        normal_exits = list(block_exits)
        for index, ((_, body), entry) in enumerate(zip(handlers, entries)):
            if index:
                self.exceptional_edge(entries[index - 1], entry)
            normal_exits += (
                self.statement(body, [entry]) if body is not None else [entry])
        self.close_handler_set(entries, escapes=escapes)
        if finalizer_entry is not None and finalizer is not None:
            self.link(normal_exits, finalizer_entry)
            final_exits = self.sequence(list(finalizer_body), [finalizer_entry])
            self.exceptional_edge(finalizer_entry, self.unwinding())
            return final_exits
        return normal_exits

    def labelled(
        self,
        label: str | None,
        body: Node | None,
        frontier: list[CfgNode],
        *,
        binds_to_body: bool,
    ) -> list[CfgNode]:
        """
        A labelled statement. When the label names a construct a jump can target directly —
        `binds_to_body` — it is parked for that construct to consume through `take_label`; otherwise
        the label names this statement itself and only a break can leave it.
        """
        if binds_to_body:
            self.park_label(label)
            return self.statement(body, frontier) if body is not None else list(frontier)
        target = _Target(label, [], None, is_continuable=False, is_breakable=False)
        self._targets.append(target)
        exits = self.statement(body, frontier) if body is not None else list(frontier)
        self._targets.pop()
        return exits + target.breaks

    def jump_out(
        self, element: Node, label: str | None, frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A jump that leaves the construct it names, or the innermost breakable one when unlabelled. A
        jump naming nothing this body holds leaves the body, which is the conservative reading.
        """
        node = self.node(element)
        self.link(frontier, node)
        target = self._break_target(label)
        if target is not None:
            target.breaks.append(node)
        else:
            self.add_edge(node, self.cfg.exit)
        return []

    def jump_back(
        self, element: Node, label: str | None, frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A jump to the next iteration of the loop it names, or of the innermost loop when unlabelled.
        """
        node = self.node(element)
        self.link(frontier, node)
        target = self._continue_target(label)
        if target is None:
            self.add_edge(node, self.cfg.exit)
        elif target.continue_to is not None:
            self.add_edge(node, target.continue_to)
        else:
            target.continues.append(node)
        return []

    def terminate(
        self, element: Node, frontier: list[CfgNode], *, exceptional: bool,
    ) -> list[CfgNode]:
        """
        A statement after which control does not continue in this body: a return, or a throw.

        A throw is `exceptional`, so it reaches the innermost open handler rather than the exit, and
        only reaches the exit when no handler is open. A return leaves the body outright — the
        finalizer question a return inside a guarded block raises is one this graph deliberately
        answers by the conservative edge rather than by modelling the unwind.
        """
        node = self.node(element)
        self.link(frontier, node)
        if exceptional:
            self.exceptional_edge(node, self.unwinding())
        else:
            self.add_edge(node, self.cfg.exit)
        return []

    def has_continue_target(self, label: str | None) -> bool:
        """
        Whether a back-jump naming *label* — or an unlabelled one — resolves to a construct
        currently being built. A language in which `continue` means something other than a back-jump
        when no such construct is open asks this to tell the two spellings apart.
        """
        return self._continue_target(label) is not None

    def has_break_target(self, label: str | None) -> bool:
        """
        Whether a jump out naming *label* — or an unlabelled one — resolves to a construct currently
        being built, the counterpart of `has_continue_target` for the language in which `break`
        means something other than leaving a construct when no construct is open to leave.
        """
        return self._break_target(label) is not None

    def _break_target(self, label: str | None) -> _Target | None:
        for target in reversed(self._targets):
            if label is None:
                if target.is_breakable:
                    return target
            elif target.label == label:
                return target
        return None

    def _continue_target(self, label: str | None) -> _Target | None:
        for target in reversed(self._targets):
            if not target.is_continuable:
                continue
            if label is None or target.label == label:
                return target
        return None


class ControlFlowModel:
    """
    The per-body control-flow graphs of one script, paired with the `ElementLocator` that maps any
    AST node to the graph node evaluating it. Built once over the script root — the graphs are purely
    syntactic and need no semantic model — and shared by every solver layered on it, which would
    otherwise each rebuild the whole set.
    """

    def __init__(self, graphs: dict[int, ControlFlowGraph]):
        self.graphs = graphs
        self._locator = ElementLocator(graphs)

    def graph_of(self, owner: Node) -> ControlFlowGraph | None:
        """
        The control-flow graph owned by *owner* — a function node or the script root — or `None` when
        it owns none.
        """
        return self.graphs.get(id(owner))

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node standing for *element*, or `None` when the graphs do not represent it
        directly. Delegates to the shared `ElementLocator`.
        """
        return self._locator.node_of(element)

    def locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The graph and node that evaluate *element*, climbing out of any enclosing expression, or
        `None` when it has no enclosing graph node. Delegates to the shared `ElementLocator`.
        """
        return self._locator.locate(element)


def build_control_flow(
    root: Node,
    builder: Callable[[Node], CfgBuilder],
    function_nodes: tuple[type, ...],
) -> dict[int, ControlFlowGraph]:
    """
    Build one control-flow graph per function and one for the script itself, keyed by the owner
    node's identity. The graphs are independent: a nested function appears in its parent's graph only
    as the statement that defines it, never as descended-into control flow.
    """
    graphs: dict[int, ControlFlowGraph] = {id(root): builder(root).build()}
    for node in root.walk():
        if isinstance(node, function_nodes):
            graphs[id(node)] = builder(node).build()
    return graphs
