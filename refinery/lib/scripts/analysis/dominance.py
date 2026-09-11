"""
Dominance over the per-body control-flow graphs of one script, in the graph-theoretic sense only.

One node *dominates* another when every path from the body's entry to the second passes through the
first, so the first is guaranteed to have executed by the time the second runs. That is a statement
about a graph and nothing else, which is why the whole of it lives here: a language contributes the
graph, and the relation over it is the same relation for every language.

The queries are keyed to AST nodes rather than to graph nodes, because that is what every caller
holds. An element the graph does not represent on its own — an expression inside a statement —
resolves to the node of the statement that evaluates it, which is the granularity the graph reasons
at. Two elements in different bodies' graphs are not ordered here at all: whether one body runs
before another is a question about calls, and a language answers it with the layer it builds on this
one.

Exceptional edges take part in the computation like any other edge. A definition is therefore
reported as dominating a use only when it runs first on *every* path, including the ones that leave a
guarded block by throwing, which is the conservative direction and the one a caller may rely on.

**A node no path from the entry reaches is dominated by nothing and dominates nothing**, itself
included. Dominance quantifies over the paths from the entry, and an unreachable node lies on none of
them, so every answer about one is vacuous. Reporting it as dominating itself would let a region the
program cannot enter order code that it can, and — worse — a *reachable* join one of whose
predecessors is unreachable would inherit that predecessor's answer and lose the dominators it really
has. Obfuscated scripts are full of the tail after a `return` or a `throw`, so this is the ordinary
case rather than the exotic one.

**Dominance orders, it does not certify.** That a definition dominates a use says the statement
holding it ran, not that the store it performs completed: a statement may throw part-way through, and
`refinery.lib.scripts.analysis.liveness` states the same asymmetry as the reason its transfer function
is not the textbook one. A caller reading dominance as evidence a value was established needs the
extra refusal, which `refinery.lib.scripts.analysis.reaching` makes.
"""
from __future__ import annotations

from typing import AbstractSet as Set
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    Projection,
    flood,
)


def _reverse_postorder(graph: ControlFlowGraph, projection: Projection) -> list[CfgNode]:
    """
    The nodes of *graph* that its entry reaches under *projection*, ordered so that a node precedes
    every successor a depth-first walk first arrived at through it. The entry comes first, and a node
    the projection does not reach does not appear at all — which is what confines every later step to
    the part of the graph the projection draws.

    The walk is iterative rather than recursive. A body of five thousand statements is a walk five
    thousand deep, and the interpreter's stack is not.
    """
    order: list[CfgNode] = []
    seen: set[int] = {id(graph.entry)}
    stack: list[tuple[CfgNode, Iterator[CfgNode]]] = [
        (graph.entry, iter(projection.successors(graph.entry)))
    ]
    while stack:
        node, successors = stack[-1]
        for successor in successors:
            if id(successor) in seen:
                continue
            seen.add(id(successor))
            stack.append((successor, iter(projection.successors(successor))))
            break
        else:
            order.append(node)
            stack.pop()
    order.reverse()
    return order


def _immediate_dominators(
    graph: ControlFlowGraph, order: list[CfgNode], projection: Projection,
) -> dict[int, int]:
    """
    The immediate dominator of every node in *order*, keyed by node identity. The entry is seeded as
    its own, which is the conventional answer and, more to the point here, what marks it as placed
    for the predecessors that resolve against it.

    Cooper, Harvey and Kennedy's iterative formulation: walk the nodes in reverse postorder and
    replace each one's immediate dominator with the nearest common ancestor of the ones its
    already-placed predecessors have, until a whole pass changes nothing. The ancestor is found by
    walking two chains up in lockstep, always advancing whichever is further from the entry, which is
    what the reverse-postorder rank measures.

    A predecessor with no immediate dominator yet is skipped rather than intersected against, which
    is how an unreachable predecessor stays out of the answer: it never gains one, so it is skipped
    forever, and a reachable node keeps the dominators its reachable predecessors give it. *That is
    also what would carry the projection on its own* — a node *order* leaves out never gains an
    immediate dominator and is therefore skipped forever — but the adjacency is read through
    *projection* here as well, so that this function and the ordering above cannot come to disagree
    about which graph they are walking.

    **The placed predecessors are folded deepest first, and that is what keeps the pass linear.**
    Which order they are folded in cannot change the answer — the ancestor operation is commutative
    and associative, and the loop runs to a fixpoint either way — but it decides how far `common`
    climbs. A `catch` clause has one predecessor per statement of the body it guards, and those
    predecessors are themselves a chain; folded shallowest first, the running answer sits at the top
    of that chain and every further predecessor climbs the whole way down to it, which is a pass
    quadratic in the size of the body. Folded deepest first, each predecessor is the immediate
    dominator of the one before it and the climb is a single step. A body of eight hundred statements
    is the difference between thirteen hundred thousand steps and thirteen thousand.

    The ordering is taken once, before the fixpoint, and not per pass. Neither the adjacency nor
    the rank changes while the loop runs; only which predecessors are placed does, and filtering
    a sorted list leaves it sorted. Reading the adjacency inside the loop would also allocate a
    fresh predecessor list per node per pass under `Projection.FORWARD`, which builds one.

    **The fixpoint is what makes the answer independent of the shape of the graph.** One pass
    suffices only where every cycle is entered at one point; on a cycle entered at two, a node placed
    from the predecessors seen so far reports a dominator it does not have, which is the direction a
    caller cannot defend against. Neither language here was seen to build such a graph and neither is
    asked to promise it — this module takes whatever graph it is handed — and the fixpoint costs one
    confirming pass on the graphs that never needed it.
    """
    rank = {id(node): index for index, node in enumerate(order)}
    idom: dict[int, int] = {id(graph.entry): id(graph.entry)}

    def common(a: int, b: int) -> int:
        while a != b:
            while rank[a] > rank[b]:
                a = idom[a]
            while rank[b] > rank[a]:
                b = idom[b]
        return a

    ranked = [
        (
            id(node),
            sorted(
                (known for known in map(id, projection.predecessors(node)) if known in rank),
                key=rank.__getitem__,
                reverse=True,
            ),
        )
        for node in order
        if node is not graph.entry
    ]
    changed = True
    while changed:
        changed = False
        for key, predecessors in ranked:
            candidate: int | None = None
            for known in predecessors:
                if known not in idom:
                    continue
                candidate = known if candidate is None else common(known, candidate)
            if candidate is not None and idom.get(key) != candidate:
                idom[key] = candidate
                changed = True
    return idom


def _dominance_intervals(
    idom: dict[int, int], graph: ControlFlowGraph, order: list[CfgNode],
) -> tuple[dict[int, int], dict[int, int]]:
    """
    Entry and exit stamps from a depth-first walk of the immediate-dominator tree, keyed by node
    identity. A node's descendants in that tree are exactly the nodes it dominates, and a depth-first
    walk visits a subtree contiguously, so *dominates* becomes the test that one stamp lies inside
    another's half-open interval.

    Iterative for the reason the postorder walk is: the tree of a straight-line body is a chain as
    long as the body.
    """
    root = id(graph.entry)
    children: dict[int, list[int]] = {id(node): [] for node in order}
    for node in order:
        key = id(node)
        if key != root:
            children[idom[key]].append(key)
    entered: dict[int, int] = {root: 0}
    left: dict[int, int] = {}
    clock = 1
    stack: list[tuple[int, Iterator[int]]] = [(root, iter(children[root]))]
    while stack:
        key, remaining = stack[-1]
        for child in remaining:
            entered[child] = clock
            clock += 1
            stack.append((child, iter(children[child])))
            break
        else:
            left[key] = clock
            stack.pop()
    return entered, left


class DominanceTree:
    """
    The dominator relation of one control-flow graph, held as the *immediate*-dominator tree with a
    depth-first numbering over it.

    A node's dominators are the path from it to the root of that tree, so the tree carries the whole
    relation in space linear in the body where a set per node is quadratic in it: one straight-line
    body of five thousand statements costs twelve million set entries as sets and five thousand
    parent links as a tree. The numbering then answers `dominates` with two comparisons rather than a
    set lookup, which matters because the callers above ask it hundreds of thousands of times per
    script.

    Only the nodes the entry reaches are in the tree. That is not an optimisation but the relation:
    see the module docstring on why an unreachable node dominates nothing.
    """

    def __init__(self, graph: ControlFlowGraph, projection: Projection):
        order = _reverse_postorder(graph, projection)
        self.idom = _immediate_dominators(graph, order, projection)
        self._entered, self._left = _dominance_intervals(self.idom, graph, order)

    @property
    def reached(self) -> Set[int]:
        """
        The ids of the nodes the entry reaches under the projection this tree was built with, which
        is exactly the set the tree holds: a node the entry does not reach is not in it at all.

        Read rather than flooded again. A caller asking which statements of a body can run is asking
        the question the tree already had to answer to exist, and a flood per body per pass over a
        script whose bodies share one graph is the same walk repeated.
        """
        return self._entered.keys()

    def dominates(self, a: CfgNode, b: CfgNode) -> bool:
        """
        Whether *a* dominates *b*. Reflexive for a reachable node; `False` whenever either node is
        unreachable, the two being one unreachable node included.
        """
        opened = self._entered.get(id(a))
        if opened is None:
            return False
        reached = self._entered.get(id(b))
        return reached is not None and opened <= reached < self._left[id(a)]


class DominatorModel:
    """
    Dominator relations for the per-body control-flow graphs of one script. A graph's dominance tree
    is computed once, on the first ordering question asked about that graph, and kept for as long as
    this model lives.

    Computing them all on construction instead would charge every caller for the whole script when
    most callers ask about one body, and the model is rebuilt from scratch whenever the tree version
    advances. This is the same laziness `refinery.lib.scripts.analysis.cycles.CycleModel` has, for the
    same reason.
    """

    def __init__(self, flow: ControlFlowModel):
        self._flow = flow
        self._trees: dict[tuple[int, Projection], DominanceTree] = {}

    def locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The control-flow graph and node that evaluate *element*, climbing out of any expression it is
        nested in, or `None` when it has no enclosing graph node. The graph identifies the body whose
        invocation runs *element*, which a caller needs to keep a query within one graph.
        """
        return self._flow.locate(element)

    def cfg_node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node of the statement or loop head that evaluates *element*, or `None` when
        *element* has no enclosing graph node.
        """
        located = self._flow.locate(element)
        return located[1] if located is not None else None

    def locate_pair(self, a: Node, b: Node) -> tuple[ControlFlowGraph, CfgNode, CfgNode] | None:
        """
        The graph and the two control-flow nodes that evaluate *a* and *b* when both lie in the same
        body's graph, or `None` when either is unlocatable or the two lie in different graphs, where
        intraprocedural dominance does not apply.
        """
        located_a = self._flow.locate(a)
        located_b = self._flow.locate(b)
        if located_a is None or located_b is None:
            return None
        graph_a, node_a = located_a
        graph_b, node_b = located_b
        if graph_a is not graph_b:
            return None
        return graph_a, node_a, node_b

    def dominates(self, a: Node, b: Node) -> bool:
        """
        Whether the statement evaluating *a* is guaranteed to have executed by the time the statement
        evaluating *b* runs. Reflexive — *a* and *b* in the same statement share one control-flow
        node, so a node dominates itself. `False` when either element is unlocatable, when the two
        lie in different graphs, or when the statement holding either cannot be reached at all.

        The `Projection.MAY` reading, which is the one an ordering question wants: it accepts *a*
        only where it runs first on *every* path the graph draws, and a path the forward projection
        declines to draw is a path the run can still take. A caller that means the forward reading —
        one flooding rather than ordering — asks `dominates_node` and names it.
        """
        located = self.locate_pair(a, b)
        return located is not None and self.dominates_node(*located, Projection.MAY)

    def strictly_dominates(self, a: Node, b: Node) -> bool:
        """
        Like `dominates`, but not reflexive: `False` when *a* and *b* share one control-flow node.

        A caller that must reject a same-statement occurrence needs this. Two occurrences inside one
        statement may be evaluated in either order as far as this granularity can tell, so the
        reflexive answer would accept a reference that is in fact evaluated first.
        """
        located = self.locate_pair(a, b)
        if located is None or located[1] is located[2]:
            return False
        return self.dominates_node(*located, Projection.MAY)

    def dominates_node(
        self, graph: ControlFlowGraph, a: CfgNode, b: CfgNode, projection: Projection,
    ) -> bool:
        """
        Whether control-flow node *a* dominates *b* within *graph*, which must be the graph both
        belong to, under *projection*. Reflexive. The node-level counterpart of `dominates`, for a
        caller that has already located the two.

        *graph* is asked for rather than looked up because it is the key the dominance tree is
        memoized under, and because a caller holding two nodes has already had to establish that they
        share a body for the question to mean anything.

        *projection* is asked for and has no default, because the two readings disagree exactly where
        this is hardest to check: under `Projection.MAY` a statement guarded by a resuming `trap`
        dominates nothing below it, since the hub draws a run arriving from every later statement,
        and under `Projection.FORWARD` it dominates what follows it. Both answers are right about
        different questions, and a caller that did not choose got whichever this happened to be
        written with.
        """
        return self.tree_of(graph, projection).dominates(a, b)

    def tree_of(self, graph: ControlFlowGraph, projection: Projection) -> DominanceTree:
        """
        The dominance tree of *graph* under *projection*, computed on first use and kept thereafter.

        A graph that `carries_resumption` reports nothing of has one tree and not two: the projections
        draw the same edges over it, so both keys answer from the `Projection.MAY` entry. That is
        nearly every script, and it is what keeps a second consumer asking the forward reading from
        doubling the dominance work of the whole run.
        """
        key = (id(graph), projection if graph.carries_resumption else Projection.MAY)
        found = self._trees.get(key)
        if found is None:
            found = self._trees[key] = DominanceTree(graph, key[1])
        return found

    def reached_from_entry(self, graph: ControlFlowGraph, projection: Projection) -> Set[int]:
        """
        The ids of the nodes of *graph* the body's entry reaches under *projection*.

        Answered from the dominance tree, which is the same walk and is memoized per graph. A
        caller deciding which statements of a body can run asks this rather than `reachable` from
        the entry: a script's bodies share one graph per function, and a pass asking per body pays
        one flood per body for an answer that does not vary within a graph.
        """
        return self.tree_of(graph, projection).reached

    def reachable(
        self, start: CfgNode, *, forward: bool, projection: Projection,
    ) -> set[int]:
        """
        The ids of the control-flow nodes reachable from *start* under *projection* — over successor
        edges when *forward*, over predecessor edges otherwise — including *start* itself. Exceptional
        edges are followed like any other, since they live in the same successor and predecessor
        lists.

        The two directions are kept separate rather than offered as one path-between query because a
        caller intersecting them memoizes each side independently: one definition is asked against
        many uses, and the forward set from the definition is the same every time.
        """
        return flood([start], forward=forward, projection=projection)
