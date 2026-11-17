"""
The path-between query — does anything in a given set of control-flow nodes lie on a path from one
node to another — and the definition selection built on it.

This is what a reaching-value question reduces to once dominance has ordered the two ends. The value
established at a definition still holds at a use when the definition runs first on every path — which
is dominance — and nothing that could change it runs in between. "In between" is the intersection of
what is reachable forward from the definition with what is reachable backward from the use, and a
kill outside that intersection cannot be on any path joining them.

What is a *kill* is entirely the caller's question and is not asked here: a language names the sites
at which the thing it tracks may change, or says it cannot enumerate them. The graph half is this
module's, and it is the same for every language.

**Between is asked by reachability, never by position.** A definition written after a use in the
source still reaches it when a back edge carries control around, and one written before it may be
re-executed by the same edge. Ordering the two by where they were typed answers both wrongly, and
answers them wrongly in the direction that keeps a stale value.
"""
from __future__ import annotations

import bisect

from typing import Generic, Iterable, Sequence, TypeVar

from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    Projection,
    walk_reading,
)
from refinery.lib.scripts.analysis.dominance import DominatorModel

_D = TypeVar('_D')


def _meets(candidates: frozenset[int], reached: frozenset[int], left_out: int | None) -> bool:
    """
    Whether *reached* holds a node of *candidates* other than *left_out*.
    """
    if left_out is None or left_out not in reached:
        return not candidates.isdisjoint(reached)
    if len(candidates) <= len(reached):
        return any(key in reached for key in candidates if key != left_out)
    return any(key in candidates for key in reached if key != left_out)


class ReachabilityQuery:
    """
    Memoized forward and backward reachability over one `DominatorModel` under one
    `refinery.lib.scripts.analysis.cfg.Projection`, the path-between question asked from them, and the
    `reaching_definition` selection asked from that.

    The memos are the reason this is an object rather than a function. A caller asking what one node
    reaches asks it again of the same node, so each set is computed once and reused, and a caller
    asking whether a candidate lies between asks it again of the same candidates and the same
    definition for every use; the graphs do not change for as long as the model lives, so nothing
    invalidates either.

    **The projection belongs to the instance and not to the call.** Every set this holds was computed
    under one reading of the graph, and the memo is keyed by node and direction with no room for a
    third dimension; a caller allowed to name a projection per call would be served whichever reading
    happened to be computed first. A consumer wanting the other reading builds a query of its own,
    which costs it its own memo and nothing else.
    """

    def __init__(self, dominators: DominatorModel, projection: Projection):
        self._dominators = dominators
        self._projection = projection
        self._reach: dict[tuple[int, bool], frozenset[int]] = {}
        self._upstream: dict[frozenset[int], dict[tuple[int, int, int | None], dict[int, bool]]] = {}
        self._asked: set[tuple[int, bool]] = set()
        self._spent: dict[int, int] = {}
        self._orders: dict[tuple[int, tuple[tuple[int, int], ...]], DefinitionOrder] = {}

    def reachable(self, node: CfgNode, *, forward: bool) -> frozenset[int]:
        """
        The ids of the nodes reachable from *node* in the given direction, including *node*.

        Frozen because it is the memo itself and not a copy of it: a caller that intersected or
        discarded in place would corrupt the answer every later query against *node* receives.
        """
        key = (id(node), forward)
        cached = self._reach.get(key)
        if cached is None:
            cached = frozenset(self._dominators.reachable(
                node, forward=forward, projection=self._projection))
            self._reach[key] = cached
        return cached

    def any_between(
        self,
        graph: ControlFlowGraph,
        source: CfgNode,
        target: CfgNode,
        candidates: Iterable[int],
        *,
        excluding: CfgNode | None = None,
    ) -> bool:
        """
        Whether any node in *candidates* — given as node ids of *graph* — lies on some path from
        *source* to *target*. The node *excluding* is never one of them, whether *candidates* lists
        it or not: a caller asking from each of several definitions whether another of them lies
        between it and a use hands over one set of all of them and names the one it asks from,
        where a set made anew for each would cost as much as all of them, every time.

        A node lies between the two exactly when it is reachable forward from *source* and *target*
        is reachable forward from it, which is the same as it being reachable backward from
        *target*.

        **Where *source* dominates *target*, one walk backward from *target* answers it.** A node
        the entry reaches, that reaches *target*, and that *source* could reach at all by the order
        of `refinery.lib.scripts.analysis.cfg.ControlFlowGraph.condensation` — whose component
        numbers fall along every edge, so nothing *source* reaches is numbered above it — is a node
        *source* does reach: a path from the entry to it avoiding *source*, continued to *target*,
        would avoid *source* too. So the walk goes upstream from *target* over components, never
        past the number of *source*, which leaves it among the components the entry reaches since
        the condensation numbers those first, and stops at the nearest one that holds a candidate
        (`refinery.lib.scripts.analysis.components.Condensation.found_within`). It never visits
        what *source* reaches but *target* does not, and what it settles is kept per candidate set
        and bound, so that the uses of one definition share one walk. That is every question
        `reaching_definition` asks and every question asked from the entry. The argument needs both
        walks to read one relation, which a hub-bound *source* does not
        (`refinery.lib.scripts.analysis.cfg.walk_reading`).

        **The walk is taken only where one of the two ends is new**: a *source* not asked from
        before, or a *target* not asked toward before. A walk visits only what the flood from its
        new end would, and a question whose ends are both old is answered by those floods, computed
        once and kept for every further candidate set between them. Two hundred variables defined
        in one statement and read in another cost one walk and two floods, where a walk per variable
        would cross the stretch between the two statements two hundred times.

        **A source whose walks have tested more nodes than the components numbered no higher than
        its own hold is flooded forward.** One source asked toward many new targets walks toward
        each of them, and where no candidate lies between, each walk crosses everything from its
        target up to the source, where the floods answer every such question from one forward
        flood. Those components hold everything the source reaches and a walk tests nothing outside
        them, so the walks from one source cost at most twice their count before it is flooded;
        from then on a candidate set that flood misses is refused at once, as the two floods refuse
        it. Two hundred variables written above one statement that defines them all again, each
        read in a statement of its own below it, cost a few short walks and one flood, where a walk
        per read would cross the stretch to every read.

        Every other question intersects the two floods `reachable` memoizes, the forward set first,
        and so does every question whose two floods are already at hand, since nothing answers it
        for less.

        Candidates stay *ids* rather than becoming nodes, which is why *graph* is asked for. Every
        layer above builds these sets as ids and memoizes them that way, and a signature taking nodes
        would be satisfied by whatever a caller could still name — quietly dropping the candidates it
        had only ids for, which is the fail-open direction and one nothing would report.

        **Under `Projection.FORWARD` the backward walk is not the transpose of the forward one**, and
        a candidate the graph calls hub-bound counts as between as soon as it is reachable forward
        from *source*. Such a candidate stands inside a handler body that resumes the block around
        it; where the run carries on afterwards is exactly what the forward edges do not draw, so the
        backward walk from *target* will not find it however certainly the real run passes through
        it. Answering from the walk alone would say a binder written in a `trap` body does not lie
        between a definition and a use it in fact rebinds. Such candidates are asked of the forward
        set before either way of answering the rest.
        """
        candidates = frozenset(candidates)
        left_out = None if excluding is None or id(excluding) not in candidates else id(excluding)
        if not candidates or left_out is not None and len(candidates) == 1:
            return False
        source_end, target_end = (id(source), True), (id(target), False)
        walk = source_end not in self._asked or target_end not in self._asked
        self._asked.add(source_end)
        self._asked.add(target_end)
        projection = self._projection
        if projection.declines_the_hub:
            unplaced = candidates & graph.hub_bound
            if unplaced and _meets(unplaced, self.reachable(source, forward=True), left_out):
                return True
        reached = self._reach.get(source_end)
        if reached is not None and not _meets(candidates, reached, left_out):
            return False
        if reached is None or target_end not in self._reach:
            reading = walk_reading(target, forward=False, projection=projection)
            if (
                walk_reading(source, forward=True, projection=projection) is reading
                and self._dominators.dominates_node(graph, source, target, projection)
            ):
                held = self._held_upstream(
                    graph, source, target, candidates, reading, walk=walk, left_out=left_out)
                if held is not None:
                    return held
        downstream = self.reachable(source, forward=True) & candidates
        if left_out is not None:
            downstream = downstream - {left_out}
        return bool(downstream) and not downstream.isdisjoint(self.reachable(target, forward=False))

    def _held_upstream(
        self,
        graph: ControlFlowGraph,
        source: CfgNode,
        target: CfgNode,
        candidates: frozenset[int],
        reading: Projection,
        *,
        walk: bool,
        left_out: int | None,
    ) -> bool | None:
        """
        `any_between` for a *source* that dominates *target* under *reading*: whether a component
        numbered no higher than that of *source*, every one of which the entry reaches, holds a
        candidate other than *left_out* and reaches *target*. `None` where no earlier walk under the
        same candidates, exclusion and bound settled it and *walk* says not to walk.

        The memos are kept by candidate set first: a caller builds an equal set afresh for every
        question, and keyed by the set alone it is held once rather than once per source. Below it,
        they are kept per graph, bound and excluded node, since a walk that leaves out one node
        settles nothing for one that counts it. A memo is kept only for a walk that is taken. Every
        node a walk tests without finding a candidate is added to what its *source* has spent, and a
        source that has spent more than the components numbered no higher than its own hold is
        flooded forward, which `any_between` reads first from then on. A component that holds a
        candidate costs one: such a walk answers what the flood back from its target would have had
        to.
        """
        condensation = graph.condensation(reading)
        start = condensation.number_of(target)
        bound = condensation.number_of(source)
        assert start is not None and bound is not None
        memos = self._upstream.get(candidates)
        key = (id(graph), bound, left_out)
        memo = None if memos is None else memos.get(key)
        known = None if memo is None else memo.get(start)
        if known is not None or not walk:
            return known
        if memo is None:
            memo = {}
            self._upstream.setdefault(candidates, {})[key] = memo
        components = condensation.components
        spent = self._spent.get(id(source), 0)

        def holds_a_candidate(number: int) -> bool:
            nonlocal spent
            members = components[number]
            for node in members:
                key = id(node)
                if key in candidates and key != left_out:
                    spent += 1
                    return True
            spent += len(members)
            return False

        held = condensation.found_within(start, holds_a_candidate, memo, downstream=False, limit=bound)
        self._spent[id(source)] = spent
        if spent > condensation.size_up_to(bound):
            self.reachable(source, forward=True)
        return held

    def reaching_definition(
        self,
        graph: ControlFlowGraph,
        use: CfgNode,
        definitions: Sequence[tuple[_D, CfgNode]],
        kills: Iterable[int] = (),
    ) -> _D | None:
        """
        The one definition among *definitions* whose value is observed at *use*, or `None` when no
        single definition is.

        *definitions* pairs each of the caller's own definition objects with the control-flow node
        that evaluates it, and the caller's object is what comes back — the graph cannot say which of
        several definitions sharing a node is meant, and does not have to. *kills* names further
        nodes that may change the value without defining it, as ids.

        A definition qualifies when it strictly dominates *use*: it runs first on every path there,
        and does not merely share *use*'s statement, which this granularity cannot order. Of those,
        the *nearest* is the one every other qualifying definition dominates — they form a chain,
        because the dominators of any node are the path from it to the root of the dominance tree —
        and it is the only one whose value can survive, since each of the others is overwritten by
        it. Two qualifying definitions sharing one node are refused before the scan, because nothing
        orders them and the scan would return whichever the caller listed first.

        **Every definition other than the chosen one is a kill, and the caller cannot opt out.** That
        is what makes an earlier definition re-entered by a back edge, and a definition on a branch
        that rejoins, both count against the answer. A caller that knows the language orders a
        particular write after the read in the same statement leaves that write out of *definitions*
        rather than being given a switch here, because the safe default has to be the one you get by
        saying nothing.
        """
        qualifying = self.order(graph, definitions)
        return qualifying.reaching(use, kills)

    def order(
        self,
        graph: ControlFlowGraph,
        definitions: Sequence[tuple[_D, CfgNode]],
    ) -> DefinitionOrder[_D]:
        """
        The definitions *definitions* of *graph* ordered for `reaching_definition` asked from many
        uses, kept per graph and per the definitions listed, in their order: a caller asking one set
        of definitions about each of its uses builds the list anew every time, and the ordering it
        then costs once is what each use would otherwise pay again.
        """
        key = (id(graph), tuple((id(value), id(node)) for value, node in definitions))
        found = self._orders.get(key)
        if found is None:
            found = self._orders[key] = DefinitionOrder(self, graph, definitions)
        return found

    def reaching_definitions(
        self,
        graph: ControlFlowGraph,
        use: CfgNode,
        definitions: Sequence[tuple[_D, CfgNode]],
        kills: Iterable[int] = (),
    ) -> list[_D] | None:
        """
        Every definition among *definitions* whose value may be observed at *use*, or `None` where a
        value none of them established may be: the one standing before *graph* ran, or one a kill
        left behind.

        A definition reaches *use* when some path runs from it to *use* with no other definition on
        it, so the answer is read off a walk backwards from *use* that stops at every definition it
        meets. Those it stops at are the answer; reaching the entry, or a node in *kills* — a
        definition's own node among them — on the way is a path along which no definition stands
        last, and the answer is then `None`. A definition or a kill sharing *use*'s node is not
        ordered against it at this granularity and is refused, as `reaching_definition` refuses it.
        """
        at: dict[int, list[_D]] = {}
        for value, node in definitions:
            at.setdefault(id(node), []).append(value)
        blocking = frozenset(kills)
        if id(use) in at or id(use) in blocking or use is graph.entry:
            return None
        found: list[_D] = []
        seen: set[int] = {id(use)}
        stack = list(self._projection.predecessors(use))
        while stack:
            node = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            if id(node) in blocking:
                return None
            reached = at.get(id(node))
            if reached is not None:
                found.extend(reached)
                continue
            if node is graph.entry:
                return None
            stack.extend(self._projection.predecessors(node))
        return found


class DefinitionOrder(Generic[_D]):
    """
    One set of definitions of one graph, ordered for the `ReachabilityQuery.reaching_definition`
    selection asked at each of many uses (`ReachabilityQuery.order`).

    The nodes holding definitions are ordered by the stamp the dominance tree gave them on entry
    (`refinery.lib.scripts.analysis.dominance.DominanceTree.interval`), each linked to the nearest
    of them whose interval holds its own. A use's dominating definitions are then the chain of
    links from the last node entered no later than it whose interval holds it, nearest first: one
    bisect and a climb over the nodes holding definitions, never over the graph's other nodes. Each
    link knows whether a node on its chain holds two definitions, which refuses every use below it,
    so that question costs nothing per use. The kill set every definition makes for another is
    built once per set of kills and shared, the nearest one left out of it by name.
    """

    def __init__(
        self,
        query: ReachabilityQuery,
        graph: ControlFlowGraph,
        definitions: Sequence[tuple[_D, CfgNode]],
    ):
        self._query = query
        self._graph = graph
        self._tree = query._dominators.tree_of(graph, query._projection)
        held: dict[int, list[_D]] = {}
        placed: list[tuple[int, int, CfgNode]] = []
        for value, node in definitions:
            values = held.get(id(node))
            if values is None:
                values = held[id(node)] = []
                interval = self._tree.interval(node)
                if interval is not None:
                    placed.append((*interval, node))
            values.append(value)
        placed.sort(key=lambda entry: entry[0])
        self._held = held
        self._placed = placed
        self._starts = [entry[0] for entry in placed]
        self._nodes = frozenset(held)
        self._blocking: dict[frozenset[int], frozenset[int]] = {frozenset(): self._nodes}
        parent = [-1] * len(placed)
        doubled = [False] * len(placed)
        open_: list[int] = []
        for index, (start, _, node) in enumerate(placed):
            while open_ and not start < placed[open_[-1]][1]:
                open_.pop()
            above = open_[-1] if open_ else -1
            parent[index] = above
            doubled[index] = len(held[id(node)]) > 1 or above >= 0 and doubled[above]
            open_.append(index)
        self._parent = parent
        self._doubled = doubled

    def reaching(self, use: CfgNode, kills: Iterable[int] = ()) -> _D | None:
        """
        The `ReachabilityQuery.reaching_definition` answer for *use*: the one definition whose value
        is observed there, or `None` when no single one is.
        """
        interval = self._tree.interval(use)
        if interval is None:
            return None
        stamp = interval[0]
        index = bisect.bisect_right(self._starts, stamp) - 1
        while index >= 0 and not stamp < self._placed[index][1]:
            index = self._parent[index]
        if index >= 0 and self._placed[index][2] is use:
            index = self._parent[index]
        if index < 0 or self._doubled[index]:
            return None
        nearest_node = self._placed[index][2]
        nearest = self._held[id(nearest_node)][0]
        kills = frozenset(kills)
        blocking = self._blocking.get(kills)
        if blocking is None:
            blocking = self._blocking[kills] = self._nodes | kills
        left_out = None if id(nearest_node) in kills else nearest_node
        if self._query.any_between(self._graph, nearest_node, use, blocking, excluding=left_out):
            return None
        return nearest
