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

from typing import Iterable, Sequence, TypeVar

from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, Projection
from refinery.lib.scripts.analysis.dominance import DominatorModel

_D = TypeVar('_D')


class ReachabilityQuery:
    """
    Memoized forward and backward reachability over one `DominatorModel` under one
    `refinery.lib.scripts.analysis.cfg.Projection`, the path-between question asked from them, and the
    `reaching_definition` selection asked from that.

    The memo is the reason this is an object rather than a function. One definition is asked against
    many uses, so the forward set from the definition is computed once and reused; the graphs do not
    change for as long as the model lives, so nothing invalidates it.

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
    ) -> bool:
        """
        Whether any node in *candidates* — given as node ids of *graph* — lies on some path from
        *source* to *target*.

        Asked as two walks rather than one path enumeration: a node lies between the two exactly when
        it is reachable forward from *source* and *target* is reachable forward from it, and the
        second half is the same as it being reachable backward from *target*. The forward set is
        intersected first and the backward walk is skipped entirely when that comes back empty, which
        is the common case for a caller whose candidate set is small.

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
        between a definition and a use it in fact rebinds.
        """
        candidates = frozenset(candidates)
        if not candidates:
            return False
        downstream = self.reachable(source, forward=True) & candidates
        if not downstream:
            return False
        if self._projection.declines_the_hub and downstream & graph.hub_bound:
            return True
        return bool(downstream & self.reachable(target, forward=False))

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
        qualifying: list[tuple[_D, CfgNode]] = []
        seen: set[int] = set()
        for value, node in definitions:
            if node is use or not self._dominators.dominates_node(
                graph, node, use, self._projection
            ):
                continue
            if id(node) in seen:
                return None
            seen.add(id(node))
            qualifying.append((value, node))
        if not qualifying:
            return None
        nearest, nearest_node = qualifying[0]
        for value, node in qualifying[1:]:
            if self._dominators.dominates_node(graph, nearest_node, node, self._projection):
                nearest, nearest_node = value, node
        blocking = {id(node) for _, node in definitions if node is not nearest_node}
        blocking.update(kills)
        if self.any_between(graph, nearest_node, use, blocking):
            return None
        return nearest

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
        last, and the answer is then `None`. A definition sharing *use*'s node is not ordered
        against it at this granularity and is refused, as `reaching_definition` refuses it.
        """
        at: dict[int, list[_D]] = {}
        for value, node in definitions:
            at.setdefault(id(node), []).append(value)
        if id(use) in at or use is graph.entry:
            return None
        blocking = frozenset(kills)
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
