"""
Strongly connected components of a directed graph given as a successor function, independent of
what the vertices stand for, and the condensation built on them. It sits beneath every other
analysis module, the control-flow graphs included, so that a walk over those graphs can condense
them without importing a module that is itself built on them.
"""
from __future__ import annotations

import itertools

from typing import Callable, Generic, Iterable, Iterator, TypeVar

_Vertex = TypeVar('_Vertex')
_Value = TypeVar('_Value')


def strongly_connected_components(
    nodes: Iterable[_Vertex],
    successors: Callable[[_Vertex], Iterable[_Vertex]],
) -> list[list[_Vertex]]:
    """
    The strongly connected components of the graph *successors* spans from *nodes*, each a list of
    nodes that can all reach one another; every node reachable from one of *nodes* is in exactly one
    of them, and nodes are told apart by identity. Each component is listed after every component it
    has an edge into, so a caller combining answers along the edges finds those of everything a
    component reaches already listed. The walk from each of *nodes* in turn lists all it reaches
    and no earlier walk did before the next one starts, so every component the first of *nodes*
    reaches is listed before every component it does not.

    Tarjan's algorithm, driven by an explicit stack rather than by recursion: the graphs are as deep
    as the script is long and a deeply nested body would otherwise exhaust the interpreter's stack
    on a script that parses fine.
    """
    index: dict[int, int] = {}
    lowlink: dict[int, int] = {}
    stacked: set[int] = set()
    pending: list[_Vertex] = []
    components: list[list[_Vertex]] = []

    def enter(node: _Vertex) -> tuple[_Vertex, Iterator[_Vertex]]:
        index[id(node)] = lowlink[id(node)] = len(index)
        pending.append(node)
        stacked.add(id(node))
        return node, iter(successors(node))

    for start in nodes:
        if id(start) in index:
            continue
        work = [enter(start)]
        while work:
            node, unvisited = work[-1]
            for successor in unvisited:
                if id(successor) not in index:
                    work.append(enter(successor))
                    break
                if id(successor) in stacked:
                    lowlink[id(node)] = min(lowlink[id(node)], index[id(successor)])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[id(parent)] = min(lowlink[id(parent)], lowlink[id(node)])
                if lowlink[id(node)] == index[id(node)]:
                    component: list[_Vertex] = []
                    while True:
                        member = pending.pop()
                        stacked.discard(id(member))
                        component.append(member)
                        if member is node:
                            break
                    components.append(component)
    return components


class Condensation(Generic[_Vertex]):
    """
    The graph *successors* spans from *nodes*, condensed into its strongly connected components: an
    acyclic graph of components over which a question about everything a node reaches, or about
    everything that reaches it, is answered once per component rather than once per node that asks.

    Components are numbered in the order `strongly_connected_components` lists them, so every
    component a component has an edge into carries a smaller number, and every component the first
    of *nodes* reaches carries a smaller number than any it does not. A component is `looped` when
    it holds more than one node or a node with an edge to itself: only then does a node reach
    itself, which is what a caller excluding the node that asks has to know.

    The components are tuples because a condensation may be shared: a control-flow graph keeps one
    per reading for every question asked of it.
    """

    def __init__(self, nodes: Iterable[_Vertex], successors: Callable[[_Vertex], Iterable[_Vertex]]):
        self.components: tuple[tuple[_Vertex, ...], ...] = tuple(
            tuple(component) for component in strongly_connected_components(nodes, successors)
        )
        self._index = {
            id(member): number
            for number, component in enumerate(self.components)
            for member in component
        }
        downstream: list[tuple[int, ...]] = []
        upstream: list[list[int]] = [[] for _ in self.components]
        looped: list[bool] = []
        for number, component in enumerate(self.components):
            reached: dict[int, None] = {}
            cycle = len(component) > 1
            for member in component:
                for target in successors(member):
                    other = self._index[id(target)]
                    if other == number:
                        cycle = True
                    else:
                        reached[other] = None
            downstream.append(tuple(reached))
            for other in reached:
                upstream[other].append(number)
            looped.append(cycle)
        self._downstream = downstream
        self._upstream = [tuple(found) for found in upstream]
        self._looped = looped
        self._sizes: list[int] | None = None

    def number_of(self, node: _Vertex) -> int | None:
        """
        The number of the component *node* belongs to, or `None` for a node the condensation was
        not built over.
        """
        return self._index.get(id(node))

    def size_up_to(self, number: int) -> int:
        """
        How many nodes the components numbered no higher than *number* hold together, which is at
        least how many a node of component *number* reaches, since nothing it reaches is numbered
        above it.
        """
        sizes = self._sizes
        if sizes is None:
            sizes = self._sizes = list(itertools.accumulate(len(component) for component in self.components))
        return sizes[number]

    def downstream(self, number: int) -> tuple[int, ...]:
        """
        The components component *number* has an edge into, itself excluded.
        """
        return self._downstream[number]

    def upstream(self, number: int) -> tuple[int, ...]:
        """
        The components with an edge into component *number*, itself excluded.
        """
        return self._upstream[number]

    def looped(self, number: int) -> bool:
        """
        Whether a node of component *number* reaches itself.
        """
        return self._looped[number]

    def accumulate(
        self,
        own: Callable[[int], _Value],
        join: Callable[[_Value, _Value], _Value],
        *,
        downstream: bool,
    ) -> list[_Value]:
        """
        For every component, *own* of it joined with the accumulation of every component on one
        side of it — what it reaches when *downstream*, what reaches it otherwise — in one pass. A
        component reached along two paths is joined once per path, so *join* has to give the same
        answer for a value joined twice as for one joined once, as a union does and a sum does not.
        """
        count = len(self.components)
        result: dict[int, _Value] = {}
        order = range(count) if downstream else range(count - 1, -1, -1)
        for number in order:
            value = own(number)
            for other in (self._downstream[number] if downstream else self._upstream[number]):
                value = join(value, result[other])
            result[number] = value
        return [result[number] for number in range(count)]

    def holds(
        self,
        number: int,
        test: Callable[[int], bool],
        memo: dict[int, bool],
        *,
        downstream: bool,
    ) -> bool:
        """
        Whether *test* holds of component *number* or of a component on one side of it,
        transitively: what it reaches when *downstream*, what reaches it otherwise. Decided on
        demand, never asking *test* of a component twice, and kept in *memo*. The memo belongs to
        the caller beside the test it was filled with, so that two tests cannot share one.
        """
        tested: dict[int, bool] = {}
        stack = [number]
        while stack:
            current = stack[-1]
            if current in memo:
                stack.pop()
                continue
            if current not in tested:
                tested[current] = test(current)
                if tested[current]:
                    memo[current] = True
                    stack.pop()
                    continue
            neighbours = self._downstream[current] if downstream else self._upstream[current]
            if any(memo.get(other) for other in neighbours):
                memo[current] = True
                stack.pop()
                continue
            pending = [other for other in neighbours if other not in memo]
            if pending:
                stack.extend(pending)
                continue
            memo[current] = False
            stack.pop()
        return memo[number]

    def found_within(
        self,
        number: int,
        test: Callable[[int], bool],
        memo: dict[int, bool],
        *,
        downstream: bool,
        limit: int,
    ) -> bool:
        """
        Whether *test* holds of component *number* or of a component on one side of it — what it
        reaches when *downstream*, what reaches it otherwise — leaving out every component numbered
        below *limit* going downstream and above it going upstream. Numbers fall along every edge,
        so no component inside that bound is reached only through one outside it.

        The question `holds` answers, asked by a caller for whom one answer is worth less than the
        walk to the far end of the bound: the walk is breadth-first and ends at the first component
        that passes, so the nearest one decides. *memo* keeps what a walk settles — every component
        visited by one that finds nothing, and the path from *number* to the component found by one
        that does — for the next walk under the same test and limit, and belongs to the caller
        beside those two.
        """
        known = memo.get(number)
        if known is not None:
            return known
        edges = self._downstream if downstream else self._upstream
        parent = {number: number}
        queue = [number]
        for current in queue:
            if memo.get(current) or test(current):
                while current != number:
                    memo[current] = True
                    current = parent[current]
                memo[number] = True
                return True
            for other in edges[current]:
                if (
                    other in parent
                    or (other < limit if downstream else other > limit)
                    or memo.get(other) is False
                ):
                    continue
                parent[other] = current
                queue.append(other)
        for current in queue:
            memo[current] = False
        return False
