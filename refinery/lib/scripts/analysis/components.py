"""
Strongly connected components of a directed graph given as a successor function, independent of
what the vertices stand for, and the condensation built on them. It sits beneath every other
analysis module, the control-flow graphs included, so that a walk over those graphs can condense
them without importing a module that is itself built on them.
"""
from __future__ import annotations

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
    component reaches already listed.

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
    component a component has an edge into carries a smaller number. A component is `looped` when it
    holds more than one node or a node with an edge to itself: only then does a node reach itself,
    which is what a caller excluding the node that asks has to know.
    """

    def __init__(self, nodes: Iterable[_Vertex], successors: Callable[[_Vertex], Iterable[_Vertex]]):
        self.components = strongly_connected_components(nodes, successors)
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

    def number_of(self, node: _Vertex) -> int | None:
        """
        The number of the component *node* belongs to, or `None` for a node the condensation was
        not built over.
        """
        return self._index.get(id(node))

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
        side of it — what it reaches when *downstream*, what reaches it otherwise — each component's
        own value counted once, in one pass.
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
