from __future__ import annotations

import itertools

from typing import Callable

from test import TestBase
from test.lib.scripts.analysis import graph_from_edges as _graph

from refinery.lib.scripts.analysis.cfg import CfgNode
from refinery.lib.scripts.analysis.components import Condensation

_SHAPES: dict[str, dict[str, list[str]]] = {
    'chain': {'a': ['b'], 'b': ['c'], 'c': []},
    'self loop in a chain': {'a': ['b'], 'b': ['b', 'c'], 'c': []},
    'diamond': {'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []},
    'ring with a tail': {'a': ['b'], 'b': ['c'], 'c': ['a', 'd'], 'd': []},
    'two rings joined': {'a': ['b'], 'b': ['a', 'm'], 'm': ['c'], 'c': ['d'], 'd': ['c']},
    'nested rings': {'a': ['b'], 'b': ['c', 'a'], 'c': ['d'], 'd': ['b', 'e'], 'e': []},
    'two entries into one ring': {'a': ['r'], 'b': ['s'], 'r': ['s'], 's': ['r', 'z'], 'z': []},
}


def _successors(node: CfgNode) -> list[CfgNode]:
    return node.successors


def _predecessors(node: CfgNode) -> list[CfgNode]:
    return node.predecessors


def _closure(start: CfgNode, step: Callable[[CfgNode], list[CfgNode]]) -> set[int]:
    seen: set[int] = set()
    stack = list(step(start))
    while stack:
        node = stack.pop()
        if id(node) not in seen:
            seen.add(id(node))
            stack.extend(step(node))
    return seen


class TestACondensationAnswersWhatTheEdgesReach(TestBase):
    """
    Every answer of the condensation is compared with a walk from each node along the edges it
    condenses, which knows nothing of components.
    """

    def test_a_node_is_on_a_looped_component_exactly_when_it_reaches_itself(self):
        for shape, edges in _SHAPES.items():
            graph, named = _graph(edges)
            condensation = Condensation(graph.nodes, _successors)
            for name, node in named.items():
                number = condensation.number_of(node)
                assert number is not None
                with self.subTest(shape=shape, node=name):
                    self.assertEqual(
                        condensation.looped(number), id(node) in _closure(node, _successors))

    def test_accumulating_downstream_joins_what_each_node_reaches(self):
        for shape, edges in _SHAPES.items():
            graph, named = _graph(edges)
            condensation = Condensation(graph.nodes, _successors)
            name_of = {id(node): name for name, node in named.items()}
            joined = condensation.accumulate(
                lambda number: frozenset(name_of[id(node)] for node in condensation.components[number]),
                frozenset.union,
                downstream=True,
            )
            for name, node in named.items():
                number = condensation.number_of(node)
                assert number is not None
                expected = {name} | {name_of[n] for n in _closure(node, _successors)}
                with self.subTest(shape=shape, node=name):
                    self.assertEqual(joined[number], expected)

    def test_accumulating_upstream_joins_what_reaches_each_node(self):
        for shape, edges in _SHAPES.items():
            graph, named = _graph(edges)
            condensation = Condensation(graph.nodes, _successors)
            name_of = {id(node): name for name, node in named.items()}
            joined = condensation.accumulate(
                lambda number: frozenset(name_of[id(node)] for node in condensation.components[number]),
                frozenset.union,
                downstream=False,
            )
            for name, node in named.items():
                number = condensation.number_of(node)
                assert number is not None
                expected = {name} | {name_of[n] for n in _closure(node, _predecessors)}
                with self.subTest(shape=shape, node=name):
                    self.assertEqual(joined[number], expected)

    def test_a_test_holds_on_one_side_exactly_when_a_node_there_passes_it(self):
        for shape, edges in _SHAPES.items():
            graph, named = _graph(edges)
            condensation = Condensation(graph.nodes, _successors)
            for marked_name, marked in named.items():
                def test(number: int) -> bool:
                    return any(node is marked for node in condensation.components[number])
                for downstream, step in ((True, _successors), (False, _predecessors)):
                    memo: dict[int, bool] = {}
                    for name, node in named.items():
                        number = condensation.number_of(node)
                        assert number is not None
                        expected = node is marked or id(marked) in _closure(node, step)
                        with self.subTest(shape=shape, marked=marked_name, node=name, downstream=downstream):
                            self.assertEqual(
                                condensation.holds(number, test, memo, downstream=downstream), expected)

    def test_a_test_is_asked_of_each_component_at_most_once_per_memo(self):
        graph, _ = _graph(_SHAPES['two entries into one ring'])
        condensation = Condensation(graph.nodes, _successors)
        asked: list[int] = []

        def test(number: int) -> bool:
            asked.append(number)
            return False

        memo: dict[int, bool] = {}
        for node in graph.nodes:
            number = condensation.number_of(node)
            assert number is not None
            condensation.holds(number, test, memo, downstream=True)
        self.assertEqual(sorted(asked), sorted(set(asked)))

    def test_every_edge_between_two_components_runs_to_a_lower_number(self):
        for shape, edges in _SHAPES.items():
            graph, _ = _graph(edges)
            condensation = Condensation(graph.nodes, _successors)
            for node in graph.nodes:
                for successor in node.successors:
                    number = condensation.number_of(node)
                    reached = condensation.number_of(successor)
                    assert number is not None and reached is not None
                    if number != reached:
                        with self.subTest(shape=shape):
                            self.assertGreater(number, reached)

    def test_a_test_is_found_within_a_limit_exactly_when_a_node_there_passes_it_and_is_on_one_side(self):
        for shape, edges in _SHAPES.items():
            graph, named = _graph(edges)
            condensation = Condensation(graph.nodes, _successors)
            count = len(condensation.components)
            for (marked_name, marked), limit in itertools.product(named.items(), range(count)):
                mark = condensation.number_of(marked)
                assert mark is not None

                def test(number: int) -> bool:
                    return number == mark
                for (downstream, step), order in itertools.product(
                    ((True, _successors), (False, _predecessors)),
                    (list, reversed),
                ):
                    inside = mark >= limit if downstream else mark <= limit
                    memo: dict[int, bool] = {}
                    for name, node in order(list(named.items())):
                        number = condensation.number_of(node)
                        assert number is not None
                        if not (number >= limit if downstream else number <= limit):
                            continue
                        expected = inside and (node is marked or id(marked) in _closure(node, step))
                        with self.subTest(
                            shape=shape, marked=marked_name, node=name, downstream=downstream, limit=limit
                        ):
                            self.assertEqual(
                                condensation.found_within(number, test, memo, downstream=downstream, limit=limit),
                                expected,
                            )

    def test_a_node_the_condensation_was_not_built_over_has_no_component(self):
        _, named = _graph({'a': ['b'], 'b': [], 'c': ['a']})
        condensation = Condensation([named['a']], _successors)
        self.assertIsNone(condensation.number_of(named['c']))
        self.assertIsNotNone(condensation.number_of(named['b']))
