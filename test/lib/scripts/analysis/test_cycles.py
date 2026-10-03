from __future__ import annotations

from test import TestBase
from test.lib.scripts.analysis import graph_from_edges as _graph

from refinery.lib.scripts.analysis.cfg import CfgNode
from refinery.lib.scripts.analysis.cycles import nodes_on_a_cycle, strongly_connected_components


def _successors(node: CfgNode) -> list[CfgNode]:
    return node.successors


class TestCycles(TestBase):

    def _on_a_cycle(self, edges: dict[str, list[str]]) -> set[str]:
        graph, named = _graph(edges)
        found = nodes_on_a_cycle(graph)
        return {name for name, node in named.items() if id(node) in found}

    def _components(self, edges: dict[str, list[str]], *starts: str) -> list[list[str]]:
        """
        The components of the graph *edges* spells, as sorted lists of names in the order they are
        listed, over the nodes reachable from *starts*, or from every node when none is given.
        """
        graph, named = _graph(edges)
        name_of = {id(node): name for name, node in named.items()}
        nodes = [named[start] for start in starts] if starts else graph.nodes
        return [
            sorted(name_of[id(node)] for node in component)
            for component in strongly_connected_components(nodes, _successors)
        ]

    def test_an_isolated_node_is_not_on_a_cycle(self):
        self.assertEqual(self._on_a_cycle({'a': []}), set())

    def test_a_chain_puts_no_node_on_a_cycle(self):
        self.assertEqual(self._on_a_cycle({'a': ['b'], 'b': ['c'], 'c': []}), set())

    def test_a_node_that_reaches_itself_directly_is_on_a_cycle(self):
        """
        A self-edge is a cycle, and its component has one member like every acyclic node's does.
        """
        self.assertEqual(self._on_a_cycle({'a': ['a']}), {'a'})

    def test_every_node_of_a_ring_is_on_a_cycle(self):
        edges = {'a': ['b'], 'b': ['c'], 'c': ['a']}
        self.assertEqual(self._on_a_cycle(edges), {'a', 'b', 'c'})

    def test_a_node_on_the_path_between_two_cycles_is_not_on_either(self):
        """
        The case that separates cycle membership from merely having a predecessor and a successor.
        """
        edges = {
            'a': ['b'],
            'b': ['a', 'm'],
            'm': ['c'],
            'c': ['d'],
            'd': ['c'],
        }
        self.assertEqual(self._on_a_cycle(edges), {'a', 'b', 'c', 'd'})

    def test_a_node_that_only_reaches_a_cycle_is_not_on_it(self):
        edges = {'s': ['a'], 'a': ['b'], 'b': ['a']}
        self.assertEqual(self._on_a_cycle(edges), {'a', 'b'})

    def test_a_node_only_reachable_from_a_cycle_is_not_on_it(self):
        edges = {'a': ['b'], 'b': ['a', 't'], 't': []}
        self.assertEqual(self._on_a_cycle(edges), {'a', 'b'})

    def test_two_cycles_sharing_a_node_form_one_component(self):
        edges = {
            'h': ['a', 'x'],
            'a': ['h'],
            'x': ['h'],
        }
        self.assertEqual(self._components(edges), [['a', 'h', 'x']])

    def test_disjoint_cycles_are_separate_components(self):
        edges = {
            'a': ['b'],
            'b': ['a'],
            'c': ['d'],
            'd': ['c'],
        }
        self.assertEqual(sorted(self._components(edges)), [['a', 'b'], ['c', 'd']])

    def test_every_node_belongs_to_exactly_one_component(self):
        edges = {
            'a': ['b'],
            'b': ['c', 'd'],
            'c': ['a'],
            'd': ['d'],
            'e': [],
        }
        graph, named = _graph(edges)
        components = strongly_connected_components(graph.nodes, _successors)
        members = [node for component in components for node in component]
        self.assertEqual(len(members), len(named))
        self.assertEqual(len({id(node) for node in members}), len(named))

    def test_every_component_is_listed_after_each_component_it_reaches(self):
        """
        `s` reaches every other component, `a` and `b` reach `c` and `d`, and those reach `x`, so
        exactly one order lists every component after each one it reaches.
        """
        edges = {
            's': ['a', 'x'],
            'a': ['b'],
            'b': ['a', 'c'],
            'c': ['d'],
            'd': ['c', 'x'],
            'x': [],
        }
        self.assertEqual(self._components(edges), [['x'], ['c', 'd'], ['a', 'b'], ['s']])

    def test_the_components_are_those_of_the_nodes_the_starts_reach(self):
        edges = {
            'u': ['s'],
            's': ['a'],
            'a': ['s'],
            'z': [],
        }
        self.assertEqual(self._components(edges, 's'), [['a', 's']])

    def test_a_chain_longer_than_the_interpreter_recursion_limit_is_handled(self):
        """
        The graphs are as deep as the script is long, so the traversal may not recurse.
        """
        length = 20000
        names = [F'n{index}' for index in range(length)]
        edges = {name: [] for name in names}
        for source, target in zip(names, names[1:]):
            edges[source] = [target]
        edges[names[-1]] = [names[0]]
        self.assertEqual(len(self._on_a_cycle(edges)), length)
