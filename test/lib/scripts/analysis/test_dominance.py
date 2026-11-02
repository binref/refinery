from __future__ import annotations

import itertools
import tracemalloc

from typing import Iterator

from test import TestBase
from test.lib.scripts.analysis import dominators_of
from test.lib.scripts.analysis import graph_from_edges as _graph

from refinery.lib.scripts.analysis.cfg import CfgNode, Projection
from refinery.lib.scripts.analysis.dominance import DominanceTree

SHAPES = {
    'straight': {'a': ['b'], 'b': ['c'], 'c': []},
    'branch': {'a': ['t', 'f'], 't': ['j'], 'f': ['j'], 'j': []},
    'branch_with_one_arm': {'a': ['t', 'j'], 't': ['j'], 'j': []},
    'loop': {'a': ['h'], 'h': ['b', 'x'], 'b': ['h'], 'x': []},
    'nested_loops': {
        'a': ['h'],
        'h': ['i', 'x'],
        'i': ['b', 'h'],
        'b': ['i'],
        'x': [],
    },
    'branch_inside_a_loop': {
        'a': ['h'],
        'h': ['t', 'f', 'x'],
        't': ['j'],
        'f': ['j'],
        'j': ['h'],
        'x': [],
    },
    'irreducible': {'a': ['b', 'c'], 'b': ['c'], 'c': ['b']},
    'loop_entered_at_two_points': {'a': ['c', 'd'], 'b': ['d'], 'c': ['b'], 'd': ['b']},
    'self_loop': {'a': ['a', 'b'], 'b': []},
    'duplicate_edge': {'a': ['b', 'b'], 'b': ['c'], 'c': []},
    'dead_tail': {'a': ['b'], 'b': ['j'], 'dead': ['j'], 'j': ['z'], 'z': []},
    'unreachable_cycle': {'a': ['b'], 'b': [], 'u': ['v'], 'v': ['u']},
    'unreachable_root': {'a': ['b'], 'b': [], 'other': ['b']},
    'cycle_reaching_the_reachable_part': {
        'a': ['b'],
        'b': ['c'],
        'c': [],
        'u': ['v', 'c'],
        'v': ['u'],
    },
}


def _paths_to(start: CfgNode, target: CfgNode) -> Iterator[list[int]]:
    """
    Every simple path from *start* to *target*, as lists of node ids, stopping at the first arrival.

    A longer path that passes through *target* and returns to it visits everything its prefix does,
    so it can remove nothing from an intersection the prefix survives, and the prefix is itself a
    path. Enumerating only the prefixes therefore gives the same intersection over far fewer paths.
    """
    stack = [(start, [id(start)], {id(start)})]
    while stack:
        node, path, seen = stack.pop()
        if node is target:
            yield path
            continue
        for successor in node.successors:
            if id(successor) in seen:
                continue
            stack.append((successor, [*path, id(successor)], seen | {id(successor)}))


def _dominators_by_enumeration(edges: dict[str, list[str]]) -> dict[str, set[str]]:
    """
    For every node the entry can reach, the names lying on *every* path from the entry to it — the
    definition of dominance, applied by enumerating the paths rather than by solving for them.
    """
    graph, named = _graph(edges)
    by_id = {id(node): name for name, node in named.items()}
    found: dict[str, set[str]] = {}
    for name, node in named.items():
        paths = [{by_id[key] for key in path} for path in _paths_to(graph.entry, node)]
        if not paths:
            continue
        found[name] = set.intersection(*paths)
    return found


class TestDominanceTree(TestBase):

    def _relation(self, edges: dict[str, list[str]]) -> dict[str, set[str]]:
        """
        For every node, the names the tree reports as dominating it, asked one pair at a time.
        """
        graph, named = _graph(edges)
        tree = DominanceTree(graph, Projection.MAY)
        return {
            below: {above for above, node in named.items() if tree.dominates(node, target)}
            for below, target in named.items()
        }

    def test_the_relation_is_the_one_the_paths_spell_out(self):
        """
        The interval query against the definition of dominance itself, over every reachable node of
        every shape. Nodes the entry cannot reach are left to the tests that pin that convention.
        """
        for name, edges in SHAPES.items():
            with self.subTest(name):
                expected = _dominators_by_enumeration(edges)
                relation = self._relation(edges)
                self.assertEqual({key: relation[key] for key in expected}, expected)

    def test_the_dominators_of_a_node_form_a_chain(self):
        """
        The property `refinery.lib.scripts.analysis.reaching` rests on when it picks the nearest of
        several dominating definitions: of any two dominators of one node, one dominates the other.
        """
        for name, edges in SHAPES.items():
            with self.subTest(name):
                graph, named = _graph(edges)
                tree = DominanceTree(graph, Projection.MAY)
                relation = self._relation(edges)
                for below, above in relation.items():
                    for first in above:
                        for second in above:
                            self.assertTrue(
                                tree.dominates(named[first], named[second])
                                or tree.dominates(named[second], named[first]),
                                F'{first} and {second} both dominate {below} in {name}',
                            )

    def test_a_reachable_node_dominates_itself(self):
        graph, named = _graph(SHAPES['branch'])
        tree = DominanceTree(graph, Projection.MAY)
        for name, node in named.items():
            self.assertTrue(tree.dominates(node, node), name)

    def test_an_unreachable_node_dominates_nothing_including_itself(self):
        """
        Dominance quantifies over the paths from the entry and an unreachable node lies on none of
        them, so it cannot be used to order anything — least of all against itself, which would make
        a definition there reach a use there.
        """
        graph, named = _graph(SHAPES['unreachable_cycle'])
        tree = DominanceTree(graph, Projection.MAY)
        self.assertFalse(tree.dominates(named['u'], named['u']))
        self.assertFalse(tree.dominates(named['u'], named['v']))
        self.assertFalse(tree.dominates(named['a'], named['u']))
        self.assertFalse(tree.dominates(named['u'], named['b']))

    def test_an_unreachable_predecessor_does_not_cost_a_join_its_dominators(self):
        """
        The tail after a `return` is unreachable but still flows into the statement that follows the
        branch. Reading its answer at that join loses every dominator the join really has, and with
        it every ordering downstream.
        """
        relation = self._relation(SHAPES['dead_tail'])
        self.assertEqual(relation['j'], {'a', 'b', 'j'})
        self.assertEqual(relation['z'], {'a', 'b', 'j', 'z'})

    def test_an_unreachable_cycle_is_dominated_by_nothing_rather_than_by_everything(self):
        relation = self._relation(SHAPES['unreachable_cycle'])
        self.assertEqual(relation['u'], set())
        self.assertEqual(relation['v'], set())

    def test_a_node_an_unreachable_cycle_reaches_keeps_its_dominators(self):
        relation = self._relation(SHAPES['cycle_reaching_the_reachable_part'])
        self.assertEqual(relation['c'], {'a', 'b', 'c'})

    def test_neither_entry_of_an_irreducible_cycle_dominates_the_other(self):
        """
        `c` is reached both from `a` directly and through `b`, and `b` from `a` directly and through
        `c`. A single pass in reverse postorder settles one of the two on a value it must later give
        up, so the shape is what distinguishes a fixpoint from one round of it.
        """
        relation = self._relation(SHAPES['irreducible'])
        self.assertEqual(relation['b'], {'a', 'b'})
        self.assertEqual(relation['c'], {'a', 'c'})

    def test_a_loop_entered_at_two_points_is_not_settled_by_one_round(self):
        """
        `b` and `d` are a cycle entered at `d` from `a` and at `b` from `c`. Placing `b` from only
        the predecessors already placed makes `c` its dominator, which the path `a -> d -> b`
        refutes — and a dominator reported that is not there is the direction no caller can defend
        against.
        """
        relation = self._relation(SHAPES['loop_entered_at_two_points'])
        self.assertEqual(relation['b'], {'a', 'b'})
        self.assertEqual(relation['c'], {'a', 'c'})
        self.assertEqual(relation['d'], {'a', 'd'})

    def test_the_entry_is_its_own_immediate_dominator(self):
        graph, named = _graph(SHAPES['branch'])
        tree = DominanceTree(graph, Projection.MAY)
        self.assertEqual(tree.idom[id(graph.entry)], id(named['a']))
        self.assertEqual(tree.idom[id(named['j'])], id(named['a']))

    def test_a_self_edge_does_not_make_a_node_its_own_dominator_twice_over(self):
        relation = self._relation(SHAPES['self_loop'])
        self.assertEqual(relation['a'], {'a'})
        self.assertEqual(relation['b'], {'a', 'b'})

    def test_an_edge_written_twice_is_the_same_relation_as_one_written_once(self):
        self.assertEqual(
            self._relation({'a': ['b', 'b'], 'b': ['c'], 'c': []}),
            self._relation({'a': ['b'], 'b': ['c'], 'c': []}),
        )

    def test_a_chain_longer_than_the_interpreter_recursion_limit_is_handled(self):
        """
        The dominance tree of a straight-line body is a chain as long as the body, and a script of
        twenty thousand statements is an ordinary size for generated code.
        """
        length = 20000
        names = [F'n{index}' for index in range(length)]
        edges = {name: [names[index + 1]] for index, name in enumerate(names[:-1])}
        edges[names[-1]] = []
        graph, named = _graph(edges)
        tree = DominanceTree(graph, Projection.MAY)
        self.assertTrue(tree.dominates(named[names[0]], named[names[-1]]))
        self.assertFalse(tree.dominates(named[names[-1]], named[names[0]]))

    def test_building_the_relation_does_not_cost_a_set_per_node(self):
        """
        A dominator set per node is quadratic in the body — four thousand statements is eight million
        set entries — where the tree is a fixed handful of integers per node. The budget is far above
        what the tree needs and far below what the sets would take.
        """
        length = 4000
        names = [F'n{index}' for index in range(length)]
        edges = {name: [names[index + 1]] for index, name in enumerate(names[:-1])}
        edges[names[-1]] = []
        graph, named = _graph(edges)
        tracemalloc.start()
        try:
            tree = DominanceTree(graph, Projection.MAY)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertTrue(tree.dominates(named[names[0]], named[names[-1]]))
        self.assertLess(peak, 8 << 20)


class TestDominatorModel(TestBase):

    def test_the_model_answers_every_pair_as_the_tree_does(self):
        for name, edges in SHAPES.items():
            graph, named = _graph(edges)
            model = dominators_of(graph)
            tree = DominanceTree(graph, Projection.MAY)
            for a, b in itertools.product(named.values(), repeat=2):
                with self.subTest(name):
                    self.assertEqual(model.dominates_node(graph, a, b, Projection.MAY), tree.dominates(a, b))
