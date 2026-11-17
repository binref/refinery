from __future__ import annotations

import itertools
import tracemalloc

from typing import Callable, Iterable, Sequence
from unittest.mock import patch

from test import TestBase
from test.lib.scripts.analysis import dominators_of, graph_from_edges
from test.lib.scripts.analysis.test_dominance import SHAPES as DOMINANCE_SHAPES

from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    Projection,
    flood,
)
from refinery.lib.scripts.analysis.components import Condensation
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery

STRAIGHT = {'a': ['b'], 'b': ['c'], 'c': []}
BRANCH = {'a': ['t', 'f'], 't': ['j'], 'f': ['j'], 'j': []}
LOOP = {'a': ['h'], 'h': ['b', 'x'], 'b': ['h'], 'x': []}
FORK = {'a': ['b', 'd'], 'b': ['c'], 'c': [], 'd': []}
NESTED_LOOPS = {'a': ['h'], 'h': ['i', 'x'], 'i': ['b', 'h'], 'b': ['i'], 'x': []}
BACK_TO_ENTRY = {'a': ['b'], 'b': ['a', 'c'], 'c': []}
ISLANDS = {'a': ['b'], 'b': [], 'orphan': ['b'], 'island': ['isle'], 'isle': ['island']}


class TestAnyBetween(TestBase):

    @staticmethod
    def _query(graph: ControlFlowGraph) -> ReachabilityQuery:
        return ReachabilityQuery(dominators_of(graph), Projection.MAY)

    def _between(self, edges: dict[str, list[str]], source: str, target: str, *names: str) -> bool:
        graph, named = graph_from_edges(edges)
        candidates = {id(named[name]) for name in names}
        return self._query(graph).any_between(graph, named[source], named[target], candidates)

    def test_a_node_lies_between_exactly_when_both_floods_from_the_ends_return_it(self):
        shapes = (STRAIGHT, BRANCH, LOOP, FORK, NESTED_LOOPS, BACK_TO_ENTRY, ISLANDS, *DOMINANCE_SHAPES.values())
        for edges, listed_backwards in itertools.product(shapes, (False, True)):
            graph, named = graph_from_edges(edges)
            if listed_backwards:
                graph.nodes.reverse()
            dominators = dominators_of(graph)
            asked_before = ReachabilityQuery(dominators, Projection.MAY)
            ids = [id(node) for node in named.values()]
            sets = [{key} for key in ids] + [set(pair) for pair in itertools.combinations(ids, 2)]
            for source, target in itertools.product(named.values(), repeat=2):
                forward = flood([source], forward=True, projection=Projection.MAY)
                backward = flood([target], forward=False, projection=Projection.MAY)
                for candidates in sets:
                    expected = bool(candidates & forward & backward)
                    asked_first = ReachabilityQuery(dominators, Projection.MAY)
                    with self.subTest(edges=edges, backwards=listed_backwards, candidates=len(candidates)):
                        self.assertEqual(asked_first.any_between(graph, source, target, candidates), expected)
                        self.assertEqual(asked_before.any_between(graph, source, target, candidates), expected)

    @staticmethod
    def _chain(names: list[str]) -> tuple[ControlFlowGraph, dict[str, CfgNode]]:
        edges = {name: [names[index + 1]] for index, name in enumerate(names[:-1])}
        edges[names[-1]] = []
        return graph_from_edges(edges)

    @staticmethod
    def _walks():
        return patch.object(Condensation, 'found_within', autospec=True, side_effect=Condensation.found_within)

    @staticmethod
    def _tests(tested: list[int]):
        walk = Condensation.found_within

        def counted(
            condensation: Condensation,
            number: int,
            test: Callable[[int], bool],
            memo: dict[int, bool],
            **bounds,
        ):
            def counting(component: int) -> bool:
                tested.append(component)
                return test(component)
            return walk(condensation, number, counting, memo, **bounds)

        return patch.object(Condensation, 'found_within', counted)

    def test_many_candidate_sets_between_the_same_two_ends_walk_the_stretch_once(self):
        names = [F'n{index}' for index in range(1200)]
        graph, named = self._chain(names)
        query = self._query(graph)
        source, target = named['n0'], named['n1000']
        with self._walks() as walks:
            for name in names[1001:]:
                self.assertFalse(query.any_between(graph, source, target, {id(named[name])}))
        self.assertEqual(walks.call_count, 1)

    def test_one_source_asked_toward_many_targets_tests_fewer_components_than_two_floods(self):
        names = [F'n{index}' for index in range(2001)]
        graph, named = self._chain(names)
        query = self._query(graph)
        source = named['n1000']
        tested: list[int] = []
        with self._tests(tested):
            for index in range(1000):
                above, below = named[names[index]], named[names[1001 + index]]
                self.assertFalse(query.any_between(graph, source, below, {id(above)}))
        self.assertLess(len(tested), 2 * len(graph.nodes))

    def test_a_question_asked_again_is_answered_without_a_walk_or_a_flood(self):
        names = [F'{kind}{index}' for index in range(500) for kind in ('first', 'second', 'read', 'third')]
        graph, named = self._chain(names)
        query = self._query(graph)
        questions = []
        for index in range(500):
            earlier, later = named[F'first{index}'], named[F'third{index}']
            questions.append((named[F'second{index}'], named[F'read{index}'], {id(earlier), id(later)}))
        for source, target, candidates in questions:
            self.assertFalse(query.any_between(graph, source, target, candidates))
        floods = patch.object(DominatorModel, 'reachable', autospec=True, side_effect=DominatorModel.reachable)
        with self._walks() as walked, floods as flooded:
            for source, target, candidates in questions:
                self.assertFalse(query.any_between(graph, source, target, candidates))
        self.assertEqual((walked.call_count, flooded.call_count), (0, 0))

    def test_equal_candidate_sets_asked_from_many_sources_are_held_once(self):
        names = [F'k{index}' for index in range(2000)]
        for index in range(200):
            names.extend((F'd{index}', F'x{index}', F'r{index}'))
        graph, named = self._chain(names)
        query = self._query(graph)
        kills = [id(node) for name, node in named.items() if name[0] in 'kx']
        self.assertTrue(query.any_between(graph, named['d0'], named['r0'], set(kills)))
        tracemalloc.start()
        try:
            before, _ = tracemalloc.get_traced_memory()
            for index in range(1, 200):
                self.assertTrue(query.any_between(graph, named[F'd{index}'], named[F'r{index}'], set(kills)))
            after, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(after - before, 1 << 21)

    def test_a_node_written_before_the_source_does_not_lie_between_it_and_a_later_node(self):
        self.assertFalse(self._between(STRAIGHT, 'b', 'c', 'a'))

    def test_a_node_on_a_loop_through_the_source_lies_between_it_and_the_loop_exit(self):
        self.assertTrue(self._between(LOOP, 'h', 'x', 'b'))

    def test_a_node_on_an_inner_loop_lies_between_the_outer_head_and_the_exit(self):
        self.assertTrue(self._between(NESTED_LOOPS, 'h', 'x', 'b'))

    def test_a_node_only_the_source_reaches_does_not_lie_between_it_and_another(self):
        self.assertFalse(self._between(FORK, 'a', 'c', 'd'))

    def test_a_node_no_run_reaches_does_not_lie_between_two_that_one_does(self):
        self.assertFalse(self._between(ISLANDS, 'a', 'b', 'orphan'))

    def test_a_node_no_run_reaches_lies_nowhere_even_when_the_graph_lists_it_first(self):
        graph, named = graph_from_edges(ISLANDS)
        graph.nodes.sort(key=lambda node: node is not named['orphan'])
        orphan = {id(named['orphan'])}
        self.assertFalse(self._query(graph).any_between(graph, named['a'], named['b'], orphan))

    def test_an_id_the_graph_does_not_hold_lies_nowhere(self):
        graph, named = graph_from_edges(STRAIGHT)
        stranger = {id(object())}
        self.assertFalse(self._query(graph).any_between(graph, named['a'], named['c'], stranger))

    def test_a_node_left_out_of_the_candidates_is_never_between(self):
        shapes = (STRAIGHT, BRANCH, LOOP, FORK, NESTED_LOOPS, BACK_TO_ENTRY, ISLANDS, *DOMINANCE_SHAPES.values())
        for edges in shapes:
            graph, named = graph_from_edges(edges)
            dominators = dominators_of(graph)
            asked_before = ReachabilityQuery(dominators, Projection.MAY)
            ids = [id(node) for node in named.values()]
            sets = [set(pair) for pair in itertools.combinations(ids, 2)] + [set(ids)]
            for source, target, left_out in itertools.product(named.values(), repeat=3):
                for candidates in sets:
                    expected = ReachabilityQuery(dominators, Projection.MAY).any_between(
                        graph, source, target, candidates - {id(left_out)})
                    with self.subTest(edges=edges, candidates=len(candidates)):
                        self.assertEqual(
                            asked_before.any_between(graph, source, target, candidates, excluding=left_out),
                            expected,
                        )

    def test_one_candidate_set_asked_from_each_of_its_members_walks_less_than_twice_as_far_when_doubled(self):
        tested: dict[int, int] = {}
        for count in (1600, 3200):
            names = [F'{kind}{index}' for index in range(count) for kind in ('store', 'read')]
            graph, named = self._chain(names)
            query = self._query(graph)
            stores = {id(named[F'store{index}']) for index in range(count)}
            walked: list[int] = []
            with self._tests(walked):
                for index in range(count):
                    source, target = named[F'store{index}'], named[F'read{index}']
                    self.assertFalse(query.any_between(graph, source, target, stores, excluding=source))
            tested[count] = len(walked)
        self.assertLess(tested[3200], 2 * tested[1600] + 2)

    def test_one_candidate_set_asked_from_each_of_its_members_keeps_a_memo_linear_in_the_questions(self):
        kept: dict[int, int] = {}
        for count in (1600, 3200):
            names = [F'{kind}{index}' for index in range(count) for kind in ('store', 'read')]
            graph, named = self._chain(names)
            query = self._query(graph)
            stores = frozenset(id(named[F'store{index}']) for index in range(count))
            self.assertFalse(query.any_between(graph, named['store0'], named['read0'], stores, excluding=named['store0']))
            tracemalloc.start()
            try:
                before, _ = tracemalloc.get_traced_memory()
                for index in range(1, count):
                    source = named[F'store{index}']
                    self.assertFalse(query.any_between(graph, source, named[F'read{index}'], stores, excluding=source))
                after, _ = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            kept[count] = after - before
        self.assertLess(kept[3200], 3 * kept[1600])


class TestReachingDefinition(TestBase):

    def _observed(
        self,
        edges: dict[str, list[str]],
        definitions: Sequence[tuple[str, str]],
        use: str,
        kills: Iterable[str] = (),
    ) -> str | None:
        """
        The label of the definition observed at *use*, where *definitions* pairs a label with the
        name of the node evaluating it.
        """
        graph, named = graph_from_edges(edges)
        query = ReachabilityQuery(dominators_of(graph), Projection.MAY)
        return query.reaching_definition(
            graph,
            named[use],
            [(label, named[name]) for label, name in definitions],
            [id(named[name]) for name in kills],
        )

    def test_the_only_dominating_definition_is_the_one_observed(self):
        self.assertEqual(self._observed(STRAIGHT, [('first', 'a')], 'c'), 'first')

    def test_no_definition_at_all_is_observed_as_nothing(self):
        self.assertIsNone(self._observed(STRAIGHT, [], 'c'))

    def test_the_nearer_of_two_dominating_definitions_is_the_one_observed(self):
        """
        The earlier definition is overwritten by the later one on every path, so only the later can
        be what the use sees.
        """
        self.assertEqual(self._observed(STRAIGHT, [('first', 'a'), ('second', 'b')], 'c'), 'second')

    def test_a_definition_in_one_arm_leaves_the_join_with_no_single_definition(self):
        """
        The arm may or may not have run, so neither it nor the definition before the branch is what
        the join observes.
        """
        self.assertEqual(self._observed(BRANCH, [('before', 'a')], 'j'), 'before')
        self.assertIsNone(self._observed(BRANCH, [('before', 'a'), ('in_arm', 't')], 'j'))

    def test_a_definition_the_back_edge_re_enters_leaves_no_single_definition(self):
        """
        The loop body's definition is written after the head and never dominates it, but the back
        edge carries it around to the head's second visit, so the head does not observe the
        definition that precedes the loop.
        """
        self.assertEqual(self._observed(LOOP, [('before', 'a')], 'h'), 'before')
        self.assertIsNone(self._observed(LOOP, [('before', 'a'), ('in_body', 'b')], 'h'))

    def test_a_definition_sharing_the_use_s_node_is_not_ordered_against_it(self):
        """
        One node cannot order what happens inside it, so a definition there neither reaches the use
        nor lets an earlier one through.
        """
        self.assertIsNone(self._observed(STRAIGHT, [('here', 'c')], 'c'))
        self.assertIsNone(self._observed(STRAIGHT, [('first', 'a'), ('here', 'c')], 'c'))

    def test_two_definitions_in_one_node_leave_no_single_definition(self):
        self.assertIsNone(self._observed(STRAIGHT, [('one', 'b'), ('two', 'b')], 'c'))

    def test_a_kill_between_the_two_stops_the_definition_reaching(self):
        self.assertEqual(self._observed(STRAIGHT, [('first', 'a')], 'c'), 'first')
        self.assertIsNone(self._observed(STRAIGHT, [('first', 'a')], 'c', kills=['b']))

    def test_a_kill_sharing_the_use_s_node_is_not_ordered_against_it(self):
        self.assertIsNone(self._observed(STRAIGHT, [('first', 'a')], 'c', kills=['c']))

    def test_a_kill_the_use_cannot_be_reached_from_does_not_stop_it(self):
        """
        `d` runs after the definition on some path but no path from it reaches `c`, so nothing it
        does can be observed there. Without this the query would reject on any kill anywhere
        downstream, which is most of the script.
        """
        self.assertEqual(self._observed(FORK, [('first', 'a')], 'c', kills=['d']), 'first')

    def test_a_definition_on_a_path_that_never_reaches_the_use_does_not_spoil_it(self):
        self.assertEqual(self._observed(FORK, [('first', 'a'), ('aside', 'd')], 'c'), 'first')

    def test_an_unreachable_definition_neither_reaches_nor_kills(self):
        """
        A node with no predecessors that is not the entry dominates only itself, and nothing it does
        lies between two nodes that are reachable.
        """
        edges = {'a': ['b'], 'b': ['c'], 'c': [], 'orphan': []}
        self.assertEqual(self._observed(edges, [('first', 'a'), ('lost', 'orphan')], 'c'), 'first')

    def test_a_use_no_path_reaches_observes_no_definition(self):
        """
        A use in an unreachable cycle is ordered against nothing, so no definition qualifies and the
        answer does not depend on the order the caller listed them in. Reporting such a use as
        dominated by both branch definitions instead — which a dominator set an unreachable region
        never narrows does — would make the selection return whichever came first.
        """
        edges = {
            'a': ['t', 'f'],
            't': ['j'],
            'f': ['j'],
            'j': [],
            'u': ['v'],
            'v': ['u'],
        }
        self.assertIsNone(self._observed(edges, [('taken', 't'), ('other', 'f')], 'u'))
        self.assertIsNone(self._observed(edges, [('other', 'f'), ('taken', 't')], 'u'))

    @staticmethod
    def _dominates(graph: ControlFlowGraph, a: CfgNode, b: CfgNode) -> bool:
        reached = flood([graph.entry], forward=True, projection=Projection.MAY)
        if id(a) not in reached or id(b) not in reached:
            return False
        if a is b:
            return True
        seen = {id(a)}
        stack = [graph.entry] if graph.entry is not a else []
        while stack:
            node = stack.pop()
            if node is b:
                return False
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(Projection.MAY.successors(node))
        return True

    def _scanned(
        self,
        graph: ControlFlowGraph,
        use: CfgNode,
        definitions: Sequence[tuple[str, CfgNode]],
        kills: Iterable[int],
    ) -> str | None:
        qualifying = [(label, node) for label, node in definitions if node is not use and self._dominates(graph, node, use)]
        if not qualifying or len({id(node) for _, node in qualifying}) != len(qualifying):
            return None
        nearest = [
            (label, node) for label, node in qualifying
            if all(self._dominates(graph, other, node) for _, other in qualifying)
        ]
        if len(nearest) != 1:
            return None
        label, node = nearest[0]
        blocking = {id(other) for _, other in definitions if other is not node} | set(kills)
        forward = flood([node], forward=True, projection=Projection.MAY)
        backward = flood([use], forward=False, projection=Projection.MAY)
        return None if blocking & forward & backward else label

    def test_the_selection_agrees_with_a_scan_of_the_definitions_on_every_shape(self):
        shapes = (STRAIGHT, BRANCH, LOOP, FORK, NESTED_LOOPS, BACK_TO_ENTRY, ISLANDS, *DOMINANCE_SHAPES.values())
        for edges in shapes:
            graph, named = graph_from_edges(edges)
            query = ReachabilityQuery(dominators_of(graph), Projection.MAY)
            nodes = list(named.items())
            for size in (1, 2, 3):
                for chosen in itertools.combinations(nodes, size):
                    definitions = [(name, node) for name, node in chosen]
                    for (kill_name, kill), (_, use) in itertools.product([(None, None), *nodes], nodes):
                        kills = [] if kill is None else [id(kill)]
                        with self.subTest(edges=edges, definitions=[name for name, _ in chosen], kill=kill_name):
                            self.assertEqual(
                                query.reaching_definition(graph, use, definitions, kills),
                                self._scanned(graph, use, definitions, kills),
                            )

    def test_a_chain_of_definitions_asked_from_each_use_costs_less_than_twice_as_much_when_doubled(self):
        cost: dict[int, int] = {}
        for count in (400, 800):
            names = [F'{kind}{index}' for index in range(count) for kind in ('store', 'read')]
            edges = {name: [names[index + 1]] for index, name in enumerate(names[:-1])}
            edges[names[-1]] = []
            graph, named = graph_from_edges(edges)
            query = ReachabilityQuery(dominators_of(graph), Projection.MAY)
            definitions = [(index, named[F'store{index}']) for index in range(count)]
            walked: list[int] = []
            ordered = patch.object(
                DominatorModel, 'dominates_node', autospec=True, side_effect=DominatorModel.dominates_node)
            with TestAnyBetween._tests(walked), ordered as asked:
                for index in range(count):
                    self.assertEqual(query.reaching_definition(graph, named[F'read{index}'], definitions), index)
            cost[count] = len(walked) + asked.call_count
        self.assertLess(cost[800], 2 * cost[400] + 2)


class TestReachingDefinitions(TestBase):

    def _observed(
        self,
        edges: dict[str, list[str]],
        definitions: Sequence[tuple[str, str]],
        use: str,
        kills: Iterable[str] = (),
    ) -> list[str] | None:
        """
        The labels of every definition that may be observed at *use*, in sorted order, where
        *definitions* pairs a label with the name of the node evaluating it.
        """
        graph, named = graph_from_edges(edges)
        query = ReachabilityQuery(dominators_of(graph), Projection.MAY)
        found = query.reaching_definitions(
            graph,
            named[use],
            [(label, named[name]) for label, name in definitions],
            [id(named[name]) for name in kills],
        )
        return None if found is None else sorted(found)

    def test_a_definition_on_the_first_node_reaches_every_later_use(self):
        self.assertEqual(self._observed(STRAIGHT, [('first', 'a')], 'c'), ['first'])

    def test_the_nearer_of_two_definitions_hides_the_earlier(self):
        self.assertEqual(
            self._observed(STRAIGHT, [('first', 'a'), ('second', 'b')], 'c'), ['second'])

    def test_both_arms_of_a_branch_reach_the_join(self):
        self.assertEqual(
            self._observed(BRANCH, [('taken', 't'), ('other', 'f')], 'j'), ['other', 'taken'])

    def test_a_definition_in_one_arm_reaches_the_join_beside_the_one_before_the_branch(self):
        self.assertEqual(
            self._observed(BRANCH, [('before', 'a'), ('in_arm', 't')], 'j'), ['before', 'in_arm'])

    def test_an_arm_without_a_definition_leaves_the_value_from_before_the_graph(self):
        self.assertIsNone(self._observed(BRANCH, [('in_arm', 't')], 'j'))

    def test_the_back_edge_carries_the_loop_body_s_definition_to_the_head(self):
        self.assertEqual(
            self._observed(LOOP, [('before', 'a'), ('in_body', 'b')], 'h'), ['before', 'in_body'])

    def test_no_definition_at_all_leaves_the_value_from_before_the_graph(self):
        self.assertIsNone(self._observed(STRAIGHT, [], 'c'))

    def test_a_use_at_the_first_node_observes_the_value_from_before_the_graph(self):
        self.assertIsNone(self._observed(STRAIGHT, [('later', 'b')], 'a'))

    def test_a_definition_sharing_the_use_s_node_is_not_ordered_against_it(self):
        self.assertIsNone(self._observed(STRAIGHT, [('first', 'a'), ('here', 'c')], 'c'))

    def test_a_kill_sharing_the_use_s_node_is_not_ordered_against_it(self):
        self.assertIsNone(self._observed(STRAIGHT, [('first', 'a')], 'c', kills=['c']))

    def test_a_kill_between_a_definition_and_the_use_leaves_no_answer(self):
        self.assertIsNone(self._observed(STRAIGHT, [('first', 'a')], 'c', kills=['b']))

    def test_a_kill_the_use_cannot_be_reached_from_does_not_stop_it(self):
        self.assertEqual(self._observed(FORK, [('first', 'a')], 'c', kills=['d']), ['first'])

    def test_a_kill_above_the_nearest_definition_does_not_stop_it(self):
        self.assertEqual(
            self._observed(STRAIGHT, [('second', 'b')], 'c', kills=['a']), ['second'])
