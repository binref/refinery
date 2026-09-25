from __future__ import annotations

from typing import Iterable, Sequence

from test import TestBase
from test.lib.scripts.analysis import graph_from_edges

from refinery.lib.scripts.analysis.cfg import ControlFlowModel, Projection
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery

STRAIGHT = {'a': ['b'], 'b': ['c'], 'c': []}
BRANCH = {'a': ['t', 'f'], 't': ['j'], 'f': ['j'], 'j': []}
LOOP = {'a': ['h'], 'h': ['b', 'x'], 'b': ['h'], 'x': []}
FORK = {'a': ['b', 'd'], 'b': ['c'], 'c': [], 'd': []}


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
        query = ReachabilityQuery(
            DominatorModel(ControlFlowModel({id(graph.owner): graph})), Projection.MAY)
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
        query = ReachabilityQuery(
            DominatorModel(ControlFlowModel({id(graph.owner): graph})), Projection.MAY)
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
