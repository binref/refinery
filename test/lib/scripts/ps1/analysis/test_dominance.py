from __future__ import annotations

import sys

from test import TestBase
from test.lib.scripts.ps1.corpus import executable

from refinery.lib.scripts.analysis import dominance
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, Projection
from refinery.lib.scripts.ps1.analysis.cfg import build_ps1_control_flow
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _immediate_dominators_from_sets(
    graph: ControlFlowGraph, order: list[CfgNode], projection: Projection
) -> dict[int, int]:
    """
    The immediate dominator of every node in *order*, keyed by node identity, computed the textbook
    way: a node is dominated by itself and by whatever dominates all of its reachable predecessors,
    iterated to a fixpoint, and its immediate dominator is the one of its strict dominators that has
    the most dominators of its own.

    Held apart from the module under test as a second opinion: the set formulation says nothing about
    the order predecessors are folded in, so it cannot share an ordering bug with the module.
    """
    reachable = {id(node) for node in order}
    everything = frozenset(reachable)
    sets = {id(node): everything for node in order}
    sets[id(graph.entry)] = frozenset({id(graph.entry)})
    changed = True
    while changed:
        changed = False
        for node in order:
            if node is graph.entry:
                continue
            found = frozenset({id(node)}).union(frozenset.intersection(*[
                sets[known]
                for known in map(id, projection.predecessors(node))
                if known in reachable
            ]))
            if found != sets[id(node)]:
                sets[id(node)] = found
                changed = True
    idom = {id(graph.entry): id(graph.entry)}
    for node in order:
        if node is graph.entry:
            continue
        strict = sets[id(node)] - {id(node)}
        idom[id(node)] = max(strict, key=lambda known: len(sets[known]))
    return idom


class TestPs1ImmediateDominators(TestBase):

    def test_the_tree_agrees_with_the_set_formulation_of_dominance(self):
        for source in executable():
            tree = Ps1Parser(source).parse()
            for index, graph in enumerate(build_ps1_control_flow(tree).values()):
                for projection in Projection:
                    order = dominance._reverse_postorder(graph, projection)
                    with self.subTest(source=source, graph=index, projection=projection.name):
                        self.assertEqual(
                            dominance._immediate_dominators(graph, order, projection),
                            _immediate_dominators_from_sets(graph, order, projection),
                        )


class TestPs1DominanceCostsABoundedClimbPerStatement(TestBase):
    """
    A `catch` clause is reached from every statement of the body it guards, so its immediate
    dominator is folded from that many predecessors. Folded in the wrong order, each fold walks the
    whole chain of statements above it and the pass is quadratic in the length of the body.
    """

    _SHORT = 200
    _LONG = 400

    #: Doubling the body doubles the work of a linear pass and quadruples that of a quadratic one, so
    #: the bound separates the two cost classes without naming a constant that a faster or slower
    #: machine, or a line added to the module, would move.
    _BUDGET = 3

    @staticmethod
    def _body(length: int) -> str:
        return ' '.join(F"'s{index}';" for index in range(length))

    def _lines_traced(self, source: str) -> int:
        """
        How many lines of the dominance module run while the immediate dominators of every graph
        *source* builds are computed.
        """
        graphs = build_ps1_control_flow(Ps1Parser(source).parse())
        counted = 0

        def within(frame, event, argument):
            nonlocal counted
            if event == 'line':
                counted += 1
            return within

        def entering(frame, event, argument):
            return within if frame.f_code.co_filename == dominance.__file__ else None

        previous = sys.gettrace()
        sys.settrace(entering)
        try:
            for graph in graphs.values():
                dominance._immediate_dominators(
                    graph,
                    dominance._reverse_postorder(graph, Projection.MAY),
                    Projection.MAY,
                )
        finally:
            sys.settrace(previous)
        return counted

    def _growth(self, shape: str) -> float:
        short = self._lines_traced(shape.format(body=self._body(self._SHORT)))
        return self._lines_traced(shape.format(body=self._body(self._LONG))) / short

    def test_doubling_a_guarded_body_does_not_quadruple_the_work_of_a_catch_clause(self):
        self.assertLess(self._growth('try {{ {body} }} catch {{ }}'), self._BUDGET)

    def test_doubling_a_guarded_body_does_not_quadruple_the_work_of_a_resuming_trap(self):
        self.assertLess(self._growth('trap {{ continue }}; {body}'), self._BUDGET)
