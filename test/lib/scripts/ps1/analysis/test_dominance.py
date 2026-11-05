from __future__ import annotations

from test import TestBase, lines_executed
from test.lib.scripts.ps1.corpus import executable

from refinery.lib.scripts.analysis import dominance
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, Projection
from refinery.lib.scripts.ps1.analysis.cfg import build_ps1_control_flow
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _immediate_dominators_from_sets(graph: ControlFlowGraph, projection: Projection) -> dict[int, int]:
    order: list[CfgNode] = [graph.entry]
    reachable = {id(graph.entry)}
    for node in order:
        for successor in projection.successors(node):
            if id(successor) not in reachable:
                reachable.add(id(successor))
                order.append(successor)
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
                    idom, _ = dominance._immediate_dominators(graph, projection)
                    with self.subTest(source=source, graph=index, projection=projection.name):
                        self.assertEqual(idom, _immediate_dominators_from_sets(graph, projection))


class TestPs1DominanceCostsABoundedClimbPerStatement(TestBase):

    @staticmethod
    def _work(head: str, statement: str, tail: str = ''):
        def work(length: int) -> int:
            body = '\n'.join(statement.format(index=index) for index in range(length))
            graphs = build_ps1_control_flow(Ps1Parser(F'{head}\n{body}\n{tail}').parse())
            return lines_executed(
                lambda: [dominance._immediate_dominators(graph, Projection.MAY) for graph in graphs.values()],
                dominance,
            )
        return work

    def test_the_work_for_a_catch_clause_grows_linearly_with_the_guarded_body(self):
        self.assertWorkGrowsLinearly(self._work('try {', "'s{index}'", '} catch { }'), 100)

    def test_the_work_for_a_resuming_trap_grows_linearly_with_the_guarded_body(self):
        self.assertWorkGrowsLinearly(self._work('trap { continue }', "'s{index}'"), 100)

    def test_the_work_for_a_resuming_trap_over_branches_grows_linearly_with_the_guarded_body(self):
        self.assertWorkGrowsLinearly(self._work('trap { continue }', "if ($x) {{ 's{index}' }}"), 100)
