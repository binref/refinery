from __future__ import annotations

import itertools

from inspect import cleandoc

from test import TestBase, wontfix

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.analysis.cfg import (
    CfgBuilder,
    CfgEdge,
    CfgNode,
    ControlFlowGraph,
    Projection,
    flood,
    flood_labels,
    plain_successors,
    reachable_forward_from_any,
    reachable_forward_labels,
    reachable_from_any,
    walk_reading,
)
from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.cfg import (
    Ps1ControlFlowModel,
    Ps1ReportNode,
    build_control_flow_model,
    build_ps1_control_flow,
)
from refinery.lib.scripts.ps1.analysis.handlers import Ps1TrapDisposition
from refinery.lib.scripts.ps1.analysis.model import build_semantic_model
from refinery.lib.scripts.ps1.ast import get_body
from refinery.lib.scripts.ps1.model import (
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1ContinueStatement,
    Ps1ExitStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser

_CORPUS = [
    "Write-Host 'a'",
    "if ($x) { 'a' }",
    "if ($x) { 'a' } else { 'b' }",
    "if ($x) { 'a' } elseif ($y) { 'b' } elseif ($z) { 'c' } else { 'd' }",
    "while ($x) { 'a' }",
    "while ($x) { break }",
    "while ($x) { continue }",
    "do { 'a' } while ($x)",
    "do { 'a' } until ($x)",
    "for ($i = 0; $i -lt 3; $i++) { 'a' }",
    "for (;;) { 'a' }",
    "foreach ($i in $x) { 'a' }",
    "switch ($x) { 1 { 'a' } 2 { 'b' } }",
    "switch ($x) { 1 { 'a' } default { 'b' } }",
    "switch ($x) { 1 { break } 2 { 'b' } }",
    "switch ($x) { 1 { trap { 'h' }\n'a' } }",
    "try { 'a' } catch { 'b' }",
    "try { 'a' } finally { 'c' }",
    "try { 'a' } catch { 'b' } finally { 'c' }",
    "switch ($x) { 1 { } 2 { } 3 { } }",
    "while ($x) { switch ($y) { 1 { continue } } }",
    "try { 'a' } catch [System.IO.IOException] { 'b' } catch { 'c' }",
    "try { try { 'a' } catch { 'i' } } catch { 'o' }",
    "try { trap { 'h' }\n'a' } catch { 'c' }",
    "try { 'a' } finally { trap { 'h' }\n'b' }",
    "trap { continue }\n'a'",
    "trap { continue }\n'a'\nthrow 'x'\n'b'",
    "trap { continue }\n'a'\nthrow 'x'\ntry { 'b' } catch { 'c' }",
    "if ($c) { trap { continue }\n'a'\nthrow 'x' }\n'b'",
    "trap { break }\n'a'",
    "trap { :t while ($true) { break t } }\n'a'",
    "while ($c) { trap { break }\n'a' }",
    "while ($c) { trap { continue }\n'a' }",
    "trap { 'h' }\ntrap [System.IO.IOException] { 'i' }\n'a'",
    "if ($c) { trap { 'h' }\n'a' }\n'b'",
    "trap { 'h' }\nif ($c) { 'a' }\n'b'",
    "trap { 'o' }\nif ($c) { trap { 'i' }\n'a' }",
    "function f { 'a' }\nf",
    "function f { return 1 }",
    "function f { dynamicparam { 'd' } begin { 'b' } process { 'p' } end { 'e' } }",
    "'a'\nexit\n'b'",
    "'a'\nthrow 'x'\n'b'",
    ":outer while ($x) { while ($y) { break outer } }",
    ":outer while ($x) { while ($y) { continue outer } }",
    "while ($x) { while ($y) { break } }\n'after'",
    "do { try { 'a' } catch { 'b' } } while ($x)",
    "for (;;) { 'a'\ncontinue }",
    "'a'",
    "1..3 | ForEach-Object { 'a' }",
    "1..3 | %{ 'a'\n'b' }",
    "& { while ($x) { 'a' } }",
    "$f = { 'a' }\n& $f",
    "1..3 | ForEach-Object { 1..3 | ForEach-Object { 'a' } }",
    "function f { 1..3 | ForEach-Object { 'a' } }",
    "1..3 | ForEach-Object { trap { 'h' }\n'a' }",
]


class _Ps1ControlFlowGraphs(TestBase):

    @staticmethod
    def _graphs(source: str) -> dict[int, ControlFlowGraph]:
        return build_ps1_control_flow(Ps1Parser(source).parse())

    def _edge_count(self, source: str) -> int:
        return sum(
            len(node.successors)
            for graph in self._graphs(source).values()
            for node in graph.nodes
        )

    def _script_graph(self, source: str) -> ControlFlowGraph:
        tree = Ps1Parser(source).parse()
        return build_ps1_control_flow(tree)[id(tree)]

    @staticmethod
    def _forward(start: CfgNode) -> set[int]:
        seen = {id(start)}
        stack = [start]
        while stack:
            for successor in stack.pop().successors:
                if id(successor) not in seen:
                    seen.add(id(successor))
                    stack.append(successor)
        return seen

    def _node_for(self, graph: ControlFlowGraph, kind: type) -> CfgNode:
        for node in graph.nodes:
            if isinstance(node.element, kind):
                return node
        self.fail(F'no control-flow node stands for a {kind.__name__}')

    def _tree_and_graph(self, source: str) -> tuple[Ps1Script, ControlFlowGraph]:
        tree = Ps1Parser(source).parse()
        return tree, build_ps1_control_flow(tree)[id(tree)]

    def _required_node(self, graph: ControlFlowGraph, element: Node) -> CfgNode:
        node = graph.node_of(element)
        if node is None:
            self.fail(F'no control-flow node stands for a {type(element).__name__}')
        return node

    def _handlers(self, graph: ControlFlowGraph, *elements: Node) -> set[CfgNode]:
        return {self._required_node(graph, element) for element in elements}

    def _guarded_statement(self, source: str) -> tuple[ControlFlowGraph, Statement]:
        tree, graph = self._tree_and_graph(source)
        construct = tree.body[0]
        if not isinstance(construct, Ps1TryCatchFinally):
            self.fail('the script does not open with a try construct')
        guarded = get_body(construct.try_block)
        if not guarded:
            self.fail('the try block holds no statement')
        return graph, guarded[0]

    def _reached_by_an_error_at(self, graph: ControlFlowGraph, element: Node) -> set[CfgNode]:
        reached: set[CfgNode] = set()
        stack = [self._required_node(graph, element)]
        while stack:
            source = stack.pop()
            for target in source.successors:
                if target in reached or not graph.is_exceptional(source, target):
                    continue
                reached.add(target)
                stack.append(target)
        return reached

    def _the_block_a_trap_is_written_in(self, tree: Ps1Script) -> list:
        for node in tree.walk_in_order():
            if isinstance(node, Ps1TrapStatement):
                block = get_body(node.parent)
                if block is not None:
                    return block
        self.fail('no trap of this script is written in a statement block')

    @staticmethod
    def _reached_without(start: CfgNode, barrier: CfgNode) -> set[int]:
        seen = {id(start), id(barrier)}
        stack = [start]
        while stack:
            for successor in stack.pop().successors:
                if id(successor) not in seen:
                    seen.add(id(successor))
                    stack.append(successor)
        seen.discard(id(barrier))
        return seen


class TestPs1ControlFlowGraph(_Ps1ControlFlowGraphs):

    def test_every_graph_is_internally_consistent(self):
        for source in _CORPUS:
            with self.subTest(source):
                for graph in self._graphs(source).values():
                    held = {id(node) for node in graph.nodes}
                    for node in graph.nodes:
                        for successor in node.successors:
                            self.assertIn(id(successor), held)
                            self.assertIn(node, successor.predecessors)
                        for predecessor in node.predecessors:
                            self.assertIn(id(predecessor), held)
                            self.assertIn(node, predecessor.successors)

    def test_entry_has_no_predecessors_and_exit_no_successors(self):
        for source in _CORPUS:
            with self.subTest(source):
                for graph in self._graphs(source).values():
                    self.assertEqual(graph.entry.predecessors, [])
                    self.assertEqual(graph.exit.successors, [])

    def test_every_statement_node_is_reachable_from_entry_unless_written_after_a_terminator(self):
        for source in _CORPUS:
            if 'exit' in source or 'throw' in source:
                continue
            with self.subTest(source):
                for graph in self._graphs(source).values():
                    reached = self._forward(graph.entry)
                    for node in graph.nodes:
                        if node.element is not None:
                            self.assertIn(id(node), reached)

    def test_a_function_definition_owns_its_own_graph(self):
        graphs = self._graphs("function f { 'a' }\nf")
        self.assertEqual(len(graphs), 2)

    def test_a_nested_function_body_is_not_descended_into(self):
        tree = Ps1Parser("function f { 'a' }\nf").parse()
        graphs = build_ps1_control_flow(tree)
        definition = next(n for n in tree.walk() if isinstance(n, Ps1FunctionDefinition))
        script = graphs[id(tree)]
        self.assertIsNotNone(script.node_of(definition))
        self.assertIsNot(graphs[id(definition.body)], script)

    def test_a_while_loop_has_a_back_edge(self):
        tree = Ps1Parser("while ($x) { 'a' }").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        head = graph.node_of(tree.body[0])
        self.assertIsNotNone(head)
        body = next(n for n in graph.nodes if n.element is not None and n is not head)
        self.assertIn(id(head), self._forward(body))

    def test_break_leaves_the_loop_and_does_not_return_to_its_head(self):
        tree, graph = self._tree_and_graph("while ($x) { break }\n'after'")
        jump = self._node_for(graph, Ps1BreakStatement)
        self.assertIn(graph.node_of(tree.body[1]), jump.successors)
        self.assertNotIn(graph.node_of(tree.body[0]), jump.successors)
        self.assertNotIn(graph.exit, jump.successors)

    def test_an_unlabelled_break_leaves_only_the_innermost_loop(self):
        tree, graph = self._tree_and_graph("while ($x) { while ($y) { break } }\n'after'")
        jump = self._node_for(graph, Ps1BreakStatement)
        inner = tree.body[0].body.body[0]
        self.assertNotIn(graph.node_of(tree.body[1]), jump.successors)
        self.assertIn(graph.node_of(tree.body[0]), jump.successors)
        self.assertNotIn(graph.node_of(inner), jump.successors)

    def test_continue_returns_to_the_loop_head(self):
        tree, graph = self._tree_and_graph("while ($x) { continue }")
        jump = self._node_for(graph, Ps1ContinueStatement)
        self.assertEqual(jump.successors, [graph.node_of(tree.body[0])])

    def test_a_labelled_break_leaves_the_named_loop(self):
        tree, graph = self._tree_and_graph(
            ":outer while ($x) { while ($y) { break outer } }\n'after'")
        jump = self._node_for(graph, Ps1BreakStatement)
        self.assertIn(graph.node_of(tree.body[1]), jump.successors)
        self.assertNotIn(graph.exit, jump.successors)

    def test_a_labelled_continue_returns_to_the_named_loop_head(self):
        tree, graph = self._tree_and_graph(":outer while ($x) { while ($y) { continue outer } }")
        jump = self._node_for(graph, Ps1ContinueStatement)
        self.assertEqual(jump.successors, [graph.node_of(tree.body[0])])

    def test_a_labelled_break_leaves_the_named_switch(self):
        tree, graph = self._tree_and_graph(":sw switch ($x) { 1 { break sw } }\n'after'")
        jump = self._node_for(graph, Ps1BreakStatement)
        self.assertIn(graph.node_of(tree.body[1]), jump.successors)
        self.assertNotIn(graph.exit, jump.successors)

    def test_a_counted_loop_evaluates_its_initializer_condition_and_iterator_at_their_own_points(
        self,
    ):
        tree, graph = self._tree_and_graph("for ($i = 0; $i -lt 3; $i++) { 'a' }")
        loop = tree.body[0]
        for part in (loop.initializer, loop.condition, loop.iterator):
            self.assertIsNotNone(graph.node_of(part))

    def test_a_counted_loop_without_test_or_update_still_has_a_back_edge_from_continue(self):
        tree, graph = self._tree_and_graph("for (;;) { 'a'\ncontinue }")
        jump = self._node_for(graph, Ps1ContinueStatement)
        body = tree.body[0].body.body[0]
        self.assertEqual(jump.successors, [graph.node_of(body)])

    def test_code_after_exit_is_unreachable(self):
        tree = Ps1Parser("'a'\nexit\n'b'").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        reached = self._forward(graph.entry)
        unreachable = [
            node for node in graph.nodes
            if node.element is not None and id(node) not in reached
        ]
        self.assertEqual(len(unreachable), 1)

    def test_code_after_throw_is_unreachable(self):
        tree = Ps1Parser("'a'\nthrow 'x'\n'b'").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        reached = self._forward(graph.entry)
        unreachable = [
            node for node in graph.nodes
            if node.element is not None and id(node) not in reached
        ]
        self.assertEqual(len(unreachable), 1)

    def test_a_guarded_statement_has_an_exceptional_edge_to_the_handler(self):
        graph, guarded = self._guarded_statement("try { 'a' } catch { 'b' }")
        handler = self._node_for(graph, Ps1CatchClause)
        self.assertTrue(graph.is_exceptional(self._required_node(graph, guarded), handler))

    def test_an_exceptional_edge_is_distinguished_from_normal_flow(self):
        graph, guarded = self._guarded_statement("try { 'a' } catch { 'b' }")
        line = self._required_node(graph, guarded)
        self.assertNotIn(self._node_for(graph, Ps1CatchClause), plain_successors(line))
        self.assertTrue(plain_successors(line))

    def test_a_trap_is_reachable_from_a_statement_written_above_it(self):
        tree, graph = self._tree_and_graph("'a'\ntrap { continue }\n'b'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertIn(graph.node_of(tree.body[0]), trap.predecessors)

    def test_a_trap_declared_inside_a_nested_block_guards_that_block(self):
        tree, graph = self._tree_and_graph("if ($c) { trap { 'h' }\n'a' }\n'b'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertIn(graph.node_of(tree.body[0].clauses[0][1].body[1]), trap.predecessors)
        self.assertIsNotNone(graph.node_of(trap.element.body.body[0]))

    def test_a_trap_declared_inside_a_nested_block_does_not_guard_the_body_around_it(self):
        tree, graph = self._tree_and_graph("if ($c) { trap { 'h' }\n'a' }\n'b'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertNotIn(trap, graph.node_of(tree.body[1]).successors)

    def test_a_trap_that_continues_resumes_in_the_body_it_guards(self):
        tree, graph = self._tree_and_graph("trap { 'h'; continue }\n'a'\n'b'")
        jump = self._node_for(graph, Ps1ContinueStatement)
        reached = self._forward(jump)
        self.assertIn(id(graph.node_of(tree.body[1])), reached)
        self.assertIn(id(graph.node_of(tree.body[2])), reached)

    def test_a_trap_does_not_guard_its_own_body(self):
        tree, graph = self._tree_and_graph("trap { return }\n'a'")
        trap = self._node_for(graph, Ps1TrapStatement)
        inside = graph.node_of(tree.body[0].body.body[0])
        self.assertNotIn(trap, inside.successors)
        self.assertFalse(CycleModel(build_control_flow_model(tree)).repeats(tree.body[0].body.body[0]))

    def test_a_trap_still_guards_the_statements_it_is_declared_beside(self):
        tree, graph = self._tree_and_graph("trap { return }\n'a'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertIn(trap, graph.node_of(tree.body[1]).successors)

    def test_a_trap_takes_the_errors_of_its_own_block_and_none_from_around_it(self):
        tree, graph = self._tree_and_graph("if ($c) { trap { 'h' }\n'a' }\n'b'")
        guarded = tree.body[0].clauses[0][1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, guarded.body[1]),
            self._handlers(graph, guarded.body[0]),
        )
        self.assertEqual(self._reached_by_an_error_at(graph, tree.body[1]), set())

    def test_a_trap_at_script_scope_takes_an_error_raised_in_a_block_nested_under_it(self):
        tree, graph = self._tree_and_graph("trap { 'h' }\nif ($c) { 'a' }\n'b'")
        self.assertEqual(
            self._reached_by_an_error_at(graph, tree.body[1].clauses[0][1].body[0]),
            self._handlers(graph, tree.body[0]),
        )

    def test_an_untyped_trap_shields_the_trap_of_the_block_around_it(self):
        tree, graph = self._tree_and_graph("trap { 'o' }\nif ($c) { trap { 'i' }\n'a' }")
        inner = tree.body[1].clauses[0][1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, inner.body[1]),
            self._handlers(graph, inner.body[0]),
        )

    def test_a_typed_trap_leaves_the_error_to_the_trap_of_the_block_around_it(self):
        tree, graph = self._tree_and_graph(
            "trap { 'o' }\nif ($c) { trap [System.IO.IOException] { 'i' }\n'a' }")
        inner = tree.body[1].clauses[0][1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, inner.body[1]),
            self._handlers(graph, inner.body[0], tree.body[0]),
        )

    def test_a_trap_that_breaks_rethrows_to_the_trap_of_the_block_around_it(self):
        tree, graph = self._tree_and_graph("trap { 'o' }\nif ($c) { trap { break }\n'a' }")
        inner = tree.body[1].clauses[0][1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, inner.body[1]),
            self._handlers(graph, inner.body[0], tree.body[0]),
        )

    def test_a_break_leaving_a_loop_written_in_the_trap_body_is_not_a_rethrow(self):
        tree, graph = self._tree_and_graph(
            "trap { 'o' }\nif ($c) { trap { :t while ($true) { break t } }\n'a' }")
        inner = tree.body[1].clauses[0][1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, inner.body[1]),
            self._handlers(graph, inner.body[0]),
        )

    def test_a_trap_that_breaks_rethrows_wherever_the_block_it_guards_is_written(self):
        for source in [
            "trap { break }\n'a'",
            "while ($c) { trap { break }\n'a' }",
            "do { trap { break }\n'a' } while ($c)",
            "for ($i = 0; $i -lt 3; $i++) { trap { break }\n'a' }",
            "foreach ($i in $x) { trap { break }\n'a' }",
            "switch ($x) { 1 { trap { break }\n'a' } }",
        ]:
            with self.subTest(source):
                tree, graph = self._tree_and_graph(source)
                guarded = self._the_block_a_trap_is_written_in(tree)
                self.assertEqual(
                    self._reached_by_an_error_at(graph, guarded[1]),
                    self._handlers(graph, guarded[0]) | {graph.exit},
                )

    def test_a_trap_that_continues_resumes_inside_the_iteration_that_raised(self):
        for source in [
            "while ($c) { trap { 'h'; continue }\n'a'\n'b' }",
            "foreach ($i in $x) { trap { 'h'; continue }\n'a'\n'b' }",
            "switch ($x) { 1 { trap { 'h'; continue }\n'a'\n'b' } }",
        ]:
            with self.subTest(source):
                tree, graph = self._tree_and_graph(source)
                guarded = self._the_block_a_trap_is_written_in(tree)
                jump = self._node_for(graph, Ps1ContinueStatement)
                head = self._required_node(graph, tree.body[0])
                reached = self._reached_without(jump, head)
                self.assertIn(id(self._required_node(graph, guarded[1])), reached)
                self.assertIn(id(self._required_node(graph, guarded[2])), reached)

    def test_a_trap_set_that_may_decline_the_error_lets_it_leave_the_body(self):
        for source in [
            "trap [System.IO.IOException] { 'h' }\n'a'",
            "trap { break }\n'a'",
        ]:
            with self.subTest(source):
                tree, graph = self._tree_and_graph(source)
                self.assertEqual(
                    self._reached_by_an_error_at(graph, tree.body[1]),
                    self._handlers(graph, tree.body[0]) | {graph.exit},
                )

    def test_an_untyped_trap_that_does_not_break_keeps_the_error_inside_the_body(self):
        tree, graph = self._tree_and_graph("trap { 'h' }\n'a'")
        self.assertEqual(
            self._reached_by_an_error_at(graph, tree.body[1]),
            self._handlers(graph, tree.body[0]),
        )

    def test_an_untyped_catch_clause_keeps_the_error_from_the_trap_around_the_try(self):
        tree, graph = self._tree_and_graph("trap { 'o' }\ntry { 'a' } catch { 'c' }")
        guarded = tree.body[1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, guarded.try_block.body[0]),
            self._handlers(graph, guarded.catch_clauses[0]),
        )

    def test_a_typed_catch_clause_leaves_the_error_to_the_trap_around_the_try(self):
        tree, graph = self._tree_and_graph(
            "trap { 'o' }\ntry { 'a' } catch [System.IO.IOException] { 'c' }")
        guarded = tree.body[1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, guarded.try_block.body[0]),
            self._handlers(graph, guarded.catch_clauses[0], tree.body[0]),
        )

    def test_an_untyped_inner_catch_clause_keeps_the_error_from_the_outer_one(self):
        tree, graph = self._tree_and_graph("try { try { 'a' } catch { 'i' } } catch { 'o' }")
        inner = tree.body[0].try_block.body[0]
        self.assertEqual(
            self._reached_by_an_error_at(graph, inner.try_block.body[0]),
            self._handlers(graph, inner.catch_clauses[0]),
        )

    def test_a_typed_inner_catch_clause_passes_the_error_to_the_outer_one(self):
        tree, graph = self._tree_and_graph(
            "try { try { 'a' } catch [System.IO.IOException] { 'i' } } catch { 'o' }")
        outer = tree.body[0]
        inner = outer.try_block.body[0]
        self.assertEqual(
            self._reached_by_an_error_at(graph, inner.try_block.body[0]),
            self._handlers(graph, inner.catch_clauses[0], outer.catch_clauses[0]),
        )

    def test_a_trap_in_a_try_block_takes_the_error_before_the_catch_clause_does(self):
        tree, graph = self._tree_and_graph("try { trap { 'h' }\n'a' } catch { 'c' }")
        guarded = tree.body[0]
        self.assertEqual(
            self._reached_by_an_error_at(graph, guarded.try_block.body[1]),
            self._handlers(graph, guarded.try_block.body[0]),
        )

    def test_a_trap_in_a_switch_clause_body_guards_that_clause_body(self):
        tree, graph = self._tree_and_graph("switch ($x) { 1 { trap { 'h' }\n'a' } }")
        clause = tree.body[0].clauses[0][1]
        self.assertEqual(
            self._reached_by_an_error_at(graph, clause.body[1]),
            self._handlers(graph, clause.body[0]),
        )

    def test_a_trap_in_a_finally_body_guards_that_finally_body(self):
        tree, graph = self._tree_and_graph("try { 'a' } finally { trap { 'h' }\n'b' }")
        cleanup = tree.body[0].finally_block
        self.assertEqual(
            self._reached_by_an_error_at(graph, cleanup.body[1]),
            self._handlers(graph, cleanup.body[0]),
        )

    def test_a_switch_clause_may_be_entered_after_the_previous_one_ran(self):
        tree, graph = self._tree_and_graph("switch ($x) { 1 { 'a' } 2 { 'b' } }")
        clauses = tree.body[0].clauses
        first = graph.node_of(clauses[0][1].body[0])
        second = graph.node_of(clauses[1][1].body[0])
        self.assertIn(second, first.successors)

    def test_a_switch_clause_may_be_skipped_when_a_later_one_matches(self):
        tree = Ps1Parser("switch ($x) { 1 { 'a' } 2 { 'b' } 3 { 'c' } }").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        clauses = tree.body[0].clauses
        first = graph.node_of(clauses[0][1].body[0])
        third = graph.node_of(clauses[2][1].body[0])
        self.assertIsNotNone(first)
        self.assertIsNotNone(third)
        self.assertIn(third, first.successors)

    def test_continue_in_a_switch_clause_advances_to_the_next_input_value(self):
        tree, graph = self._tree_and_graph("while ($x) { switch ($y) { 1 { continue } } }")
        jump = self._node_for(graph, Ps1ContinueStatement)
        switch = tree.body[0].body.body[0]
        self.assertEqual(jump.successors, [graph.node_of(switch)])

    def test_a_switch_with_a_default_clause_may_still_be_left_without_entering_an_arm(self):
        """
        Over an empty input collection no clause of a PowerShell `switch` runs, `default` included.
        """
        tree, graph = self._tree_and_graph("switch ($x) { 1 { 'a' } default { 'b' } }\n'c'")
        head = graph.node_of(tree.body[0])
        self.assertIn(graph.node_of(tree.body[1]), head.successors)

    def test_a_second_catch_clause_is_entered_only_on_the_exceptional_path(self):
        tree, graph = self._tree_and_graph("try { 'a' } catch [System.IO.IOException] { 'b' } "
                                           "catch { 'c' }")
        clauses = tree.body[0].catch_clauses
        first = graph.node_of(clauses[0])
        second = graph.node_of(clauses[1])
        self.assertIn(second, first.successors)
        self.assertTrue(graph.is_exceptional(first, second))

    def test_a_switch_of_empty_clauses_stays_linear_in_the_number_of_clauses(self):
        clauses = ' '.join(F'{index} {{ }}' for index in range(20))
        graph = self._script_graph(F"switch ($x) {{ {clauses} 20 {{ 'z' }} }}")
        edges = sum(len(node.successors) for node in graph.nodes)
        self.assertLess(edges, 200)

    def test_a_trap_that_continues_stays_linear_in_the_size_of_the_body_it_guards(self):
        body = ' '.join(F"'s{index}';" for index in range(80))
        graph = self._script_graph(F'trap {{ continue }}; {body}')
        edges = sum(len(node.successors) for node in graph.nodes)
        self.assertLess(edges, 500)

    def test_the_edges_of_resuming_traps_nested_in_one_another_grow_linearly_with_the_depth(self):
        def nested(depth: int) -> str:
            source = "trap { continue }; 'x'; 'y'"
            for _ in range(depth - 1):
                source = 'trap { continue }; if ($true) { ' + source + ' }'
            return source

        self.assertWorkGrowsLinearly(lambda depth: self._edge_count(nested(depth)), 16)

    def test_dynamicparam_runs_before_the_begin_block(self):
        tree = Ps1Parser("function f { dynamicparam { 'd' } begin { 'b' } end { 'e' } }").parse()
        definition = next(n for n in tree.walk() if isinstance(n, Ps1FunctionDefinition))
        graph = build_ps1_control_flow(tree)[id(definition.body)]
        code = definition.body
        dynamic = graph.node_of(code.dynamicparam_block.body[0])
        begin = graph.node_of(code.begin_block.body[0])
        self.assertIn(id(begin), self._forward(dynamic))
        self.assertNotIn(id(dynamic), self._forward(begin))

    def test_every_statement_is_represented_by_a_node_or_by_one_of_its_parts(self):
        for source in _CORPUS:
            with self.subTest(source):
                tree = Ps1Parser(source).parse()
                graphs = build_ps1_control_flow(tree)
                held = {
                    id(node.element)
                    for graph in graphs.values()
                    for node in graph.nodes
                    if node.element is not None
                }
                for statement in tree.walk():
                    if statement is tree or not isinstance(statement, Statement):
                        continue
                    self.assertTrue(
                        any(id(part) in held for part in statement.walk()),
                        F'no node stands for {type(statement).__name__} or any part of it',
                    )

    def test_an_advanced_function_body_is_not_empty(self):
        tree = Ps1Parser("function f { begin { 'a' } process { 'b' } end { 'c' } }").parse()
        definition = next(n for n in tree.walk() if isinstance(n, Ps1FunctionDefinition))
        graph = build_ps1_control_flow(tree)[id(definition.body)]
        self.assertGreater(len([n for n in graph.nodes if n.element is not None]), 2)

    def test_each_elseif_condition_is_its_own_point(self):
        tree = Ps1Parser("if ($x) { 'a' } elseif ($y) { 'b' } else { 'c' }").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        self.assertIsNotNone(graph.node_of(tree.body[0]))
        self.assertIsNotNone(graph.node_of(tree.body[0].clauses[1][0]))

    def test_the_script_root_owns_a_graph(self):
        tree = Ps1Parser("'a'").parse()
        graphs = build_ps1_control_flow(tree)
        self.assertIsInstance(tree, Ps1Script)
        self.assertIn(id(tree), graphs)

    def test_the_bodies_that_own_a_graph_are_the_bodies_that_own_a_scope(self):
        for source in _CORPUS:
            with self.subTest(source):
                tree = Ps1Parser(source).parse()
                graphs = build_ps1_control_flow(tree)
                model = build_semantic_model(tree)
                scopes = [model.root_scope]
                owners: set[int] = set()
                while scopes:
                    scope = scopes.pop()
                    owners.add(id(scope.node))
                    scopes.extend(scope.children)
                self.assertEqual(set(graphs), owners)

    def test_a_script_block_owns_its_own_graph(self):
        tree = Ps1Parser("1..3 | ForEach-Object { 'a' }").parse()
        graphs = build_ps1_control_flow(tree)
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        self.assertIn(id(block), graphs)
        self.assertIsNotNone(graphs[id(block)].node_of(block.body[0]))

    def test_a_statement_in_a_script_block_is_not_ordered_against_one_outside_it(self):
        tree = Ps1Parser("$a = 1\n1..3 | ForEach-Object { $b = 2 }\n$c = 3").parse()
        dominators = DominatorModel(build_control_flow_model(tree))
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        inside = block.body[0]
        self.assertFalse(dominators.dominates(inside, tree.body[2]))
        self.assertFalse(dominators.dominates(tree.body[0], inside))

    def test_two_statements_in_one_script_block_are_ordered_against_each_other(self):
        tree = Ps1Parser("1..3 | ForEach-Object { $b = 2\n$c = 3 }").parse()
        dominators = DominatorModel(build_control_flow_model(tree))
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        self.assertTrue(dominators.dominates(block.body[0], block.body[1]))
        self.assertFalse(dominators.dominates(block.body[1], block.body[0]))

    def test_a_switch_arm_can_be_reached_again_because_the_switch_enumerates_its_input(self):
        tree = Ps1Parser("switch ($x) { 1 { 'a' } }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        self.assertTrue(cycles.repeats(tree.body[0].clauses[0][1].body[0]))

    def test_a_branch_of_an_if_is_not_reached_again(self):
        tree = Ps1Parser("if ($x) { 'a' } else { 'b' }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        self.assertFalse(cycles.repeats(tree.body[0].clauses[0][1].body[0]))
        self.assertFalse(cycles.repeats(tree.body[0].else_block.body[0]))

    def test_a_for_loop_initializer_does_not_repeat_with_the_body_it_precedes(self):
        tree = Ps1Parser("for ($q = 0; $q -lt 3; $q++) { 'a' }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        loop = tree.body[0]
        self.assertFalse(cycles.repeats(loop.initializer))
        self.assertTrue(cycles.repeats(loop.condition))
        self.assertTrue(cycles.repeats(loop.iterator))
        self.assertTrue(cycles.repeats(loop.body.body[0]))

    def test_a_script_block_written_inside_a_loop_repeats_with_the_loop(self):
        tree = Ps1Parser("while ($x) { 1..3 | ForEach-Object { $a = 1 } }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        self.assertTrue(cycles.repeats(block.body[0]))

    def test_a_script_block_written_outside_a_loop_does_not_repeat(self):
        tree = Ps1Parser("& { $a = 1 }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        self.assertFalse(cycles.repeats(block.body[0]))

    def test_a_parameter_default_is_not_placed_in_the_body_around_its_block(self):
        tree = Ps1Parser("$a = 1\n$f = { param($p = 2) $p }\n$c = 3").parse()
        flow = build_control_flow_model(tree)
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        default = block.param_block.parameters[0].default_value
        self.assertIsNotNone(default)
        self.assertIsNone(flow.locate(default))

    def test_an_element_the_graphs_do_not_place_is_reported_as_repeating(self):
        tree = Ps1Parser("while ($c) { & { param($p = ($x = 1)) $p } }").parse()
        flow = build_control_flow_model(tree)
        cycles = CycleModel(flow)
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        default = block.param_block.parameters[0].default_value
        self.assertIsNone(flow.locate(default))
        self.assertTrue(cycles.repeats(default))

    def test_a_function_body_repeats_with_the_loop_its_definition_is_written_in(self):
        tree = Ps1Parser("while ($x) { function f { $a = 1 } }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        definition = next(n for n in tree.walk() if isinstance(n, Ps1FunctionDefinition))
        self.assertTrue(cycles.repeats(definition.body.body[0]))

    def test_a_function_body_outside_a_loop_does_not_repeat(self):
        tree = Ps1Parser("function f { $a = 1 }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        definition = next(n for n in tree.walk() if isinstance(n, Ps1FunctionDefinition))
        self.assertFalse(cycles.repeats(definition.body.body[0]))

    def test_a_switch_whose_only_arm_is_empty_still_returns_to_its_head(self):
        tree = Ps1Parser("switch ($x) { 1 { } }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        self.assertTrue(cycles.repeats(tree.body[0]))


class TestPs1AGraphKnowsWhichNodesEachStatementOfASequenceBuilt(TestBase):

    @staticmethod
    def _inside(element: Node, statement: Node) -> bool:
        cursor: Node | None = element
        while cursor is not None:
            if cursor is statement:
                return True
            cursor = cursor.parent
        return False

    def test_the_nodes_built_for_a_statement_are_exactly_those_standing_for_a_part_of_it(self):
        recorded = 0
        wrong: list[tuple[str, str, str]] = []
        for source in [
            *_CORPUS,
            "trap { continue }\n$x = $([int]'a'; 'b')\nif ($c) { trap { break }\n$y = @([int]$s) }",
            "trap { continue }\nforeach ($i in $l) { try { if ($c) { break } } catch { continue } }",
        ]:
            tree = Ps1Parser(source).parse()
            for graph in build_control_flow_model(tree, descend=True).graphs.values():
                for statement in tree.walk():
                    within = graph.builder_of([statement])
                    if within is None:
                        continue
                    recorded += 1
                    wrong.extend(
                        (source, str(statement), str(node.element))
                        for node in graph.nodes
                        if node.element is not None
                        and within(node) != self._inside(node.element, statement)
                    )
        self.assertEqual(wrong, [])
        self.assertGreater(recorded, len(_CORPUS))

    def test_a_trap_its_block_hoists_and_a_finally_block_record_nothing(self):
        tree = Ps1Parser("trap { 'h' }\ntry { 'a' } finally { 'c' }").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        trap, guarded = tree.body
        assert isinstance(guarded, Ps1TryCatchFinally) and guarded.finally_block is not None
        self.assertIsNone(graph.builder_of([trap]))
        self.assertIsNone(graph.builder_of([guarded.finally_block]))
        self.assertIsNotNone(graph.builder_of([guarded.finally_block.body[0]]))

    def test_nested_and_apart_statements_answer_as_the_union_of_their_own_answers(self):
        tree = Ps1Parser("if ($a) { 'x'\nif ($b) { 'y' } }\n'z'\nif ($c) { 'w' }").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        outer, _, apart = tree.body
        nested = next(node for node in outer.walk() if node is not outer and type(node) is type(outer))
        statements = [outer, nested, apart]
        together = graph.builder_of(statements)
        alone = [graph.builder_of([statement]) for statement in statements]
        assert together is not None and all(within is not None for within in alone)
        for node in graph.nodes:
            self.assertEqual(together(node), any(within(node) for within in alone if within is not None))


class TestPs1ATrapSetIsWiredInTheOrder51TriesItsMembers(_Ps1ControlFlowGraphs):

    @staticmethod
    def _sets(source: str):
        tree = Ps1Parser(source).parse()
        model = build_control_flow_model(tree)
        traps = [node for node in tree.walk_in_order() if isinstance(node, Ps1TrapStatement)]
        return tree, model, traps

    def test_typed_members_are_tried_before_the_first_untyped_one_and_later_untyped_ones_never(self):
        _, model, (first, typed, second) = self._sets(
            "trap { 'a' }\ntrap [System.IO.IOException] { 'b' }\ntrap { 'c' }\n'x'")
        trap_set = model.trap_set_of(first)
        assert trap_set is not None
        self.assertEqual(trap_set.selectable, (typed, first))
        self.assertEqual(trap_set.never_selected, (second,))

    def test_a_member_naming_every_error_leaves_every_untyped_member_unselected(self):
        _, model, (universal, untyped) = self._sets("trap [System.Exception] { 'a' }\ntrap { 'b' }\n'x'")
        trap_set = model.trap_set_of(universal)
        assert trap_set is not None
        self.assertEqual(trap_set.selectable, (universal,))
        self.assertEqual(trap_set.never_selected, (untyped,))

    def test_an_error_is_offered_only_to_the_members_51_may_select(self):
        tree, graph = self._tree_and_graph(
            "trap { 'a' }\ntrap [System.IO.IOException] { 'b' }\ntrap { 'c' }\n'x'")
        first, typed, second, guarded = tree.body
        self.assertEqual(self._reached_by_an_error_at(graph, guarded), self._handlers(graph, typed, first))
        self.assertEqual(self._required_node(graph, second).predecessors, [])

    def test_a_member_never_selected_does_not_make_its_block_resume(self):
        tree, graph = self._tree_and_graph("trap { break }\ntrap { 'x'; continue }\n'a'\n'b'")
        raiser = self._required_node(graph, tree.body[2])
        self.assertFalse(any(
            graph.edge_kind(raiser, target) & CfgEdge.RESUMPTION_FORWARD for target in raiser.successors))
        self.assertIn(graph.exit, self._reached_by_an_error_at(graph, tree.body[2]))

    def test_an_error_gets_past_the_set_exactly_where_the_member_51_picks_may_hand_it_on(self):
        for source, escapes in [
            ("trap { break }\ntrap { continue }\n'a'", True),
            ("trap { continue }\ntrap { break }\n'a'", False),
            ("trap { continue }\ntrap [System.Management.Automation.RuntimeException] { break }\n'a'", True),
            ("trap [System.Exception] { continue }\ntrap { break }\n'a'", False),
        ]:
            with self.subTest(source):
                tree, graph = self._tree_and_graph(source)
                self.assertEqual(graph.exit in self._reached_by_an_error_at(graph, tree.body[-1]), escapes)

    def test_a_set_nested_in_a_resuming_block_is_resumed_where_that_block_resumes_its_statement(self):
        tree, model, (outer, inner) = self._sets("trap { continue }\nif ($c) { trap { break }\n'a' }\n'b'")
        outer_set = model.trap_set_of(outer)
        inner_set = model.trap_set_of(inner)
        assert outer_set is not None and inner_set is not None
        entry = inner_set.entry(inner)
        resumed = [
            target for target in entry.successors
            if entry.graph.edge_kind(entry, target) & CfgEdge.RESUMPTION_FORWARD
        ]
        self.assertEqual(resumed, [outer_set.slots[id(tree.body[1])]])

    def test_the_disposition_of_a_member_is_what_its_body_may_do_with_the_error(self):
        for body, disposition in [
            ('{ }', Ps1TrapDisposition.FALLS_THROUGH),
            ('{ continue }', Ps1TrapDisposition.RESUMES),
            ('{ break }', Ps1TrapDisposition.RETHROWS),
            ('{ foreach ($i in $l) { break } }', Ps1TrapDisposition.FALLS_THROUGH),
            ('{ if ($c) { continue }; break }', Ps1TrapDisposition.RESUMES | Ps1TrapDisposition.RETHROWS),
        ]:
            with self.subTest(body):
                _, model, (trap,) = self._sets(F"trap {body}\n'a'")
                trap_set = model.trap_set_of(trap)
                assert trap_set is not None
                self.assertEqual(trap_set.disposition(trap), disposition)


class TestPs1ACatchWhoseTypeFilterCannotBeReadIsNotUnfiltered(_Ps1ControlFlowGraphs):

    def test_a_catch_carrying_a_filter_lets_the_error_leave_the_construct(self):
        graph, guarded = self._guarded_statement(
            "try { 'a' } catch [System.IO.IOException] { 'b' }")
        self.assertIn(graph.exit, self._reached_by_an_error_at(graph, guarded))

    def test_a_catch_whose_filter_is_an_empty_bracket_lets_the_error_leave_the_construct(self):
        graph, guarded = self._guarded_statement("try { 'a' } catch [] { 'b' }")
        self.assertIn(graph.exit, self._reached_by_an_error_at(graph, guarded))


class TestPs1TrapResumptionIsCarriedForwardAsWellAsThroughTheHub(_Ps1ControlFlowGraphs):

    @staticmethod
    def _resumption_landings(graph: ControlFlowGraph) -> list[CfgNode]:
        return [
            target
            for node in graph.nodes if node.element is None
            for target in node.successors
            if target.element is not None
            and graph.edge_kind(node, target) & CfgEdge.RESUMPTION_HUB
        ]

    def test_a_guarded_statement_resumes_below_itself_and_not_above(self):
        tree, graph = self._tree_and_graph("trap { 'h'; continue }\n'one'\n'two'\n'three'")
        one, two, three = (self._required_node(graph, tree.body[k]) for k in (1, 2, 3))
        forward = reachable_forward_from_any(graph, [two])
        self.assertIn(id(three), forward)
        self.assertNotIn(id(one), forward)
        self.assertIn(id(one), reachable_from_any([two]))

    def test_a_set_that_acts_nowhere_resumes_along_the_forward_edges_alone(self):
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\n'two'\n'three'")
        one, two, three = (self._required_node(graph, tree.body[k]) for k in (1, 2, 3))
        self.assertIn(id(three), reachable_forward_from_any(graph, [two]))
        self.assertNotIn(id(one), reachable_from_any([two]))

    def test_a_terminator_reaches_the_statement_resumption_lands_on(self):
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\nthrow 'x'\n'three'")
        one, raiser, three = (self._required_node(graph, tree.body[k]) for k in (1, 2, 3))
        forward = reachable_forward_from_any(graph, [raiser])
        self.assertIn(id(three), forward)
        self.assertNotIn(id(one), forward)

    def test_resumption_lands_where_control_enters_the_next_statement(self):
        tree, graph = self._tree_and_graph(
            "trap { continue }\n'one'\nthrow 'x'\ntry { 'body' } catch { 'clause' }")
        raiser = self._required_node(graph, tree.body[2])
        guarded = tree.body[3]
        self.assertIn(
            id(self._required_node(graph, guarded.try_block.body[0])),
            reachable_forward_from_any(graph, [raiser]),
        )

    def test_a_raise_in_the_last_guarded_statement_resumes_past_the_block(self):
        tree, graph = self._tree_and_graph(
            "if ($c) { trap { continue }\n'in'\nthrow 'x' }\n'after'")
        guarded = tree.body[0].clauses[0][1]
        raiser = self._required_node(graph, guarded.body[2])
        self.assertIn(
            id(self._required_node(graph, tree.body[1])),
            reachable_forward_from_any(graph, [raiser]),
        )

    def test_a_statement_of_the_handler_is_flooded_through_the_hub_instead(self):
        tree, graph = self._tree_and_graph("trap { 'handled'\ncontinue }\n'one'\n'two'")
        handled = self._required_node(graph, tree.body[0].body.body[0])
        forward = reachable_forward_from_any(graph, [handled])
        self.assertTrue(handled.is_hub_bound)
        self.assertFalse(self._required_node(graph, tree.body[1]).is_hub_bound)
        self.assertIn(id(self._required_node(graph, tree.body[1])), forward)
        self.assertIn(id(self._required_node(graph, tree.body[2])), forward)

    def test_every_door_onto_the_forward_reading_falls_back_for_such_a_statement(self):
        tree, graph = self._tree_and_graph("trap { 'handled'\ncontinue }\n'one'\n'two'")
        handled = self._required_node(graph, tree.body[0].body.body[0])
        self.assertEqual(
            flood([handled], forward=True, projection=Projection.FORWARD),
            set(reachable_forward_from_any(graph, [handled])),
        )

    def test_a_forward_walk_seeded_at_a_hub_leaves_it_by_no_edge(self):
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\n'two'")
        one = self._required_node(graph, tree.body[1])
        hub, = (target for target in one.predecessors if target.is_resumption_hub)
        self.assertEqual(flood([hub], forward=True, projection=Projection.FORWARD), {id(hub)})
        self.assertEqual(flood([hub], forward=False, projection=Projection.FORWARD), {id(hub)})

    def test_a_hub_of_a_set_nested_in_a_handler_body_is_not_also_hub_bound(self):
        _, graph = self._tree_and_graph(
            "trap { if ($q) { trap { continue }\n'p' }\ncontinue }\n'x'\n'y'")
        self.assertEqual(
            [node for node in graph.nodes if node.is_hub_bound and node.is_resumption_hub], [])

    def test_a_forward_flood_refuses_a_source_belonging_to_another_body(self):
        tree = Ps1Parser("trap { continue }\nfunction f { 'in' }\n'out'").parse()
        graphs = build_ps1_control_flow(tree)
        script = graphs[id(tree)]
        definition = next(
            node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        inside = self._required_node(graphs[id(definition.body)], definition.body.body[0])
        with self.assertRaises(ValueError):
            reachable_forward_from_any(script, [inside])

    def test_a_resumption_edge_is_taken_on_a_throw_and_carries_no_error(self):
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\n'two'")
        one = self._required_node(graph, tree.body[1])
        hub, = (target for target in one.predecessors if target.is_resumption_hub)
        forward, = (
            target for target in one.successors
            if graph.edge_kind(one, target) is CfgEdge.RESUMPTION_FORWARD
        )
        for source, target in [(hub, one), (one, forward)]:
            with self.subTest(graph.edge_kind(source, target)):
                self.assertFalse(graph.is_exceptional(source, target))
                self.assertTrue(graph.raise_taken(source, target))

    def test_the_edge_into_a_resumption_hub_is_the_handler_body_completing(self):
        tree, graph = self._tree_and_graph("trap { $x = 'b'\ncontinue }\n'one'")
        jump = self._node_for(graph, Ps1ContinueStatement)
        hub, = (target for target in jump.successors if target.is_resumption_hub)
        self.assertFalse(graph.raise_taken(jump, hub))
        self.assertTrue(graph.raise_taken(hub, self._required_node(graph, tree.body[1])))

    def test_a_trap_written_below_a_statement_leaves_one_resumption_point(self):
        tree, graph = self._tree_and_graph(
            "'one'\ntrap { continue }\ntrap [System.Exception] { continue }\n'two'")
        one, two = (self._required_node(graph, tree.body[k]) for k in (0, 3))
        slots = [
            target for target in one.successors
            if graph.edge_kind(one, target) is CfgEdge.RESUMPTION_FORWARD
        ]
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].successors, [two])

    def test_every_statement_a_resumption_lands_on_leaves_by_a_forward_edge(self):
        for source in _CORPUS:
            with self.subTest(source):
                stranded: list[str] = []
                for graph in self._graphs(source).values():
                    for landing in self._resumption_landings(graph):
                        if landing.is_hub_bound:
                            continue
                        if any(
                            graph.edge_kind(landing, target) & CfgEdge.RESUMPTION_FORWARD
                            for target in landing.successors
                        ):
                            continue
                        stranded.append(type(landing.element).__name__)
                self.assertEqual(stranded, [])

    def test_every_statement_of_a_resuming_handler_is_hub_bound(self):
        for source in _CORPUS:
            with self.subTest(source):
                tree = Ps1Parser(source).parse()
                graphs = build_ps1_control_flow(tree)
                for trap in tree.walk_in_order():
                    if not isinstance(trap, Ps1TrapStatement) or trap.body is None:
                        continue
                    for graph in graphs.values():
                        if graph.node_of(trap) is None:
                            continue
                        if not graph.carries_resumption:
                            continue
                        for statement in trap.body.walk():
                            node = graph.node_of(statement)
                            if node is not None:
                                self.assertTrue(node.is_hub_bound)

    def test_a_guarded_statement_forward_reaches_every_statement_below_it(self):
        blocks = [
            "trap { continue }\n'one'\nthrow 'x'\n'three'\n'four'",
            "while ($c) { trap { continue }\n'one'\nthrow 'x'\n'three'\n'four' }",
            "do { trap { continue }\n'one'\nthrow 'x'\n'three' } while ($c)",
            "foreach ($i in $x) { trap { continue }\n'one'\nthrow 'x'\n'three' }",
            "for ($i = 0; $i -lt 3; $i++) { trap { continue }\n'one'\nthrow 'x'\n'three' }",
            "switch ($x) { 1 { trap { continue }\n'one'\nthrow 'x'\n'three' } }",
            "try { trap { continue }\n'one'\nthrow 'x'\n'three' } catch { 'c' }",
            "try { 'a' } catch { trap { continue }\n'one'\nthrow 'x'\n'three' }",
            "try { 'a' } finally { trap { continue }\n'one'\nthrow 'x'\n'three' }",
            "if ($c) { trap { continue }\n'one'\nthrow 'x'\n'three' }\n'after'",
        ]
        for source in blocks:
            with self.subTest(source):
                tree, graph = self._tree_and_graph(source)
                guarded = self._the_block_a_trap_is_written_in(tree)[1:]
                unreached: list[tuple[int, int]] = []
                for index, statement in enumerate(guarded):
                    forward = reachable_forward_from_any(
                        graph, [self._required_node(graph, statement)])
                    for offset, below in enumerate(guarded[index + 1:], index + 1):
                        if id(self._required_node(graph, below)) not in forward:
                            unreached.append((index, offset))
                self.assertEqual(unreached, [])


class _BuildFailed(Exception):
    pass


class TestPs1AResumableBlockTakesOnlyTheNodesBuiltInsideIt(TestBase):

    def test_a_node_built_after_an_error_left_a_resumable_block_carries_no_resumption(self):
        tree = Ps1Parser("'a'\n'b'").parse()
        builder = CfgBuilder(tree)
        guarded, following = tree.body
        with self.assertRaises(_BuildFailed):
            with builder.resumption([builder.detached_node(guarded)]):
                raise _BuildFailed
        node = builder.detached_node(following)
        self.assertEqual((node.predecessors, node.successors), ([], []))


class TestPs1ALabelledWalkAnswersEveryLabelAsItsOwnWalkWould(TestBase):

    _SCRIPTS = [
        cleandoc("""
            trap { 'handled'; continue }
            'one'
            if ($c) { trap { continue }; Get-Item nope; 'two' }
        """),
        cleandoc("""
            while ($x) { trap { 'h'; continue }; Get-Item a; $y = [int]$s; 'tail' }
            'after'
        """),
        cleandoc("""
            trap { if ($q) { trap { continue }; 'p' }; continue }
            'x'
            'y'
        """),
        cleandoc("""
            try { Get-Item a; 'b' } catch { 'c' } finally { 'f' }
            function f { trap { break }; 'in' }
        """),
        cleandoc("""
            switch ($x) { 1 { 'a' } 2 { trap { continue }; Get-Item b } default { 'c' } }
            'z'
        """),
        cleandoc("""
            do { trap { continue }; Get-Item a; if ($y) { break }; $v = [int]$s } while ($x)
            'end'
        """),
    ]

    def _labelled_graphs(self):
        for script in self._SCRIPTS:
            for graph in build_ps1_control_flow(Ps1Parser(script).parse()).values():
                labels: dict[object, list[CfgNode]] = {
                    index: [node] for index, node in enumerate(graph.nodes)}
                for bound in (node for node in graph.nodes if node.is_hub_bound):
                    for other in graph.nodes:
                        labels[(id(bound), id(other))] = [bound, other]
                yield script, graph, labels

    def test_a_labelled_flood_answers_every_label_as_its_own_flood(self):
        for script, graph, labels in self._labelled_graphs():
            for forward in (True, False):
                for projection in Projection:
                    walk = flood_labels(labels, forward=forward, projection=projection)
                    wrong = [
                        (label, index)
                        for label, sources in labels.items()
                        for reached in (flood(sources, forward=forward, projection=projection),)
                        for index, node in enumerate(graph.nodes)
                        if walk.reaches(label, node) != (id(node) in reached)
                    ]
                    with self.subTest(script=script, forward=forward, projection=projection.name):
                        self.assertEqual(wrong, [])

    def test_a_labelled_forward_reach_answers_every_label_as_its_own_reach(self):
        for script, graph, labels in self._labelled_graphs():
            walk = reachable_forward_labels(graph, labels)
            wrong = [
                (label, index)
                for label, sources in labels.items()
                for reached in (reachable_forward_from_any(graph, sources),)
                for index, node in enumerate(graph.nodes)
                if walk.reaches(label, node) != (id(node) in reached)
            ]
            with self.subTest(script=script):
                self.assertEqual(wrong, [])

    def test_a_label_seeded_in_a_handler_body_reaches_the_block_the_handler_resumes_into(self):
        tree = Ps1Parser(cleandoc("""
            trap { 'handled'; continue }
            'one'
            'two'
        """)).parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        trap = tree.body[0]
        assert isinstance(trap, Ps1TrapStatement) and trap.body is not None
        handled = graph.node_of(trap.body.body[0])
        one = graph.node_of(tree.body[1])
        two = graph.node_of(tree.body[2])
        assert handled is not None and one is not None and two is not None
        walk = reachable_forward_labels(graph, {'handled': [handled]})
        self.assertTrue(walk.reaches('handled', one))
        self.assertTrue(walk.reaches('handled', two))

    def test_a_label_never_named_reaches_nothing(self):
        _, graph, labels = next(self._labelled_graphs())
        walk = flood_labels(labels, forward=True, projection=Projection.MAY)
        self.assertFalse(any(walk.reaches('unnamed', node) for node in graph.nodes))

    def test_a_labelled_forward_reach_refuses_a_source_belonging_to_another_body(self):
        tree = Ps1Parser(cleandoc("""
            trap { continue }
            function f { 'in' }
            'out'
        """)).parse()
        graphs = build_ps1_control_flow(tree)
        definition = next(node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        body = definition.body
        assert body is not None
        inside = graphs[id(body)].node_of(body.body[0])
        assert inside is not None
        with self.assertRaises(ValueError):
            reachable_forward_labels(graphs[id(tree)], {'inside': [inside]})


class TestPs1APathBetweenQuestionAnswersAsTheTwoFloodsWould(TestBase):

    def test_every_node_lies_between_two_others_exactly_when_the_floods_say_so(self):
        for script in TestPs1ALabelledWalkAnswersEveryLabelAsItsOwnWalkWould._SCRIPTS:
            graphs = build_ps1_control_flow(Ps1Parser(script).parse())
            dominators = DominatorModel(Ps1ControlFlowModel(graphs, {}))
            for graph in graphs.values():
                for projection in Projection:
                    asked_before = ReachabilityQuery(dominators, projection)
                    unplaced = graph.hub_bound if projection.declines_the_hub else frozenset()
                    wrong = []
                    for source, target in itertools.product(graph.nodes, repeat=2):
                        forward = flood([source], forward=True, projection=projection)
                        backward = flood([target], forward=False, projection=projection)
                        for node in graph.nodes:
                            key = id(node)
                            expected = key in forward and (key in backward or key in unplaced)
                            asked_first = ReachabilityQuery(dominators, projection)
                            if (
                                asked_first.any_between(graph, source, target, {key}) != expected
                                or asked_before.any_between(graph, source, target, {key}) != expected
                            ):
                                wrong.append((source, target, node))
                    with self.subTest(script=script, projection=projection.name):
                        self.assertEqual(len(wrong), 0)

    def test_the_components_reached_under_a_walk_s_reading_hold_what_a_flood_from_its_start_returns(self):
        for script in TestPs1ALabelledWalkAnswersEveryLabelAsItsOwnWalkWould._SCRIPTS:
            graphs = build_ps1_control_flow(Ps1Parser(script).parse())
            for graph in graphs.values():
                for projection, forward in itertools.product(Projection, (True, False)):
                    walked: dict[Projection, list[frozenset[int]]] = {}
                    wrong = []
                    for node in graph.nodes:
                        reading = walk_reading(node, forward=forward, projection=projection)
                        condensation = graph.condensation(reading)
                        if reading not in walked:
                            walked[reading] = condensation.accumulate(
                                lambda number: frozenset(id(member) for member in condensation.components[number]),
                                frozenset.union,
                                downstream=forward,
                            )
                        number = condensation.number_of(node)
                        assert number is not None
                        if walked[reading][number] != flood([node], forward=forward, projection=projection):
                            wrong.append(node)
                    with self.subTest(script=script, projection=projection.name, forward=forward):
                        self.assertEqual(len(wrong), 0)

    def test_a_statement_of_a_resuming_handler_lies_between_a_failing_statement_and_the_next(self):
        tree = Ps1Parser(cleandoc("""
            trap { 'handled'; continue }
            $v = [int]$args[0]
            $w = [int]$args[1]
        """)).parse()
        graphs = build_ps1_control_flow(tree)
        graph = graphs[id(tree)]
        trap = tree.body[0]
        assert isinstance(trap, Ps1TrapStatement) and trap.body is not None
        handled = graph.node_of(trap.body.body[0])
        first = graph.node_of(tree.body[1])
        second = graph.node_of(tree.body[2])
        assert handled is not None and first is not None and second is not None
        for projection in Projection:
            query = ReachabilityQuery(DominatorModel(Ps1ControlFlowModel(graphs, {})), projection)
            with self.subTest(projection=projection.name):
                self.assertTrue(query.any_between(graph, first, second, {id(handled)}))


class TestPs1AnErrorNothingTakesIsReportedPastItsStatement(_Ps1ControlFlowGraphs):

    def _reports(self, graph: ControlFlowGraph) -> list[Ps1ReportNode]:
        return [node for node in graph.nodes if isinstance(node, Ps1ReportNode)]

    def _reachable(self, source: str, statement: int) -> bool:
        tree, graph = self._tree_and_graph(cleandoc(source))
        return id(self._required_node(graph, tree.body[statement])) in self._forward(graph.entry)

    def test_the_report_node_carries_on_after_the_innermost_statement_nothing_guards(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            if ($x) {
              try {
                [int]$s
              } finally {}
              'if-rest'
            }
            'after'
        """))
        branch = tree.body[0]
        assert isinstance(branch, Ps1IfStatement)
        construct, rest = branch.clauses[0][1].body
        report, = self._reports(graph)
        self.assertIs(report.carries_on_after, construct)
        self.assertIn(self._required_node(graph, rest), report.successors)

    def test_the_report_node_of_the_last_statement_carries_on_to_the_exit(self):
        graph = self._script_graph("try { throw 'x' } catch { Write-Host 'a'; $null = [int]$s }")
        report, = self._reports(graph)
        self.assertIn(graph.exit, plain_successors(report))

    def test_no_report_node_stands_where_no_error_reaches_one(self):
        for source in ("try { throw 'x' } catch { 'b' }", 'try { } catch { }', "try { 'a' } catch { continue }"):
            with self.subTest(source):
                self.assertEqual(self._reports(self._script_graph(source)), [])

    def test_a_throw_nothing_takes_ends_the_run_rather_than_carrying_on(self):
        self.assertFalse(self._reachable("""
            try {
              throw 'x'
            } catch {
              throw 'y'
            }
            'after'
        """, 1))

    def test_a_line_that_cannot_fail_is_not_reported_past_its_statement(self):
        self.assertFalse(self._reachable("""
            try {
              throw 'x'
            } catch {
              'b'
              return
            }
            'after'
        """, 1))

    def test_a_line_that_may_fail_is_reported_past_its_statement(self):
        self.assertTrue(self._reachable("""
            try {
              throw 'x'
            } catch {
              [int]$s
              return
            }
            'after'
        """, 1))

    def test_a_line_that_cannot_fail_is_still_offered_to_the_handler_guarding_it(self):
        tree, graph = self._tree_and_graph("try { 'a' } catch { 'b' }")
        construct = tree.body[0]
        assert isinstance(construct, Ps1TryCatchFinally) and construct.try_block is not None
        clause, = construct.catch_clauses
        line = self._required_node(graph, construct.try_block.body[0])
        self.assertIn(self._required_node(graph, clause), line.successors)

    def test_a_trap_set_taking_every_error_inside_a_body_nothing_guards_names_a_node_of_the_graph(self):
        for source, holder in (
            ("try { throw 'x' } catch { trap { continue }; 'v' }\n'after'", 0),
            ("if ($x) { trap { if ($True) { trap { continue }; 'v' } }; [int]$s }\n'after'", 0),
        ):
            with self.subTest(source):
                tree = Ps1Parser(source).parse()
                model = build_control_flow_model(tree)
                inner = [node for node in tree.walk_in_order() if isinstance(node, Ps1TrapStatement)][-1]
                trap_set = model.trap_set_of(inner)
                assert trap_set is not None and isinstance(trap_set.outward, Ps1ReportNode)
                self.assertIs(trap_set.outward.carries_on_after, tree.body[holder])
                self.assertTrue(any(node is trap_set.outward for node in trap_set.graph.nodes))


class TestPs1TheGraphRoutesAnErrorWhereTheEvaluatorSendsIt(_Ps1ControlFlowGraphs):

    def test_a_trap_whose_body_runs_off_its_end_lets_the_error_past_under_stop(self):
        for preference, passes in (("$ErrorActionPreference = 'Stop'", True), ('', False)):
            with self.subTest(preference=preference):
                tree, graph = self._tree_and_graph(cleandoc(F"""
                    {preference}
                    try {{
                      trap {{ }}
                      $null = [int]$s
                    }} catch {{
                      'c'
                    }}
                """))
                construct = next(node for node in tree.walk() if isinstance(node, Ps1TryCatchFinally))
                assert construct.try_block is not None
                clause, = construct.catch_clauses
                reached = self._reached_by_an_error_at(graph, construct.try_block.body[1])
                self.assertEqual(self._required_node(graph, clause) in reached, passes)

    def test_a_throw_where_an_error_may_be_silenced_carries_on_and_may_end_the_run(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            $ErrorActionPreference = 'SilentlyContinue'
            throw 'x'
            'after'
        """))
        raised = self._required_node(graph, tree.body[1])
        self.assertIn(self._required_node(graph, tree.body[2]), plain_successors(raised))
        self.assertIn(graph.exit, self._reached_by_an_error_at(graph, tree.body[1]))

    def test_the_head_of_a_foreach_in_a_catch_body_may_fail_and_is_reported(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            try { throw 'x' } catch {
              foreach ($i in 'a') { }
              'r'
            }
            'after'
        """))
        loop = next(node for node in tree.walk() if isinstance(node, Ps1ForEachLoop))
        report, = (node for node in graph.nodes if isinstance(node, Ps1ReportNode))
        self.assertIs(report.carries_on_after, tree.body[0])
        self.assertIn(report, self._reached_by_an_error_at(graph, loop))

    def test_an_error_a_trap_body_raises_may_run_the_trap_again_where_it_ran_inside_a_try(self):
        for clause, again in (('catch [System.IO.IOException] { }', True), ('catch { }', False)):
            with self.subTest(clause=clause):
                tree, graph = self._tree_and_graph(cleandoc(F"""
                    trap {{ $null = [int]$s }}
                    try {{ throw 'x' }} {clause}
                """))
                trap = tree.body[0]
                assert isinstance(trap, Ps1TrapStatement) and trap.body is not None
                reached = self._reached_by_an_error_at(graph, trap.body.body[0])
                self.assertEqual(self._required_node(graph, trap) in reached, again)

    def test_an_error_a_catch_inside_a_trap_body_takes_does_not_run_the_trap_again(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            trap { try { $null = [int]$s } catch { } finally { 'f' } }
            try { throw 'x' } catch [System.IO.IOException] { }
        """))
        trap = tree.body[0]
        construct = next(node for node in trap.walk() if isinstance(node, Ps1TryCatchFinally))
        assert construct.try_block is not None and construct.finally_block is not None
        entry = self._required_node(graph, trap)
        for element in (construct.try_block.body[0], construct.finally_block):
            with self.subTest(element=type(element).__name__):
                self.assertNotIn(entry, self._reached_by_an_error_at(graph, element))


class TestPs1AJumpRunsTheFinallyItLeaves(_Ps1ControlFlowGraphs):

    def _finally_entries(self, graph: ControlFlowGraph, tree: Ps1Script) -> list[CfgNode]:
        return [
            self._required_node(graph, node.finally_block.body[0])
            for node in tree.walk_in_order()
            if isinstance(node, Ps1TryCatchFinally) and node.finally_block is not None
        ]

    def _reached_from(self, graph: ControlFlowGraph, kind: type) -> set[int]:
        return self._forward(self._node_for(graph, kind))

    def test_a_jump_reaches_the_finally_it_leaves(self):
        for source, kind in (
            ("try { return } finally { 'f' }", Ps1ReturnStatement),
            ("try { exit } finally { 'f' }", Ps1ExitStatement),
            ("foreach ($i in 1, 2) { try { break } finally { 'f' } }", Ps1BreakStatement),
            ("foreach ($i in 1, 2) { try { continue } finally { 'f' } }", Ps1ContinueStatement),
        ):
            with self.subTest(source=source):
                tree, graph = self._tree_and_graph(source)
                entry, = self._finally_entries(graph, tree)
                self.assertIn(id(entry), self._reached_from(graph, kind))

    def test_a_break_does_not_run_a_finally_around_the_loop_it_leaves(self):
        tree, graph = self._tree_and_graph(
            "try { foreach ($i in 1, 2) { break } } finally { 'outer' }")
        outer, = self._finally_entries(graph, tree)
        jump = self._node_for(graph, Ps1BreakStatement)
        self.assertNotIn(outer, jump.successors)

    def test_the_finally_a_break_leaves_carries_on_where_the_break_goes(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            foreach ($i in 1, 2) {
              try { break } finally { 'f' }
              return
            }
            'after'
        """))
        entry, = self._finally_entries(graph, tree)
        after = self._required_node(graph, tree.body[-1])
        self.assertIn(id(after), self._forward(entry))

    def test_a_break_leaving_two_finally_bodies_runs_the_inner_then_the_outer(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            foreach ($i in 1, 2) {
              try {
                try { break } finally { 'inner' }
                'rest'
              } finally { 'outer' }
              return
            }
            'after'
        """))
        outer, inner = self._finally_entries(graph, tree)
        jump = self._node_for(graph, Ps1BreakStatement)
        after = self._required_node(graph, tree.body[-1])
        self.assertNotIn(id(outer), self._reached_without(jump, inner))
        self.assertNotIn(id(after), self._reached_without(jump, outer))
        self.assertIn(id(after), self._forward(jump))

    def test_a_return_leaving_two_finally_bodies_runs_both_before_leaving_the_function(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            function f {
              try {
                try { return } finally { 'inner' }
              } finally { 'outer' }
              'rest'
            }
        """))
        definition = tree.body[0]
        assert isinstance(definition, Ps1FunctionDefinition) and definition.body is not None
        graph = build_ps1_control_flow(tree)[id(definition.body)]
        outer, inner = self._finally_entries(graph, tree)
        jump = self._node_for(graph, Ps1ReturnStatement)
        self.assertNotIn(id(graph.exit), self._reached_without(jump, inner))
        self.assertNotIn(id(graph.exit), self._reached_without(jump, outer))
        self.assertIn(id(graph.exit), self._forward(jump))

    def test_a_finally_that_throws_drops_the_break_it_was_entered_with(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            foreach ($i in 1, 2) {
              try { break } finally { throw 'f' }
            }
            'after'
        """))
        jump = self._node_for(graph, Ps1BreakStatement)
        after = self._required_node(graph, tree.body[-1])
        self.assertNotIn(id(after), self._forward(jump))

    def test_an_error_no_catch_takes_runs_the_finally_before_it_leaves(self):
        tree, graph = self._tree_and_graph("try { throw 'x' } finally { 'f' }")
        entry, = self._finally_entries(graph, tree)
        raised = self._node_for(graph, Ps1ThrowStatement)
        self.assertNotIn(id(graph.exit), self._reached_without(raised, entry))

    @wontfix('no obfuscator writes a continue that resumes a trap from inside a try with a finally')
    def test_a_continue_resuming_a_trap_from_inside_a_try_runs_the_finally_first(self):
        tree, graph = self._tree_and_graph(cleandoc("""
            trap { try { continue } finally { 'f' } }
            $null = [int]$s
            'next'
        """))
        entry, = self._finally_entries(graph, tree)
        jump = self._node_for(graph, Ps1ContinueStatement)
        after = self._required_node(graph, tree.body[2])
        self.assertNotIn(id(after), self._reached_without(jump, entry))

    def test_an_error_a_typed_catch_does_not_take_runs_the_finally(self):
        tree, graph = self._tree_and_graph(
            "try { throw 'x' } catch [System.IO.IOException] { 'c' } finally { 'f' }")
        construct = tree.body[0]
        assert isinstance(construct, Ps1TryCatchFinally)
        clause, = construct.catch_clauses
        entry, = self._finally_entries(graph, tree)
        caught = self._required_node(graph, clause.body.body[0])
        raised = self._node_for(graph, Ps1ThrowStatement)
        self.assertIn(id(entry), self._reached_without(raised, caught))


class TestPs1AProcessBlockRunsOncePerInput(_Ps1ControlFlowGraphs):

    def test_end_is_reached_without_running_process(self):
        tree = Ps1Parser("function f { begin { 'b' } process { 'p' } end { 'e' } }").parse()
        definition = next(node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        code = definition.body
        assert code is not None and code.process_block is not None and code.end_block is not None
        assert code.begin_block is not None
        graph = build_ps1_control_flow(tree)[id(code)]
        begin = self._required_node(graph, code.begin_block.body[0])
        process = self._required_node(graph, code.process_block.body[0])
        end = self._required_node(graph, code.end_block.body[0])
        self.assertIn(id(end), self._reached_without(begin, process))
        self.assertTrue(any(id(process) in self._forward(successor) for successor in process.successors))

    def test_the_body_of_a_filter_may_run_again_after_itself(self):
        tree = Ps1Parser("filter f { 'p' }").parse()
        definition = next(node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        assert definition.body is not None
        graph = build_ps1_control_flow(tree)[id(definition.body)]
        statement = self._required_node(graph, definition.body.body[0])
        self.assertTrue(any(id(statement) in self._forward(successor) for successor in statement.successors))
