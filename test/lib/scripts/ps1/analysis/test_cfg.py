from __future__ import annotations

import unittest

from test import TestBase

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.analysis.cfg import (
    CfgBuilder,
    CfgEdge,
    CfgNode,
    ControlFlowGraph,
    Projection,
    flood,
    reachable_forward_from_any,
    reachable_from_any,
)
from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model, build_ps1_control_flow
from refinery.lib.scripts.ps1.analysis.model import build_semantic_model
from refinery.lib.scripts.ps1.ast import get_body
from refinery.lib.scripts.ps1.model import (
    Ps1BreakStatement,
    Ps1ContinueStatement,
    Ps1FunctionDefinition,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser

#: One script per construct the builder recognises. The invariants below are asserted over every
#: entry, so a construct added to the dispatch without an entry here is covered by nothing.
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
    """
    The graph fixtures every test below reads, kept apart from the tests so that a pin needing
    one inherits the fixtures and not another class's assertions.
    """

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

    def _reached_by_an_error_at(self, graph: ControlFlowGraph, element: Node) -> set[CfgNode]:
        """
        The nodes an error raised at *element* may travel to, walked over exceptional edges alone.
        Each of them is a handler that may be offered the error, except for the graph exit, which
        stands for the error leaving this body with no handler having taken it.
        """
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
        """
        The nodes forward-reachable from *start* along paths that never enter *barrier*.
        """
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
        # Asserted against the statement *after* the loop rather than against the graph exit. A
        # break that never resolved to its target is wired to the exit as a fallback, and with the
        # loop written last the two answers coincide, so the exit assertion cannot discriminate.
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
        """
        The three parts run at three different points, and none of them is the loop statement.
        """
        # Asserted per part. The parts are expressions rather than statements, so the invariant that
        # every statement is represented does not reach them: a builder that dropped the initializer
        # would still produce a graph with a node for the loop body.
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
        graph = self._script_graph("try { 'a' } catch { 'b' }")
        exceptional = [
            (source, target)
            for source in graph.nodes
            for target in source.successors
            if graph.is_exceptional(source, target)
        ]
        self.assertTrue(exceptional)

    def test_an_exceptional_edge_is_distinguished_from_normal_flow(self):
        graph = self._script_graph("try { 'a' } catch { 'b' }")
        normal = [
            (source, target)
            for source in graph.nodes
            for target in source.successors
            if not graph.is_exceptional(source, target)
        ]
        self.assertTrue(normal)

    def test_a_trap_is_reachable_from_a_statement_written_above_it(self):
        """
        A trap catches for the whole body it is declared in, statements before it included.
        """
        # Asserted as an edge from that specific statement. The resumption fan-out gives the trap
        # node a predecessor whatever the handler's scope is, so a non-empty predecessor list holds
        # even when the handler is installed only from the point the trap is written.
        tree, graph = self._tree_and_graph("'a'\ntrap { continue }\n'b'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertIn(graph.node_of(tree.body[0]), trap.predecessors)

    def test_a_trap_declared_inside_a_nested_block_guards_that_block(self):
        tree, graph = self._tree_and_graph("if ($c) { trap { 'h' }\n'a' }\n'b'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertIn(graph.node_of(tree.body[0].clauses[0][1].body[1]), trap.predecessors)
        self.assertIsNotNone(graph.node_of(trap.element.body.body[0]))

    def test_a_trap_declared_inside_a_nested_block_does_not_guard_the_body_around_it(self):
        """
        A trap belongs to the statement block it is written in, so an error raised outside that
        block is never offered to it. Reading it as a handler for the body around it hands errors to
        a trap no run reaches, and hands them to a type filter that guards nothing they can occur
        in.
        """
        tree, graph = self._tree_and_graph("if ($c) { trap { 'h' }\n'a' }\n'b'")
        trap = self._node_for(graph, Ps1TrapStatement)
        self.assertNotIn(trap, graph.node_of(tree.body[1]).successors)

    def test_a_trap_that_continues_resumes_in_the_body_it_guards(self):
        """
        `continue` inside a trap resumes at the statement after the one that threw, so the guarded
        body is reachable from it — it is not a loop back-jump and does not leave the body.
        """
        tree, graph = self._tree_and_graph("trap { continue }\n'a'\n'b'")
        jump = self._node_for(graph, Ps1ContinueStatement)
        reached = self._forward(jump)
        self.assertIn(id(graph.node_of(tree.body[1])), reached)
        self.assertIn(id(graph.node_of(tree.body[2])), reached)

    def test_a_trap_does_not_guard_its_own_body(self):
        """
        An error raised inside a trap body leaves the scope; it does not re-enter the handler it was
        raised in. An exceptional edge back to that handler would close a cycle through it that no
        run can take, and every statement of every trap body would read as repeating.
        """
        tree, graph = self._tree_and_graph("trap { return }\n'a'")
        trap = self._node_for(graph, Ps1TrapStatement)
        inside = graph.node_of(tree.body[0].body.body[0])
        self.assertNotIn(trap, inside.successors)
        self.assertFalse(CycleModel(build_control_flow_model(tree)).repeats(tree.body[0].body.body[0]))

    def test_a_trap_still_guards_the_statements_it_is_declared_beside(self):
        # The floor under the test above: building the trap bodies outside the handler must not take
        # the guarded body out with them.
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
        """
        `break` ends the trap after its body has run and hands the error on, so both the trap and
        the handler around it are on the path the error may take.
        """
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
        """
        `break` inside a `trap` body ends the trap and hands the error on, whatever construct the
        guarded block is written inside. Measured on 5.1: a `trap { break }` written in a `while`
        body stops the script at the raise, exactly as one written at script scope does.
        """
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
        """
        `continue` inside a `trap` body resumes the guarded block at the statement after the one
        that threw rather than starting the next iteration of the loop the block is written in.
        Measured on 5.1: every iteration of a `while` whose body raises under `trap { continue }`
        runs the statements written after the raise.
        """
        for source in [
            "while ($c) { trap { continue }\n'a'\n'b' }",
            "foreach ($i in $x) { trap { continue }\n'a'\n'b' }",
            "switch ($x) { 1 { trap { continue }\n'a'\n'b' } }",
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
        # Asserted as a direct edge from the first clause's body to the second's. Under EXCLUSIVE
        # the head still reaches every arm, so counting the head's successors measures nothing;
        # only an arm-to-arm edge distinguishes the answers.
        tree, graph = self._tree_and_graph("switch ($x) { 1 { 'a' } 2 { 'b' } }")
        clauses = tree.body[0].clauses
        first = graph.node_of(clauses[0][1].body[0])
        second = graph.node_of(clauses[1][1].body[0])
        self.assertIn(second, first.successors)

    def test_a_switch_clause_may_be_skipped_when_a_later_one_matches(self):
        """
        The path in which the first and third clauses match and the second does not.
        """
        # Asserted as a *direct* edge rather than as reachability. Under C-style fallthrough the
        # third clause is reachable from the first anyway — through the second — so a reachability
        # assertion passes whichever answer the builder gives and measures nothing. The edge that
        # only PowerShell's semantics produce is the one that skips the clause in between.
        tree = Ps1Parser("switch ($x) { 1 { 'a' } 2 { 'b' } 3 { 'c' } }").parse()
        graph = build_ps1_control_flow(tree)[id(tree)]
        clauses = tree.body[0].clauses
        first = graph.node_of(clauses[0][1].body[0])
        third = graph.node_of(clauses[2][1].body[0])
        self.assertIsNotNone(first)
        self.assertIsNotNone(third)
        self.assertIn(third, first.successors)

    def test_continue_in_a_switch_clause_advances_to_the_next_input_value(self):
        """
        A PowerShell `switch` enumerates its input, so `continue` inside one re-enters the switch
        rather than the loop around it.
        """
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

    def test_a_trap_that_declines_hands_the_error_to_the_trap_written_after_it(self):
        """
        The counterfactual of a handler is where its errors would go if it were not written, and a
        set is consulted in order, so for every member but the last that is the member after it.
        """
        tree, graph = self._tree_and_graph(
            "trap { 'o' }\nif ($c) { trap { 'a' }\ntrap { 'b' }\n'x' }")
        first, second = tree.body[1].clauses[0][1].body[:2]
        self.assertIs(
            graph.fallback_of(self._required_node(graph, first)),
            self._required_node(graph, second),
        )
        self.assertIs(
            graph.fallback_of(self._required_node(graph, second)),
            self._required_node(graph, tree.body[0]),
        )

    def test_a_catch_clause_that_declines_hands_the_error_to_the_clause_written_after_it(self):
        tree, graph = self._tree_and_graph(
            "try { 'x' } catch [System.IO.IOException] { 'a' } catch { 'b' }")
        first, second = tree.body[0].catch_clauses
        self.assertIs(
            graph.fallback_of(self._required_node(graph, first)),
            self._required_node(graph, second),
        )
        self.assertIs(graph.fallback_of(self._required_node(graph, second)), graph.exit)

    def test_a_switch_of_empty_clauses_stays_linear_in_the_number_of_clauses(self):
        """
        The frontier a clause carries into the next one must not accumulate duplicates.
        """
        # An empty clause hands its incoming frontier back unchanged, so concatenating the two
        # doubles it per clause. The last clause is deliberately not empty: that is where the
        # accumulated frontier turns into edges, and without one the doubling stays invisible in a
        # list nobody counts. At twenty clauses an unguarded builder wires 2**20 of them.
        clauses = ' '.join(F'{index} {{ }}' for index in range(20))
        graph = self._script_graph(F"switch ($x) {{ {clauses} 20 {{ 'z' }} }}")
        edges = sum(len(node.successors) for node in graph.nodes)
        self.assertLess(edges, 200)

    def test_a_trap_that_continues_stays_linear_in_the_size_of_the_body_it_guards(self):
        """
        A `trap` that resumes reaches every statement of the body it guards, which is a relation of
        size `resumes * guarded` and must not be spelled as that many edges.
        """
        # Written as one edge per pair, a body of eighty statements costs thousands, and every
        # reachability walk over the graph pays it — one real sample reached half a million edges
        # and three minutes of deobfuscation. The bound sits far above the linear count and far
        # below the quadratic one, so it moves only if the shape regresses.
        body = ' '.join(F"'s{index}';" for index in range(80))
        graph = self._script_graph(F'trap {{ continue }}; {body}')
        edges = sum(len(node.successors) for node in graph.nodes)
        self.assertLess(edges, 500)

    def test_a_resuming_trap_nested_in_another_costs_the_same_edges_at_every_level(self):
        """
        The relation each level of nesting adds is again `resumes * guarded`, and a level that names
        the nodes of the levels below it pays that relation once per level it is written inside.
        """
        # Written that way, a script nested sixty-four deep costs 12867 edges where the shape itself
        # holds 960, and doubling the depth quadruples the count — the same failure class the hub was
        # built to prevent, reached through nesting rather than through the size of one block. Both
        # halves are named against the innermost level alone, so the cost per level is a constant and
        # the count below is exactly proportional to the depth.
        def nested(depth: int) -> str:
            source = "trap { continue }; 'x'; 'y'"
            for _ in range(depth - 1):
                source = 'trap { continue }; if ($true) { ' + source + ' }'
            return source

        self.assertEqual(
            {depth: self._edge_count(nested(depth)) for depth in (2, 8, 32, 64)},
            {2: 30, 8: 120, 32: 480, 64: 960},
        )

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
        """
        A construct whose body the builder drops leaves no node behind, and a graph that never
        created a node is not the same as one whose node is unreachable — no edge invariant sees it.
        """
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
        # `Ps1Code` fills begin/process/end instead of `body`, and reading only `body` would report
        # a graph with no statements for a function that runs a great deal.
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
        """
        A body is one unit for both layers: the same braces introduce a scope and a graph.
        """
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
        """
        A block is a value where it is written and runs when it is invoked, so nothing in it is
        guaranteed to have run by the time the statement after the block does. Asserted in both
        directions and against a statement *before* the block as well: a model that placed the
        block's statements on the enclosing graph would order them against the code after it,
        which is the claim that licenses carrying a value across the block.
        """
        tree = Ps1Parser("$a = 1\n1..3 | ForEach-Object { $b = 2 }\n$c = 3").parse()
        dominators = DominatorModel(build_control_flow_model(tree))
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        inside = block.body[0]
        self.assertFalse(dominators.dominates(inside, tree.body[2]))
        self.assertFalse(dominators.dominates(tree.body[0], inside))

    def test_two_statements_in_one_script_block_are_ordered_against_each_other(self):
        """
        The counterpart of the test above: refusing to place the block's statements at all would
        satisfy that one while losing every ordering the block does have.
        """
        tree = Ps1Parser("1..3 | ForEach-Object { $b = 2\n$c = 3 }").parse()
        dominators = DominatorModel(build_control_flow_model(tree))
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        self.assertTrue(dominators.dominates(block.body[0], block.body[1]))
        self.assertFalse(dominators.dominates(block.body[1], block.body[0]))

    def test_a_switch_arm_can_be_reached_again_because_the_switch_enumerates_its_input(self):
        """
        `switch ($array)` runs its clauses once per element, so a store in an arm is not a store
        that happens once.
        """
        tree = Ps1Parser("switch ($x) { 1 { 'a' } }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        self.assertTrue(cycles.repeats(tree.body[0].clauses[0][1].body[0]))

    def test_a_branch_of_an_if_is_not_reached_again(self):
        """
        The floor under the switch test above: a model that called every arm of every multi-way
        construct repeated would satisfy it while saying nothing about iteration.
        """
        tree = Ps1Parser("if ($x) { 'a' } else { 'b' }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        self.assertFalse(cycles.repeats(tree.body[0].clauses[0][1].body[0]))
        self.assertFalse(cycles.repeats(tree.body[0].else_block.body[0]))

    def test_a_for_loop_initializer_does_not_repeat_with_the_body_it_precedes(self):
        """
        Being written inside the `for` is not being on its cycle: the initializer runs once, before
        the head, and only the condition, iterator and body are reached again.
        """
        tree = Ps1Parser("for ($q = 0; $q -lt 3; $q++) { 'a' }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        loop = tree.body[0]
        self.assertFalse(cycles.repeats(loop.initializer))
        self.assertTrue(cycles.repeats(loop.condition))
        self.assertTrue(cycles.repeats(loop.iterator))
        self.assertTrue(cycles.repeats(loop.body.body[0]))

    def test_a_script_block_written_inside_a_loop_repeats_with_the_loop(self):
        """
        The block's own graph is acyclic; the repetition belongs to the body it is written in.
        """
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
        """
        It is evaluated when the block is invoked, which is not where the block is written.
        """
        tree = Ps1Parser("$a = 1\n$f = { param($p = 2) $p }\n$c = 3").parse()
        flow = build_control_flow_model(tree)
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        default = block.param_block.parameters[0].default_value
        self.assertIsNotNone(default)
        self.assertIsNone(flow.locate(default))

    def test_an_element_the_graphs_do_not_place_is_reported_as_repeating(self):
        """
        A parameter default is evaluated once per invocation of its block, and the graphs hold no
        invocation. Reporting it as running once would be a claim these graphs cannot support, and
        a caller asking whether a single-visit fact still holds would act on it.
        """
        tree = Ps1Parser("while ($c) { & { param($p = ($x = 1)) $p } }").parse()
        flow = build_control_flow_model(tree)
        cycles = CycleModel(flow)
        block = next(n for n in tree.walk_in_order() if isinstance(n, Ps1ScriptBlock))
        default = block.param_block.parameters[0].default_value
        self.assertIsNone(flow.locate(default))
        self.assertTrue(cycles.repeats(default))

    def test_a_function_body_repeats_with_the_loop_its_definition_is_written_in(self):
        """
        The other spelling of the owner walk: a function body's graph is reached from its
        definition, which is a statement of the enclosing graph, where a bare block is reached from
        the statement that merely mentions it.
        """
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
        """
        The head is then one node reaching only itself, which a component-size test reads as
        acyclic.
        """
        tree = Ps1Parser("switch ($x) { 1 { } }").parse()
        cycles = CycleModel(build_control_flow_model(tree))
        self.assertTrue(cycles.repeats(tree.body[0]))


class TestPs1ACatchWhoseTypeFilterCannotBeReadIsNotUnfiltered(_Ps1ControlFlowGraphs):
    """
    A `catch` carrying no type filter takes every error, and one carrying a filter takes only what
    the filter matches — so whether a throw the guarded block makes can get past the clause is
    decided by reading the filter. `Ps1CatchClause.types` spells *no filter written* and *a filter
    this could not read* the same way, as the empty list, so `Ps1CatchClause.filtered` records that
    a bracket was written and keeps the two apart.

    5.1 rejects `catch [] { }` outright, reporting `MissingTypename`, so the conflation is out of
    reach of any script a host will run. What pins it is the direction it would err in: a clause
    read as taking everything closes the exceptional edge the construct would otherwise pass
    outward, and an enclosing handler then looks like one no error reaches. An unread filter takes
    nothing certain, so the error leaves the construct.
    """

    def _guarded_statement(self, source: str) -> tuple[ControlFlowGraph, Statement]:
        tree, graph = self._tree_and_graph(source)
        construct = tree.body[0]
        if not isinstance(construct, Ps1TryCatchFinally):
            self.fail('the script does not open with a try construct')
        guarded = get_body(construct.try_block)
        if not guarded:
            self.fail('the try block holds no statement')
        return graph, guarded[0]

    def test_a_catch_carrying_a_filter_lets_the_error_leave_the_construct(self):
        graph, guarded = self._guarded_statement(
            "try { 'a' } catch [System.IO.IOException] { 'b' }")
        self.assertIn(graph.exit, self._reached_by_an_error_at(graph, guarded))

    def test_a_catch_whose_filter_is_an_empty_bracket_lets_the_error_leave_the_construct(self):
        graph, guarded = self._guarded_statement("try { 'a' } catch [] { 'b' }")
        self.assertIn(graph.exit, self._reached_by_an_error_at(graph, guarded))


class TestPs1TrapResumptionIsCarriedForwardAsWellAsThroughTheHub(_Ps1ControlFlowGraphs):
    """
    A `trap { continue }` resumes the block it guards at the statement *after* the one that threw.
    Measured on 5.1: `trap { continue }; Write-Host 'one'; throw 'e'; Write-Host 'three'` writes
    `one` once and then `three`, so nothing above the raiser runs again.

    The graph cannot know which statement threw and so carries the shape twice — see
    `refinery.lib.scripts.analysis.cfg.CfgEdge`. The tests above read the over-approximate half,
    which claims a resumption reaches every statement of the block; these read the precise half,
    which a flood follows through `reachable_forward_from_any` and which is what stops a leak late
    in a guarded script from poisoning the whole of it.
    """

    @staticmethod
    def _resumption_landings(graph: ControlFlowGraph) -> list[CfgNode]:
        """
        The statements a resuming handler may carry on at, read off the hub the graph joins them
        through: every element node a hub node reaches.
        """
        return [
            target
            for node in graph.nodes if node.element is None
            for target in node.successors
            if target.element is not None
            and graph.edge_kind(node, target) & CfgEdge.RESUMPTION_HUB
        ]

    def test_a_guarded_statement_resumes_below_itself_and_not_above(self):
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\n'two'\n'three'")
        one, two, three = (self._required_node(graph, tree.body[k]) for k in (1, 2, 3))
        forward = reachable_forward_from_any(graph, [two])
        self.assertIn(id(three), forward)
        self.assertNotIn(id(one), forward)
        self.assertIn(id(one), reachable_from_any([two]))

    def test_a_terminator_reaches_the_statement_resumption_lands_on(self):
        """
        The path only resumption draws. A `throw` has no normal successor at all, so the statement
        after it is reachable from it through nothing else — and a walk that declined the hub
        without this edge would report the rest of the block unreachable and vouch for every read
        in it.
        """
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\nthrow 'x'\n'three'")
        one, raiser, three = (self._required_node(graph, tree.body[k]) for k in (1, 2, 3))
        forward = reachable_forward_from_any(graph, [raiser])
        self.assertIn(id(three), forward)
        self.assertNotIn(id(one), forward)

    def test_resumption_lands_where_control_enters_the_next_statement(self):
        """
        A `try` builds its handler entry before the body it guards, so the point control resumes at
        cannot be read off the order the nodes were created in: that answers the `catch` clause and
        leaves the guarded body reachable only through the hub, which is the backward reach this
        half exists to remove.
        """
        tree, graph = self._tree_and_graph(
            "trap { continue }\n'one'\nthrow 'x'\ntry { 'body' } catch { 'clause' }")
        raiser = self._required_node(graph, tree.body[2])
        guarded = tree.body[3]
        self.assertIn(
            id(self._required_node(graph, guarded.try_block.body[0])),
            reachable_forward_from_any(graph, [raiser]),
        )

    def test_a_raise_in_the_last_guarded_statement_resumes_past_the_block(self):
        """
        Measured on 5.1: `if ($true) { trap { continue }; Write-Host 'in'; throw 'e' };
        Write-Host 'after'` writes `in` and then `after`. Resumption past the end of a guarded block
        carries on with whatever follows the *block*, which for a nested one is not the end of the
        body — so the fall-off belongs in the frontier the caller threads and not on the body exit.
        """
        tree, graph = self._tree_and_graph(
            "if ($c) { trap { continue }\n'in'\nthrow 'x' }\n'after'")
        guarded = tree.body[0].clauses[0][1]
        raiser = self._required_node(graph, guarded.body[2])
        self.assertIn(
            id(self._required_node(graph, tree.body[1])),
            reachable_forward_from_any(graph, [raiser]),
        )

    def test_a_statement_of_the_handler_is_flooded_through_the_hub_instead(self):
        """
        The forward edges join guarded statements to one another, and a statement of the handler is
        on neither end of one: a precise walk started there would stop at the resumption point,
        where the run carries on into the block. The graph says so and the flood falls back.
        """
        tree, graph = self._tree_and_graph("trap { 'handled'\ncontinue }\n'one'\n'two'")
        handled = self._required_node(graph, tree.body[0].body.body[0])
        forward = reachable_forward_from_any(graph, [handled])
        self.assertTrue(handled.is_hub_bound)
        self.assertFalse(self._required_node(graph, tree.body[1]).is_hub_bound)
        self.assertIn(id(self._required_node(graph, tree.body[1])), forward)
        self.assertIn(id(self._required_node(graph, tree.body[2])), forward)

    def test_every_door_onto_the_forward_reading_falls_back_for_such_a_statement(self):
        """
        The fallback belongs to the walk and not to one function that wraps it, so the answer does
        not depend on which of the two entry points a consumer happened to reach the graph through.
        `refinery.lib.scripts.analysis.reaching.ReachabilityQuery` is the other one, and a binder it
        floods from inside a handler body has to reach the block the handler resumes into.
        """
        tree, graph = self._tree_and_graph("trap { 'handled'\ncontinue }\n'one'\n'two'")
        handled = self._required_node(graph, tree.body[0].body.body[0])
        self.assertEqual(
            flood([handled], forward=True, projection=Projection.FORWARD),
            set(reachable_forward_from_any(graph, [handled])),
        )

    def test_a_forward_walk_seeded_at_a_hub_leaves_it_by_no_edge(self):
        """
        The hub is declined as a *node* under the forward reading, which is what
        `refinery.lib.scripts.analysis.cfg.Projection.successors` says by returning nothing for one.
        A sweep that screened only the nodes it arrived at would agree everywhere except here, and
        a caller holding a hub would be handed the over-approximate closure under a forward label.
        """
        tree, graph = self._tree_and_graph("trap { continue }\n'one'\n'two'")
        one = self._required_node(graph, tree.body[1])
        hub, = (target for target in one.predecessors if target.is_resumption_hub)
        self.assertEqual(flood([hub], forward=True, projection=Projection.FORWARD), {id(hub)})
        self.assertEqual(flood([hub], forward=False, projection=Projection.FORWARD), {id(hub)})

    def test_a_hub_of_a_set_nested_in_a_handler_body_is_not_also_hub_bound(self):
        """
        The two flags are the two readings of one construct and no node is both: a hub is the node
        the forward walk declines to stand at, and a hub-bound node is one it fails to reach and
        floods coarsely instead. A handler body naming everything built while it was walked names
        the hub of any resumable block written inside it, which is neither of those things.
        """
        _, graph = self._tree_and_graph(
            "trap { if ($q) { trap { continue }\n'p' }\ncontinue }\n'x'\n'y'")
        self.assertEqual(
            [node for node in graph.nodes if node.is_hub_bound and node.is_resumption_hub], [])

    def test_a_forward_flood_refuses_a_source_belonging_to_another_body(self):
        """
        The precondition made a refusal rather than a comment. Hub and hub-bound are recorded per
        graph, so a node of another body reads as neither and would slip onto the plain-flow route;
        the walk raises instead.
        """
        tree = Ps1Parser("trap { continue }\nfunction f { 'in' }\n'out'").parse()
        graphs = build_ps1_control_flow(tree)
        script = graphs[id(tree)]
        definition = next(
            node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        inside = self._required_node(graphs[id(definition.body)], definition.body.body[0])
        with self.assertRaises(ValueError):
            reachable_forward_from_any(script, [inside])

    def test_a_resumption_edge_is_taken_on_a_throw_and_carries_no_error(self):
        """
        The handler swallowed the error, so nothing travels a resumption edge and `faults` must not
        read one as a route an error took; the statement it leaves is nonetheless the one that did
        not finish, so `dataflow` must not read a store it makes as done.
        """
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
        """
        The asymmetry of the hub, and the answer it costs to get wrong. What reaches the hub is the
        handler body running to its end — a statement that *completed*, whose store did happen — so
        that edge is plain. Reading it as taken-on-a-throw empties the completed-exit walk of every
        store a `trap` body makes, and no read below one could observe any of them.
        """
        tree, graph = self._tree_and_graph("trap { $x = 'b'\ncontinue }\n'one'")
        jump = self._node_for(graph, Ps1ContinueStatement)
        hub, = (target for target in jump.successors if target.is_resumption_hub)
        self.assertFalse(graph.raise_taken(jump, hub))
        self.assertTrue(graph.raise_taken(hub, self._required_node(graph, tree.body[1])))

    def test_a_trap_written_below_a_statement_leaves_one_resumption_point(self):
        """
        A `trap` declaration builds nothing and hands its frontier back, the resumption slot of the
        statement above it among it. Threading that frontier on without dropping the repetition
        draws the slot's edge into the next statement once per declaration that passed it along.
        """
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
        """
        What licenses `reachable_forward_from_any` declining the hub. The forward edges may stand
        for the hub's runs only if every statement the hub lands on carries one of its own —
        otherwise the precise walk stops where the run carries on, and a read a leak precedes is
        granted. A statement the graph calls `is_hub_bound` is the exception the flood already
        handles by walking the hub instead.
        """
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
        """
        What `mark_hub_bound` is recorded for, asserted rather than trusted. The marking is what
        sends a flood seeded inside a `trap` body through the hub instead of the forward edges, and
        it is recorded from the nodes each handler body built: one missed is the silent direction —
        a leak written in a handler body would stop poisoning the block the handler resumes into,
        and every read in it would be granted.

        Asked of everything a body owns and not only the statements written at its top level,
        because a leak nested in an `if` inside the body reaches the same statements a leak beside
        it does.
        """
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
        """
        The property the test above only tests the existence of an edge for, and the one the flood
        is sound under: a leak written at a guarded statement must poison every statement of the
        block after it, whatever the statement is built out of. Shapes whose guarded block holds
        several statements inside a construct the corpus above only ever guards one statement of —
        a loop body, a `switch` arm, a `catch` and a `finally` body.
        """
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
    """
    A resumable block claims every node built while it is open, so leaving it has to end that claim
    on every path out of it. A build that raises part-way through a guarded block would otherwise
    leave the frame on the stack, and every node built afterwards would draw both halves of
    resumption against a handler that no longer guards anything.
    """

    def test_a_node_built_after_an_error_left_a_resumable_block_carries_no_resumption(self):
        tree = Ps1Parser("'a'\n'b'").parse()
        builder = CfgBuilder(tree)
        guarded, following = tree.body
        with self.assertRaises(_BuildFailed):
            with builder.resumption([builder.detached_node(guarded)]):
                raise _BuildFailed
        node = builder.detached_node(following)
        self.assertEqual((node.predecessors, node.successors), ([], []))
