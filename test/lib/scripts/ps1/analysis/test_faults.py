from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts import Statement
from refinery.lib.scripts.analysis.cfg import ControlFlowModel
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.effects import statement_can_raise
from refinery.lib.scripts.ps1.analysis.faults import (
    Ps1FaultReach,
    Ps1FaultRouting,
    build_fault_reach,
    ends_the_script,
    handler_acts,
)
from refinery.lib.scripts.ps1.ast import get_body, resolve_command_name
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1CommandInvocation,
    Ps1Script,
    Ps1SubExpression,
    Ps1TrapStatement,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _parse(source: str) -> Ps1Script:
    return Ps1Parser(cleandoc(source)).parse()


def _model(source: str) -> tuple[Ps1Script, Ps1FaultReach]:
    tree = _parse(source)
    return tree, build_fault_reach(build_control_flow_model(tree))


def _may_raise(reach: Ps1FaultReach):
    """
    The real fault-possibility predicate the transpose is injected with, so the unit tests judge a
    `trap` by the raisers a removal site sees rather than by every statement its block offers.
    """
    return lambda node: statement_can_raise(node, reach)


#: The subexpression that `TestPs1ATrapWrittenInASubexpressionGuardsThatSubexpression` is measured
#: over, and whose shape `TestPs1TheBracketFixturesHoldTheShapeTheirPinsAssume` keeps.
_TRAP_IN_A_SUBEXPRESSION = "$x = $(trap { 'h' }; 'a')"

#: The array expression twin of `_TRAP_IN_A_SUBEXPRESSION`.
_TRAP_IN_AN_ARRAY_EXPRESSION = "$x = @(trap { 'h' }; 'a')"


class TestPs1FaultRoutingOffersTheRaiseToTheHandlersThatGuardIt(TestBase):

    def test_a_raise_in_a_try_block_is_offered_to_that_constructs_catch_clause(self):
        tree, reach = _model("try { 'a' } catch { 'b' }")
        construct = tree.body[0]
        clause, = construct.catch_clauses
        self.assertEqual(reach.routing_at(construct.try_block.body[0]).handlers, (clause,))

    def test_a_raise_after_the_construct_is_offered_to_no_catch_clause(self):
        tree, reach = _model("""
            try { 'a' } catch { 'b' }
            'c'
        """)
        self.assertEqual(reach.routing_at(tree.body[1]).handlers, ())

    def test_every_catch_clause_of_the_construct_is_offered_the_raise(self):
        tree, reach = _model("try { 'a' } catch [System.IO.IOException] { 'x' } catch { 'y' }")
        construct = tree.body[0]
        self.assertEqual(
            set(reach.routing_at(construct.try_block.body[0]).handlers),
            set(construct.catch_clauses),
        )

    def test_a_trap_is_offered_a_raise_written_above_it(self):
        tree, reach = _model("""
            'a'
            trap { 'h' }
        """)
        self.assertEqual(reach.routing_at(tree.body[0]).handlers, (tree.body[1],))

    def test_a_trap_is_offered_a_raise_from_a_block_nested_in_the_one_it_guards(self):
        tree, reach = _model("""
            trap { 'h' }
            if ($c) { 'a' }
        """)
        nested = tree.body[1].clauses[0][1].body[0]
        self.assertEqual(reach.routing_at(nested).handlers, (tree.body[0],))

    def test_a_trap_is_not_offered_a_raise_written_outside_the_block_it_belongs_to(self):
        tree, reach = _model("""
            if ($c) {
                trap { 'h' }
                'a'
            }
            'b'
        """)
        self.assertEqual(reach.routing_at(tree.body[1]).handlers, ())

    def test_only_the_innermost_untyped_trap_is_offered_the_raise(self):
        tree, reach = _model("""
            trap { 'o' }
            if ($c) {
                trap { 'i' }
                'a'
            }
        """)
        guarded = tree.body[1].clauses[0][1]
        self.assertEqual(reach.routing_at(guarded.body[1]).handlers, (guarded.body[0],))

    def test_a_typed_innermost_trap_passes_the_raise_on_to_the_trap_around_it(self):
        tree, reach = _model("""
            trap [System.IO.IOException] { 'o' }
            if ($c) {
                trap [System.IO.IOException] { 'i' }
                'a'
            }
        """)
        guarded = tree.body[1].clauses[0][1]
        self.assertEqual(
            set(reach.routing_at(guarded.body[1]).handlers),
            {guarded.body[0], tree.body[0]},
        )

    def test_an_untyped_catch_clause_passes_the_raise_on_to_nothing(self):
        tree, reach = _model("""
            try {
                try { 'a' } catch { 'i' }
            } catch { 'o' }
        """)
        inner = tree.body[0].try_block.body[0]
        self.assertEqual(
            reach.routing_at(inner.try_block.body[0]).handlers,
            (inner.catch_clauses[0],),
        )

    def test_a_narrow_catch_clause_passes_the_raise_on_to_what_guards_the_construct(self):
        tree, reach = _model("""
            try {
                try { 'a' } catch [System.IO.IOException] { 'i' }
            } catch { 'o' }
        """)
        outer = tree.body[0]
        inner = outer.try_block.body[0]
        self.assertEqual(
            set(reach.routing_at(inner.try_block.body[0]).handlers),
            {inner.catch_clauses[0], outer.catch_clauses[0]},
        )


class TestPs1FaultLeavesTheBody(TestBase):

    def test_a_raise_that_nothing_guards_stays_in_the_body(self):
        tree, reach = _model("'a'")
        self.assertFalse(reach.leaves_the_body(tree.body[0]))

    def test_a_catch_clause_lets_the_raise_past_exactly_when_its_filter_is_narrower_than_exception(
        self,
    ):
        broad, broad_reach = _model("try { 'a' } catch [System.Exception] { 'b' }")
        narrow, narrow_reach = _model("try { 'a' } catch [System.IO.IOException] { 'b' }")
        self.assertFalse(broad_reach.leaves_the_body(broad.body[0].try_block.body[0]))
        self.assertTrue(narrow_reach.leaves_the_body(narrow.body[0].try_block.body[0]))

    def test_a_trap_lets_the_raise_past_exactly_when_it_carries_a_type_filter(self):
        untyped, untyped_reach = _model("""
            trap { 'h' }
            'a'
        """)
        typed, typed_reach = _model("""
            trap [System.IO.IOException] { 'h' }
            'a'
        """)
        self.assertFalse(untyped_reach.leaves_the_body(untyped.body[1]))
        self.assertTrue(typed_reach.leaves_the_body(typed.body[1]))

    def test_a_trap_lets_the_raise_past_when_it_breaks_but_not_when_it_continues(self):
        rethrowing, rethrowing_reach = _model("""
            trap { break }
            'a'
        """)
        resuming, resuming_reach = _model("""
            trap { continue }
            'a'
        """)
        self.assertTrue(rethrowing_reach.leaves_the_body(rethrowing.body[1]))
        self.assertFalse(resuming_reach.leaves_the_body(resuming.body[1]))

    def test_a_point_the_graphs_cannot_place_is_answered_as_leaving_the_body(self):
        _, reach = _model("'a'")
        elsewhere = _parse("'z'").body[0]
        self.assertIsNone(reach.routing_at(elsewhere))
        self.assertTrue(reach.leaves_the_body(elsewhere))


class TestPs1ATrapDisposesOfTheErrorWhateverConstructEnclosesItsBlock(TestBase):
    """
    A `trap` body is a scope of its own for `break` and `continue`, so what the set does with an
    error is decided by the body alone and not by the loop or `switch` the guarded block happens to
    be written inside. Measured on 5.1: a `trap { break }` written in a `while` body stops the
    script where the raise is, exactly as one written at script scope does, and a
    `trap { continue }` written there resumes at the statement after the raise on every iteration.
    """

    _SPELLINGS = [
        "trap { %s }\n'a'",
        "while ($c) {\n  trap { %s }\n  'a'\n}",
        "do {\n  trap { %s }\n  'a'\n} while ($c)",
        "for ($i = 0; $i -lt 3; $i++) {\n  trap { %s }\n  'a'\n}",
        "foreach ($i in $x) {\n  trap { %s }\n  'a'\n}",
        "switch ($x) {\n  1 {\n    trap { %s }\n    'a'\n  }\n}",
    ]

    def _trap_and_the_raise_it_guards(
        self, source: str
    ) -> tuple[Ps1FaultReach, Ps1TrapStatement, Statement]:
        tree, reach = _model(source)
        for node in tree.walk_in_order():
            if isinstance(node, Ps1TrapStatement):
                block = get_body(node.parent)
                if block is not None:
                    return reach, node, block[1]
        self.fail('no trap of this script is written in a statement block')

    def test_a_trap_that_breaks_lets_the_raise_past_wherever_its_block_is_written(self):
        for spelling in self._SPELLINGS:
            source = spelling % 'break'
            with self.subTest(source):
                reach, trap, raised = self._trap_and_the_raise_it_guards(source)
                self.assertEqual(reach.routing_at(raised).handlers, (trap,))
                self.assertTrue(reach.leaves_the_body(raised))
                self.assertTrue(reach.observed_at(raised))

    def test_a_trap_that_continues_keeps_the_raise_wherever_its_block_is_written(self):
        for spelling in self._SPELLINGS:
            source = spelling % 'continue'
            with self.subTest(source):
                reach, trap, raised = self._trap_and_the_raise_it_guards(source)
                self.assertEqual(reach.routing_at(raised).handlers, (trap,))
                self.assertFalse(reach.leaves_the_body(raised))
                self.assertFalse(reach.observed_at(raised))


class TestPs1HandlerActs(TestBase):

    def test_a_catch_clause_acts_exactly_when_its_body_is_not_empty(self):
        acting, = _parse("try { 'a' } catch { 'b' }").body[0].catch_clauses
        swallowing, = _parse("try { 'a' } catch { }").body[0].catch_clauses
        self.assertTrue(handler_acts(acting))
        self.assertFalse(handler_acts(swallowing))

    def test_a_trap_holding_only_an_unlabelled_jump_does_not_act(self):
        self.assertFalse(handler_acts(_parse('trap { break }').body[0]))
        self.assertFalse(handler_acts(_parse('trap { continue }').body[0]))

    def test_a_trap_holding_a_labelled_jump_acts(self):
        self.assertTrue(handler_acts(_parse('trap { break outer }').body[0]))
        self.assertTrue(handler_acts(_parse('trap { continue outer }').body[0]))

    def test_a_trap_whose_body_is_a_bare_value_acts(self):
        self.assertTrue(handler_acts(_parse('trap { 5 }').body[0]))


class TestPs1FaultIsObservedWhereAHandlerActsOrATrapMayDecline(TestBase):

    def test_a_raise_that_nothing_guards_is_not_observed(self):
        tree, reach = _model("'a'")
        self.assertFalse(reach.observed_at(tree.body[0]))

    def test_a_raise_is_observed_by_a_catch_clause_with_a_body_but_not_by_an_empty_one(self):
        acting, acting_reach = _model("try { 'a' } catch { 'b' }")
        swallowing, swallowing_reach = _model("try { 'a' } catch { }")
        self.assertTrue(acting_reach.observed_at(acting.body[0].try_block.body[0]))
        self.assertFalse(swallowing_reach.observed_at(swallowing.body[0].try_block.body[0]))

    def test_a_raise_guarded_by_a_trap_that_only_continues_is_not_observed(self):
        tree, reach = _model("""
            trap { continue }
            'a'
        """)
        self.assertFalse(reach.observed_at(tree.body[1]))

    def test_a_raise_guarded_by_a_trap_that_only_breaks_is_observed_although_it_does_not_act(self):
        tree, reach = _model("""
            trap { break }
            'a'
        """)
        self.assertFalse(handler_acts(tree.body[0]))
        self.assertTrue(reach.observed_at(tree.body[1]))

    def test_a_raise_guarded_by_a_typed_trap_is_observed_because_the_set_may_decline_it(self):
        tree, reach = _model("""
            trap [System.IO.IOException] { continue }
            'a'
        """)
        self.assertFalse(handler_acts(tree.body[0]))
        self.assertTrue(reach.observed_at(tree.body[1]))

    def test_a_raise_guarded_by_a_trap_whose_body_is_a_bare_value_is_observed(self):
        tree, reach = _model("""
            trap { 5 }
            'a'
        """)
        self.assertTrue(reach.observed_at(tree.body[1]))

    def test_a_point_the_graphs_cannot_place_is_answered_as_observed(self):
        _, reach = _model("'a'")
        elsewhere = _parse("'z'").body[0]
        self.assertIsNone(reach.routing_at(elsewhere))
        self.assertTrue(reach.observed_at(elsewhere))


class TestPs1FaultPointsIn(TestBase):

    def test_a_simple_statement_is_the_only_point_it_holds(self):
        tree, reach = _model("'a'")
        self.assertEqual(list(reach.points_in(tree.body[0])), [tree.body[0]])

    def test_a_while_loop_is_a_point_of_its_own_beside_each_statement_of_its_body(self):
        tree, reach = _model("""
            while ($c) {
                'a'
                'b'
            }
        """)
        loop = tree.body[0]
        self.assertEqual(set(reach.points_in(loop)), {loop, *loop.body.body})

    def test_a_counted_loop_holds_its_three_parts_and_its_body_rather_than_itself(self):
        tree, reach = _model("for ($i = 0; $i -lt 3; $i++) { 'a' }")
        loop = tree.body[0]
        self.assertIsNone(reach.routing_at(loop))
        self.assertEqual(set(reach.points_in(loop)), {
            loop.initializer,
            loop.condition,
            loop.iterator,
            loop.body.body[0],
        })

    def test_an_if_chain_holds_a_point_per_test_beside_the_statements_of_its_branches(self):
        tree, reach = _model("if ($c) { 'a' } elseif ($d) { 'b' } else { 'e' }")
        branch = tree.body[0]
        (_, first), (second_test, second) = branch.clauses
        self.assertEqual(set(reach.points_in(branch)), {
            branch,
            second_test,
            first.body[0],
            second.body[0],
            branch.else_block.body[0],
        })

    def test_a_try_construct_holds_its_clauses_and_blocks_rather_than_itself(self):
        tree, reach = _model("try { 'a' } catch { 'b' } finally { 'c' }")
        construct = tree.body[0]
        clause, = construct.catch_clauses
        self.assertIsNone(reach.routing_at(construct))
        self.assertEqual(set(reach.points_in(construct)), {
            construct.try_block.body[0],
            clause,
            clause.body.body[0],
            construct.finally_block,
            construct.finally_block.body[0],
        })

    def test_a_construct_holds_the_points_of_a_construct_nested_in_it(self):
        tree, reach = _model("""
            try {
                if ($c) { 'a' }
            } catch { 'b' }
        """)
        construct = tree.body[0]
        clause, = construct.catch_clauses
        branch = construct.try_block.body[0]
        self.assertEqual(set(reach.points_in(construct)), {
            branch,
            branch.clauses[0][1].body[0],
            clause,
            clause.body.body[0],
        })

    def test_a_subtree_the_graphs_model_nowhere_holds_no_points(self):
        _, reach = _model("'a'")
        elsewhere = _parse("'z'").body[0]
        self.assertEqual(list(reach.points_in(elsewhere)), [])


class TestPs1RemovingATrapIsJudgedByWhereItsErrorsWouldGoInstead(TestBase):

    def test_a_trap_matters_only_while_its_block_still_holds_something_that_may_raise(self):
        guarding, guarding_reach = _model("""
            trap { 'o' }
            if ($c) {
                trap { continue }
                [int]'a'
            }
        """)
        alone, alone_reach = _model("""
            trap { 'o' }
            if ($c) {
                trap { continue }
            }
        """)
        self.assertTrue(guarding_reach.removing_a_handler_is_observed(
            guarding.body[1].clauses[0][1].body[0], _may_raise(guarding_reach)))
        self.assertFalse(alone_reach.removing_a_handler_is_observed(
            alone.body[1].clauses[0][1].body[0], _may_raise(alone_reach)))

    def test_a_trap_at_script_scope_may_go_where_the_only_statement_it_guards_cannot_raise(self):
        tree, reach = _model("""
            trap { 'h' }
            'a'
        """)
        self.assertTrue(reach.observed_at(tree.body[1]))
        self.assertFalse(reach.removing_a_handler_is_observed(tree.body[0], _may_raise(reach)))

    def test_a_resuming_trap_in_a_try_block_may_go_only_where_the_catch_clause_swallows(self):
        acting, acting_reach = _model("""
            try {
                trap { continue }
                [int]'a'
            } catch { 'c' }
        """)
        swallowing, swallowing_reach = _model("""
            try {
                trap { continue }
                [int]'a'
            } catch { }
        """)
        self.assertTrue(acting_reach.removing_a_handler_is_observed(
            acting.body[0].try_block.body[0], _may_raise(acting_reach)))
        self.assertFalse(swallowing_reach.removing_a_handler_is_observed(
            swallowing.body[0].try_block.body[0], _may_raise(swallowing_reach)))


class TestPs1AResumingTrapOverASoftErrorInABracketedStatementListIsKept(TestBase):
    """
    A statement-terminating error inside `$( )` or `@( )` steps over to the next statement within
    the bracket, and the bracket then yields that value; a resuming `trap` around the whole statement
    instead resumes past it. Where those two land differently the trap changes what runs and cannot
    be removed. The coarse graph cannot tell them apart, because the whole assignment is one node
    there; the finer graph the transpose reads separates the local step-over from the resume point.

    The reader is handed only the coarse model — the one construction there is — and draws that finer
    graph itself from its own root, so every reader here reads the step-over and none can be left
    blind and silently remove a load-bearing trap.
    """

    def _trap_removal_is_observed(self, source: str) -> bool:
        tree, reach = _model(source)
        trap = tree.body[0]
        if not isinstance(trap, Ps1TrapStatement):
            self.fail('the source does not open with a trap')
        return reach.removing_a_handler_is_observed(trap, _may_raise(reach))

    def test_a_soft_error_inside_a_subexpression_keeps_the_trap_that_resumes_past_it(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $([int]'a'; 'in'); Write-Host $x"))

    def test_a_soft_error_that_is_the_last_statement_of_the_subexpression_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $('a'; [int]'b')"))

    def test_a_division_by_zero_inside_a_subexpression_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $(1/0; 'in'); Write-Host $x"))

    def test_a_soft_error_inside_an_array_expression_keeps_the_trap_that_resumes_past_it(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = @([int]'a'; 'in'); Write-Host $x"))

    def test_an_array_expression_that_raises_no_soft_error_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(
            "trap { continue }; $x = @('a'; 'b'); Write-Host $x"))

    def test_a_soft_error_at_script_scope_whose_step_over_reconverges_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(
            "trap { continue }; [int]'a'; Write-Host 'after'"))

    def test_a_subexpression_that_raises_no_soft_error_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(
            "trap { continue }; $x = $('a'; 'b')"))

    def test_every_soft_error_shape_the_roster_lists_keeps_the_trap(self):
        for source in (
            "trap { continue }; $x = $('A'.Substring(5); 'in'); Write-Host $x",
            "trap { continue }; $x = $('abc' -band 1; 'in'); Write-Host $x",
            "trap { continue }; $x = $(([char]65) * 3; 'in'); Write-Host $x",
            "trap { continue }; $x = $(-bnot 'abc'; 'in'); Write-Host $x",
            "trap { continue }; $x = $(Get-Zqfrob; 'in'); Write-Host $x",
        ):
            with self.subTest(source):
                self.assertTrue(self._trap_removal_is_observed(source))


class TestPs1ATrapWrittenInASubexpressionGuardsThatSubexpression(TestBase):
    """
    `$( )` and `@( )` hold statements, and a `trap` written among them is a handler for those
    statements and for nothing else. Measured on 5.1: `$x = $(trap { continue }; [int]'a'; 'in')`
    leaves `in` in `$x`, so the handler took the error and resumption carried on inside the bracket;
    and `$(trap { continue }); [int]'a'; Write-Host 'after'` writes nothing at all, so the same
    handler guards no part of the block the bracket is written in.

    The reader reads the sub-statement graph, so it places the `trap` and the statements it stands
    beside: a raise inside the bracket is offered to the handler written among them, and a raise
    outside the bracket is offered to no trap written inside one. Both halves of the measurement hold
    for the reason the measurement gives — the handler's scope is the bracket — rather than the second
    surviving only because the handler was invisible.
    """

    def _bracket(self, source: str) -> tuple[Ps1TrapStatement, Statement, Ps1FaultReach]:
        tree, reach = _model(source)
        bracket = next(
            node for node in tree.walk_in_order()
            if isinstance(node, (Ps1ArrayExpression, Ps1SubExpression))
        )
        trap, raise_site = bracket.body
        if not isinstance(trap, Ps1TrapStatement):
            self.fail('the bracket does not open with a trap')
        return trap, raise_site, reach

    def test_a_raise_in_a_subexpression_is_offered_to_the_trap_written_beside_it(self):
        trap, raise_site, reach = self._bracket(_TRAP_IN_A_SUBEXPRESSION)
        self.assertEqual(reach.routing_at(raise_site), Ps1FaultRouting((trap,), False))

    def test_a_raise_in_an_array_expression_is_offered_to_the_trap_written_beside_it(self):
        trap, raise_site, reach = self._bracket(_TRAP_IN_AN_ARRAY_EXPRESSION)
        self.assertEqual(reach.routing_at(raise_site), Ps1FaultRouting((trap,), False))

    def test_a_raise_outside_the_bracket_is_offered_to_no_trap_written_inside_one(self):
        tree, reach = _model("""
            $x = $(trap { 'h' })
            'a'
        """)
        self.assertEqual(reach.routing_at(tree.body[1]), Ps1FaultRouting((), False))


class TestPs1TheBracketFixturesHoldTheShapeTheirPinsAssume(TestBase):
    """
    `TestPs1ATrapWrittenInASubexpressionGuardsThatSubexpression` reads its `trap` and the statement
    beside it out of the one bracket its fixture parses to, and every reader of that fixture is an
    expected failure, which takes a fixture that no longer parses to that shape for the wrong answer
    the pin exists to record. A parser that stopped holding the statements of a bracket in its body,
    or that stopped placing the `trap` first among them, would retire those pins in silence. This
    reads the same two sources and fails loudly instead.
    """

    def _which_statements_are_traps(self, source: str) -> list[list[bool]]:
        return [
            [isinstance(statement, Ps1TrapStatement) for statement in bracket.body]
            for bracket in _parse(source).walk_in_order()
            if isinstance(bracket, (Ps1ArrayExpression, Ps1SubExpression))
        ]

    def test_each_fixture_parses_to_one_bracket_holding_a_trap_and_one_other_statement(self):
        sources = [_TRAP_IN_A_SUBEXPRESSION, _TRAP_IN_AN_ARRAY_EXPRESSION]
        self.assertEqual(
            {source: self._which_statements_are_traps(source) for source in sources},
            {source: [[True, False]] for source in sources},
        )


class TestPs1TheReaderPlacesBracketInternalStatementsWithoutATrapToKeep(TestBase):
    """
    The reader offers a bracket-written raise to a `trap` beside it because it reads one sub-statement
    graph, not because a `trap` makes it descend. A `$( )` holding no handler at all has its inner
    statements placed just the same: `routing_at` returns a routing that guards them for nothing, and
    `points_in` over the statement the bracket sits in reaches them.
    """

    def _bracket_of(self, source: str) -> tuple[Ps1Script, Ps1SubExpression, Ps1FaultReach]:
        tree, reach = _model(source)
        bracket = next(
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1SubExpression)
        )
        return tree, bracket, reach

    def test_a_bracket_internal_statement_with_no_handler_is_placed_and_guarded_by_nothing(self):
        _, bracket, reach = self._bracket_of("$x = $('a'; 'b')")
        self.assertEqual(reach.routing_at(bracket.body[1]), Ps1FaultRouting((), False))

    def test_points_in_the_statement_holding_the_bracket_reach_the_bracket_internals(self):
        tree, bracket, reach = self._bracket_of("$x = $('a'; 'b')")
        self.assertLessEqual(set(bracket.body), set(reach.points_in(tree.body[0])))


class TestPs1ACommandToldToStopEndsTheScriptHoweverItIsTold(TestBase):
    """
    `-ErrorAction` takes a `[System.Management.Automation.ActionPreference]`, of which `Stop` is the
    member whose ordinal is 1. Windows PowerShell 5.1 binds that member from its name, from any
    abbreviation of the name that no other member of the set answers to, and from any integer
    spelling of the ordinal; it binds the parameter itself from any prefix of `ErrorAction` that no
    other parameter of the command answers to, and from the documented alias `EA`, whether the
    argument is written beside the parameter or attached to it with a colon. A command told to stop
    reports a terminating error and ends the script wherever nothing takes it, and every member
    other than `Stop` leaves what it reports non-terminating, so the next statement runs.
    """

    def _verdicts(self, commands: list[str]) -> dict[str, bool]:
        return {command: ends_the_script(_parse(command).body[0]) for command in commands}

    def _assertEveryActionStops(self, actions: list[str]) -> None:
        commands = [F'Get-Item nope -ErrorAction {action}' for action in actions]
        self.assertEqual(self._verdicts(commands), dict.fromkeys(commands, True))

    def _assertNoActionStops(self, actions: list[str]) -> None:
        commands = [F'Get-Item nope -ErrorAction {action}' for action in actions]
        self.assertEqual(self._verdicts(commands), dict.fromkeys(commands, False))

    def _assertEveryParameterCarriesTheStop(self, parameters: list[str]) -> None:
        commands = [F'Get-Item nope {parameter} Stop' for parameter in parameters]
        self.assertEqual(self._verdicts(commands), dict.fromkeys(commands, True))

    def test_the_member_name_of_stop_is_read_however_it_is_cased_or_quoted(self):
        self._assertEveryActionStops(['Stop', 'stop', 'STOP', "'Stop'", '"Stop"'])

    def test_an_abbreviation_no_other_member_answers_to_names_stop(self):
        self._assertEveryActionStops(['St', 'Sto'])

    def test_the_ordinal_of_stop_names_it_however_the_integer_is_spelled(self):
        self._assertEveryActionStops(['1', '01', '0x1'])

    def test_a_prefix_no_other_parameter_answers_to_binds_the_action(self):
        self._assertEveryParameterCarriesTheStop(
            ['-ErrorAction', '-erroraction', '-ErrorActio', '-ErrorAc', '-ErrorA']
        )

    def test_the_documented_alias_of_the_parameter_binds_the_action(self):
        self._assertEveryParameterCarriesTheStop(['-EA', '-ea'])

    def test_a_member_name_other_than_stop_leaves_the_error_non_terminating(self):
        self._assertNoActionStops(['Continue', 'SilentlyContinue', 'Ignore'])

    def test_an_abbreviation_of_a_member_other_than_stop_leaves_the_error_non_terminating(self):
        self._assertNoActionStops(['Cont', 'Sil', 'Ig'])

    def test_the_ordinal_of_a_member_other_than_stop_leaves_the_error_non_terminating(self):
        self._assertNoActionStops(['0', '2', '4', '0x2'])

    def test_an_action_attached_to_the_parameter_with_a_colon_binds_it(self):
        commands = ['Get-Item nope -ErrorAction:Stop', 'Get-Item nope -EA:Stop']
        self.assertEqual(self._verdicts(commands), dict.fromkeys(commands, True))

    def test_a_member_other_than_stop_attached_with_a_colon_leaves_the_error_non_terminating(self):
        commands = ['Get-Item nope -ErrorAction:Continue', 'Get-Item nope -EA:SilentlyContinue']
        self.assertEqual(self._verdicts(commands), dict.fromkeys(commands, False))

    def test_a_command_given_no_action_at_all_leaves_the_error_non_terminating(self):
        self.assertEqual(self._verdicts(['Get-Item nope']), {'Get-Item nope': False})


class TestPs1AStopPreferenceIsWhatMakesTheTrapUnderItWorthKeeping(TestBase):
    """
    `$ErrorActionPreference = 'Stop'` makes every error a command reports terminating, session-wide,
    and it is the same write however the target is spelled and however `Stop` is named. Under any of
    those the command below ends the script where nothing takes its error, so removing the `trap`
    that does take it changes what runs. Under none of them the command reports and the script
    carries on to the next statement either way, so the handler may go; `$env:ErrorActionPreference`
    is a process environment variable no error path reads and belongs to that half.
    """

    def _removing_the_trap_is_observed(self, assignment: str) -> bool:
        tree, reach = _model(F"""
            {assignment}
            trap {{ continue }}
            Get-Item nope
            'after'
        """)
        trap = next(node for node in tree.walk_in_order() if isinstance(node, Ps1TrapStatement))
        return reach.removing_a_handler_is_observed(trap, _may_raise(reach))

    def _observations(self, assignments: list[str]) -> dict[str, bool]:
        return {
            assignment: self._removing_the_trap_is_observed(assignment)
            for assignment in assignments
        }

    def test_the_trap_may_go_where_nothing_is_written_above_the_command_at_all(self):
        self.assertFalse(self._removing_the_trap_is_observed(''))

    def test_every_spelling_of_a_write_that_selects_stop_keeps_the_trap(self):
        assignments = [
            "$ErrorActionPreference = 'Stop'",
            "[string]$ErrorActionPreference = 'Stop'",
            "($ErrorActionPreference) = 'Stop'",
            "$a, $ErrorActionPreference = 1, 'Stop'",
            "$global:ErrorActionPreference = 'Stop'",
            "$script:ErrorActionPreference = 'Stop'",
            "${ErrorActionPreference} = 'Stop'",
            '$ErrorActionPreference = 1',
        ]
        self.assertEqual(self._observations(assignments), dict.fromkeys(assignments, True))

    def test_a_write_that_selects_no_stop_leaves_the_trap_removable(self):
        assignments = [
            "$env:ErrorActionPreference = 'Stop'",
            "$ErrorActionPreference = 'Continue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            '$ErrorActionPreference = 2',
        ]
        self.assertEqual(self._observations(assignments), dict.fromkeys(assignments, False))


class TestPs1AStrictModeArmingIsReadOverTheWholeScript(TestBase):
    """
    Reading a variable that was never set yields `$null` and raises nothing. `Set-StrictMode` makes
    the same read a statement-terminating error that a `catch` and a `trap` both take, so a script
    that arms it anywhere is a script where deleting such a read is observable. Both halves are
    measured on 5.1 in `test.lib.scripts.ps1.corpus.BEHAVIOURS`.

    Whether it is armed is asked of the whole script and never of a position, because which scopes
    an arming covers is not decidable here: `Set-StrictMode` writes the scope it stands in and
    `Set-PSDebug -Strict` writes the global one, so a call inside a function arms nothing outside it
    in the first spelling and everything in the second. `Set-StrictMode -Off` is an arming here like
    every other spelling, and what that costs is the recall of a script that turns it off again.
    """

    def _armings(self, scripts: list[str]) -> dict[str, bool]:
        return {
            script: _model(script)[1].strict_mode_may_be_in_force()
            for script in scripts
        }

    def test_every_spelling_that_resolves_to_the_command_arms_strict_mode(self):
        scripts = [
            'Set-StrictMode -Version 1',
            'Set-StrictMode -Version Latest',
            'set-strictmode -version 2',
            "& 'Set-StrictMode' -Version 1",
            "& 'global:Set-StrictMode' -Version 1",
            'Set-StrictMode -Off',
            'function f { Set-StrictMode -Version 1 }',
            'if ($a) { Set-StrictMode -Version 1 }',
        ]
        self.assertEqual(self._armings(scripts), dict.fromkeys(scripts, True))

    def test_the_second_command_that_arms_it_is_read_as_an_arming_too(self):
        """
        `Set-PSDebug -Strict` writes the same engine slot that `Set-StrictMode -Version 1` writes,
        and writes it for the global scope rather than the current one. Measured on 5.1 in
        `test.lib.scripts.ps1.corpus.BEHAVIOURS`: the guarded read below it raises and the `catch`
        runs, exactly as it does under the spelling this scan was first written for.
        """
        scripts = [
            'Set-PSDebug -Strict',
            'set-psdebug -strict',
            'Set-PSDebug -Trace 1 -Strict',
            "& 'Set-PSDebug' -Strict",
            "Invoke-Expression 'Set-PSDebug -Strict'",
            'function f { Set-PSDebug -Strict }',
        ]
        self.assertEqual(self._armings(scripts), dict.fromkeys(scripts, True))

    def test_a_string_holding_the_name_arms_strict_mode_wherever_it_stands(self):
        scripts = [
            "Invoke-Expression 'Set-StrictMode -Version 1'",
            "$c = 'Set-StrictMode -Version 1'; Invoke-Expression $c",
            "Set-Item Variable:c 'set-strictmode -version 1'",
        ]
        self.assertEqual(self._armings(scripts), dict.fromkeys(scripts, True))

    def test_a_script_that_never_spells_the_name_arms_nothing(self):
        scripts = [
            "Write-Host 'strict mode'",
            '$strictmode = 1',
            'Set-Variable StrictMode 1',
            "Write-Host 'Set-Strict'",
            "'a' + 'b'",
        ]
        self.assertEqual(self._armings(scripts), dict.fromkeys(scripts, False))

    def test_a_name_assembled_out_of_pieces_is_not_read_as_an_arming(self):
        """
        The miss this scan shares with `a_stop_may_be_in_force`: a value is matched as it is
        written, so a payload no literal spells is invisible. It costs nothing at the tool level
        for the two spellings that fold — the concatenation and the base64 blob are resolved to the
        literal before the removal is weighed — and what is left is a payload the analysis cannot
        read at all, which
        `test.lib.scripts.ps1.deobfuscation.test_fault_observability` refuses on the world instead.
        """
        script = "$c = 'Set-Strict' + 'Mode -Version 1'; Invoke-Expression $c"
        self.assertEqual(self._armings([script]), {script: False})

    def test_a_model_the_graphs_hold_no_script_for_refuses_the_grant(self):
        """
        The pole this fact does not share with `_stops_on_every_error`, which answers `False` there.
        What this one grants is a removal, so an empty model has to refuse it: a script nothing was
        read of is not a script that was read and found to arm nothing.
        """
        self.assertTrue(Ps1FaultReach(ControlFlowModel({})).strict_mode_may_be_in_force())


class TestPs1WhetherAnErrorLeavesTheBodyItWasRaisedIn(TestBase):
    """
    The half of the position question that says nothing about where the error goes next, only that
    the body it was raised in does not decide it. A caller that knows what runs the body reads this
    and answers the rest for itself.
    """

    def _escapes(self, source: str) -> bool:
        tree, faults = _model(source)
        point = next(
            node for node in tree.walk()
            if isinstance(node, Ps1CommandInvocation)
            and resolve_command_name(node) == 'get-random'
        )
        return faults.escapes_the_body(point)

    def test_a_body_with_no_handler_settles_nothing(self):
        self.assertTrue(self._escapes("1, 2 | ForEach-Object { Get-Random }"))

    def test_a_catch_that_acts_settles_it(self):
        self.assertFalse(self._escapes(
            "1, 2 | ForEach-Object { try { Get-Random } catch { Write-Host 'h' } }"))

    def test_an_empty_catch_settles_it_too(self):
        """
        Nothing observable happens, but the error stops there all the same, so where the body runs
        cannot change where it went.
        """
        self.assertFalse(self._escapes("1, 2 | ForEach-Object { try { Get-Random } catch { } }"))

    def test_a_trap_that_may_decline_the_error_ends_the_body_and_settles_it(self):
        self.assertFalse(self._escapes(
            "1, 2 | ForEach-Object { trap [System.IO.IOException] { } Get-Random }"))

    def test_a_position_the_graphs_place_nowhere_escapes_nothing(self):
        tree = _parse("function f ($p = $(Get-Random)) { }")
        faults = build_fault_reach(build_control_flow_model(tree))
        point = next(
            node for node in tree.walk()
            if isinstance(node, Ps1CommandInvocation)
            and resolve_command_name(node) == 'get-random'
        )
        self.assertFalse(faults.escapes_the_body(point))
        self.assertTrue(faults.observed_at(point))
