from __future__ import annotations

from inspect import cleandoc

from test import TestBase, wontfix, opportunity, todo

from refinery.lib.scripts import Node, Statement, set_body
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import Ps1ControlFlowModel, build_control_flow_model
from refinery.lib.scripts.ps1.analysis.effects import Ps1HandlerVerdicts
from refinery.lib.scripts.analysis.cfg import distinct
from refinery.lib.scripts.ps1.analysis.dispatch import EVERY_KIND, Ps1ErrorKind
from refinery.lib.scripts.ps1.analysis.faults import (
    Ps1FaultReach,
    RaiseVerdicts,
    build_fault_reach,
    ends_the_script,
)
from refinery.lib.scripts.ps1.analysis.handlers import handler_acts
from refinery.lib.scripts.ps1.analysis.raising import Ps1RaiseModel
from refinery.lib.scripts.ps1.ast import get_body, resolve_command_name
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1CastExpression,
    Ps1CatchClause,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1SubExpression,
    Ps1TrapStatement,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _parse(source: str) -> Ps1Script:
    return Ps1Parser(cleandoc(source)).parse()


def _model(source: str) -> tuple[Ps1Script, Ps1FaultReach]:
    tree = _parse(source)
    return tree, _reach(tree)


def _reach(tree: Ps1Script) -> Ps1FaultReach:
    cache = Ps1ModelCache(tree)
    return build_fault_reach(build_control_flow_model(tree), lambda: cache.call_graph)


def _offered(reach: Ps1FaultReach, node: Node) -> tuple[Node, ...] | None:
    found = reach.fate_of(node, Ps1ErrorKind.STATEMENT)
    if found is None:
        return None
    graph, start, _ = found
    handlers: list[Node] = []
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for target in distinct(t for t in current.successors if graph.is_exceptional(current, t)):
            if target in seen:
                continue
            seen.add(target)
            stack.append(target)
            if isinstance(target.element, (Ps1CatchClause, Ps1TrapStatement)):
                handlers.append(target.element)
    return tuple(handlers)


def _offered_where_placed(reach: Ps1FaultReach, node: Node) -> tuple[Node, ...]:
    offered = _offered(reach, node)
    if offered is None:
        raise AssertionError(F'the graphs place nothing for {node}')
    return offered


def _leaves(reach: Ps1FaultReach, node: Node) -> bool:
    found = reach.fate_of(node, Ps1ErrorKind.STATEMENT)
    if found is None:
        return True
    graph, start, _ = found
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for target in current.successors:
            if target in seen or not graph.is_exceptional(current, target):
                continue
            if target is graph.exit:
                return True
            seen.add(target)
            stack.append(target)
    return False


def _observed(reach: Ps1FaultReach, node: Node) -> bool:
    kinds = Ps1ErrorKind.STATEMENT
    if reach.error_is_terminating(node):
        kinds |= Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED
    return reach.observed_at(node, kinds)


class _Answering:

    def __init__(self, answer: bool):
        self._answer = answer

    def kinds(self, point: Node) -> Ps1ErrorKind:
        return EVERY_KIND if self._answer else Ps1ErrorKind.NONE

    def bodies_run_by(self, call: Node) -> None:
        return None

    def bodies_consulted(self, node: Node) -> tuple[tuple[Ps1ScriptBlock, ...], bool]:
        return (), True

    def is_recursive(self, body: Node) -> bool:
        return True

    def observers(self, graph, regions) -> list:
        return [lambda member: self._answer for _ in regions]


def _no_trap_is_asked_about(trap: Ps1TrapStatement) -> bool:
    raise AssertionError(F'the fixture holds a trap: {trap}')


def _handler_verdicts(tree: Ps1Script, reach: Ps1FaultReach) -> Ps1HandlerVerdicts:
    cache = Ps1ModelCache(tree)

    def raises(under_the_world: bool) -> Ps1RaiseModel:
        return Ps1RaiseModel(
            reach,
            cache.world_reach if under_the_world else None,
            lambda: cache.call_graph,
            lambda: cache.commands,
            lambda: cache.calls_after_a_definition,
            lambda: cache.names_may_be_removed,
            lambda: cache.names_may_be_constrained,
            cache.control_flow,
            tree,
        )

    return Ps1HandlerVerdicts(reach, raises, tree)


def _trap(node: Node) -> Ps1TrapStatement:
    assert isinstance(node, Ps1TrapStatement), F'the fixture names a {type(node).__name__}, not a trap'
    return node


def _handler_removal_is_observed(tree: Ps1Script, reach: Ps1FaultReach, *traps: Node) -> bool:
    verdicts = _handler_verdicts(tree, reach)
    return reach.removing_traps_is_observed(
        [_trap(trap) for trap in traps], verdicts.raises(False), verdicts.skips)


_TRAP_IN_A_SUBEXPRESSION = "$x = $(trap { 'h' }; 'a')"

_TRAP_IN_AN_ARRAY_EXPRESSION = "$x = @(trap { 'h' }; 'a')"


class TestPs1FaultRoutingOffersTheRaiseToTheHandlersThatGuardIt(TestBase):

    def test_a_raise_in_a_try_block_is_offered_to_that_constructs_catch_clause(self):
        tree, reach = _model("try { 'a' } catch { 'b' }")
        construct = tree.body[0]
        clause, = construct.catch_clauses
        self.assertEqual(_offered(reach, construct.try_block.body[0]), (clause,))

    def test_a_raise_after_the_construct_is_offered_to_no_catch_clause(self):
        tree, reach = _model("""
            try { 'a' } catch { 'b' }
            'c'
        """)
        self.assertEqual(_offered(reach, tree.body[1]), ())

    def test_every_catch_clause_of_the_construct_is_offered_the_raise(self):
        tree, reach = _model("try { 'a' } catch [System.IO.IOException] { 'x' } catch { 'y' }")
        construct = tree.body[0]
        self.assertEqual(
            set(_offered_where_placed(reach, construct.try_block.body[0])),
            set(construct.catch_clauses),
        )

    def test_a_trap_is_offered_a_raise_written_above_it(self):
        tree, reach = _model("""
            'a'
            trap { 'h' }
        """)
        self.assertEqual(_offered(reach, tree.body[0]), (tree.body[1],))

    def test_a_trap_is_offered_a_raise_from_a_block_nested_in_the_one_it_guards(self):
        tree, reach = _model("""
            trap { 'h' }
            if ($c) { 'a' }
        """)
        nested = tree.body[1].clauses[0][1].body[0]
        self.assertEqual(_offered(reach, nested), (tree.body[0],))

    def test_a_trap_is_not_offered_a_raise_written_outside_the_block_it_belongs_to(self):
        tree, reach = _model("""
            if ($c) {
                trap { 'h' }
                'a'
            }
            'b'
        """)
        self.assertEqual(_offered(reach, tree.body[1]), ())

    def test_only_the_innermost_untyped_trap_is_offered_the_raise(self):
        tree, reach = _model("""
            trap { 'o' }
            if ($c) {
                trap { 'i' }
                'a'
            }
        """)
        guarded = tree.body[1].clauses[0][1]
        self.assertEqual(_offered(reach, guarded.body[1]), (guarded.body[0],))

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
            set(_offered_where_placed(reach, guarded.body[1])),
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
            _offered(reach, inner.try_block.body[0]),
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
            set(_offered_where_placed(reach, inner.try_block.body[0])),
            {inner.catch_clauses[0], outer.catch_clauses[0]},
        )


class TestPs1FaultLeavesTheBody(TestBase):

    def test_a_raise_that_nothing_guards_stays_in_the_body(self):
        tree, reach = _model("'a'")
        self.assertFalse(_leaves(reach, tree.body[0]))

    def test_a_catch_clause_lets_the_raise_past_exactly_when_its_filter_is_narrower_than_exception(
        self,
    ):
        broad, broad_reach = _model("try { 'a' } catch [System.Exception] { 'b' }")
        narrow, narrow_reach = _model("try { 'a' } catch [System.IO.IOException] { 'b' }")
        self.assertFalse(_leaves(broad_reach, broad.body[0].try_block.body[0]))
        self.assertTrue(_leaves(narrow_reach, narrow.body[0].try_block.body[0]))

    def test_a_trap_lets_the_raise_past_exactly_when_it_carries_a_type_filter(self):
        untyped, untyped_reach = _model("""
            trap { 'h' }
            'a'
        """)
        typed, typed_reach = _model("""
            trap [System.IO.IOException] { 'h' }
            'a'
        """)
        self.assertFalse(_leaves(untyped_reach, untyped.body[1]))
        self.assertTrue(_leaves(typed_reach, typed.body[1]))

    def test_a_trap_lets_the_raise_past_when_it_breaks_but_not_when_it_continues(self):
        rethrowing, rethrowing_reach = _model("""
            trap { break }
            'a'
        """)
        resuming, resuming_reach = _model("""
            trap { continue }
            'a'
        """)
        self.assertTrue(_leaves(rethrowing_reach, rethrowing.body[1]))
        self.assertFalse(_leaves(resuming_reach, resuming.body[1]))

    def test_a_point_the_graphs_cannot_place_is_answered_as_leaving_the_body(self):
        _, reach = _model("'a'")
        elsewhere = _parse("'z'").body[0]
        self.assertIsNone(_offered(reach, elsewhere))
        self.assertTrue(_leaves(reach, elsewhere))


class TestPs1ATrapDisposesOfTheErrorWhateverConstructEnclosesItsBlock(TestBase):

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
                self.assertEqual(_offered(reach, raised), (trap,))
                self.assertTrue(_leaves(reach, raised))
                self.assertTrue(_observed(reach, raised))

    def test_a_trap_that_continues_keeps_the_raise_wherever_its_block_is_written(self):
        for spelling in self._SPELLINGS:
            source = spelling % 'continue'
            with self.subTest(source):
                reach, trap, raised = self._trap_and_the_raise_it_guards(source)
                self.assertEqual(_offered(reach, raised), (trap,))
                self.assertFalse(_leaves(reach, raised))
                self.assertFalse(_observed(reach, raised))


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
        self.assertFalse(_observed(reach, tree.body[0]))

    def test_a_raise_is_observed_by_a_catch_clause_with_a_body_but_not_by_an_empty_one(self):
        acting, acting_reach = _model("try { 'a' } catch { 'b' }")
        swallowing, swallowing_reach = _model("try { 'a' } catch { }")
        self.assertTrue(_observed(acting_reach, acting.body[0].try_block.body[0]))
        self.assertFalse(_observed(swallowing_reach, swallowing.body[0].try_block.body[0]))

    def test_a_raise_guarded_by_a_trap_that_only_continues_is_not_observed(self):
        tree, reach = _model("""
            trap { continue }
            'a'
        """)
        self.assertFalse(_observed(reach, tree.body[1]))

    def test_a_raise_guarded_by_a_trap_that_only_breaks_is_observed_although_it_does_not_act(self):
        tree, reach = _model("""
            trap { break }
            'a'
        """)
        self.assertFalse(handler_acts(tree.body[0]))
        self.assertTrue(_observed(reach, tree.body[1]))

    def test_a_raise_guarded_by_a_typed_trap_is_observed_because_the_set_may_decline_it(self):
        tree, reach = _model("""
            trap [System.IO.IOException] { continue }
            'a'
        """)
        self.assertFalse(handler_acts(tree.body[0]))
        self.assertTrue(_observed(reach, tree.body[1]))

    def test_a_raise_guarded_by_a_trap_whose_body_is_a_bare_value_is_observed(self):
        tree, reach = _model("""
            trap { 5 }
            'a'
        """)
        self.assertTrue(_observed(reach, tree.body[1]))

    def test_a_point_the_graphs_cannot_place_is_answered_as_observed(self):
        _, reach = _model("'a'")
        elsewhere = _parse("'z'").body[0]
        self.assertIsNone(_offered(reach, elsewhere))
        self.assertTrue(_observed(reach, elsewhere))


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
        self.assertIsNone(_offered(reach, loop))
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
        self.assertIsNone(_offered(reach, construct))
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

    def test_the_transpose_honours_the_predicate_it_is_given_not_an_earlier_verdict(self):
        tree, reach = _model("""
            trap { 'h' }
            [int]'a'
        """)
        trap = _trap(tree.body[0])
        self.assertTrue(reach.removing_traps_is_observed([trap], _Answering(True), _Answering(True)))
        self.assertFalse(reach.removing_traps_is_observed([trap], _Answering(False), _Answering(False)))

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
        self.assertTrue(_handler_removal_is_observed(
            guarding, guarding_reach, guarding.body[1].clauses[0][1].body[0]))
        self.assertFalse(_handler_removal_is_observed(
            alone, alone_reach, alone.body[1].clauses[0][1].body[0]))

    def test_a_trap_at_script_scope_may_go_where_the_only_statement_it_guards_cannot_raise(self):
        tree, reach = _model("""
            trap { 'h' }
            'a'
        """)
        self.assertTrue(_observed(reach, tree.body[1]))
        self.assertFalse(_handler_removal_is_observed(tree, reach, tree.body[0]))

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
        self.assertTrue(_handler_removal_is_observed(
            acting, acting_reach, acting.body[0].try_block.body[0]))
        self.assertFalse(_handler_removal_is_observed(
            swallowing, swallowing_reach, swallowing.body[0].try_block.body[0]))


def _traps_of(tree: Ps1Script) -> list[Ps1TrapStatement]:
    return [node for node in tree.walk_in_order() if isinstance(node, Ps1TrapStatement)]


class TestPs1DeletingTrapsIsJudgedForTheirWholeSet(TestBase):

    def test_a_member_that_breaks_written_before_one_that_continues_is_why_the_script_stops(self):
        tree, reach = _model("""
            trap { break }
            trap { continue }
            [int]'a'
            Write-Host 'after'
        """)
        breaks, continues = _traps_of(tree)
        self.assertTrue(_handler_removal_is_observed(tree, reach, breaks))
        self.assertFalse(_handler_removal_is_observed(tree, reach, continues))

    def test_a_typed_member_is_tried_before_an_untyped_one_written_above_it(self):
        tree, reach = _model("""
            trap { continue }
            trap [System.Management.Automation.RuntimeException] { break }
            $z = 0
            1/$z
            Write-Host 'after'
        """)
        _, typed = _traps_of(tree)
        self.assertTrue(_handler_removal_is_observed(tree, reach, typed))

    def test_an_inner_resuming_set_is_kept_where_the_outer_one_would_skip_the_rest_of_its_block(self):
        for opening in ('if ($true) {', 'foreach ($q in 1, 2) {'):
            with self.subTest(opening):
                tree, reach = _model(F"""
                    trap {{ continue }}
                    {opening}
                      trap {{ continue }}
                      [int]'a'
                      Write-Host 'tail'
                    }}
                    Write-Host 'after'
                """)
                _, inner = _traps_of(tree)
                self.assertTrue(_handler_removal_is_observed(tree, reach, inner))

    def test_a_resuming_set_in_a_try_is_kept_where_the_empty_catch_would_skip_the_rest_of_it(self):
        tree, reach = _model("""
            try {
              trap { continue }
              [int]'a'
              Write-Host 'tail'
            } catch { }
            Write-Host 'after'
        """)
        self.assertTrue(_handler_removal_is_observed(tree, reach, *_traps_of(tree)))

    def test_a_resuming_set_under_a_breaking_one_under_a_resuming_one_is_kept(self):
        tree, reach = _model("""
            trap { continue }
            if ($true) {
              trap { break }
              if ($true) {
                trap { continue }
                [int]'a'
                Write-Host 'tail'
              }
              Write-Host 'mid'
            }
            Write-Host 'after'
        """)
        *_, innermost = _traps_of(tree)
        self.assertTrue(_handler_removal_is_observed(tree, reach, innermost))

    def test_a_member_that_runs_off_its_end_under_stop_is_not_alike_one_that_continues(self):
        tree, reach = _model("""
            $ErrorActionPreference = 'Stop'
            trap { }
            trap { continue }
            [int]'a'
            Write-Host 'after'
        """)
        falls_through, _ = _traps_of(tree)
        self.assertTrue(_handler_removal_is_observed(tree, reach, falls_through))

    def test_a_member_that_breaks_is_not_alike_one_that_runs_off_its_end_where_stop_is_set_after_the_raise(self):
        tree, reach = _model("""
            trap [System.Management.Automation.PSInvalidCastException] { break }
            trap { }
            [int]'a'
            Write-Host 'after'
            $ErrorActionPreference = 'Stop'
        """)
        breaks, _ = _traps_of(tree)
        self.assertTrue(_handler_removal_is_observed(tree, reach, breaks))

    def test_a_resuming_set_is_kept_where_a_typed_set_around_it_declines_to_a_resuming_set_further_out(self):
        tree, reach = _model("""
            trap { continue }
            if ($true) {
              trap [System.IO.IOException] { continue }
              if ($true) {
                trap { continue }
                [int]'a'
              }
              Write-Host 'mid'
            }
            Write-Host 'after'
        """)
        *_, innermost = _traps_of(tree)
        self.assertTrue(_handler_removal_is_observed(tree, reach, innermost))

    def test_one_of_two_alike_members_may_go_but_not_both(self):
        tree, reach = _model("""
            trap { continue }
            if ($c) {
              trap { continue }
              trap { continue }
              [int]'a'
              Write-Host 'tail'
            }
        """)
        _, first, second = _traps_of(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, first))
        self.assertFalse(_handler_removal_is_observed(tree, reach, second))
        self.assertTrue(_handler_removal_is_observed(tree, reach, first, second))
        verdicts = _handler_verdicts(tree, reach)
        self.assertEqual(len(reach.removable_traps([first, second], verdicts.raises(False), verdicts.skips)), 1)

    def test_a_member_never_selected_may_go_although_its_body_acts(self):
        tree, reach = _model("""
            trap { continue }
            trap { Write-Host 'p' }
            $u = [int]'a'
            Write-Host 'after'
        """)
        _, acting = _traps_of(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, acting))

    def test_a_typed_member_that_alone_stands_for_the_set_is_the_member_kept(self):
        tree, reach = _model("""
            $ErrorActionPreference = 'Stop'
            trap [System.Exception] { continue }
            trap { break }
            [int]'a'
            Write-Host 'after'
        """)
        typed, untyped = _traps_of(tree)
        verdicts = _handler_verdicts(tree, reach)
        self.assertEqual(reach.removable_traps([typed, untyped], verdicts.raises(False), verdicts.skips), [untyped])

    def test_a_typed_member_may_go_where_the_member_naming_every_error_takes_its_errors_alike(self):
        tree, reach = _model("""
            $ErrorActionPreference = 'Stop'
            trap [System.IO.IOException] { continue }
            trap [Exception] { continue }
            [int]'a'
            Write-Host 'after'
        """)
        narrow, universal = _traps_of(tree)
        verdicts = _handler_verdicts(tree, reach)
        self.assertEqual(reach.removable_traps([narrow, universal], verdicts.raises(False), verdicts.skips), [narrow])

    def test_an_outer_set_an_inner_typed_set_declines_into_is_kept(self):
        for opening in ('if ((Get-Date).Year -gt 2000) {', 'foreach ($q in (Get-Date).Year) {'):
            with self.subTest(opening):
                tree, reach = _model(F"""
                    trap {{ continue }}
                    {opening}
                      trap [System.IO.IOException] {{ continue }}
                      $v = [int]'a'
                    }}
                    Write-Host 'after'
                """)
                outer, _ = _traps_of(tree)
                self.assertTrue(_handler_removal_is_observed(tree, reach, outer))

    def test_an_outer_set_an_inner_set_hands_errors_to_past_a_finally_is_kept(self):
        for inner in ('trap { break }', 'trap [System.IO.IOException] { continue }'):
            with self.subTest(inner):
                tree, reach = _model(F"""
                    trap {{ continue }}
                    try {{
                      {inner}
                      $v = [int]'a'
                    }} finally {{ }}
                    Write-Host 'after'
                """)
                outer, _ = _traps_of(tree)
                self.assertTrue(_handler_removal_is_observed(tree, reach, outer))

    def test_an_inner_set_that_re_raises_past_a_finally_to_the_outer_one_may_go(self):
        tree, reach = _model("""
            trap { continue }
            try {
              trap { break }
              $v = [int]'a'
            } finally { }
            Write-Host 'after'
        """)
        _, inner = _traps_of(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, inner))

    def test_traps_of_two_sets_are_not_one_question(self):
        tree, reach = _model("""
            trap { continue }
            if ($c) {
              trap { continue }
              [int]'a'
            }
        """)
        with self.assertRaises(ValueError):
            _handler_removal_is_observed(tree, reach, *_traps_of(tree))
        with self.assertRaises(ValueError):
            _handler_removal_is_observed(tree, reach)

    def test_a_model_held_across_an_edit_refuses_the_question(self):
        tree, reach = _model("""
            trap { continue }
            'a'
            'b'
        """)
        trap, = _traps_of(tree)
        self.assertFalse(reach.removing_traps_is_observed([trap], _Answering(False), _Answering(False)))
        set_body(tree, list(tree.body[:-1]))
        self.assertTrue(reach.removing_traps_is_observed([trap], _Answering(False), _Answering(False)))


class TestPs1ATrapIsKeptWhereTheRunWithoutItDoesWhatTheRunWithItDoesNot(TestBase):

    @staticmethod
    def _removal_is_observed(source: str) -> bool:
        tree = _parse(source)
        cache = Ps1ModelCache(tree)
        handlers = cache.handlers
        first = _traps_of(tree)[0]
        return cache.faults.removing_traps_is_observed([first], handlers.raises(True), handlers.skips)

    def test_a_catch_body_the_trap_runs_before_its_errors_would_land_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            try {
              trap { continue }
              [int]'a'
              try { throw 'x' } catch { Write-Host 'caught' }
            } catch { }
            Write-Host 'after'
        """))

    def test_a_catch_body_the_untrapped_run_steps_into_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            $s = Read-Host
            $c = Read-Host
            trap { continue }
            if ($c) {
              $null = [int]'a'
              try { $q = [int]$s } catch { $global:caught = 1 }
            }
            Write-Host $global:caught
        """))

    def test_what_follows_an_inner_resumption_before_the_errors_would_land_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            try {
              trap { continue }
              $null = [int]'a'
              try {
                trap { continue }
                throw 'x'
                Write-Host 'y'
              } finally { }
            } catch { }
            Write-Host 'after'
        """))

    def test_an_inner_trap_that_acts_before_the_errors_would_land_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            $s = Read-Host
            $c = Read-Host
            try {
              trap { continue }
              $null = [int]$s
              try {
                trap { Write-Host 'b'; continue }
                $null = [int]$c
              } finally { }
            } catch { }
            Write-Host 'after'
        """))

    def test_an_inner_typed_trap_declining_into_a_catch_the_untrapped_run_reaches_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            $s = Read-Host
            $c = Read-Host
            trap { continue }
            if ($c) {
              $null = [int]$s
              try { trap [System.IO.IOException] { continue }; $null = [int]$s } catch { Write-Host 'caught' }
            }
            Write-Host 'after'
        """))

    def test_a_loop_the_trap_leaves_by_break_before_the_errors_would_land_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            foreach ($i in 1, 2) {
              try {
                trap { continue }
                $null = [int]'a'
                break
              } catch { }
              Write-Host "after $i"
            }
        """))

    def test_a_function_the_trap_leaves_by_return_before_the_errors_would_land_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            function f {
              try {
                trap { continue }
                $null = [int]'a'
                return
              } catch { }
              Write-Host 'after'
            }
            f
        """))

    def test_a_function_the_untrapped_run_leaves_by_return_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            function f {
              trap { continue }
              if ($c) {
                $null = [int]$s
                return
              }
              Write-Host 'after'
            }
            f
        """))

    def test_a_loop_the_untrapped_run_leaves_into_code_that_ends_at_a_re_raising_trap_is_observed(self):
        self.assertTrue(self._removal_is_observed("""
            $s = Read-Host
            $c = Read-Host
            foreach ($i in 1, 2) {
              trap { continue }
              if ($c) { $null = [int]$s; break }
              Write-Host "it $i"
            }
            try { trap { break }; throw 'x' } catch { }
        """))

    def test_a_trap_whose_errors_would_land_where_it_resumes_may_go(self):
        self.assertFalse(self._removal_is_observed("""
            try {
              trap { continue }
              Write-Host 'x'
              $null = [int]'a'
            } catch { }
            Write-Host 'after'
        """))

    def test_a_trap_whose_untrapped_run_continues_the_loop_around_it_may_go(self):
        self.assertFalse(self._removal_is_observed("""
            $s = Read-Host
            $c = Read-Host
            foreach ($i in 1, 2) {
              trap { continue }
              if ($c) { $null = [int]$s; continue }
            }
            Write-Host 'after'
        """))

    @wontfix('a run that loops forever after the trap resumes it is compared as if it ended')
    def test_a_trap_whose_resumption_loops_forever_is_kept(self):
        self.assertTrue(self._removal_is_observed("""
            try {
              trap { continue }
              [int]'a'
              while ($true) { }
            } catch { }
            Write-Host 'after'
        """))


class TestPs1ATrapRemovalWaitsOnlyForATrapRemovedFromABlockAroundIt(TestBase):

    @staticmethod
    def _traps(tree: Ps1Script) -> list[Node]:
        return [node for node in tree.walk_in_order() if isinstance(node, Ps1TrapStatement)]

    @staticmethod
    def _waiting(tree: Ps1Script, reach: Ps1FaultReach, groups: list[list[Node]]) -> set[int]:
        waiting, _ = reach.edits_that_wait(groups, groups, _handler_verdicts(tree, reach).raises(False))
        return waiting

    def test_a_trap_waits_for_the_removal_of_the_resuming_trap_its_errors_land_at(self):
        tree, reach = _model("""
            function f {
              trap { continue }
              try {
                trap { }
                $null = [int]$s
              } catch [System.IO.IOException] { }
            }
            try { f } catch { Write-Host 'caught' }
        """)
        without_outer, without_outer_reach = _model("""
            function f {
              try {
                trap { }
                $null = [int]$s
              } catch [System.IO.IOException] { }
            }
            try { f } catch { Write-Host 'caught' }
        """)
        outer, inner = self._traps(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, inner))
        self.assertFalse(_handler_removal_is_observed(tree, reach, outer))
        self.assertTrue(_handler_removal_is_observed(
            without_outer, without_outer_reach, *self._traps(without_outer)))
        self.assertEqual(self._waiting(tree, reach, [[outer], [inner]]), {1})

    def test_a_trap_waits_for_the_removal_of_a_trap_two_blocks_around_it(self):
        tree, reach = _model("""
            function f {
              trap { continue }
              try {
                try {
                  trap { }
                  $null = [int]$s
                } catch [System.IO.IOException] { }
              } catch [System.IO.IOException] { }
            }
            try { f } catch { Write-Host 'caught' }
        """)
        without_outer, without_outer_reach = _model("""
            function f {
              try {
                try {
                  trap { }
                  $null = [int]$s
                } catch [System.IO.IOException] { }
              } catch [System.IO.IOException] { }
            }
            try { f } catch { Write-Host 'caught' }
        """)
        outer, inner = self._traps(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, inner))
        self.assertFalse(_handler_removal_is_observed(tree, reach, outer))
        self.assertTrue(_handler_removal_is_observed(
            without_outer, without_outer_reach, *self._traps(without_outer)))
        self.assertEqual(self._waiting(tree, reach, [[outer], [inner]]), {1})

    def test_a_trap_in_a_function_does_not_wait_for_the_removal_of_a_trap_at_script_scope(self):
        tree, reach = _model("""
            trap { continue }
            function f {
              trap { continue }
              'a'
            }
            f
        """)
        outer, inner = self._traps(tree)
        self.assertEqual(self._waiting(tree, reach, [[outer], [inner]]), set())

    def test_a_trap_waits_for_the_removal_of_a_resuming_trap_in_a_finally_block_around_it(self):
        tree, reach = _model("""
            function f {
              try {} finally {
                try {
                  trap { }
                  $null = [int]$s
                } catch [System.IO.IOException] { }
                trap { continue }
              }
            }
            try { f } catch { Write-Host 'caught' }
        """)
        without_outer, without_outer_reach = _model("""
            function f {
              try {} finally {
                try {
                  trap { }
                  $null = [int]$s
                } catch [System.IO.IOException] { }
              }
            }
            try { f } catch { Write-Host 'caught' }
        """)
        inner, outer = self._traps(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, inner))
        self.assertFalse(_handler_removal_is_observed(tree, reach, outer))
        self.assertTrue(_handler_removal_is_observed(
            without_outer, without_outer_reach, *self._traps(without_outer)))
        self.assertEqual(self._waiting(tree, reach, [[outer], [inner]]), {1})

    def test_a_trap_nothing_may_raise_into_does_not_wait_for_the_trap_around_it(self):
        tree, reach = _model("""
            trap { continue }
            if ($x) {
              trap { continue }
              'a'
            }
        """)
        without_outer, without_outer_reach = _model("""
            if ($x) {
              trap { continue }
              'a'
            }
        """)
        outer, inner = self._traps(tree)
        self.assertFalse(_handler_removal_is_observed(tree, reach, inner))
        self.assertFalse(_handler_removal_is_observed(without_outer, without_outer_reach, *self._traps(without_outer)))
        self.assertEqual(self._waiting(tree, reach, [[outer], [inner]]), set())

    def test_traps_judged_by_one_verdict_do_not_wait_for_each_other(self):
        tree, reach = _model("""
            trap { continue }
            trap { break }
            'a'
        """)
        self.assertEqual(self._waiting(tree, reach, [self._traps(tree)]), set())


class TestPs1AResumingTrapOverASoftErrorInABracketedStatementListIsKept(TestBase):

    def _trap_removal_is_observed(self, source: str) -> bool:
        tree, reach = _model(source)
        trap = tree.body[0]
        if not isinstance(trap, Ps1TrapStatement):
            self.fail('the source does not open with a trap')
        return _handler_removal_is_observed(tree, reach, trap)

    def test_a_soft_error_inside_a_subexpression_keeps_the_trap_that_resumes_past_it(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $([int]'a'; 'in'); Write-Host $x"))

    def test_a_soft_error_that_is_the_last_statement_of_the_subexpression_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $('a'; [int]'b'); Write-Host $x"))

    def test_a_last_statement_soft_error_whose_bracket_value_is_unread_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(
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

    def test_a_soft_error_in_a_loop_body_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(
            "trap { continue }; for ($i = 0; $i -lt 3; $i++) { $y = 1 % 0 }; Write-Host 'after'"))

    def test_a_soft_error_whose_later_runs_write_what_is_read_after_the_loop_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(cleandoc("""
            trap { continue }
            $a = @('x', '5')
            for ($i = 0; $i -lt 2; $i++) { $y = [int]$a[$i] }
            Write-Host $y
        """)))

    def test_a_soft_error_in_a_block_a_pipeline_runs_ends_the_whole_statement_and_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(cleandoc("""
            trap { continue }
            $s = [string][char]256 + 'b'
            $k = [char[]]$s | ForEach-Object { [byte][char]$_ }
            Write-Host "count=$($k.Count) key=$($k -join ',')"
        """)))

    def test_a_soft_error_whose_later_runs_write_what_nothing_reads_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(cleandoc("""
            trap { continue }
            $a = @('x', '5')
            for ($i = 0; $i -lt 2; $i++) { $y = [int]$a[$i] }
            Write-Host 'after'
        """)))

    def test_a_soft_error_after_a_statement_at_script_scope_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(cleandoc("""
            trap { continue }
            'out'
            $null = [int]$s
            'after'
        """)))

    def test_a_soft_error_after_a_statement_in_an_if_body_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(cleandoc("""
            trap { continue }
            if ($c) { 'out'; $null = [int]$s }
            'after'
        """)))

    def test_a_soft_error_before_a_live_tail_in_an_if_body_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; if ($true) { [int]'a'; 'tail' }; Write-Host 'after'"))

    def test_a_soft_error_in_a_for_body_inside_a_subexpression_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $(for ($i = 0; $i -lt 1; $i++) { [int]'a' }; 'in'); Write-Host $x"))

    def test_a_skipped_global_write_read_on_the_continuation_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $([int]'a'; $global:g = 5); Write-Host $global:g"))

    def test_a_skipped_index_write_read_on_the_continuation_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $a = @(1, 2); $x = $([int]'a'; $a[0] = 9); $a[0]"))

    def test_a_skipped_member_write_read_on_the_continuation_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $o = [pscustomobject]@{ P = 1 }; $x = $([int]'a'; $o.P = 9); $o.P"))

    def test_a_skipped_write_read_by_an_increment_on_the_continuation_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $([int]'a'; $q = 99); Write-Host ($q++)"))

    def test_a_skipped_write_a_get_variable_in_a_body_may_read_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; function f { Get-Variable y }; $x = $([int]'a'; $y = 5); f"))

    def test_a_skipped_read_of_a_non_shape_member_keeps_the_trap(self):
        self.assertTrue(self._trap_removal_is_observed(
            "trap { continue }; $x = $([int]'a'; $proc.Path); Write-Host 'z'"))

    def test_a_skipped_read_of_a_shape_member_lets_the_trap_go(self):
        self.assertFalse(self._trap_removal_is_observed(
            "trap { continue }; $x = $([int]'a'; $y.Length); Write-Host 'z'"))

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
        self.assertEqual((_offered(reach, raise_site), _leaves(reach, raise_site)), ((trap,), False))

    def test_a_raise_in_an_array_expression_is_offered_to_the_trap_written_beside_it(self):
        trap, raise_site, reach = self._bracket(_TRAP_IN_AN_ARRAY_EXPRESSION)
        self.assertEqual((_offered(reach, raise_site), _leaves(reach, raise_site)), ((trap,), False))

    def test_a_raise_outside_the_bracket_is_offered_to_no_trap_written_inside_one(self):
        tree, reach = _model("""
            $x = $(trap { 'h' })
            'a'
        """)
        self.assertEqual((_offered(reach, tree.body[1]), _leaves(reach, tree.body[1])), ((), False))


class TestPs1TheBracketFixturesHoldTheShapeTheirPinsAssume(TestBase):

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

    def _bracket_of(self, source: str) -> tuple[Ps1Script, Ps1SubExpression, Ps1FaultReach]:
        tree, reach = _model(source)
        bracket = next(
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1SubExpression)
        )
        return tree, bracket, reach

    def test_a_bracket_internal_statement_with_no_handler_is_placed_and_guarded_by_nothing(self):
        _, bracket, reach = self._bracket_of("$x = $('a'; 'b')")
        self.assertEqual((_offered(reach, bracket.body[1]), _leaves(reach, bracket.body[1])), ((), False))

    def test_points_in_the_statement_holding_the_bracket_reach_the_bracket_internals(self):
        tree, bracket, reach = self._bracket_of("$x = $('a'; 'b')")
        self.assertLessEqual(set(bracket.body), set(reach.points_in(tree.body[0])))


class TestPs1ACommandToldToStopEndsTheScriptHoweverItIsTold(TestBase):

    def _verdicts(self, commands: list[str]) -> dict[str, bool]:
        return {
            command: ends_the_script(_parse(command).body[0], converts=_no_trap_is_asked_about)
            for command in commands
        }

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

    def _removing_the_trap_is_observed(self, assignment: str) -> bool:
        tree, reach = _model(F"""
            {assignment}
            trap {{ continue }}
            Get-Item nope
            'after'
        """)
        trap = next(node for node in tree.walk_in_order() if isinstance(node, Ps1TrapStatement))
        return _handler_removal_is_observed(tree, reach, trap)

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


class TestPs1TheDefaultTableTerminatesACommandButNotACast(TestBase):

    def _verdicts(self, arming: str) -> dict[str, bool]:
        tree, reach = _model(F"""
            {arming}
            Get-Item nope
            [int]'a'
        """)
        command = next(
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1CommandInvocation)
            and resolve_command_name(node) == 'get-item'
        )
        cast = next(
            node for node in tree.body[-1].walk() if isinstance(node, Ps1CastExpression))
        return {
            'command': reach.error_is_terminating(command),
            'cast': reach.error_is_terminating(cast),
        }

    def test_a_default_table_stop_terminates_a_command_but_not_a_cast(self):
        self.assertEqual(
            self._verdicts("$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'"),
            {'command': True, 'cast': False},
        )

    def test_a_command_scoped_default_terminates_a_command_but_not_a_cast(self):
        self.assertEqual(
            self._verdicts("$PSDefaultParameterValues.Add('Get-Item:ErrorAction', 'Stop')"),
            {'command': True, 'cast': False},
        )

    @opportunity
    def test_a_key_scoped_to_another_command_leaves_this_one_non_terminating(self):
        self.assertEqual(
            self._verdicts("$PSDefaultParameterValues['Set-Location:ErrorAction'] = 'Stop'"),
            {'command': False, 'cast': False},
        )

    def test_a_preference_stop_terminates_both_a_command_and_a_cast(self):
        self.assertEqual(
            self._verdicts("$ErrorActionPreference = 'Stop'"),
            {'command': True, 'cast': True},
        )

    def test_a_cmdlet_write_of_the_preference_terminates_both(self):
        self.assertEqual(
            self._verdicts('New-Variable ErrorActionPreference Stop -Force'),
            {'command': True, 'cast': True},
        )

    def test_a_default_that_binds_continue_terminates_neither(self):
        self.assertEqual(
            self._verdicts("$PSDefaultParameterValues['*:ErrorAction'] = 'Continue'"),
            {'command': False, 'cast': False},
        )

    def test_no_arming_terminates_neither(self):
        self.assertEqual(self._verdicts(''), {'command': False, 'cast': False})


class TestPs1ACmdletWriteOfTheStopPreferenceArmsEveryError(TestBase):

    def _cast_is_terminating(self, arming: str) -> bool:
        tree, reach = _model(F"""
            {arming}
            [int]'a'
        """)
        cast = next(node for node in tree.body[-1].walk() if isinstance(node, Ps1CastExpression))
        return reach.error_is_terminating(cast)

    def _verdicts(self, armings: list[str]) -> dict[str, bool]:
        return {arming: self._cast_is_terminating(arming) for arming in armings}

    def test_every_cmdlet_spelling_that_writes_stop_arms_the_preference(self):
        armings = [
            'New-Variable ErrorActionPreference Stop -Force',
            'Set-Variable ErrorActionPreference Stop',
            'Set-Variable ErrorActionPreference -Value Stop',
            'Set-Variable -Name ErrorActionPreference Stop',
            'sv ErrorActionPreference Stop',
            'Set-Variable global:ErrorActionPreference Stop',
            'Set-Item Variable:ErrorActionPreference Stop',
            'New-Variable ErrorActionPreference 1',
        ]
        self.assertEqual(self._verdicts(armings), dict.fromkeys(armings, True))

    def test_a_cmdlet_write_of_a_member_other_than_stop_arms_nothing(self):
        armings = [
            'New-Variable ErrorActionPreference Continue -Force',
            'Set-Variable ErrorActionPreference SilentlyContinue',
            'Set-Variable ErrorActionPreference -Value 2',
        ]
        self.assertEqual(self._verdicts(armings), dict.fromkeys(armings, False))

    def test_a_cmdlet_that_binds_no_value_arms_nothing(self):
        armings = [
            'Clear-Variable ErrorActionPreference',
            'New-Variable ErrorActionPreference',
            'Get-Process -OutVariable ErrorActionPreference',
        ]
        self.assertEqual(self._verdicts(armings), dict.fromkeys(armings, False))


class TestPs1AStrictModeArmingIsReadOverTheWholeScript(TestBase):

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
            'function f { Set-StrictMode -Version 1 }',
            'if ($a) { Set-StrictMode -Version 1 }',
        ]
        self.assertEqual(self._armings(scripts), dict.fromkeys(scripts, True))

    @opportunity
    def test_turning_strict_mode_off_arms_nothing(self):
        self.assertEqual(self._armings(['Set-StrictMode -Off']), {'Set-StrictMode -Off': False})

    def test_the_second_command_that_arms_it_is_read_as_an_arming_too(self):
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

    @todo
    def test_a_name_assembled_out_of_pieces_and_run_arms_strict_mode(self):
        script = "$c = 'Set-Strict' + 'Mode -Version 1'; Invoke-Expression $c"
        self.assertEqual(self._armings([script]), {script: True})

    def test_a_model_the_graphs_hold_no_script_for_refuses_the_grant(self):
        calls = Ps1ModelCache(_parse("'a'")).call_graph
        self.assertTrue(Ps1FaultReach(Ps1ControlFlowModel({}, {}), lambda: calls).strict_mode_may_be_in_force())


class TestPs1WhetherAnErrorLeavesTheBodyItWasRaisedIn(TestBase):

    def _escapes(self, source: str) -> bool:
        tree, faults = _model(source)
        point = next(
            node for node in tree.walk()
            if isinstance(node, Ps1CommandInvocation)
            and resolve_command_name(node) == 'get-random'
        )
        return faults.escapes_the_body(point, Ps1ErrorKind.STATEMENT)

    def test_a_body_with_no_handler_settles_nothing(self):
        self.assertTrue(self._escapes("1, 2 | ForEach-Object { Get-Random }"))

    def test_a_catch_that_acts_settles_it(self):
        self.assertFalse(self._escapes(
            "1, 2 | ForEach-Object { try { Get-Random } catch { Write-Host 'h' } }"))

    def test_an_empty_catch_settles_it_too(self):
        self.assertFalse(self._escapes("1, 2 | ForEach-Object { try { Get-Random } catch { } }"))

    def test_a_trap_that_may_decline_the_error_ends_the_body_and_settles_it(self):
        self.assertFalse(self._escapes(
            "1, 2 | ForEach-Object { trap [System.IO.IOException] { } Get-Random }"))

    def test_a_position_the_graphs_place_nowhere_escapes_nothing(self):
        tree = _parse("function f ($p = $(Get-Random)) { }")
        faults = _reach(tree)
        point = next(
            node for node in tree.walk()
            if isinstance(node, Ps1CommandInvocation)
            and resolve_command_name(node) == 'get-random'
        )
        self.assertFalse(faults.escapes_the_body(point, Ps1ErrorKind.STATEMENT))
        self.assertTrue(_observed(faults, point))


class TestPs1AnErrorOfAFunctionDefinedInABodyLeavesOnlyWhereTheFunctionRuns(TestBase):

    def test_a_function_definition_raises_nothing_out_of_the_body_and_a_call_to_it_may(self):
        tree = _parse("function f { function g { throw 'e' }; g }")
        outer = tree.body[0]
        assert isinstance(outer, Ps1FunctionDefinition) and outer.body is not None
        definition, call = outer.body.body
        handlers = Ps1ModelCache(tree).handlers
        self.assertFalse(handlers.raises_out_of_the_body(definition))
        self.assertTrue(handlers.raises_out_of_the_body(call))


class TestPs1ARaiseEscapesATrapBodyThatRunsOnlyWhereItsBlockMayFireTheTrap(TestBase):

    def _first_trap_body_statement(self, source: str) -> tuple[Ps1FaultReach, RaiseVerdicts, Statement]:
        tree, faults = _model(source)
        trap = next(node for node in tree.walk() if isinstance(node, Ps1TrapStatement))
        body = get_body(trap.body)
        self.assertIsNotNone(body)
        assert body is not None
        return faults, _handler_verdicts(tree, faults).raises(False), body[0]

    def test_a_body_raise_escapes_where_a_cast_in_its_block_fires_the_trap(self):
        faults, raises, body_raise = self._first_trap_body_statement("""
            trap { $null = [int]'a' }
            $null = [int]$args[0]
        """)
        self.assertTrue(faults.escapes_a_trap_body(body_raise, Ps1ErrorKind.STATEMENT))
        self.assertFalse(faults.never_runs(body_raise, raises))

    def test_the_same_body_runs_where_only_a_command_nothing_defines_may_fire_the_trap(self):
        faults, raises, body_raise = self._first_trap_body_statement("""
            trap { $null = [int]'a' }
            Invoke-Nonexistent
        """)
        self.assertFalse(faults.never_runs(body_raise, raises))

    def test_the_same_body_runs_where_only_an_if_test_may_fire_the_trap(self):
        faults, raises, body_raise = self._first_trap_body_statement("""
            trap { $null = [int]'a' }
            if ([int]$args[0]) { }
        """)
        self.assertFalse(faults.never_runs(body_raise, raises))

    def test_the_same_body_never_runs_where_nothing_in_its_block_may_fail(self):
        faults, raises, body_raise = self._first_trap_body_statement("""
            trap { $null = [int]'a' }
            $null = 'x'
        """)
        self.assertTrue(faults.never_runs(body_raise, raises))

    def test_a_raise_in_no_trap_body_escapes_no_firing_trap(self):
        tree, faults = _model("$null = [int]'a'")
        self.assertFalse(faults.escapes_a_trap_body(tree.body[0], Ps1ErrorKind.STATEMENT))
        self.assertFalse(faults.never_runs(tree.body[0], _handler_verdicts(tree, faults).raises(False)))

    def test_a_body_raise_behind_a_scriptblock_boundary_escapes_no_firing_trap(self):
        tree, faults = _model("""
            trap { & { [int]'a' } }
            $null = [int]'b'
        """)
        inner = next(
            node for node in tree.walk()
            if isinstance(node, Ps1ExpressionStatement)
            and isinstance(node.expression, Ps1CastExpression)
        )
        self.assertFalse(faults.escapes_a_trap_body(inner, Ps1ErrorKind.STATEMENT))

    def test_a_body_raise_a_handler_nested_in_the_trap_body_takes_escapes_no_firing_trap(self):
        tree, faults = _model("""
            trap {
              try { [int]'a' } catch { 'h' }
            }
            $null = [int]'b'
        """)
        inner = next(
            node for node in tree.walk()
            if isinstance(node, Ps1ExpressionStatement)
            and isinstance(node.expression, Ps1CastExpression)
        )
        self.assertFalse(faults.escapes_a_trap_body(inner, Ps1ErrorKind.STATEMENT))


class TestPs1AnErrorIsTakenPastAStatementARunCarriesOnAfter(TestBase):

    @staticmethod
    def _raises_past_the_guard(trap: str) -> bool:
        tree = _parse(F"""
            {trap}
            try {{ throw 'a' }} catch {{ if ($x) {{ throw 'b' }}; Write-Host 'b' }}
            Write-Host 'after'
        """)
        guard = next(node for node in tree.walk() if isinstance(node, Ps1IfStatement))
        return Ps1ModelCache(tree).handlers.raises_past(guard)

    def test_a_trap_that_resumes_takes_a_throw_past_the_statement_holding_it(self):
        for trap in ('trap { continue }', 'trap { }', "trap { Write-Host 't' }"):
            with self.subTest(trap):
                self.assertTrue(self._raises_past_the_guard(trap))

    def test_a_trap_that_breaks_at_once_takes_no_throw_past_it(self):
        self.assertFalse(self._raises_past_the_guard('trap { break }'))


class TestPs1AnEditWaitsForATrapDeletionWhoseScopeItTouches(TestBase):

    @staticmethod
    def _waits(source: str, deleted, touched):
        tree = _parse(source)
        cache = Ps1ModelCache(tree)
        faults = cache.faults
        groups_deleted = [[node for node in deleted(tree)], []]
        groups_touched = [[node for node in deleted(tree)], [touched(tree)]]
        return faults.edits_that_wait(groups_deleted, groups_touched, cache.handlers.raises(True))

    def test_an_edit_at_the_call_of_a_body_whose_trap_goes_waits(self):
        waiting, _ = self._waits(
            """
                function f { trap { continue }; $null = [int]$args[0]; Write-Host 'f' }
                f 1
                Write-Host 'after'
            """,
            lambda tree: [tree.body[0].body.body[0]],
            lambda tree: tree.body[1],
        )
        self.assertEqual(waiting, {1})

    def test_an_edit_elsewhere_does_not_wait(self):
        waiting, _ = self._waits(
            """
                function f { trap { continue }; $null = [int]$args[0]; Write-Host 'f' }
                function g { Write-Host 'g' }
                g
            """,
            lambda tree: [tree.body[0].body.body[0]],
            lambda tree: tree.body[2],
        )
        self.assertEqual(waiting, set())

    def test_an_edit_beside_a_trap_offered_nothing_does_not_wait(self):
        waiting, _ = self._waits(
            """
                function f { trap { continue }; Write-Host 'f' }
                f
            """,
            lambda tree: [tree.body[0].body.body[0]],
            lambda tree: tree.body[1],
        )
        self.assertEqual(waiting, set())

    def test_an_edit_of_the_same_plan_in_the_list_of_the_set_is_withheld(self):
        tree = _parse("""
            trap { continue }
            $null = [int]$args[0]
            Write-Host 'after'
        """)
        cache = Ps1ModelCache(tree)
        trap, raiser = tree.body[0], tree.body[1]
        waiting, withheld = cache.faults.edits_that_wait([[trap]], [[trap, raiser]], cache.handlers.raises(True))
        self.assertEqual((waiting, withheld), (set(), {id(raiser)}))
