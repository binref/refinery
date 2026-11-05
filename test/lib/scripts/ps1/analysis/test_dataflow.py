from __future__ import annotations

from test import TestBase, opportunity, todo

from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.ps1.analysis.blocks import build_block_model
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.dataflow import (
    Ps1FlowUnknown,
    Ps1ObservedWrite,
    build_variable_flow,
)
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.model import (
    Ps1SemanticModel,
    build_semantic_model,
    is_write_occurrence,
)
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1IndexExpression, Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _models(source: str):
    tree = Ps1Parser(source).parse()
    semantic = build_semantic_model(tree)
    control = build_control_flow_model(tree)
    blocks = build_block_model(tree)
    dominance = build_dominance(control)
    flow = build_variable_flow(
        semantic, control, dominance, blocks, CycleModel(control, blocks.body_site))
    return tree, semantic, flow


def _in_source_order(node):
    yield node
    for child in node.children():
        yield from _in_source_order(child)


class TestPs1VariableFlow(TestBase):

    def _flow(self, source: str, name: str = 'x'):
        tree, _, flow = _models(source)
        occurrences = [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable) and node.name.lower() == name
        ]
        writes = [node for node in occurrences if is_write_occurrence(node)]
        reads = [node for node in occurrences if not is_write_occurrence(node)]
        return flow, writes, reads

    def _observed(self, source: str, name: str = 'x', read: int = -1) -> int | None:
        flow, writes, reads = self._flow(source, name)
        found = flow.reaching_definition(reads[read])
        if found is None:
            return None
        return next(index for index, write in enumerate(writes) if write is found)

    def test_the_only_write_before_a_read_is_the_one_observed(self):
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x"), 0)

    def test_the_nearest_of_two_writes_is_the_one_observed(self):
        self.assertEqual(self._observed("$x = 'a'; $x = 'b'; Write-Host $x"), 1)

    def test_a_write_in_a_branch_leaves_the_read_after_it_with_no_single_write(self):
        self.assertIsNone(self._observed("$x = 'a'; if ($c) { $x = 'b' }; Write-Host $x"))
        self.assertIsNone(self._observed("$x = 'a'; if ($c) { $x = $y }; Write-Host $x"))

    def test_a_branch_that_does_not_write_leaves_the_write_before_it_standing(self):
        self.assertEqual(self._observed("$x = 'a'; if ($c) { Write-Host 1 }; Write-Host $x"), 0)

    def test_a_dotted_block_writing_the_name_kills_the_write_before_it(self):
        self.assertIn(self._observed("$x = 'a'; . { $x = 'b' }; Write-Host $x"), (None, 1))

    def test_an_ampersand_block_writing_the_name_does_not_kill_it(self):
        self.assertEqual(self._observed("$x = 'a'; & { $x = 'b' }; Write-Host $x"), 0)

    def test_a_write_a_loop_returns_to_leaves_the_read_with_no_single_write(self):
        self.assertIsNone(self._observed("$x = 'a'; while ($c) { Write-Host $x; $x = 'b' }"))

    def test_a_loop_that_only_reads_leaves_the_write_before_it_standing(self):
        self.assertEqual(self._observed("$x = 'a'; while ($c) { Write-Host $x }"), 0)

    def test_a_store_that_may_not_have_completed_is_not_observed_in_the_handler(self):
        self.assertIsNone(self._observed("try { [int]$x = 'abc' } catch { Write-Host $x }"))

    def test_a_write_inside_a_trap_is_never_what_a_later_read_observes(self):
        self.assertIn(
            self._observed("$x = 'a'; trap { $x = 'b'; continue }; throw 'e'; Write-Host $x"),
            (None, 0),
        )

    @opportunity
    def test_a_bare_write_in_a_trap_body_leaves_the_write_above_it_standing(self):
        # A `trap` body is a scope of its own, so its bare write binds another `$x`: 5.1 writes `a`.
        self.assertEqual(
            self._observed("$x = 'a'; trap { $x = 'b'; continue }; throw 'e'; Write-Host $x"), 0)

    def test_a_script_qualified_write_in_a_trap_body_is_what_the_read_below_may_observe(self):
        source = "$x = 'a'; trap { $script:x = 'b'; continue }; throw 'e'; Write-Host $x"
        self.assertIn(self._observed(source), (None, 1))

    def test_a_global_write_in_a_trap_body_leaves_the_read_below_with_no_single_write(self):
        self.assertIsNone(
            self._observed("$x = 'a'; trap { $global:x = 'b'; continue }; throw 'e'; Write-Host $x")
        )

    def test_a_foreach_object_body_writing_the_name_kills_it(self):
        self.assertIn(
            self._observed("$x = 'a'; 1..3 | ForEach-Object { $x = 'b' }; Write-Host $x"), (None, 1)
        )

    def test_a_handler_observes_its_own_completed_store(self):
        self.assertEqual(self._observed("try { f } catch { $x = 'b'; Write-Host $x }"), 0)

    def test_a_read_inside_a_body_is_answered_at_the_statement_that_runs_the_body(self):
        for source in [
            "$x = 'a'; 1..3 | ForEach-Object { Write-Host $x }",
            "$x = 'a'; . { Write-Host $x }",
            "$x = 'a'; & { Write-Host $x }",
            "$x = 'a'; & { & { Write-Host $x } }",
        ]:
            with self.subTest(source):
                self.assertEqual(self._observed(source), 0)

    def test_a_read_inside_a_body_observes_the_writes_the_site_is_ordered_against(self):
        for source, expected in [
            ("$x = 'a'; & { Write-Host $x }; $x = 'b'", 0),
            ("$x = 'a'; $x = 'b'; & { Write-Host $x }", 1),
            ("$x = 'a'; if ($c) { $x = 'b' }; & { Write-Host $x }", None),
        ]:
            with self.subTest(source):
                self.assertEqual(self._observed(source), expected)

    @opportunity
    def test_a_read_inside_a_block_invoke_command_runs_observes_the_write_before_the_call(self):
        self.assertEqual(self._observed("$x = 'a'; Invoke-Command { Write-Host $x }; $x = 'b'"), 0)

    def test_a_read_inside_a_body_a_call_site_reaches_is_not_placed_where_it_is_written(self):
        for source in [
            "$x = 'a'; function f { Write-Host $x }; $x = 'b'; f",
            "$x = 'a'; $b = { Write-Host $x }; $x = 'b'; & $b",
        ]:
            with self.subTest(source):
                self.assertIn(self._observed(source, read=0), (None, 1))

    def test_a_body_running_before_a_write_in_its_own_statement_observes_the_earlier_one(self):
        self.assertEqual(self._observed("$x = 'a'; (& { $x }), ($x = 'b')"), 0)

    def test_a_read_beside_the_writes_is_answered_though_a_function_body_reads_the_name_too(self):
        self.assertEqual(
            self._observed("$x = 'a'; function f { Write-Host $x }; Write-Host $x"), 0)

    def test_a_read_and_its_writes_inside_one_block_are_ordered_normally(self):
        self.assertEqual(self._observed("$b = { $x = 'a'; Write-Host $x }"), 0)

    def test_a_write_the_graphs_do_not_place_is_refused_rather_than_ignored(self):
        self.assertIsNone(
            self._observed("function f { param($x = 'a') Write-Host $x }"))

    def test_a_write_the_same_statement_stores_after_the_read_is_not_what_it_observes(self):
        self.assertEqual(self._observed("$x = 'a'; $x = $x + 'b'; Write-Host $x", read=0), 0)

    def test_a_target_written_left_of_the_read_still_stores_after_it(self):
        self.assertEqual(self._observed('$x = 39; $x = [char]($x)', read=0), 0)

    def test_an_argument_evaluated_before_a_later_assignment_observes_the_earlier_write(self):
        self.assertEqual(self._observed("$x = 'old'; Write-Host $x ($x = 'new')", read=0), 0)

    def test_a_write_the_same_statement_stores_before_the_read_hides_the_one_before_it(self):
        self.assertIn(self._observed("$x = 'old'; Write-Host ($x = 'new') $x"), (None, 1))

    def test_a_self_referencing_write_control_returns_to_observes_no_single_value(self):
        self.assertIsNone(self._observed("$x = 'a'; while ($c) { $x = $x + 'b' }", read=0))

    def test_a_multi_assignment_target_is_a_write_like_any_other(self):
        self.assertEqual(self._observed("$x, $y = 1, 2; Write-Host $x"), 0)

    def test_a_store_through_the_name_is_the_write_a_read_below_it_observes(self):
        for source in (
            "$x = @('a', 'b'); $x[0] = 'z'; Write-Host $x",
            "$x = @{ A = 1 }; $x.A = 5; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertEqual(self._observed(source), 1)

    def test_a_store_through_the_name_leaves_a_read_above_it_with_the_write_before_it(self):
        self.assertEqual(self._observed("$x = @('a', 'b'); Write-Host $x; $x[0] = 'z'"), 0)

    def test_a_store_through_the_name_on_one_branch_leaves_the_read_below_it_unanswered(self):
        self.assertIsNone(
            self._observed("$x = @('a', 'b'); if ($c) { $x[0] = 'z' }; Write-Host $x"))

    def test_a_store_through_the_name_a_loop_returns_to_leaves_the_read_unanswered(self):
        self.assertIsNone(
            self._observed("$x = @('a', 'b'); while ($c) { Write-Host $x; $x[0] = 'z' }"))

    def test_a_child_scope_store_through_the_name_reaches_the_callers_value_unlike_a_binding(self):
        self.assertEqual(self._observed("$x = @('a', 'b'); & { $x = 'b' }; Write-Host $x"), 0)
        self.assertIn(
            self._observed("$x = @('a', 'b'); & { $x[0] = 'z' }; Write-Host $x"), (None, 1)
        )


class TestPs1EveryWriteThatMayGiveAReadItsObject(TestPs1VariableFlow):

    def _reaching(self, source: str, name: str = 'x', read: int = -1) -> list[int] | None:
        flow, writes, reads = self._flow(source, name)
        found = flow.writes_reaching(reads[read])
        if found is None:
            return None
        return sorted(
            next(index for index, write in enumerate(writes) if write is node) for node in found)

    def test_the_only_write_before_a_read_reaches_it(self):
        self.assertEqual(self._reaching('$x = 1, 2; Write-Output $x'), [0])

    def test_a_later_write_hides_the_earlier_one(self):
        self.assertEqual(self._reaching('$x = 1, 2; $x = 3, 4; Write-Output $x'), [1])

    def test_both_arms_of_a_branch_reach_the_read_after_it(self):
        self.assertEqual(
            self._reaching('if ($a) { $x = 1, 2 } else { $x = 3, 4 }; Write-Output $x'), [0, 1])

    def test_a_write_in_one_arm_reaches_beside_the_write_before_the_branch(self):
        self.assertEqual(
            self._reaching('$x = 1, 2; if ($a) { $x = 3, 4 }; Write-Output $x'), [0, 1])

    def test_a_write_in_a_loop_body_reaches_the_condition_beside_the_write_before_the_loop(self):
        self.assertEqual(self._reaching('$x = 1, 2; while ($x) { $x = 3, 4 }', read=0), [0, 1])

    def test_a_store_through_the_name_does_not_hide_the_write_before_it(self):
        self.assertEqual(self._reaching('$x = 0, 0; $x[0] = 7; Write-Output $x'), [0])

    def test_a_read_that_may_observe_the_value_from_before_the_script_has_no_answer(self):
        self.assertIsNone(self._reaching('if ($a) { $x = 1, 2 }; Write-Output $x'))

    def test_a_rebinding_in_the_statement_of_the_read_hides_the_write_it_replaced(self):
        for source in (
            '$x = 0, 0; $y = 1, 2; $null = (. { $x = $y }), ($x[0] = 9)',
            '$x = 0, 0; $y = 1, 2; $x[0] = (. { $x = $y; 9 })',
        ):
            with self.subTest(source):
                flow, writes, _ = self._flow(source)
                store, = (write for write in writes if isinstance(write.parent, Ps1IndexExpression))
                rebinding, = (write for write in writes[1:] if write is not store)
                self.assertIn(flow.writes_reaching(store), (None, [rebinding]))
                self.assertIn(flow.reaching_definition(store), (None, rebinding))

    def test_an_automatic_variable_holds_what_the_engine_gave_it(self):
        source = '$_ = 0, 0; switch (1, 2) { default { Write-Output $_ } }'
        self.assertIsNone(self._reaching(source, name='_'))
        self.assertIsNone(self._observed(source, name='_'))


class TestPs1ABareReadAnswersOnlyWhereItReachesItsBinding(TestPs1VariableFlow):

    def test_a_bare_read_in_a_function_body_of_a_script_variable_has_no_answer(self):
        source = 'function f { $script:o = 0, 0; Write-Output $o }'
        self.assertIsNone(self._observed(source, 'o'))
        flow, _, reads = self._flow(source, 'o')
        self.assertIsNone(flow.writes_reaching(reads[-1]))

    def test_a_read_that_names_the_scope_it_reads_is_answered(self):
        source = 'function f { $script:o = 0, 0; Write-Output $script:o }'
        self.assertEqual(self._observed(source, 'o'), 0)


class TestPs1FlowUnknowns(TestBase):

    def _unknowns(self, source: str, name: str = 'x') -> Ps1FlowUnknown:
        _, semantic, flow = _models(source)
        return flow.unknowns(semantic.script_scope.bindings[name])

    def test_a_binding_written_and_read_in_one_body_has_no_unknowns(self):
        self.assertIs(self._unknowns("$x = 'a'; Write-Host $x"), Ps1FlowUnknown.NONE)

    def test_writes_in_two_bodies_leave_the_binding_unorderable(self):
        self.assertIn(
            Ps1FlowUnknown.WRITES_IN_SEVERAL_BODIES,
            self._unknowns("$x = 'a'; & { $script:x = 'b' }"))

    def test_a_read_in_another_body_leaves_the_binding_itself_answerable(self):
        self.assertIs(
            self._unknowns("$x = 'a'; function f { Write-Host $x }; Write-Host $x"),
            Ps1FlowUnknown.NONE)

    def test_a_read_naming_the_scope_the_writes_land_in_leaves_the_binding_answerable(self):
        for source in [
            "$x = 'a'; Write-Host $script:x",
            "$x = 'a'; Write-Host $local:x",
            "$x = 'a'; Write-Host $variable:x",
            "$global:x = 'a'; Write-Host $global:x",
            "$private:x = 'a'; Write-Host $x",
        ]:
            with self.subTest(source):
                self.assertIs(self._unknowns(source), Ps1FlowUnknown.NONE)

    def test_a_using_reader_is_reported_separately_from_an_unorderable_write(self):
        found = self._unknowns("$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $using:x }")
        self.assertIn(Ps1FlowUnknown.READ_THROUGH_USING, found)
        self.assertNotIn(Ps1FlowUnknown.WRITES_IN_SEVERAL_BODIES, found)

    def test_a_read_naming_one_scope_of_a_name_written_through_the_other_shadows(self):
        for source in [
            "$x = 'a'; Write-Host $global:x",
            "$global:x = 'a'; Write-Host $script:x",
            "$global:x = 'a'; Write-Host $local:x",
        ]:
            with self.subTest(source):
                self.assertIn(Ps1FlowUnknown.SHADOWS_A_WIDER_SCOPE, self._unknowns(source))

    def test_a_private_variable_read_from_another_scope_is_hidden_from_that_reader(self):
        for source in [
            "$private:x = 'a'; & { Write-Host $x }",
            # 5.1 hides the private variable from the child scope even where the read names it.
            "$private:x = 'a'; & { Write-Host $script:x }",
        ]:
            with self.subTest(source):
                self.assertIn(Ps1FlowUnknown.HIDDEN_FROM_A_READER, self._unknowns(source))

    def test_a_private_variable_read_in_a_trap_body_is_hidden_from_that_reader(self):
        # A `trap` body is a scope of its own.
        source = "$private:x = 'a'; if (1) { trap { Write-Host $x; continue }; throw 'e' }"
        self.assertIn(Ps1FlowUnknown.HIDDEN_FROM_A_READER, self._unknowns(source))

    def test_a_variable_a_command_makes_private_is_hidden_from_a_child_scope(self):
        for source in [
            "New-Variable -Name x -Option Private; $x = 'a'; & { Write-Host $x }",
            "Set-Variable -Name x -Value 'a' -Option Private; & { Write-Host $x }",
        ]:
            with self.subTest(source):
                self.assertIn(Ps1FlowUnknown.HIDDEN_FROM_A_READER, self._unknowns(source))

    def test_a_variable_handed_out_is_written_through_it_in_every_scope(self):
        for source in (
            "$x = 'a'; $v = Get-Variable x",
            "$x = 'a'; function g { $v = Get-Variable x }",
        ):
            with self.subTest(source):
                self.assertIn(Ps1FlowUnknown.WRITTEN_THROUGH_ITS_VARIABLE, self._unknowns(source))

    def test_a_value_read_where_the_variable_is_fetched_hands_nothing_out(self):
        self.assertIs(
            self._unknowns("$x = 'a'; Write-Host (Get-Variable x).Value"), Ps1FlowUnknown.NONE)

    def test_a_command_giving_other_options_hides_nothing(self):
        self.assertNotIn(
            Ps1FlowUnknown.HIDDEN_FROM_A_READER,
            self._unknowns("New-Variable -Name x -Option ReadOnly; & { Write-Host $x }"),
        )

    def test_a_stored_block_writing_the_name_defers_the_binding(self):
        self.assertIn(
            Ps1FlowUnknown.WRITTEN_BY_DEFERRED_BODY,
            self._unknowns("$x = 'a'; $b = { $x = 'b' }"))

    def test_reading_through_an_index_leaves_the_binding_trackable(self):
        self.assertIs(
            self._unknowns("$x = @('a', 'b'); Write-Host $x[0]"), Ps1FlowUnknown.NONE)

    def test_storing_through_an_index_leaves_the_binding_trackable(self):
        for source in ("$x = @('a', 'b'); $x[0] = 'z'", "$x = 'hello'; $x.Length = 5"):
            with self.subTest(source):
                self.assertIs(self._unknowns(source), Ps1FlowUnknown.NONE)


class TestPs1VariableFlowRegressions(TestPs1VariableFlow):

    def test_a_use_the_throwing_path_also_reaches_observes_no_store(self):
        self.assertIsNone(self._observed("try { [int]$x = 'abc' } catch { }; Write-Host $x"))

    def test_a_statement_a_trap_resumes_into_observes_no_store(self):
        self.assertIsNone(self._observed("trap { continue }; [int]$x = 'abc'; Write-Host $x"))

    def test_a_use_reached_only_by_completing_still_observes_the_store(self):
        self.assertEqual(self._observed("try { $x = 'a'; Write-Host $x } catch { }"), 0)

    def test_every_receiver_chain_an_assignment_stores_through_kills_the_write_before_it(self):
        for source in (
            "$x = @('a', 'b'), @('c'); $x[0][1] = 'z'; Write-Host $x",
            "$x = @{ A = @{} }; $x.A.B = 5; Write-Host $x",
            "$x = @('a', 'b'); ($x)[0] = 'z'; Write-Host $x",
            "$x = @('a', 'b'); ([array]$x)[0] = 'z'; Write-Host $x",
            "$x = @('a', 'b'); $x[0] += 'z'; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertEqual(self._observed(source), 1)

    def test_of_two_stores_through_one_name_in_one_statement_only_the_later_may_be_observed(self):
        self.assertIn(
            self._observed("$x = @('a', 'b'); $x[0], $x[1] = 'p', 'q'; Write-Host $x"), (None, 2)
        )


class TestPs1FlowUnknownRegressions(TestPs1FlowUnknowns):

    def test_a_stored_block_outside_the_binding_body_is_still_a_deferred_writer(self):
        _, semantic, flow = _models(
            "$b = { $x = 'INNER' }\n. {\n  $x = 'OUTER'\n  . $b\n  Write-Host $x\n}")
        inner = next(
            scope for scope in semantic.script_scope.children if 'x' in scope.bindings)
        self.assertIn(
            Ps1FlowUnknown.WRITTEN_BY_DEFERRED_BODY,
            flow.unknowns(inner.bindings['x']))


class TestPs1UnattributableWrites(TestPs1VariableFlow):

    def test_a_read_before_a_computed_write_still_observes_its_write(self):
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x; Set-Variable $n 'v'"), 0)

    def test_a_computed_write_between_a_write_and_a_read_kills_it(self):
        self.assertIsNone(self._observed("$x = 'a'; Set-Variable $n 'v'; Write-Host $x"))

    def test_a_dotted_block_running_a_computed_write_kills_the_callers_write(self):
        self.assertIsNone(self._observed("$x = 'a'; . { Set-Variable $n 'v' }; Write-Host $x"))

    def test_a_body_nested_inside_a_caller_scoped_one_still_reaches_the_outermost_caller(self):
        for source in (
            "$x = 'a'; . { . { Set-Variable $n 'v' } }; Write-Host $x",
            "$x = 'a'; 1..3 | %{ Set-Variable $n 'v' }; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    def test_a_computed_write_naming_the_script_scope_kills_from_inside_a_child_scope(self):
        self.assertIsNone(
            self._observed("$x = 'a'; & { Set-Variable $n 'v' -Scope Global }; Write-Host $x"))

    def test_a_scope_the_lexical_chain_cannot_name_kills_wherever_it_is_written(self):
        self.assertIsNone(
            self._observed("$x = 'a'; & { Set-Variable $n 'v' -Scope 1 }; Write-Host $x"))

    def test_a_computed_write_in_a_stored_block_kills_without_a_point_to_stand_at(self):
        source = "$x = 'a'; $b = { Set-Variable $n 'v' }; . $b; Write-Host $x"
        self.assertIsNone(self._observed(source))
        _, semantic, flow = _models(source)
        self.assertIn(
            Ps1FlowUnknown.WRITTEN_BY_UNREADABLE_NAME,
            flow.unknowns(semantic.script_scope.bindings['x']))

    def test_the_kill_is_placed_at_the_statement_that_runs_the_write(self):
        tree, _, flow = _models(
            "$x = 'a'\n. { Set-Variable $n 'v' }\nWrite-Host $x")
        graph = flow.flow.graph_of(tree)
        placed = [node.element for node in flow.unattributable_writes(graph)]
        self.assertEqual(placed, [tree.body[1]])

    def test_a_literal_named_write_is_no_kill_at_all(self):
        tree, _, flow = _models("$x = 'a'\nSet-Variable y 'v'\nWrite-Host $x")
        self.assertEqual(flow.unattributable_writes(flow.flow.graph_of(tree)), ())
        self.assertEqual(self._observed("$x = 'a'; Set-Variable y 'v'; Write-Host $x"), 0)

    def test_a_call_running_unreadable_code_in_the_callers_scope_kills_across_it(self):
        for source in (
            "$x = 'a'; iex $c; Write-Host $x",
            "$x = 'a'; . 'stage2.ps1'; Write-Host $x",
            "$x = 'a'; . $sb; Write-Host $x",
            "$x = 'a'; . { iex $c }; Write-Host $x",
            "$x = 'a'; 1..3 | %{ iex $c }; Write-Host $x",
            "$x = 'a'; Invoke-Command -NoNewScope -ScriptBlock $sb; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    def test_a_dotted_block_that_writes_nothing_kills_nothing(self):
        self.assertEqual(self._observed("$x = 'a'; . { Write-Host 1 }; Write-Host $x"), 0)

    def test_the_argument_a_call_expands_is_read_before_the_call_runs(self):
        self.assertEqual(self._observed("$x = 'Write-Host hi'; iex $x"), 0)
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x (iex $c)"), 0)

    def test_an_argument_is_built_before_the_call_however_many_bodies_it_runs(self):
        self.assertEqual(
            self._observed("$x = 'a'; iex (1..2 | %{ [char]($_ -bxor $x) })"), 0)

    def test_a_call_a_loop_returns_to_may_have_rewritten_its_own_argument(self):
        self.assertIsNone(self._observed("$x = 'a'; while ($c) { iex $x }"))
        self.assertIsNone(self._observed("$x = 'a'; 1..3 | %{ iex $x }"))

    def test_a_read_beside_the_body_that_writes_is_ordered_where_the_body_is_not(self):
        self.assertIsNone(self._observed("$x = 'a'; . { iex $c; Write-Host $x }"))
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x (. { iex $c })"), 0)
        self.assertIsNone(self._observed("$x = 'a'; Write-Host (. { iex $c }) $x"))

    def test_a_read_the_call_cannot_have_reached_yet_is_still_answered(self):
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x; iex $c"), 0)
        self.assertEqual(self._observed("$x = 'a'; 1..3 | %{ Write-Host $x }; iex $c"), 0)

    @opportunity
    def test_a_read_in_a_body_above_the_call_in_that_body_is_still_answered(self):
        self.assertEqual(self._observed("$x = 'a'; . { Write-Host $x; iex $c }"), 0)

    def test_a_read_the_call_may_already_have_reached_is_refused(self):
        self.assertIsNone(self._observed("$x = 'a'; Write-Host (iex $c) $x"))

    def test_one_statement_may_hold_several_and_the_earliest_is_what_decides(self):
        for source in (
            "$x = 'a'; Write-Host (iex $a) $x (iex $b)",
            "$x = 'a'; Write-Host (Set-Variable $n 1) $x (iex $b)",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    def test_a_read_projected_onto_the_statement_gets_no_ordering_from_it(self):
        self.assertIsNone(self._observed("$x = 'a'; 1..2 | %{ Write-Output $x } | %{ iex $s }"))

    def test_an_ambient_value_is_a_definition_at_the_scripts_entry(self):
        for source, survives in (
            ('Write-Host $env:ComSpec', True),
            ('Write-Host $env:ComSpec; iex $c', True),
            ('iex $c; Write-Host $env:ComSpec', False),
            ("; . 'stage2.ps1'; Write-Host $env:ComSpec", False),
            ("Set-Variable $n 'v'; Write-Host $env:ComSpec", False),
        ):
            with self.subTest(source):
                tree, _, flow = _models(source)
                read = next(
                    node for node in _in_source_order(tree)
                    if isinstance(node, Ps1Variable) and node.name.lower() == 'comspec'
                )
                self.assertEqual(flow.ambient_value_survives(read), survives)

    def test_an_ambient_value_a_body_reads_survives_where_nothing_can_displace_it(self):
        for source, survives in (
            ('$b = { Write-Host $env:ComSpec }', True),
            ('function f { Write-Host $env:ComSpec }', True),
            ('$b = { Write-Host $env:ComSpec }; iex $c', False),
            ("$b = { Write-Host $env:ComSpec }; Set-Variable $n 'v'", False),
        ):
            with self.subTest(source):
                tree, _, flow = _models(source)
                read = next(
                    node for node in _in_source_order(tree)
                    if isinstance(node, Ps1Variable) and node.name.lower() == 'comspec'
                )
                self.assertEqual(flow.ambient_value_survives(read), survives)

    def test_an_ambient_value_is_refused_where_the_doubt_has_no_point(self):
        for source in (
            "Set-Variable $n 'v' -Scope Global; Write-Host $env:ComSpec",
            "$b = { iex $c }; . $b; Write-Host $env:ComSpec",
        ):
            with self.subTest(source):
                tree, _, flow = _models(source)
                read = next(
                    node for node in _in_source_order(tree)
                    if isinstance(node, Ps1Variable) and node.name.lower() == 'comspec'
                )
                self.assertFalse(flow.ambient_value_survives(read))

    def test_a_relative_path_command_kills_nothing(self):
        self.assertEqual(self._observed(r"$x = 'a'; .\tool.exe; Write-Host $x"), 0)
        self.assertIsNone(self._observed(r"$x = 'a'; . .\stage2.ps1; Write-Host $x"))

    def test_a_write_naming_another_scope_is_not_one_of_the_placed_ones(self):
        for source in (
            "$x = 'a'\nSet-Variable $n 'v' -Scope Global\nWrite-Host $x",
            "$x = 'a'\nSet-Variable $n 'v' -Scope 1\nWrite-Host $x",
        ):
            with self.subTest(source):
                tree, _, flow = _models(source)
                self.assertEqual(flow.unattributable_writes(flow.flow.graph_of(tree)), ())


class TestPs1UnattributableWritesFromAChildScope(TestPs1VariableFlow):

    @todo
    def test_a_function_body_running_unreadable_code_kills_across_its_call_sites(self):
        self.assertIsNone(self._observed("$x = 'a'; function f { iex $c }; f; Write-Host $x"))

    @todo
    def test_a_qualified_write_from_inside_a_child_scope_kills_the_callers_write(self):
        self.assertIsNone(self._observed('''$x = 'a'; & { iex '$script:x = 1' }; Write-Host $x'''))

    @todo
    def test_a_call_running_unreadable_code_in_a_child_scope_kills_across_it(self):
        for source in (
            "$x = 'a'; & 'stage2.ps1'; Write-Host $x",
            "$x = 'a'; & $sb; Write-Host $x",
            "$x = 'a'; & { iex $c }; Write-Host $x",
            "$x = 'a'; Invoke-Command -ScriptBlock $sb; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    @todo
    def test_a_computed_write_in_a_child_scope_may_reach_the_callers_variable(self):
        for source in (
            "$x = 'a'; & { Set-Variable $n 'v' }; Write-Host $x",
            "$x = 'a'; function f { Set-Variable $n 'v' }; f; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    @todo
    def test_a_computed_write_dot_sourced_inside_a_child_scope_may_reach_the_callers_variable(self):
        self.assertIsNone(
            self._observed("$x = 'a'; & { . { Set-Variable $n 'v' } }; Write-Host $x")
        )


class TestPs1WhatStandsWhereNoSingleWriteIsObserved(TestBase):

    def _observed_at(self, source: str, site: int = -1, name: str = 'x'):
        tree, _, flow = _models(source)
        occurrences = [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable) and node.name.lower() == name
        ]
        writes = [node for node in occurrences if is_write_occurrence(node)]
        found = flow.write_observed_at(name, tree.body[site])
        if isinstance(found, Ps1ObservedWrite):
            return found
        return next(index for index, write in enumerate(writes) if write is found)

    def test_a_name_no_statement_writes_still_holds_what_the_session_established(self):
        self.assertIs(self._observed_at('Write-Host $x'), Ps1ObservedWrite.NOTHING)

    def test_a_variable_handed_out_is_written_where_no_write_of_it_stands(self):
        self.assertIs(
            self._observed_at("$x = 'a'; $v = Get-Variable x; $v.Value = 'b'; Write-Host $x"),
            Ps1ObservedWrite.UNKNOWN,
        )

    def test_the_session_value_of_a_variable_handed_out_is_not_what_stands(self):
        tree, _, flow = _models(
            "$v = Get-Variable ErrorActionPreference; $v.Value = 'Stop'\n"
            'Write-Host $ErrorActionPreference')
        read = [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable) and node.name.lower() == 'erroractionpreference'
        ][-1]
        self.assertFalse(flow.ambient_value_survives(read))

    def test_the_write_standing_at_the_point_is_the_one_observed_there(self):
        self.assertEqual(self._observed_at("$x = 'a'; Write-Host $x"), 0)

    def test_a_write_the_point_precedes_is_not_yet_the_one_standing_there(self):
        self.assertIs(self._observed_at("Write-Host $x; $x = 'a'", site=0), Ps1ObservedWrite.NOTHING)

    def test_a_write_inside_a_child_scope_leaves_the_session_value_standing(self):
        self.assertIs(
            self._observed_at("& { $x = 'a' }; Write-Host $x"), Ps1ObservedWrite.NOTHING)

    def test_a_branch_that_may_have_written_the_name_is_not_the_name_being_unwritten(self):
        self.assertIs(
            self._observed_at("if ($c) { $x = 'a' }; Write-Host $x"), Ps1ObservedWrite.UNKNOWN)

    def test_a_while_body_that_may_have_written_the_name_is_not_the_name_being_unwritten(self):
        self.assertIs(
            self._observed_at("while ($c) { $x = 'a' }; Write-Host $x"), Ps1ObservedWrite.UNKNOWN)

    def test_a_foreach_body_over_a_literal_collection_writes_the_name(self):
        self.assertIn(
            self._observed_at("foreach ($i in 1, 2) { $x = 'a' }; Write-Host $x"),
            (Ps1ObservedWrite.UNKNOWN, 0),
        )

    def test_a_dotted_block_writes_the_name_of_whoever_ran_it(self):
        self.assertIn(
            self._observed_at(". { $x = 'a' }; Write-Host $x"), (Ps1ObservedWrite.UNKNOWN, 0)
        )

    def test_a_write_spelled_as_a_command_naming_the_variable_is_the_one_observed(self):
        tree, _, flow = _models("Set-Variable x 'v'; Write-Host $x")
        command = next(
            node for node in _in_source_order(tree.body[0])
            if isinstance(node, Ps1CommandInvocation)
        )
        self.assertIs(flow.write_observed_at('x', tree.body[-1]), command)

    def test_a_call_that_may_write_any_name_is_not_the_name_being_unwritten(self):
        self.assertIs(self._observed_at('iex $c; Write-Host $x'), Ps1ObservedWrite.UNKNOWN)


class TestPs1WrittenBefore(TestBase):

    def _written_before(self, source: str, read: int = -1, name: str = 'x') -> bool:
        tree, _, flow = _models(source)
        reads = [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable)
            and node.name.lower() == name
            and not is_write_occurrence(node)
        ]
        return flow.written_before(reads[read])

    def test_a_name_the_script_never_writes_holds_nothing_the_script_put_there(self):
        self.assertFalse(self._written_before('Write-Host $x'))

    def test_a_write_the_read_follows_has_run(self):
        self.assertTrue(self._written_before("$x = 'a'; Write-Host $x"))

    def test_a_write_the_read_precedes_has_not_run(self):
        self.assertFalse(self._written_before("Write-Host $x; $x = 'a'"))

    def test_a_write_on_one_branch_only_has_not_certainly_run(self):
        self.assertFalse(self._written_before("if ($c) { $x = 'a' }; Write-Host $x"))

    def test_a_write_before_a_branch_that_writes_again_has_run(self):
        self.assertTrue(self._written_before("$x = 'a'; if ($c) { $x = 'b' }; Write-Host $x"))

    def test_a_loop_body_read_above_the_only_write_is_reached_on_the_first_visit(self):
        self.assertFalse(self._written_before("while ($c) { Write-Host $x; $x = 'a' }"))

    def test_a_write_before_the_loop_has_run_at_a_read_inside_it(self):
        self.assertTrue(self._written_before("$x = 'a'; while ($c) { Write-Host $x; $x = 'b' }"))

    def test_a_write_earlier_in_the_one_statement_they_share_has_run(self):
        self.assertTrue(self._written_before("$($x = 'a'; Write-Host $x)"))

    def test_a_write_later_in_the_one_statement_they_share_has_not_run(self):
        self.assertFalse(self._written_before("$(Write-Host $x; $x = 'a')"))

    def test_a_write_the_read_produces_the_value_for_has_not_run(self):
        self.assertFalse(self._written_before('$x = [char]($x)'))

    def test_a_write_later_in_a_repeated_statement_has_not_run_on_the_first_visit(self):
        self.assertFalse(self._written_before("while ($c) { Write-Host $x ($x = 'a') }"))

    def test_a_write_before_a_repeated_statement_has_run_at_every_visit_of_it(self):
        self.assertTrue(self._written_before("$x = 'a'; while ($c) { Write-Host $x ($x = 'b') }"))

    def test_a_store_the_handler_is_only_reached_without_has_not_run(self):
        self.assertFalse(self._written_before("try { [int]$x = 'abc' } catch { Write-Host $x }"))

    def test_a_store_the_statement_after_the_try_may_be_reached_without_has_not_run(self):
        self.assertFalse(self._written_before("try { [int]$x = 'abc' } catch { }; Write-Host $x"))

    def test_a_read_inside_a_trap_body_is_not_told_a_write_below_the_trap_has_run(self):
        self.assertFalse(self._written_before("trap { Write-Host $x }; $x = 'a'"))

    @opportunity
    def test_a_write_in_a_trap_body_above_a_read_in_it_has_run(self):
        self.assertTrue(self._written_before("trap { $x = 'a'; Write-Host $x }"))

    def test_a_read_only_the_completed_store_reaches_has_it(self):
        self.assertTrue(self._written_before("try { $x = 'a'; Write-Host $x } catch { }"))


class TestPs1WrittenBeforeAtAnOccurrenceThatObservesWhatItWrites(TestPs1WrittenBefore):

    def _written_before_its_own_store(self, source: str, name: str = 'x') -> bool:
        _, semantic, flow = _models(source)
        observing, = [
            write.node for write in semantic.script_scope.bindings[name].writes
            if write.role.observes
            and isinstance(write.node, Ps1Variable)
        ]
        return flow.written_before(observing)

    def test_an_occurrence_has_not_stored_the_value_it_is_evaluated_to_produce(self):
        for source in ['$x += 1', '$x++', '$x--']:
            with self.subTest(source):
                self.assertFalse(self._written_before_its_own_store(source))

    def test_a_write_standing_before_such_an_occurrence_has_run_by_the_time_it_reads(self):
        for source in ['$x = 1; $x += 1', '$x = 1; $x++']:
            with self.subTest(source):
                self.assertTrue(self._written_before_its_own_store(source))


class TestPs1AnAliasThroughAConversionKillsWithoutNamingAValue(TestBase):

    @staticmethod
    def _occurrences(tree, name: str) -> list[Ps1Variable]:
        return [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable) and node.name.lower() == name
        ]

    def test_a_read_below_a_store_through_a_conversion_shared_name_has_no_definition(self):
        for definition in (
            '$y = [array]$x',
            '$y = $x -as [array]',
            '[array]$y = $x',
            '[int[]]$y = $x',
            '$y = [int[]]$x',
        ):
            for store, name in (('$y[0] = 9', 'x'), ('$x[0] = 9', 'y')):
                with self.subTest(F'{definition}; {store}'):
                    source = F'$x = $args[0]\n{definition}\n{store}\nWrite-Output ${name}'
                    tree, _, flow = _models(source)
                    read = self._occurrences(tree, name)[-1]
                    self.assertIsNone(flow.reaching_definition(read))

    def test_a_read_below_a_store_through_a_name_handed_the_object_observes_that_store(self):
        for definition in ('$y = $x', '$y = ($x)'):
            with self.subTest(definition):
                source = F'$x = 1, 2, 3\n{definition}\n$y[0] = 9\nWrite-Output $x'
                tree, _, flow = _models(source)
                store = self._occurrences(tree, 'y')[1]
                read = self._occurrences(tree, 'x')[-1]
                self.assertIs(flow.reaching_definition(read), store)

    def test_a_read_below_a_store_through_a_copy_still_observes_the_names_own_write(self):
        source = '$x = 1, 2, 3\n$y = $($x)\n$y[0] = 9\nWrite-Output $x'
        tree, _, flow = _models(source)
        occurrences = self._occurrences(tree, 'x')
        self.assertIs(flow.reaching_definition(occurrences[-1]), occurrences[0])
