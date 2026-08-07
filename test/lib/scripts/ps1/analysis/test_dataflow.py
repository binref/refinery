from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.ps1.analysis.blocks import build_block_model
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1FlowUnknown, build_variable_flow
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.model import (
    Ps1SemanticModel,
    build_semantic_model,
    is_write_occurrence,
)
from refinery.lib.scripts.ps1.model import Ps1Variable
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
    """
    Pre-order over `children()`, which is source order. `Node.walk` is driven by a stack and comes
    back reversed, and `Ps1Variable.offset` is never set by the parser, so neither orders occurrences.
    """
    yield node
    for child in node.children():
        yield from _in_source_order(child)


class TestPs1VariableFlow(TestBase):
    """
    Which write each read observes, named by its position among the writes of that variable rather
    than by its value — two writes may carry the same text, and the question is which occurrence.
    Expectations are what PowerShell does, not what the ordering rules imply.
    """

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
        """
        The index among the writes of *name* of the one the *read*-th read observes, or `None`.
        """
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
        """
        The reproduction the two-table split produced: the pass this replaces kept `'a'` here while
        correctly refusing the identical shape with a non-constant value. Both must refuse.
        """
        self.assertIsNone(self._observed("$x = 'a'; if ($c) { $x = 'b' }; Write-Host $x"))
        self.assertIsNone(self._observed("$x = 'a'; if ($c) { $x = $y }; Write-Host $x"))

    def test_a_branch_that_does_not_write_leaves_the_write_before_it_standing(self):
        """
        The floor under the branch rule: refusing on any branch at all would pass the test above and
        inline nothing anywhere.
        """
        self.assertEqual(self._observed("$x = 'a'; if ($c) { Write-Host 1 }; Write-Host $x"), 0)

    def test_a_dotted_block_writing_the_name_kills_the_write_before_it(self):
        self.assertIsNone(self._observed("$x = 'a'; . { $x = 'b' }; Write-Host $x"))

    def test_an_ampersand_block_writing_the_name_does_not_kill_it(self):
        """
        The floor under the block work, and the case a scope model must not over-approximate: `&`
        opens a child scope, so the caller's `$x` is still `'a'` and PowerShell prints `a`.
        """
        self.assertEqual(self._observed("$x = 'a'; & { $x = 'b' }; Write-Host $x"), 0)

    def test_a_read_inside_a_stored_block_observes_nothing(self):
        """
        `$b` may be invoked at any time, including after `$x = 'b'`, so the read inside it is not
        ordered against the script that wrote it.
        """
        self.assertIsNone(self._observed("$x = 'a'; $b = { Write-Host $x }; $x = 'b'; & $b"))

    def test_a_write_a_loop_returns_to_leaves_the_read_with_no_single_write(self):
        self.assertIsNone(self._observed("$x = 'a'; while ($c) { Write-Host $x; $x = 'b' }"))

    def test_a_loop_that_only_reads_leaves_the_write_before_it_standing(self):
        self.assertEqual(self._observed("$x = 'a'; while ($c) { Write-Host $x }"), 0)

    def test_a_store_that_may_not_have_completed_is_not_observed_in_the_handler(self):
        """
        Dominance says the statement ran, not that its store landed: the cast raises before the
        assignment takes effect, so the handler must not be told `$x` holds `'abc'`.
        """
        self.assertIsNone(self._observed("try { [int]$x = 'abc' } catch { Write-Host $x }"))

    def test_a_write_inside_a_trap_is_never_what_a_later_read_observes(self):
        """
        5.1 runs a trap body in a child scope, so the enclosing `$x` is untouched by it. The semantic
        model binds the two together, and the exceptional-entry rule is what stops the write escaping.
        """
        self.assertIsNone(
            self._observed("$x = 'a'; trap { $x = 'b'; continue }; throw 'e'; Write-Host $x"))

    def test_a_foreach_object_body_writing_the_name_kills_it(self):
        self.assertIsNone(
            self._observed("$x = 'a'; 1..3 | ForEach-Object { $x = 'b' }; Write-Host $x"))

    def test_a_handler_observes_its_own_completed_store(self):
        """
        The floor under the partial-store rule, and the case a handler-keyed rule gets wrong: the
        store here is in the handler and completes, so its own read does see it.
        """
        self.assertEqual(self._observed("try { f } catch { $x = 'b'; Write-Host $x }"), 0)

    def test_a_read_inside_a_body_is_answered_at_the_statement_that_runs_the_body(self):
        """
        The read is one graph in and every write is in the script's, and each of these bodies runs
        exactly where it is written, so the statement running it is a point both can be ordered
        against. Refusing them costs most of what obfuscated PowerShell reads through.
        """
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

    def test_a_read_inside_a_body_a_call_site_reaches_is_not_placed_where_it_is_written(self):
        """
        The floor under the projection, and what separates a body that runs where it stands from one
        that does not: `f` and `$b` may run at any time, including after the second write.
        """
        for source in [
            "$x = 'a'; function f { Write-Host $x }; $x = 'b'; f",
            "$x = 'a'; $b = { Write-Host $x }; $x = 'b'; & $b",
            "$x = 'a'; Invoke-Command { Write-Host $x }; $x = 'b'",
        ]:
            with self.subTest(source):
                self.assertIsNone(self._observed(source, read=0))

    def test_a_body_running_before_a_write_in_its_own_statement_observes_the_earlier_one(self):
        """
        Evaluation order reaches into the body: the block is the first element, so it runs before the
        assignment beside it and reads what stood before the statement.
        """
        self.assertEqual(self._observed("$x = 'a'; (& { $x }), ($x = 'b')"), 0)

    def test_a_read_beside_the_writes_is_answered_though_a_function_body_reads_the_name_too(self):
        """
        The floor under the cross-body refusal: `f` may run at any time, so the read inside it is
        unanswerable, but the one beside the write is not and refusing it inlines nothing in any
        script that defines a function.
        """
        self.assertEqual(
            self._observed("$x = 'a'; function f { Write-Host $x }; Write-Host $x"), 0)

    def test_a_read_and_its_writes_inside_one_block_are_ordered_normally(self):
        """
        The floor under the cross-body rule. Refusing every read inside a block would pass the stored
        block test above while answering nothing anywhere.
        """
        self.assertEqual(self._observed("$b = { $x = 'a'; Write-Host $x }"), 0)

    def test_a_write_the_graphs_do_not_place_is_refused_rather_than_ignored(self):
        """
        A `param` declaration is evaluated when the function is invoked, which is not a point these
        graphs hold. Ignoring it would leave the default as the only write in sight and publish it
        for every call that passed an argument.
        """
        self.assertIsNone(
            self._observed("function f { param($x = 'a') Write-Host $x }"))

    def test_a_write_the_same_statement_stores_after_the_read_is_not_what_it_observes(self):
        """
        `$x + 'b'` is produced before it is stored, so the read is of the value from before the
        statement. The graphs place both occurrences at one node and can order neither.
        """
        self.assertEqual(self._observed("$x = 'a'; $x = $x + 'b'; Write-Host $x", read=0), 0)

    def test_a_target_written_left_of_the_read_still_stores_after_it(self):
        """
        The case source position answers backwards: the target of `$x = [char]($x)` is written first
        and stored last, so a rule reading the statement left to right calls the read stale.
        """
        self.assertEqual(self._observed('$x = 39; $x = [char]($x)', read=0), 0)

    def test_an_argument_evaluated_before_a_later_assignment_observes_the_earlier_write(self):
        self.assertEqual(self._observed("$x = 'old'; Write-Host $x ($x = 'new')", read=0), 0)

    def test_a_write_the_same_statement_stores_before_the_read_leaves_it_unanswered(self):
        """
        The floor under the rule above, and what stops it becoming *any* write sharing a node is
        ignored: here `'new'` is stored first, so the read sees neither write for certain.
        """
        self.assertIsNone(self._observed("$x = 'old'; Write-Host ($x = 'new') $x"))

    def test_a_self_referencing_write_control_returns_to_observes_no_single_value(self):
        """
        The floor under evaluation order: it orders one visit to a statement, and a second visit
        reads what the first stored, so the write is no longer merely later than the read.
        """
        self.assertIsNone(self._observed("$x = 'a'; while ($c) { $x = $x + 'b' }", read=0))

    def test_a_multi_assignment_target_is_a_write_like_any_other(self):
        """
        That `$x, $y = 1, 2` writes `$x` is this layer's question; what the write is *worth* is the
        caller's, and conflating the two is how `$x` came to inline to the whole list.
        """
        self.assertEqual(self._observed("$x, $y = 1, 2; Write-Host $x"), 0)


class TestPs1FlowUnknowns(TestBase):

    def _unknowns(self, source: str, name: str = 'x') -> Ps1FlowUnknown:
        _, semantic, flow = _models(source)
        return flow.unknowns(semantic.script_scope.bindings[name])

    def test_a_binding_written_and_read_in_one_body_has_no_unknowns(self):
        self.assertIs(self._unknowns("$x = 'a'; Write-Host $x"), Ps1FlowUnknown.NONE)

    def test_writes_in_two_bodies_leave_the_binding_unorderable(self):
        """
        A qualified write reaches the script scope from inside a block, so this binding is written
        at two points no graph orders against each other.
        """
        self.assertIn(
            Ps1FlowUnknown.WRITES_IN_SEVERAL_BODIES,
            self._unknowns("$x = 'a'; & { $script:x = 'b' }"))

    def test_a_read_in_another_body_leaves_the_binding_itself_answerable(self):
        """
        The floor under the rule above, and the difference between refusing a read and refusing a
        name: a function body mentioning `$x` says nothing about the writes of `$x`, and treating it
        as an unknown of the binding refuses every read of the name anywhere.
        """
        self.assertIs(
            self._unknowns("$x = 'a'; function f { Write-Host $x }; Write-Host $x"),
            Ps1FlowUnknown.NONE)

    def test_a_qualified_reader_is_reported_separately_from_an_unorderable_write(self):
        """
        The reason this is a flag: a caller may be able to live with one of these and not the other,
        and a single boolean would make them indistinguishable.
        """
        found = self._unknowns("$x = 'a'; Write-Host $script:x")
        self.assertIn(Ps1FlowUnknown.REACHED_BY_QUALIFIER, found)
        self.assertNotIn(Ps1FlowUnknown.WRITES_IN_SEVERAL_BODIES, found)

    def test_a_stored_block_writing_the_name_defers_the_binding(self):
        self.assertIn(
            Ps1FlowUnknown.WRITTEN_BY_DEFERRED_BODY,
            self._unknowns("$x = 'a'; $b = { $x = 'b' }"))

    def test_an_index_assignment_changes_the_value_without_writing_the_name(self):
        """
        `$x[0] = 'z'` writes no occurrence of `$x` — the name is read to reach the slot — so every
        occurrence lands in `reads` and the value the binding holds changes with nothing to order.
        """
        self.assertIn(
            Ps1FlowUnknown.MUTATED_IN_PLACE,
            self._unknowns("$x = @('a', 'b'); $x[0] = 'z'"))

    def test_a_member_assignment_changes_the_value_without_writing_the_name(self):
        self.assertIn(
            Ps1FlowUnknown.MUTATED_IN_PLACE,
            self._unknowns("$x = 'hello'; $x.Length = 5"))

    def test_reading_through_an_index_leaves_the_binding_trackable(self):
        """
        The floor: refusing every name an index expression mentions refuses every array this layer
        exists to resolve.
        """
        self.assertIs(
            self._unknowns("$x = @('a', 'b'); Write-Host $x[0]"), Ps1FlowUnknown.NONE)


class TestPs1VariableFlowRegressions(TestPs1VariableFlow):

    def test_a_use_the_throwing_path_also_reaches_observes_no_store(self):
        """
        The statement after a `try` is reached both by the body completing and by the handler it
        threw into, so dominance and a completed-exit walk on their own both accept it. The run that
        enters the handler is the run in which the cast raised and `$x` was never stored.
        """
        self.assertIsNone(self._observed("try { [int]$x = 'abc' } catch { }; Write-Host $x"))

    def test_a_statement_a_trap_resumes_into_observes_no_store(self):
        """
        The same asymmetry spelled as error handling: `continue` resumes at the statement after the
        one that threw, so that statement is reached with the store never performed.
        """
        self.assertIsNone(self._observed("trap { continue }; [int]$x = 'abc'; Write-Host $x"))

    def test_a_use_reached_only_by_completing_still_observes_the_store(self):
        """
        The floor under both tests above: refusing whenever the definition has an exceptional edge
        at all refuses every write inside a `try`.
        """
        self.assertEqual(self._observed("try { $x = 'a'; Write-Host $x } catch { }"), 0)


class TestPs1FlowUnknownRegressions(TestPs1FlowUnknowns):

    def test_a_stored_block_outside_the_binding_body_is_still_a_deferred_writer(self):
        """
        `. $b` performs the block's bare writes on whoever dot-sources it, so a block written at the
        root reaches a binding local to a body it is not written inside.
        """
        _, semantic, flow = _models(
            "$b = { $x = 'INNER' }\n. {\n  $x = 'OUTER'\n  . $b\n  Write-Host $x\n}")
        inner = next(
            scope for scope in semantic.script_scope.children if 'x' in scope.bindings)
        self.assertIn(
            Ps1FlowUnknown.WRITTEN_BY_DEFERRED_BODY,
            flow.unknowns(inner.bindings['x']))

    def test_a_receiver_chain_an_assignment_stores_through_mutates_the_binding_in_place(self):
        for source in (
            "$x = @(@('a','b'))\n$x[0][1] = 'z'",
            "$x = 'abc'\n$x.A.B = 5",
            "$x = @('a','b')\n($x)[0] = 'z'",
            "$x = @('a','b')\n$x[0], $x[1] = 'p', 'q'",
        ):
            with self.subTest(source):
                self.assertIn(Ps1FlowUnknown.MUTATED_IN_PLACE, self._unknowns(source))


class TestPs1UnattributableWrites(TestPs1VariableFlow):
    """
    `Set-Variable $n 'v'` writes a name nothing can read off the source. Which binding it landed on
    stays unknown, but *when* it ran does not, so a read that reaches its write without passing the
    command observes the value it always would have — and one that does pass it observes nothing.

    Measured on 5.1 (`temp/ps1/census_measurements.md`): a bare `Set-Variable` writes the scope the
    command stands in, so `. { }` running one writes its caller's scope, `& { }` and a function body
    do not, and `-Scope 1` writes a scope the lexical chain cannot name at all.
    """

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

    def test_a_caller_scoped_body_inside_a_child_scope_stops_at_that_child(self):
        """
        The inner dot writes the `&` block's scope, and that scope ends with the block, so nothing
        it wrote outlives it — the same asymmetry `writes_reaching_caller` turns on.
        """
        self.assertEqual(
            self._observed("$x = 'a'; & { . { Set-Variable $n 'v' } }; Write-Host $x"), 0)

    def test_a_child_scope_running_a_computed_write_kills_nothing_outside_it(self):
        for source in (
            "$x = 'a'; & { Set-Variable $n 'v' }; Write-Host $x",
            "$x = 'a'; function f { Set-Variable $n 'v' }; f; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertEqual(self._observed(source), 0)

    def test_a_computed_write_naming_the_script_scope_kills_from_inside_a_child_scope(self):
        self.assertIsNone(
            self._observed("$x = 'a'; & { Set-Variable $n 'v' -Scope Global }; Write-Host $x"))

    def test_a_scope_the_lexical_chain_cannot_name_kills_wherever_it_is_written(self):
        self.assertIsNone(
            self._observed("$x = 'a'; & { Set-Variable $n 'v' -Scope 1 }; Write-Host $x"))

    def test_a_computed_write_in_a_stored_block_kills_without_a_point_to_stand_at(self):
        """
        A stored block runs whenever its value is invoked, so the kill has no position and the doubt
        is about the binding rather than about any node.
        """
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

    def test_a_call_running_unreadable_code_kills_across_it(self):
        for source in (
            "$x = 'a'; iex $c; Write-Host $x",
            "$x = 'a'; . 'stage2.ps1'; Write-Host $x",
            "$x = 'a'; . $sb; Write-Host $x",
            "$x = 'a'; . { iex $c }; Write-Host $x",
            "$x = 'a'; 1..3 | %{ iex $c }; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    def test_a_call_opening_a_child_scope_kills_nothing_outside_it(self):
        for source in (
            "$x = 'a'; & 'stage2.ps1'; Write-Host $x",
            "$x = 'a'; & $sb; Write-Host $x",
            "$x = 'a'; & { iex $c }; Write-Host $x",
            "$x = 'a'; . { Write-Host 1 }; Write-Host $x",
        ):
            with self.subTest(source):
                self.assertEqual(self._observed(source), 0)

    def test_the_argument_a_call_expands_is_read_before_the_call_runs(self):
        """
        The case where a kill in the wrong place does more than lose a fold. `Invoke-Expression $x`
        reads the payload to run it, so a kill that blocks that read stops the call becoming
        literal, which stops it expanding, which leaves the kill in place — the loader comes back
        out as the obfuscator wrote it.
        """
        self.assertEqual(self._observed("$x = 'Write-Host hi'; iex $x"), 0)
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x (iex $c)"), 0)

    def test_an_argument_is_built_before_the_call_however_many_bodies_it_runs(self):
        """
        The obfuscated loader's own shape: the payload is decoded by a body inside the argument, and
        the whole argument is evaluated — iterations and all — before `Invoke-Expression` is called.
        """
        self.assertEqual(
            self._observed("$x = 'a'; iex (1..2 | %{ [char]($_ -bxor $x) })"), 0)

    def test_a_call_a_loop_returns_to_may_have_rewritten_its_own_argument(self):
        """
        The floor under the rule above. One visit reads before the call, but the visit before it did
        not: iteration two's read may observe whatever iteration one's call wrote.
        """
        self.assertIsNone(self._observed("$x = 'a'; while ($c) { iex $x }"))
        self.assertIsNone(self._observed("$x = 'a'; 1..3 | %{ iex $x }"))

    def test_a_read_beside_the_body_that_writes_is_ordered_where_the_body_is_not(self):
        """
        A block projected onto a statement stands for the whole body, so a read *within* it is not
        an argument the block consumes — which order they run in is the block's graph to answer and
        not this one's. A read that really is an argument beside it still folds.
        """
        self.assertIsNone(self._observed("$x = 'a'; . { iex $c; Write-Host $x }"))
        self.assertIsNone(self._observed("$x = 'a'; . { Write-Host $x; iex $c }"))
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x (. { iex $c })"), 0)
        self.assertIsNone(self._observed("$x = 'a'; Write-Host (. { iex $c }) $x"))

    def test_a_read_the_call_cannot_have_reached_yet_is_still_answered(self):
        self.assertEqual(self._observed("$x = 'a'; Write-Host $x; iex $c"), 0)
        self.assertEqual(self._observed("$x = 'a'; 1..3 | %{ Write-Host $x }; iex $c"), 0)

    def test_a_read_the_call_may_already_have_reached_is_refused(self):
        self.assertIsNone(self._observed("$x = 'a'; Write-Host (iex $c) $x"))

    def test_one_statement_may_hold_several_and_the_earliest_is_what_decides(self):
        """
        A statement is one node to the graph however many unattributable writes it holds, so a
        reading that clears the node as soon as *one* of them runs after the read folds across the
        one that ran before it.
        """
        for source in (
            "$x = 'a'; Write-Host (iex $a) $x (iex $b)",
            "$x = 'a'; Write-Host (Set-Variable $n 1) $x (iex $b)",
        ):
            with self.subTest(source):
                self.assertIsNone(self._observed(source))

    def test_a_read_projected_onto_the_statement_gets_no_ordering_from_it(self):
        """
        A pipeline streams, so the second object reaches the first body only after the first object
        has reached the second: iteration two's `Write-Host $x` runs after iteration one's `iex`.
        Reading the order off the projected statement says otherwise, and `CycleModel.repeats` does
        not correct it, because what repeats is the body and not the pipeline.
        """
        self.assertIsNone(self._observed("$x = 'a'; 1..2 | %{ Write-Host $x } | %{ iex $s }"))
        self.assertIsNone(self._observed("$x = 'a'; . { Write-Host $x; iex $s }"))

    def test_an_ambient_value_is_a_definition_at_the_scripts_entry(self):
        """
        A default the engine established before the script ran has no write occurrence, which reads
        as having no position — but its position is the entry, so a write nobody can attribute is
        ordered against it exactly as against any other definition.
        """
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
        """
        A read inside a stored block has no position in the script's graph, so nothing orders it —
        which leaves only the question of whether there is anything to order it against. Refusing
        it outright costs the `$env:` and `$PSHome` unpacking of every loader whose first stage
        sits inside a body.
        """
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
        """
        `.\\tool.exe` runs a program, not a dot-source, so it writes no variable of this script at
        all — while `. .\\stage2.ps1` reads a file into the caller's scope and kills everything.
        """
        self.assertEqual(self._observed(r"$x = 'a'; .\tool.exe; Write-Host $x"), 0)
        self.assertIsNone(self._observed(r"$x = 'a'; . .\stage2.ps1; Write-Host $x"))

    def test_invoke_command_kills_only_where_it_is_told_not_to_open_a_scope(self):
        self.assertIsNone(
            self._observed("$x = 'a'; Invoke-Command -NoNewScope -ScriptBlock $sb; Write-Host $x"))
        self.assertEqual(
            self._observed("$x = 'a'; Invoke-Command -ScriptBlock $sb; Write-Host $x"), 0)

    def test_a_write_naming_another_scope_is_not_one_of_the_placed_ones(self):
        """
        A `-Scope Global` write reaches every binding of the script scope, from any body, for as
        long as the run lasts. Listing it among the writes that land where they stand would say the
        reads before it are safe from it, which is the one thing it does not promise — so it stays
        with `Scope.writes_unreadable_names`, where it refuses them all.
        """
        for source in (
            "$x = 'a'\nSet-Variable $n 'v' -Scope Global\nWrite-Host $x",
            "$x = 'a'\nSet-Variable $n 'v' -Scope 1\nWrite-Host $x",
        ):
            with self.subTest(source):
                tree, _, flow = _models(source)
                self.assertEqual(flow.unattributable_writes(flow.flow.graph_of(tree)), ())


class TestPs1UnattributableWriteHoles(TestPs1VariableFlow):
    """
    Shapes where a write nobody can attribute still reaches a read this layer answers. Each is a
    fold this package performs across a write that may have changed the value — recorded so the hole
    is a stated fact with a test that changes when it closes, rather than an assumption nobody wrote
    down.
    """

    def test_a_function_body_running_unreadable_code_is_not_seen_at_its_call_sites(self):
        """
        `. f` writes the caller and is recognised, but `f` reaches its body through the call graph,
        which this layer does not follow. A body is `FUNCTION`/`CHILD`, so nothing projects out of
        it and the call site carries no kill.
        """
        self.assertEqual(
            self._observed("$x = 'a'; function f { iex $c }; f; Write-Host $x"), 0)

    def test_a_qualified_write_from_inside_a_child_scope_is_not_seen(self):
        """
        Measured: `& { iex '$script:probe = "REPLACED"' }` does reach the caller, because the
        qualifier names the scope outright rather than relying on the block's own. Treating every
        `&` as a caller-scope write would close it and cost every fold across a call operator.
        """
        self.assertEqual(
            self._observed('''$x = 'a'; & { iex '$script:x = 1' }; Write-Host $x'''), 0)
