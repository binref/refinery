from __future__ import annotations

import re
import unittest

from collections.abc import Callable
from contextlib import ExitStack
from unittest.mock import patch

from test import TestBase
from test.lib.scripts.ps1 import test_deobfuscation
from test.lib.scripts.ps1.analysis import (
    test_blocks,
    test_callgraph,
    test_faults,
    test_worldflow,
)
from test.lib.scripts.ps1.deobfuscation import (
    test_deadcode,
    test_emulator,
    test_fault_escalation,
    test_fault_observability,
    test_folding,
    test_iexinline,
    test_removal,
    test_removal_observability,
    test_unused,
    test_wildcards,
)

from refinery.lib.scripts import Node, owning_list
from refinery.lib.scripts.ps1.analysis import (
    blocks,
    callgraph,
    commands,
    effects,
    faults,
    mutation,
    worldflow,
)
from refinery.lib.scripts.ps1.analysis.effects import (
    OutputSink,
    is_fault_free,
    is_side_effect_free,
)
from refinery.lib.scripts.ps1.deobfuscation import (
    constants,
    deadcode,
    emulator,
    folding,
    removal,
    substitution,
    unused,
    wildcards,
)
from refinery.lib.scripts.ps1.model import (
    Ps1ExpressionStatement,
    Ps1Script,
    Ps1TryCatchFinally,
    Ps1Variable,
)


def _witness(witness: type) -> str:
    """
    The dotted name `unittest.TestLoader` resolves. Spelled from the class rather than by hand,
    because `unittest.loader.loadTestsFromNames` answers a name it cannot resolve with a test that
    *errors*, and a probe cannot tell that apart from a guard its witnesses noticed. Written this
    way a renamed witness is an `AttributeError` here, before any probe runs.
    """
    return F'{witness.__module__}.{witness.__qualname__}'


_ARRAY_EFFECT = _witness(
    test_folding.TestPs1AnArrayACallWritesThroughIsComputedWhereverItsEffectIsDetermined)
_CALL_GRAPH = _witness(test_callgraph.TestPs1CallGraphReadability)
_DEAD_CODE = _witness(test_deadcode.TestPs1DeadCodeElimination)
_DEAD_CODE_EXTRA = _witness(test_deadcode.TestPs1DeadCodeExtra)
_DEAD_CODE_TREE = _witness(test_deadcode.TestPs1DeadCodeLeavesTheTreeConsistent)
_DIRECT_GUARD = _witness(
    test_fault_observability.TestPs1ARaisingStatementDirectlyInAGuardedTryBlockIsKept)
_EMPTY_CATCH = _witness(
    test_fault_observability.TestPs1AnEmptyCatchSwallowsSoTheRaisingStatementIsRemovable)
_ERROR_RECORD = _witness(
    test_removal_observability.TestPs1ANoiseBarewordIsKeptWhereTheRecordItLeavesIsRead)
_EMULATOR = _witness(test_emulator.TestPs1FunctionEvaluator)
_EMULATOR_EXTRA = _witness(test_emulator.TestPs1EmulatorExtra)
_ESCALATION = _witness(test_faults.TestPs1FaultIsObservedWhereAHandlerActsOrATrapMayDecline)
_FOREACH_PIPELINE = _witness(test_emulator.TestPs1EmulatorRedirections)
_HANDLER = _witness(test_removal.TestPs1DeadCodeEliminationDoesNotUnhookAHandler)
_IEX_REDIRECTIONS = _witness(test_iexinline.TestPs1IexRedirections)
_INTEGRATION = _witness(test_deobfuscation.TestPs1Integration)
_KEPT_EITHER_WAY = _witness(test_unused.TestPs1OutputSomethingElseHoldsIsKeptEitherWay)
_KEPT_WHEN_ASKED = _witness(test_unused.TestPs1BareOutputIsKeptWhenAsked)
_MATCHING_HANDLER = _witness(
    test_removal_observability.TestPs1TheHandlerAroundANoiseBarewordHasToMatchIt)
_NESTED_GUARD = _witness(test_fault_observability.TestPs1AStatementNestedInAGuardedTryBlock)
_PLAN = _witness(test_removal.TestPs1RemovalPlan)
_PROTECTED_BODY = _witness(test_removal.TestPs1RemovalDoesNotEmptyAProtectedTryBody)
_QUALIFIED = _witness(test_unused.TestPs1AQualifiedCallKeepsTheNameItResolvesOnto)
_RAISE_ABANDONS = _witness(
    test_removal_observability.TestPs1ARaiseAbandonsTheStatementsBelowItInTheSameBlock)
_REFERENCE = _witness(test_unused.TestPs1RemovalLeavesNoDanglingReference)
_SELECTION = _witness(test_folding.TestPs1SelectionKeepsWhatBuildingTheContainerDid)
_ARMING_COST = _witness(
    test_fault_observability.TestPs1TheStrictModeScanStaysLinearInTheSizeOfTheScript)
_ENUMERATOR = _witness(
    test_unused.TestPs1AReadThatConsumesWhatItReadsIsNotBareOutput)
_STRICT_MODE = _witness(
    test_fault_observability.TestPs1AReadOfAnUnsetVariableRaisesOnlyWhereStrictModeIsArmed)
_STRICT_MODE_FACT = _witness(
    test_faults.TestPs1AStrictModeArmingIsReadOverTheWholeScript)
_STRICT_MODE_PAYLOAD = _witness(
    test_fault_observability.TestPs1AnUnreadablePayloadMayArmStrictModeWithoutSpellingIt)
_STRICT_MODE_SHAPE = _witness(
    test_fault_observability.TestPs1OnlyABareNameIsGrantedTheStrictModeReading)
_SELECTION_COUNT = _witness(test_folding.TestPs1CountingAnArrayKeepsWhatBuildingItDid)
_STRIPPED_BY_DEFAULT = _witness(test_unused.TestPs1BareOutputIsStrippedByDefault)
_SCRIPTBLOCK_SLOT = _witness(
    test_blocks.TestPs1AnIteratingCommandRunsOnlyTheBlocksItIsHandedToRun)
_SHADOWED_ITERATOR = _witness(
    test_blocks.TestPs1AShadowedIteratingCommandRunsItsOwnBodyNotTheBlock)
_SITE_POSITION = _witness(
    test_worldflow.TestPs1AReadInsideABlockTheStatementRunsHasTheStatementsPosition)
_STATEMENT_RUNS_THE_BODY = _witness(
    test_unused.TestPs1AHandlerElsewhereDoesNotGuardABodyTheStatementItselfRuns)
_SWALLOWING_TRAP = _witness(
    test_fault_escalation.TestPs1ATrapThatTakesTheErrorAndSwallowsLeavesTheRaiseRemovable)
_TREE = _witness(test_unused.TestPs1RemovalLeavesTheTreeConsistent)
_TRUST_BY_POSITION = _witness(
    test_unused.TestPs1CommandNameTrustIsReadWhereTheBarewordStands)
_UNREACHED_TRAP = _witness(
    test_fault_escalation.TestPs1ATrapTheRaisingBlockDoesNotReachLeavesItRemovable)
_UNUSED = _witness(test_unused.TestPs1UnusedVariableRemoval)
_WILDCARD_REDIRECTIONS = _witness(test_wildcards.TestPs1WildcardRedirections)


def _accepted_before_the_vetoes(plan: removal.Ps1RemovalPlan) -> list:
    return [proposal.statement for proposal in plan._proposals.values()]


def _plans_accepted_before_the_vetoes(plans: removal.Ps1RemovalPlans) -> list:
    accepted = [
        statement
        for plan in plans._plans.values()
        for statement in _accepted_before_the_vetoes(plan)
    ]
    accepted.extend(proposal.statement for proposal in plans._rewrites.values())
    return accepted


def _propose_repairing_only_a_replacement(
    self: removal.Ps1RemovalPlan,
    statement,
    replacement=None,
) -> None:
    self._proposals[id(statement)] = proposal = removal._Proposal(
        statement, list(replacement or ()))
    if proposal.replacement:
        removal.reattach(statement)


def _commit_interleaving_verdicts_and_edits(self: removal.Ps1RemovalPlans) -> bool:
    """
    `Ps1RemovalPlans.commit` with its verdicts left lazy, which is the whole mutation: read out of a
    generator inside the loop that edits, each plan decides after the plan before it has moved the
    tree. Kept a token away from the original so that a `commit` which grows a phase reads as stale
    here rather than quietly modelling a different bug.
    """
    verdicts = ((plan, plan._allowed()) for plan in self._plans.values())
    rewrites = self._installable()
    landed = []
    moved = False
    for plan, allowed in verdicts:
        was_moved, installed = plan._apply(allowed)
        moved = moved or was_moved
        landed.extend(installed)
    for proposal, replacement in rewrites:
        if not removal._replace_in_parent(proposal.statement, replacement):
            continue
        landed.append(replacement)
        moved = True
    removal._restore(landed)
    return moved


def _withdraw_rediscovering_the_owning_list(self: removal.Ps1RemovalPlans, statement) -> None:
    """
    The withdrawal as it read before the plan was remembered beside the statement: the owning list
    is looked up again, and a statement the tree has moved since is withdrawn from nothing at all.
    """
    if self._rewrites.pop(id(statement), None) is not None:
        return
    self._filed.pop(id(statement), None)
    owner = owning_list(statement)
    if owner is not None:
        self._plan_for(*owner).withdraw(statement)


def _apply_repairing_every_allowed_replacement(original: Callable) -> Callable:
    def mutated(self, allowed):
        moved, _ = original(self, allowed)
        landed = [statement for proposal in allowed for statement in proposal.replacement]
        return moved, landed if moved else []
    return mutated


def _dead_bindings_over_every_candidate(original: Callable) -> Callable:
    def mutated(self, candidates, dissolving):
        return original(self, candidates, {
            id(mutation) for mutations in candidates.values() for mutation in mutations})
    return mutated


def _resolved_reaching_the_host_always(self: effects.Ps1OutputFlow, path) -> OutputSink:
    """
    The destination question with the call graph taken out of it: every body writes to the host, so
    every write to the output stream is text on a console and deletable. This is what the model
    looked like before a function's callers were consulted, and what it collapses back to if the
    resolution ever stops distinguishing.
    """
    return OutputSink.HOST


def _leaves_anything_counting_its_own_residue(original: Callable) -> staticmethod:
    def mutated(plans, node, installed):
        return original(plans, node, set())
    return staticmethod(mutated)


def _iterating_command_ignoring_the_shadow_set(original: Callable) -> Callable:
    def mutated(cmd, shadowed=frozenset()):
        return original(cmd, frozenset())
    return mutated


def _try_body_survivors_relaxing(*, fault_freedom: bool, abandonment: bool) -> Callable:
    """
    The survivor walk with one of its rules taken out, so that each is measured alone.

    Without `fault_freedom` the two predicates read as they did before fault-freedom separated
    them: a statement is carried out when it is merely side-effect free, which hoists `[Int]'abc'`
    past the empty `catch` that was swallowing it. Without `abandonment` a statement written below
    a dropped bareword is carried out, although the raise the drop claims never reaches it.

    The third rule is not among these: it is `swallows_every_error`, mutated where it is named.
    """
    def mutated(node: Ps1TryCatchFinally, cache) -> list | None:
        body = node.try_block.body if node.try_block is not None else []
        confined = deadcode.swallows_every_error(node)
        survivors = []
        dropped = False
        for stmt in body:
            if not isinstance(stmt, Ps1ExpressionStatement):
                return None
            if stmt.expression is None:
                continue
            if fault_freedom:
                carried = is_fault_free(stmt.expression)
            else:
                carried = is_side_effect_free(stmt.expression, cache.world_reach)
            if carried:
                if dropped and abandonment:
                    return None
                survivors.append(stmt)
                continue
            if confined and deadcode._is_injected_noise_bareword(stmt.expression, cache):
                dropped = True
                continue
            return None
        return survivors
    return mutated


def _fault_observed_where_the_clause_is_written(
    stmt: Node,
    reach: faults.Ps1FaultReach,
    world=None,
) -> bool:
    """
    The reading the routing walk superseded: a deletion is refused where the statement stands
    *directly* in the `try` block of a construct one of whose `catch` clauses has a body. One
    syntactic position and no graph at all, so a raise one nesting level down, a raise in a body the
    block calls, and every raise a `trap` guards are raises this cannot see.
    """
    block = stmt.parent
    guard = block.parent if block is not None else None
    if not isinstance(guard, Ps1TryCatchFinally) or guard.try_block is not block:
        return False
    return any(
        clause.body is not None and clause.body.body
        for clause in guard.catch_clauses
    )


def _fault_observed_wherever_an_error_would_go(
    stmt: Node,
    reach: faults.Ps1FaultReach,
    world=None,
) -> bool:
    """
    The guard with its first half dropped: every point inside *stmt* is asked where an error raised
    there would go, and no point is asked whether it can raise one, so every statement is judged as
    though it might. This refuses **more** than the guard does, which is what the padding an
    obfuscator writes by the hundred used to cost — so what notices it is a test asserting that
    something is still deleted.
    """
    judged = False
    for site in reach.points_in(stmt):
        judged = True
        if reach.observed_at(site):
            return True
    return not judged


def _observed_at_reading_only_what_acts(self: faults.Ps1FaultReach, node: Node) -> bool:
    """
    The position question with the escalation taken out of it and every other step left standing: a
    handler that acts still makes the error observable, and a `trap` set that may decline it no
    longer does, although declining is what ends the body rather than reporting the error and
    stepping over it. Kept a token away from the original so that a reading which grows a step reads
    as stale here rather than quietly modelling a different bug.
    """
    located = self._control_flow.locate(node)
    if located is None:
        return True
    graph, _ = located
    routing = self.routing_at(node)
    if routing is None:
        return True
    if any(faults.handler_acts(handler) for handler in routing.handlers):
        return True
    if routing.handlers and not routing.leaves_the_body:
        return False
    return not isinstance(graph.owner, Ps1Script) and self._handled_elsewhere(graph)


def _strict_mode_read_without_the_memo(self: faults.Ps1FaultReach) -> bool:
    """
    The same answer with the `_strict` slot never consulted. Nothing about what the model says
    changes, which is the point: the memo is a cost guard and not a correctness one, so the only
    thing that may notice its removal is a test that counts.
    """
    root = self._script
    return root is None or any(faults._arms_strict_mode(node) for node in root.walk())


def _strict_mode_with_the_siblings_empty_pole(self: faults.Ps1FaultReach) -> bool:
    """
    The whole-script fact copied from `_stops_on_every_error` verbatim, pole and all. That one
    answers `False` where the graphs place no script, which keeps a handler there; this one grants a
    removal, so the same pole grants it against a script nothing was read of.
    """
    root = self._script
    return root is not None and any(faults._arms_strict_mode(node) for node in root.walk())


def _expression_cannot_fault_without_the_world(
    operand: Node,
    position: Node,
    reach: faults.Ps1FaultReach,
    world,
) -> bool:
    """
    The gate with only the half the script spells out. What it stops asking is whether anything the
    analysis cannot read may have run before *position* — and a payload it cannot read may arm
    strict mode without the script naming it anywhere.
    """
    return effects.is_fault_free(operand) or (
        effects._is_bare_variable_read(operand)
        and not reach.strict_mode_may_be_in_force()
    )


def _removing_a_handler_asked_at_the_handler(
    self: faults.Ps1FaultReach, handler: Node, may_raise,
) -> bool:
    """
    The transpose answered by the forward question, which is the confusion the two queries exist to
    prevent. A `trap` raises nothing, so where an error raised *at* it would go is a question about
    a position nothing raises at, and its answer says nothing about the errors the removal re-routes
    or about what they would fall back to. The injected raiser predicate the real transpose takes is
    accepted and ignored, so the mutation is noticed as a wrong answer rather than a broken call.
    """
    return self.observed_at(handler)


def _value_after_refusing_an_unsettled_slot(original: Callable) -> Callable:
    """
    The value rule with the `settled` term put back into its slot guard, so a call the arity does
    not narrow to one overload is refused — the guard as it read before `[Array]::Sort`, whose
    one-argument form binds two captured overloads, needed answering. `[Array]::Reverse` and
    `[Array]::Clear` settle at their folding arities and are untouched, which is what lets a Sort
    fold be the thing that notices.
    """
    def mutated(occurrence: Ps1Variable, previous):
        found = mutation.written_call_slot(occurrence)
        if found is not None and not found.written.settled:
            return None
        return original(occurrence, previous)
    return mutated


class TestPs1RemovalGuardsAreWitnessed(TestBase):
    """
    Each test removes one guard in memory and runs the tests that are supposed to notice. A guard
    whose removal leaves them green is unprotected however its docstring reads, and the next
    refactor takes it out for nothing; the failure names the guard that lost its last witness.
    """

    @staticmethod
    def _run(witnesses: list[str], mutations=()) -> unittest.TestResult:
        suite = unittest.defaultTestLoader.loadTestsFromNames(witnesses)
        result = unittest.TestResult()
        with ExitStack() as stack:
            for mutation in mutations:
                stack.enter_context(mutation)
            suite.run(result)
        return result

    @staticmethod
    def _reported(outcomes) -> list[str]:
        return sorted(str(test) for test, _ in outcomes)

    @staticmethod
    def _methods(outcomes) -> set[str]:
        """
        The test methods among `outcomes`, read through `unittest.TestCase.subTest`'s wrapper where
        one is present: a failed subtest reports as a `_SubTest` whose own method name is `runTest`,
        so reading it directly names every such witness identically and matches any probe at all.
        """
        return {getattr(test, 'test_case', test)._testMethodName for test, _ in outcomes}

    def _assertWitnessed(self, witnesses: list[str], *mutations, notices: str) -> None:
        """
        A witness has to be green before the mutation and red after it, red by *failing*, and the
        test named in `notices` has to be among the ones that failed.

        All three halves are load bearing. Without the first, a witness already red for a reason of
        its own satisfies every probe that names it, and the guard behind it stops being measured at
        the moment someone is editing near it. Without the second, an error counts: a mutation whose
        calling convention no longer matches the guard it replaces raises at every call site and is
        reported as a guard the tests noticed, which is the one answer this file must never give.

        Without the third, a probe names a *class* and any failure in it satisfies the probe — so a
        guard whose own test stopped covering it stays green as long as some unrelated neighbour in
        the same class notices something. `notices` says which test is the witness, and the class
        stays in the list because the surrounding tests are what establish the mutation did not
        simply break everything.
        """
        intact = self._run(witnesses)
        self.assertEqual(
            self._reported(intact.failures + intact.errors),
            [],
            F'{witnesses} do not pass with this guard in place')
        without = self._run(witnesses, mutations)
        self.assertEqual(
            self._reported(without.errors),
            [],
            F'the mutation broke {witnesses} rather than being noticed by them')
        self.assertTrue(
            without.failures,
            F'{intact.testsRun} tests in {witnesses} all pass without this guard')
        self.assertIn(
            notices,
            self._methods(without.failures),
            F'{notices} is not among the tests that noticed; '
            F'{sorted(self._methods(without.failures))} did')

    def test_folding_a_sort_although_its_slot_is_unsettled_is_witnessed(self):
        self._assertWitnessed(
            [_ARRAY_EFFECT],
            patch.object(
                constants, 'value_after',
                _value_after_refusing_an_unsettled_slot(constants.value_after)),
            notices='test_a_sort_of_elements_that_share_a_type_orders_the_array_it_is_handed')

    def test_the_handler_veto_is_witnessed(self):
        self._assertWitnessed(
            [_HANDLER],
            patch.object(removal, '_removes_a_handler', lambda statement: False),
            notices='test_a_trap_inside_a_protected_try_body_is_kept')

    def test_regranting_what_a_replacement_adopted_is_witnessed(self):
        self._assertWitnessed(
            [_DEAD_CODE, _PLAN, _TREE],
            patch.object(removal, '_restore', lambda landed: None),
            notices='test_a_live_store_holding_a_dead_one')

    def test_releasing_what_a_registration_adopted_is_witnessed(self):
        self._assertWitnessed(
            [_DEAD_CODE_TREE, _PLAN],
            patch.object(removal.Ps1RemovalPlan, 'propose', _propose_repairing_only_a_replacement),
            notices='test_a_replacement_the_caller_discarded_is_given_back_too')

    def test_repairing_only_what_an_edit_landed_is_witnessed(self):
        mutated = _apply_repairing_every_allowed_replacement(removal.Ps1RemovalPlan._apply)
        self._assertWitnessed(
            [_PLAN],
            patch.object(removal.Ps1RemovalPlan, '_apply', mutated),
            notices='test_the_edit_that_landed_decides_alone_what_is_repaired')

    def test_reaching_every_verdict_before_the_first_edit_is_witnessed(self):
        self._assertWitnessed(
            [_PLAN],
            patch.object(
                removal.Ps1RemovalPlans, 'commit', _commit_interleaving_verdicts_and_edits),
            notices='test_every_verdict_is_reached_before_the_first_edit_lands')

    def test_accepted_on_a_single_plan_is_witnessed(self):
        self._assertWitnessed(
            [_PLAN, _REFERENCE],
            patch.object(removal.Ps1RemovalPlan, 'accepted', property(_accepted_before_the_vetoes)),
            notices='test_an_assignment_the_fault_veto_keeps_keeps_the_variable_it_reads')

    def test_accepted_across_a_batch_of_plans_is_witnessed(self):
        self._assertWitnessed(
            [_PLAN, _REFERENCE],
            patch.object(
                removal.Ps1RemovalPlans,
                'accepted',
                property(_plans_accepted_before_the_vetoes)),
            notices='test_an_assignment_the_fault_veto_keeps_keeps_the_variable_it_reads')

    def test_a_withdrawal_reaching_the_plan_that_holds_it_is_witnessed(self):
        self._assertWitnessed(
            [_PLAN],
            patch.object(
                removal.Ps1RemovalPlans, 'withdraw', _withdraw_rediscovering_the_owning_list),
            notices='test_a_withdrawal_reaches_the_plan_that_holds_the_proposal')

    def test_liveness_asking_what_survives_is_witnessed(self):
        self._assertWitnessed(
            [_REFERENCE],
            patch.object(
                unused.Ps1UnusedVariableRemoval, '_dead_bindings',
                _dead_bindings_over_every_candidate(
                    unused.Ps1UnusedVariableRemoval._dead_bindings)),
            notices='test_a_kept_value_keeps_the_variable_it_reads')

    def test_reading_the_shadow_set_before_placing_an_iterating_body_is_witnessed(self):
        self._assertWitnessed(
            [_SHADOWED_ITERATOR],
            patch.object(
                blocks, 'names_an_intact_iterating_command',
                _iterating_command_ignoring_the_shadow_set(
                    blocks.names_an_intact_iterating_command)),
            notices='test_a_function_redefinition_makes_the_body_unplaced')

    def test_the_target_slot_gate_on_a_dissolving_value_is_witnessed(self):
        self._assertWitnessed(
            [_REFERENCE],
            patch.object(unused, 'assignment_target_is_all_variables', lambda target: True),
            notices='test_a_target_slot_that_is_not_a_variable_keeps_the_whole_statement_alive')

    def test_the_erasure_guard_discounting_its_own_residue_is_witnessed(self):
        self._assertWitnessed(
            [_UNUSED, _EMULATOR, _INTEGRATION],
            patch.object(
                unused.Ps1UnusedVariableRemoval, '_leaves_anything',
                _leaves_anything_counting_its_own_residue(
                    unused.Ps1UnusedVariableRemoval._leaves_anything)),
            notices='test_a_script_reduced_to_this_passs_own_discards_is_left_alone')

    def test_carrying_only_fault_free_statements_out_of_a_try_is_witnessed(self):
        self._assertWitnessed(
            [_DEAD_CODE_EXTRA],
            patch.object(
                deadcode, '_try_body_survivors',
                _try_body_survivors_relaxing(fault_freedom=False, abandonment=True)),
            notices='test_a_try_body_that_may_raise_keeps_its_construct')

    def test_abandoning_what_a_dropped_bareword_raised_past_is_witnessed(self):
        self._assertWitnessed(
            [_RAISE_ABANDONS],
            patch.object(
                deadcode, '_try_body_survivors',
                _try_body_survivors_relaxing(fault_freedom=True, abandonment=False)),
            notices='test_a_value_below_a_dropped_noise_bareword_is_not_carried_out_of_the_try')

    def test_refusing_where_the_record_of_the_raise_is_read_is_witnessed(self):
        self._assertWitnessed(
            [_ERROR_RECORD],
            patch.object(commands.Ps1CommandModel, 'reads_the_error_record', lambda self: False),
            notices='test_a_noise_bareword_is_kept_where_the_script_reads_the_error_list')

    def test_refusing_where_the_record_is_spelled_only_in_text_is_witnessed(self):
        # The half that has no variable node to find the read by. Patched to a pattern nothing
        # matches rather than to the whole method, so the node walk beside it stays in force and
        # only the text scan is taken away.
        self._assertWitnessed(
            [_ERROR_RECORD],
            patch.object(commands, '_ERROR_RECORD_SPELLED_OUT', re.compile('(?!)')),
            notices='test_a_noise_bareword_is_kept_where_the_read_arrives_through_a_resolved_payload')

    def test_reading_command_name_trust_at_the_position_is_witnessed(self):
        self._assertWitnessed(
            [_TRUST_BY_POSITION],
            patch.object(
                worldflow.Ps1WorldReach, 'may_trust_command_name_at',
                lambda self, name, node: True),
            notices='test_a_bareword_below_a_leak_is_kept')

    def test_dropping_only_under_a_handler_that_takes_the_error_is_witnessed(self):
        self._assertWitnessed(
            [_MATCHING_HANDLER],
            patch.object(deadcode, 'swallows_every_error', lambda node: True),
            notices='test_a_noise_bareword_under_a_catch_that_cannot_match_is_kept')

    def test_discarding_a_hoisted_for_initializer_is_witnessed(self):
        # `for (5; $False; ) { }` puts nothing on the output; the bare statement `5` does. Hoisting
        # one plainly is the mirror image of deleting output.
        self._assertWitnessed(
            [_DEAD_CODE_EXTRA, _DEAD_CODE_TREE],
            patch.object(
                deadcode, '_hoisted_initializer',
                lambda expr: Ps1ExpressionStatement(expression=expr)),
            notices='test_a_hoisted_for_initializer_does_not_start_printing_its_value')

    def test_resolving_a_destination_rather_than_assuming_one_is_witnessed(self):
        # The analysis half of the conditional guard. Reading every body as writing to the host is
        # what a model with no call graph does, and it is the mutation the switch cannot cover for:
        # a value someone stores is not the switch's to give away under either setting.
        self._assertWitnessed(
            [_KEPT_EITHER_WAY],
            patch.object(effects.Ps1OutputFlow, 'resolved', _resolved_reaching_the_host_always),
            notices='test_a_value_a_caller_stores_is_kept')

    def test_reading_the_preserve_switch_at_all_is_witnessed(self):
        # A conditional guard goes vacuous in two more ways than an unconditional one, and neither
        # is the analysis being wrong. This is the switch never consulted.
        self._assertWitnessed(
            [_KEPT_WHEN_ASKED],
            patch.object(unused, 'bare_output_is_preserved', lambda options: False),
            notices='test_a_bare_literal_at_the_root_is_kept')

    def test_the_preserve_switch_being_off_by_default_is_witnessed(self):
        # And this is the switch stuck on, which reads as a deobfuscator that simply strips nothing.
        self._assertWitnessed(
            [_STRIPPED_BY_DEFAULT],
            patch.object(unused, 'bare_output_is_preserved', lambda options: True),
            notices='test_a_bare_literal_at_the_root_is_stripped')

    def test_the_fault_gate_on_a_deleted_write_is_witnessed(self):
        # What separates `42` from `[Int]'abc'`, both of which are output and only one of which
        # terminates the script where it stands.
        self._assertWitnessed(
            [_KEPT_EITHER_WAY],
            patch.object(
                unused,
                'expression_cannot_fault',
                lambda operand, position, faults, world: True,
            ),
            notices='test_a_statement_that_can_raise_is_kept')

    def test_the_redirection_gate_on_a_deleted_write_is_witnessed(self):
        # Patched in `effects`, where the outward walk reads it, because a redirection decides where
        # the value goes and not whether the statement around it is shaped like a discard.
        self._assertWitnessed(
            [_KEPT_EITHER_WAY],
            patch.object(effects, '_redirection_takes_output_away', lambda redirection: False),
            notices='test_a_value_a_redirection_moves_elsewhere_is_kept')

    def test_the_refusal_to_substitute_away_a_redirection_is_witnessed(self):
        # The rule itself, patched in the module that owns it. Both callers are named, because the
        # two shapes reach it by different routes: an expression in a slot asks through
        # `substitute`, and a pass returning a replacement from `visit_X` asks through
        # `substituted`. Both are in the owning module, so this one mutation reaches both.
        self._assertWitnessed(
            [_IEX_REDIRECTIONS, _WILDCARD_REDIRECTIONS, _FOREACH_PIPELINE],
            patch.object(substitution, 'may_substitute', lambda *parts: True),
            notices='test_a_redirected_iex_statement_is_not_replaced_by_the_code_it_holds')

    def test_asking_the_rule_where_a_wildcard_rewrite_decides_is_witnessed(self):
        # `refinery.lib.scripts.Transformer.generic_visit` installs whatever a `visit_X` returns, so
        # a pass that does not ask is a pass whose replacement lands unexamined. Patched at the
        # pass rather than in the owner: what this measures is that the pass asks at all.
        self._assertWitnessed(
            [_WILDCARD_REDIRECTIONS],
            patch.object(wildcards, 'substituted', lambda old, new, moved=(): new),
            notices='test_a_redirected_variable_read_is_not_rewritten_to_the_variable')

    def test_asking_the_rule_where_a_foreach_pipeline_fold_decides_is_witnessed(self):
        self._assertWitnessed(
            [_FOREACH_PIPELINE],
            patch.object(emulator, 'substituted', lambda old, new, moved=(): new),
            notices='test_a_redirected_foreach_pipeline_is_not_folded_into_its_value')

    def test_the_interpreter_refusing_a_body_that_opens_a_file_is_witnessed(self):
        # The emulator's own half: the call site carries no redirection, the body does, and folding
        # the call deletes the body along with the file it creates.
        self._assertWitnessed(
            [_EMULATOR_EXTRA],
            patch.object(emulator, 'opens_a_redirection_target', lambda node: False),
            notices='test_a_body_that_opens_a_file_is_not_folded_into_the_value_it_returns')

    def test_the_gate_on_an_element_a_selection_drops_is_witnessed(self):
        # Selecting out of a literal container evaluates the whole container, so what the selection
        # does not carry forward is work the folded script no longer does.
        self._assertWitnessed(
            [_SELECTION, _SELECTION_COUNT],
            patch.object(folding, 'may_be_dropped', lambda node, oracle: True),
            notices='test_an_array_element_that_runs_a_command_is_not_dropped')

    def test_the_fault_half_of_that_gate_is_witnessed(self):
        # And the half a purity argument alone would have granted: `[Int]'abc'` is side-effect free
        # and raises where it stands.
        self._assertWitnessed(
            [_SELECTION],
            patch.object(effects, 'is_fault_free', lambda node: True),
            notices='test_an_array_element_that_can_raise_is_not_dropped')

    def test_the_collision_row_on_a_qualified_call_is_witnessed(self):
        # Only the collision detection is patched. Pinning `is_readable` False instead produces 22
        # failures across the package, so a blanket mutation would be satisfied by tests that have
        # nothing to do with this row and would prove nothing about it.
        self._assertWitnessed(
            [_QUALIFIED, _CALL_GRAPH],
            patch.object(
                callgraph, '_collides_with_a_definition', lambda resolved, definitions: False),
            notices='test_a_quoted_module_qualified_call_keeps_the_definition_it_resolves_onto')

    def test_walking_the_routing_rather_than_reading_a_position_is_witnessed(self):
        # The defect the rebuild was for. Patched in `effects`, where `deletion_is_observable` reads
        # the name for the handler half of its answer. The one position the old reading did see stays
        # green, and so does every statement that runs to completion, so what the mutation costs is
        # exactly the raises a graph walk finds and a syntactic position cannot.
        self._assertWitnessed(
            [_NESTED_GUARD, _DIRECT_GUARD],
            patch.object(effects, 'fault_is_observed', _fault_observed_where_the_clause_is_written),
            notices='test_a_raising_cast_in_a_nested_if_body_is_kept')

    def test_the_short_circuit_on_a_statement_that_cannot_raise_is_witnessed(self):
        self._assertWitnessed(
            [_NESTED_GUARD],
            patch.object(effects, 'fault_is_observed', _fault_observed_wherever_an_error_would_go),
            notices='test_a_quiet_cast_in_a_nested_if_body_is_removed')

    def test_the_strict_mode_gate_on_a_deleted_variable_read_is_witnessed(self):
        # The one fault a bare read can raise, and the reason the grant is not unconditional.
        self._assertWitnessed(
            [_STRICT_MODE],
            patch.object(
                faults.Ps1FaultReach, 'strict_mode_may_be_in_force', lambda self: False),
            notices='test_the_discard_and_the_output_are_both_kept_where_strict_mode_is_armed')

    def test_the_second_command_that_arms_strict_mode_is_witnessed(self):
        # `Set-PSDebug -Strict` arms the same error engine-wide and resolves to a name of its own,
        # so a table holding only the obvious command grants every removal below it.
        self._assertWitnessed(
            [_STRICT_MODE],
            patch.object(faults, '_STRICT_MODE_COMMANDS', frozenset({'set-strictmode'})),
            notices='test_the_discard_and_the_output_are_both_kept_where_the_other_command_arms_it')

    def test_the_memo_that_keeps_the_arming_scan_affordable_is_witnessed(self):
        # The scan is a walk over the whole tree and the removal path asks for it per candidate, so
        # the slot is the only thing between one walk per batch and one per statement. Measured, the
        # call order is *not* such a thing: asking the fact before the cheaper halves of the gate
        # costs nothing, so a probe over the order would be satisfied by a mutation that changes no
        # work at all.
        self._assertWitnessed(
            [_ARMING_COST],
            patch.object(
                faults.Ps1FaultReach,
                'strict_mode_may_be_in_force',
                _strict_mode_read_without_the_memo,
            ),
            notices='test_the_walk_is_taken_a_bounded_number_of_times')

    def test_the_enumerator_being_denied_purity_is_witnessed(self):
        # Reading `$input` advances what the statements below it read, so the one variable whose
        # read is not free has to be denied where every other one is granted.
        self._assertWitnessed(
            [_ENUMERATOR],
            patch.object(effects, '_reads_the_pipeline_enumerator', lambda node: False),
            notices='test_a_bare_read_of_the_enumerator_is_kept')

    def test_the_empty_pole_of_that_fact_being_the_opposite_of_its_sibling_is_witnessed(self):
        # Mirroring `_stops_on_every_error` verbatim is the implementation a reader would write,
        # and no deobfuscation-string test reaches the model it answers for.
        self._assertWitnessed(
            [_STRICT_MODE_FACT],
            patch.object(
                faults.Ps1FaultReach,
                'strict_mode_may_be_in_force',
                _strict_mode_with_the_siblings_empty_pole,
            ),
            notices='test_a_model_the_graphs_hold_no_script_for_refuses_the_grant')

    def test_the_world_half_of_that_gate_is_witnessed(self):
        # Patched in both modules that read the name: `fault_is_observed` reads the one in `effects`
        # and the output twin imported its own.
        self._assertWitnessed(
            [_STRICT_MODE_PAYLOAD],
            patch.object(
                effects, 'expression_cannot_fault', _expression_cannot_fault_without_the_world),
            patch.object(
                unused, 'expression_cannot_fault', _expression_cannot_fault_without_the_world),
            notices='test_a_discarded_unset_read_below_an_unreadable_payload_is_kept')

    def test_the_shape_the_grant_is_restricted_to_is_witnessed(self):
        # An index runs an indexer and a qualified name runs a provider, neither of which strict
        # mode decides; granting them reads those faults as absent. The member read in the same
        # class is not a witness of this gate — a getter is impure, so it never reaches the fault
        # question at all — which is why the probe names one that is.
        self._assertWitnessed(
            [_STRICT_MODE_SHAPE],
            patch.object(effects, '_is_bare_variable_read', lambda node: True),
            notices='test_a_discarded_index_read_is_kept')

    def test_asking_whether_a_handler_acts_at_all_is_witnessed(self):
        # Patched in the module that owns it, where both readings of the routing consult it. The
        # empty `catch` an obfuscator writes is inert either way, so the class built on one stays
        # green while the class built on a handler with a body goes red — which is the distinction
        # the mutation erases, spelled as two outcomes rather than one.
        self._assertWitnessed(
            [_DIRECT_GUARD, _EMPTY_CATCH],
            patch.object(faults, 'handler_acts', lambda handler: False),
            notices='test_a_raising_cast_directly_in_the_try_block_is_kept')

    def test_reading_the_escalation_off_the_routing_is_witnessed(self):
        # Measured: with the clause dropped the position question answers differently in two tests
        # of the whole package, and both are in the unit test over the reading itself. No pass in
        # the deobfuscator is reached by a `trap` set that may decline an error, so this is the
        # only witness there is.
        self._assertWitnessed(
            [_ESCALATION, _SWALLOWING_TRAP],
            patch.object(faults.Ps1FaultReach, 'observed_at', _observed_at_reading_only_what_acts),
            notices=(
                'test_a_raise_guarded_by_a_typed_trap_is_observed_because_the_set_may_decline_it'))

    def test_judging_a_handler_by_the_transpose_is_witnessed(self):
        # Both directions of the confusion, so that neither reads as the mutation merely refusing
        # more: a swallowing `trap` whose errors would fall back to a live one is deleted, and a
        # `trap` a `catch` with a payload depends on is unhooked.
        self._assertWitnessed(
            [_UNREACHED_TRAP, _HANDLER],
            patch.object(
                faults.Ps1FaultReach,
                'removing_a_handler_is_observed',
                _removing_a_handler_asked_at_the_handler),
            notices='test_a_raising_cast_whose_innermost_trap_continues_is_removed')

    def test_refusing_a_batch_that_would_empty_a_protected_body_is_witnessed(self):
        # The set-level half, which the per-statement veto cannot stand in for: what the witnesses
        # put in a guarded body cannot raise, so no removal of one is vetoed on its own, and what
        # keeps the handler beside it in the listing is the refusal to clear the block.
        self._assertWitnessed(
            [_PROTECTED_BODY],
            patch.object(removal, 'emptying_unhooks_a_handler', lambda block: False),
            notices='test_junk_removal_keeps_a_protected_try_body')

    def test_the_scriptblock_slot_a_block_fills_is_witnessed(self):
        # A block a command takes as data is one it may hand on rather than run, so reading every
        # argument of an iterating command as a body it runs invents a site for it.
        self._assertWitnessed(
            [_SCRIPTBLOCK_SLOT],
            patch.object(blocks, '_fills_a_scriptblock_slot', lambda cmd, block, command: True),
            notices='test_a_block_handed_to_a_data_slot_has_no_site')

    def test_the_name_the_climb_out_of_a_body_rests_on_is_witnessed(self):
        # The lift is worth what the command name is worth: a script that takes `ForEach-Object`
        # over may hand the block to something that keeps it.
        self._assertWitnessed(
            [_SITE_POSITION],
            patch.object(
                worldflow.Ps1WorldReach, '_climb_is_trusted',
                lambda self, climbed, position: True),
            notices='test_a_redefined_iterator_refuses_the_climb_out_of_its_body')

    def test_that_a_statement_answers_for_the_bodies_it_runs_is_witnessed(self):
        # Without it the fallback for a body something may call answers for every block written
        # inside a discarded pipeline, and one `try` anywhere in the file keeps all of them.
        self._assertWitnessed(
            [_STATEMENT_RUNS_THE_BODY],
            patch.object(effects, '_leaves_a_block_of', lambda site, stmt, faults: False),
            notices='test_a_discarded_pipeline_is_removed_beside_an_unrelated_handler')

    def test_the_parameter_set_a_positional_block_lands_in_is_witnessed(self):
        # A command picks one parameter set from its arguments, and the first positional argument is
        # a body in one of them and a method's argument list in another.
        self._assertWitnessed(
            [_SCRIPTBLOCK_SLOT],
            patch.object(blocks, '_selects_a_scriptblock_set', lambda cmd, command: True),
            notices='test_a_member_name_makes_the_positional_block_an_argument_rather_than_a_body')
