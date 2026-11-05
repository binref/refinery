from __future__ import annotations

import unittest.mock

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.handoff import Ps1Handoff
from refinery.lib.scripts.ps1.analysis.objects import Ps1ObjectFlow
from refinery.lib.scripts.ps1.analysis.world import runs_code_it_cannot_read
from refinery.lib.scripts.ps1.model import Ps1ArrayLiteral, Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _occurrences(tree: Node, name: str) -> list[Ps1Variable]:
    return [
        node for node in tree.walk_in_order()
        if isinstance(node, Ps1Variable) and node.name.lower() == name
    ]


def _objects(source: str) -> tuple[Node, Ps1ObjectFlow]:
    tree = Ps1Parser(source).parse()
    return tree, Ps1ModelCache(tree).object_flow


class TestPs1ACodeNobodyCanReadIsAChange(TestBase):

    def test_every_runner_of_code_from_a_string_runs_code_nobody_can_read(self):
        for source in (
            'iex $c',
            '& ([scriptblock]::Create($c))',
            '$ExecutionContext.InvokeCommand.InvokeScript($c)',
            '& $s',
            'Invoke-Command -ScriptBlock $s',
            'function f { iex $c }',
        ):
            with self.subTest(source):
                _, objects = _objects(source)
                self.assertTrue(objects.unreadable_code)

    def test_a_call_of_a_block_the_source_spells_runs_nothing_unreadable(self):
        for source in ('& { $x = 1 }', 'Write-Host hi', '[string]::Join(" ", $b)'):
            with self.subTest(source):
                _, objects = _objects(source)
                self.assertEqual(objects.unreadable_code, ())

    def test_code_run_by_a_created_block_is_unreadable_whatever_the_options_say(self):
        tree = Ps1Parser('& ([scriptblock]::Create($c))').parse()
        self.assertTrue(any(runs_code_it_cannot_read(node) for node in tree.walk()))


class TestPs1AChangeIsOrderedWhereTheNodeIsPlaced(TestBase):

    def test_a_change_after_the_statement_that_runs_a_block_follows_a_node_in_it(self):
        tree, objects = _objects('$x = 1, 2, 3; $y = & { ,$x }; $y[0] = 9')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_unreadable_code_after_the_statement_that_runs_a_block_follows_a_node_in_it(self):
        tree, objects = _objects('$x = 1, 2, 3; $y = & { ,$x }; iex $c')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_a_change_before_the_statement_that_runs_a_block_does_not_follow_a_node_in_it(self):
        tree, objects = _objects('$z = 0, 0; $z[0] = 7; $x = 1, 2, 3; $y = & { ,$x }')
        self.assertFalse(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_a_change_in_a_function_body_may_follow_anything(self):
        tree, objects = _objects('function f { $z[0] = 7 }; $x = 1, 2, 3; Write-Output $x')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))


class TestPs1AChangeTheObjectMaySeeBetweenAWriteAndARead(TestBase):

    @staticmethod
    def _unseen(source: str) -> Ps1Handoff:
        tree, objects = _objects(source)
        occurrences = _occurrences(tree, 'x')
        return objects.unseen_change(occurrences[0], occurrences[-1])

    def test_a_store_through_a_container_holding_the_array_changes_it(self):
        self.assertIs(
            self._unseen("$x = 1, 2, 3; $h = @{ k = $x }; $h['k'][0] = 9; Write-Output $x"),
            Ps1Handoff.OBJECT,
        )

    def test_a_store_into_an_array_made_elsewhere_changes_nothing_the_read_observes(self):
        self.assertIs(
            self._unseen("$x = 1, 2, 3; $h = @{ k = $x }; $z = 0, 0; $z[0] = 9; Write-Output $x"),
            Ps1Handoff.NOWHERE,
        )

    def test_a_store_into_an_array_either_arm_may_have_made_changes_the_read(self):
        self.assertIs(
            self._unseen(
                "$x = 1, 2, 3; $h = @{ k = $x }; if ($a) { $z = 0, 0 } else { $z = $x }; "
                '$z[0] = 9; Write-Output $x'),
            Ps1Handoff.OBJECT,
        )

    def test_code_nobody_can_read_may_store_through_a_second_name(self):
        self.assertIs(
            self._unseen('$x = 1, 2, 3; $y = $x; function f { iex $c }; f; Write-Output $x'),
            Ps1Handoff.OBJECT,
        )

    def test_a_change_before_the_hand_off_changes_nothing_the_read_observes(self):
        self.assertIs(
            self._unseen("$z = 0, 0; $z[0] = 7; $x = 1, 2, 3; $h = @{ k = $x }; Write-Output $x"),
            Ps1Handoff.NOWHERE,
        )


class TestPs1TheObjectANameHoldsIsWhereItWasMade(TestBase):

    @staticmethod
    def _made(source: str) -> tuple[set[int], set[int] | None]:
        tree, objects = _objects(source)
        literals = {id(node) for node in tree.walk() if isinstance(node, Ps1ArrayLiteral)}
        made = objects.allocations_at(_occurrences(tree, 'x')[-1])
        return literals, None if made is None else {id(node) for node in made}

    def test_a_name_assigned_an_array_literal_holds_what_the_literal_made(self):
        literals, made = self._made('$x = 1, 2; Write-Output $x')
        self.assertEqual(made, literals)

    def test_a_second_name_holds_what_the_first_one_held(self):
        literals, made = self._made('$y = 1, 2; $x = $y; Write-Output $x')
        self.assertEqual(made, literals)

    def test_a_name_assigned_on_two_arms_holds_what_either_made(self):
        literals, made = self._made('if ($a) { $x = 1, 2 } else { $x = 3, 4 }; Write-Output $x')
        self.assertEqual(len(literals), 2)
        self.assertEqual(made, literals)

    def test_the_output_of_a_command_may_be_any_object(self):
        _, made = self._made('$x = Get-Thing; Write-Output $x')
        self.assertIsNone(made)

    def test_a_parameter_may_be_any_object(self):
        _, made = self._made('function f($x) { Write-Output $x }')
        self.assertIsNone(made)


class TestPs1AChangeReachesTheObjectsItsNameMayHold(TestBase):

    @staticmethod
    def _may_change(source: str) -> bool:
        tree, objects = _objects(source)
        held = objects.allocations_at(_occurrences(tree, 'x')[-1])
        for change in (*objects.semantic.object_change_sites, *objects.unreadable_code):
            changed = objects.changes_of(change)
            if held is None or changed is None or not changed.isdisjoint(held):
                return True
        return False

    def test_a_store_into_an_element_changes_what_the_name_holds(self):
        self.assertTrue(self._may_change('$x = 0, 0; $z = $x; $z[0] = 7; Write-Output $x'))

    def test_a_store_into_an_element_of_another_array_does_not(self):
        self.assertFalse(self._may_change('$x = 0, 0; $z = 1, 1; $z[0] = 7; Write-Output $x'))

    def test_a_reversal_changes_what_the_name_it_is_handed_holds(self):
        self.assertTrue(
            self._may_change('$x = 1, 2; $z = $x; [Array]::Reverse($z); Write-Output $x'))

    def test_a_reversal_of_another_array_does_not(self):
        self.assertFalse(
            self._may_change('$x = 1, 2; $z = 3, 4; [Array]::Reverse($z); Write-Output $x'))

    def test_reversing_a_list_adapter_may_change_the_array_it_wraps(self):
        self.assertTrue(self._may_change(
            '$x = 1, 2, 3; $w = [Collections.ArrayList]::Adapter($x); $w.Reverse(); '
            'Write-Output $x'))

    def test_a_store_two_steps_in_changes_an_array_held_inside_another(self):
        self.assertTrue(self._may_change('$x = 1, 2; $z = $x, 1; $z[0][0] = 7; Write-Output $x'))

    def test_code_nobody_can_read_may_change_any_array(self):
        self.assertTrue(self._may_change('$x = 1, 2; iex $c; Write-Output $x'))


class TestPs1ACallAroundAnAssignmentChangesWhatItStored(TestBase):

    @staticmethod
    def _unseen(source: str) -> Ps1Handoff:
        tree, objects = _objects(source)
        occurrences = _occurrences(tree, 'x')
        return objects.unseen_change(occurrences[0], occurrences[-1])

    def test_a_call_writing_the_slot_an_assignment_fills_changes_what_it_stored(self):
        for source in (
            '[Array]::Reverse(($x = 1, 2, 3)); Write-Output $x',
            '[Array]::Clear(($x = 1, 2, 3), 0, 3); Write-Output $x',
            '$s = 7, 8; [Array]::Copy($s, ($x = 0, 0), 2); Write-Output $x',
        ):
            with self.subTest(source):
                self.assertIsNot(self._unseen(source), Ps1Handoff.NOWHERE)

    def test_the_reversal_a_name_is_read_off_is_not_a_change_it_has_not_seen(self):
        tree, objects = _objects('$x = 1, 2, 3; [Array]::Reverse($x); Write-Output $x')
        occurrences = _occurrences(tree, 'x')
        self.assertIs(objects.unseen_change(occurrences[1], occurrences[-1]), Ps1Handoff.NOWHERE)


class TestPs1ABodyRunAgainRunsItsChangesAfterItsReads(TestBase):

    def test_a_change_before_a_read_in_a_body_run_per_object_follows_the_read(self):
        tree, objects = _objects(
            '1..2 | ForEach-Object { $h.k[0] = 9; $x = 1, 2, 3; $h = @{ k = $x } }')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_a_change_before_a_read_in_a_block_a_loop_runs_follows_the_read(self):
        tree, objects = _objects(
            'foreach ($i in 1..2) { . { $h.k[0] = 9; $x = 1, 2, 3; $h = @{ k = $x } } }')
        self.assertTrue(objects.change_may_follow(_occurrences(tree, 'x')[1]))

    def test_a_change_before_a_read_in_a_block_run_once_does_not_follow_the_read(self):
        tree, objects = _objects('. { $h.k[0] = 9; $x = 1, 2, 3; $h = @{ k = $x } }')
        self.assertFalse(objects.change_may_follow(_occurrences(tree, 'x')[1]))


class TestPs1ANameOfAChainIsHandedTheWholeObject(TestBase):

    def test_an_assignment_used_as_a_value_keeps_the_object_whatever_is_read_off_it(self):
        for source in (
            '$n = ($y = $x).Count',
            '$w = ($z = $y = $x)[0]',
            'foreach ($e in ($y = $x)) { }',
        ):
            with self.subTest(source):
                tree, objects = _objects(source)
                self.assertIs(objects.handoff(_occurrences(tree, 'x')[0]), Ps1Handoff.OBJECT)


class TestPs1TheObjectANameHoldsIsFollowedOncePerRead(TestBase):

    def test_a_chain_of_branches_is_followed_once_per_read(self):
        length = 12
        lines = ['$a0 = 5, 6']
        lines.extend(
            F'if ($c) {{ $a{k} = $a{k - 1} }} else {{ $a{k} = $a{k - 1} }}'
            for k in range(1, length + 1)
        )
        lines.append(F'Write-Output $a{length}')
        tree, objects = _objects('\n'.join(lines))
        variables = objects.variables
        with unittest.mock.patch.object(
            variables, 'writes_reaching', wraps=variables.writes_reaching
        ) as asked:
            self.assertIsNotNone(objects.allocations_at(_occurrences(tree, F'a{length}')[-1]))
        self.assertLessEqual(asked.call_count, 2 * length + 1)


class TestPs1AnAutomaticVariableHoldsWhatTheEngineGaveIt(TestBase):

    def test_a_store_through_a_switchs_pipeline_variable_may_change_the_array_it_is_handed(self):
        tree, objects = _objects(
            '$_ = 0, 0; $x = 1, 2, 3; switch (,$x) { default { $_[0] = 9 } }; Write-Output $x')
        store = [node for node in _occurrences(tree, '_') if node.parent is not None][-1]
        held = objects.allocations_at(_occurrences(tree, 'x')[-1])
        changed = objects.changes_of(store)
        self.assertTrue(held is None or changed is None or not changed.isdisjoint(held))
