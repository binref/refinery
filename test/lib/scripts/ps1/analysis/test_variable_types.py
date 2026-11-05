from __future__ import annotations

from inspect import cleandoc

from test import TestBase, opportunity

from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.ps1.analysis.blocks import build_block_model
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.dataflow import build_variable_flow
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.model import build_semantic_model, is_write_occurrence
from refinery.lib.scripts.ps1.analysis.variable_types import type_at
from refinery.lib.scripts.ps1.model import Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _in_source_order(node):
    yield node
    for child in node.children():
        yield from _in_source_order(child)


class TestPs1TypeAt(TestBase):

    def _type_at(self, source: str, read: int = -1, name: str = 'q') -> str | None:
        tree = Ps1Parser(source).parse()
        semantic = build_semantic_model(tree)
        control = build_control_flow_model(tree)
        blocks = build_block_model(tree)
        flow = build_variable_flow(
            semantic,
            control,
            build_dominance(control),
            blocks,
            CycleModel(control, blocks.body_site),
        )
        reads = [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable)
            and node.name.lower() == name
            and not is_write_occurrence(node)
        ]
        found = type_at(reads[read], flow)
        return None if found is None else str(found)

    def test_a_name_the_script_never_writes_has_no_type(self):
        self.assertIsNone(self._type_at("$q.downloadstring('u')"))

    def test_a_read_after_the_only_write_carries_what_that_write_established(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_write_inside_a_function_body_does_not_type_a_read_outside_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """)))

    def test_a_write_inside_a_function_body_types_a_read_inside_that_body(self):
        self.assertEqual(self._type_at(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
        """)), 'System.Net.WebClient')

    def test_a_write_inside_one_function_body_does_not_type_a_read_inside_another(self):
        self.assertIsNone(self._type_at(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            function g {
              $q.downloadstring('u')
            }
        """)))

    def test_two_function_bodies_writing_one_name_are_typed_from_their_own_write(self):
        source = cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
            function g {
              $q = New-Object Text.StringBuilder
              $q.tostring()
            }
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.Net.WebClient')
        self.assertEqual(self._type_at(source, read=1), 'System.Text.StringBuilder')

    def test_a_store_through_a_member_leaves_the_name_holding_what_it_held(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q.Proxy = $null
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_write_and_a_read_inside_one_subexpression_are_typed(self):
        self.assertEqual(
            self._type_at("$($q = New-Object Net.WebClient; $q.downloadstring('u'))"),
            'System.Net.WebClient',
        )

    def test_a_read_before_the_write_it_shares_a_subexpression_with_is_refused(self):
        self.assertIsNone(
            self._type_at('$(($q | Get-Member)[0].Name; $q = New-Object Net.WebClient)'))

    def test_each_read_is_typed_by_the_write_it_observes_where_the_writes_disagree(self):
        source = cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
            $q = New-Object Text.StringBuilder
            $q.tostring()
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.Net.WebClient')
        self.assertEqual(self._type_at(source, read=1), 'System.Text.StringBuilder')

    def test_a_read_no_single_write_reaches_is_refused_where_the_writes_disagree(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Text.StringBuilder
            }
            $q.tostring()
        """)))

    def test_a_read_no_single_write_reaches_is_typed_where_the_writes_agree(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Net.WebClient
            }
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_read_preceding_every_write_of_the_name_is_refused(self):
        self.assertIsNone(self._type_at(cleandoc("""
            ($q | Get-Member)[0].Name
            $q = New-Object Net.WebClient
        """)))

    def test_a_read_at_the_top_of_a_loop_body_precedes_the_write_below_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            while ($c) {
              ($q | Get-Member)[0].Name
              $q = New-Object Net.WebClient
            }
        """)))

    def test_a_loop_body_read_is_typed_once_a_write_before_the_loop_reaches_it(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            while ($c) {
              $q.downloadstring('u')
              $q = New-Object Net.WebClient
            }
        """)), 'System.Net.WebClient')

    def test_a_write_on_one_branch_only_does_not_type_the_read_after_the_branch(self):
        self.assertIsNone(self._type_at(cleandoc("""
            if ($c) {
              $q = New-Object Net.WebClient
            }
            $q.downloadstring('u')
        """)))

    def test_a_write_inside_a_body_reached_by_a_qualifier_does_not_type_a_read_outside(self):
        self.assertIsNone(self._type_at(cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """)))

    def test_a_write_through_a_qualifier_types_the_reads_that_follow_it_in_its_body(self):
        self.assertEqual(self._type_at(cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
        """)), 'System.Net.WebClient')

    def test_a_write_carrying_no_type_of_its_own_is_not_looked_past(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = 5
            $q += $n
            $q.tostring()
        """)))

    def test_a_read_an_unattributable_write_may_precede_is_refused(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            Invoke-Expression $code
            $q.downloadstring('u')
        """)))

    def test_an_unattributable_write_after_the_read_leaves_the_type_standing(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
            Invoke-Expression $code
        """)), 'System.Net.WebClient')

    def test_a_read_through_a_scope_qualifier_carries_the_type_of_the_write_it_names(self):
        for source in [
            cleandoc("""
                $global:q = New-Object Net.WebClient
                $global:q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                $script:q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')

    def test_a_foreach_over_a_string_binds_the_string_and_not_its_characters(self):
        self.assertEqual(
            self._type_at("foreach ($s in 'abc') { $s.substring(0, 1) }", name='s'),
            'System.String',
        )

    def test_a_foreach_binding_carries_the_type_the_iterated_elements_share(self):
        for source, expected in [
            ("foreach ($s in 'a', 'b') { $s.tostring() }", 'System.String'),
            ('foreach ($s in 1, 2) { $s.tostring() }', 'System.Int32'),
            ("foreach ($s in 'a', 1) { $s.tostring() }", None),
            ('foreach ($s in $items) { $s.tostring() }', None),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source, name='s'), expected)


class TestPs1AWriteThroughAWiderScopeIsNotTheNameABareReadResolves(TestPs1TypeAt):

    def test_a_bare_read_does_not_carry_what_a_write_to_a_wider_scope_stored(self):
        for qualifier in ['global', 'using']:
            with self.subTest(qualifier):
                self.assertIsNone(self._type_at(cleandoc(F"""
                    $q = $text
                    ${qualifier}:q = New-Object Net.WebClient
                    $q.downloadstring('u')
                """)))

    def test_a_bare_write_standing_beside_a_wider_one_is_refused_and_not_read_past(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = 'text'
            $global:q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)))

    def test_a_read_naming_one_scope_does_not_carry_a_write_through_the_other(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                $global:q.downloadstring('u')
            """),
            cleandoc("""
                $global:q = New-Object Net.WebClient
                $script:q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_name_only_a_wider_scope_writes_is_the_one_a_bare_read_resolves_to(self):
        self.assertEqual(self._type_at(cleandoc("""
            $global:q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_the_script_qualifier_names_the_scope_a_bare_write_already_lands_in(self):
        for source in [
            cleandoc("""
                $q = $text
                $script:q = New-Object Net.WebClient
                $q.downloadstring('u')
            """),
            cleandoc("""
                $script:q = $text
                $q = New-Object Net.WebClient
                $q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')


class TestPs1ATypeIsNotTakenFromAStoreThatMayNotHaveCompleted(TestPs1TypeAt):

    def test_a_handler_does_not_carry_the_write_its_try_body_may_not_have_completed(self):
        self.assertIsNone(self._type_at(cleandoc("""
            try {
              $q = New-Object Net.WebClient
            } catch {
              ($q | Get-Member)[0].Name
            }
        """)))

    def test_a_read_after_the_whole_try_does_not_carry_the_write_inside_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            try {
              $q = New-Object Net.WebClient
            } catch {}
            ($q | Get-Member)[0].Name
        """)))

    def test_a_read_only_the_completing_body_reaches_still_carries_the_write(self):
        self.assertEqual(self._type_at(cleandoc("""
            try {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            } catch {}
        """)), 'System.Net.WebClient')


class TestPs1AReadInsideATrapBodyCarriesTheWritesThatCompletedBeforeTheThrow(TestPs1TypeAt):

    def test_a_write_standing_below_the_trap_does_not_type_a_read_inside_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            trap {
              ($q | Get-Member)[0].Name
            }
            $q = New-Object Net.WebClient
        """)))

    @opportunity
    def test_a_write_the_trap_body_performs_itself_types_the_read_below_it(self):
        self.assertEqual(self._type_at(cleandoc("""
            trap {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
        """)), 'System.Net.WebClient')

    @opportunity
    def test_a_write_that_cannot_throw_types_a_read_inside_the_trap(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = 'abc'
            trap {
              $q.substring(0, 1)
            }
        """)), 'System.String')


class TestPs1AWriteNobodyCanReadTypesNoReadWhereverThatReadStands(TestPs1TypeAt):

    def test_a_read_the_call_precedes_carries_no_type(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                1..3 | %{ $q.downloadstring('u') }
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                & { $q.downloadstring('u') }
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_read_the_call_follows_still_carries_the_write(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                $q.downloadstring('u')
                Invoke-Expression $code
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | %{ $q.downloadstring('u') }
                Invoke-Expression $code
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                & { $q.downloadstring('u') }
                Invoke-Expression $code
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')


class TestPs1ATypeIsNotCarriedPastABlockThatWritesItsCallersName(TestPs1TypeAt):

    _BLOCK_STORES = [
        (
            cleandoc("""
                $q = 'abc'
                . { $q = New-Object Net.WebClient }
                ($q | Get-Member)[0].Name
            """),
            'System.Net.WebClient',
        ),
        (
            cleandoc("""
                $q = New-Object Net.WebClient
                . { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
            'System.Int32',
        ),
        (
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
            'System.Int32',
        ),
        (
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | Where-Object { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
            'System.Int32',
        ),
    ]

    def test_a_read_below_a_caller_scope_block_carries_what_the_block_stored_or_no_type(self):
        for source, stored in self._BLOCK_STORES:
            with self.subTest(source):
                self.assertIn(self._type_at(source), (None, stored))

    @opportunity
    def test_a_read_below_a_caller_scope_block_carries_what_the_block_stored(self):
        for source, stored in self._BLOCK_STORES:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), stored)

    def test_a_block_that_writes_no_such_name_leaves_the_write_above_it_standing(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                . { $z = 5 }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object { $z = 5 }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | Where-Object { $z = 5 }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                & { $q = 5 }
                $q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')


class TestPs1AConstrainedTargetTypesTheNameFromItsConstraint(TestPs1TypeAt):

    def test_the_constraint_and_not_the_assigned_value_names_the_type(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = 5
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constraint_naming_the_type_the_value_already_has_carries_it_too(self):
        self.assertEqual(self._type_at(cleandoc("""
            [Net.WebClient]$q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_constraint_types_the_name_where_the_assigned_value_has_no_type_of_its_own(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = $unknown
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constraint_naming_no_type_this_layer_knows_is_refused(self):
        self.assertIsNone(self._type_at(cleandoc("""
            [NoSuchType]$q = 5
            $q.tostring()
        """)))

    def test_each_read_carries_the_constraint_of_the_write_it_observes(self):
        source = cleandoc("""
            [string]$q = 5
            $q.substring(0, 1)
            [int]$q = '5'
            $q.tostring()
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.String')
        self.assertEqual(self._type_at(source, read=1), 'System.Int32')

    def test_a_constrained_and_a_plain_write_agreeing_type_a_read_neither_of_them_reaches(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = 'abc'
            if ($c) {
              [string]$q = 5
            }
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constraint_disagreeing_with_a_plain_write_refuses_the_read_neither_reaches(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = 5
            if ($c) {
              [string]$q = 5
            }
            $q.tostring()
        """)))

    def test_a_constrained_write_and_a_read_inside_one_subexpression_are_typed(self):
        self.assertEqual(
            self._type_at('$([string]$q = 5; $q.substring(0, 1))'), 'System.String')

    def test_the_constraint_is_the_type_its_name_resolves_to(self):
        for constraint, expected in [
            ('System.String', 'System.String'),
            ('STRING', 'System.String'),
            ('int32', 'System.Int32'),
            ('long', 'System.Int64'),
            ('char', 'System.Char'),
            ('bool', 'System.Boolean'),
            ('decimal', 'System.Decimal'),
        ]:
            with self.subTest(constraint):
                self.assertEqual(self._type_at(cleandoc(F"""
                    [{constraint}]$q = 1
                    $q.tostring()
                """)), expected)

    def test_a_constraint_naming_an_array_type_leaves_the_name_holding_the_array(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string[]]$q = 1, 2
            $q.Length
        """)), 'System.String[]')

    def test_a_constraint_converts_the_object_a_read_would_otherwise_reach_a_member_on(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = New-Object Net.WebClient
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_cast_on_the_assigned_value_constrains_nothing_and_the_write_below_it_answers(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = [string]5
            $q = 1, 2, 3
            $q.Length
        """)), 'System.Object[]')

    def test_a_later_plain_write_the_constraint_leaves_alone_types_the_name(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = 5
            $q = 'abc'
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constrained_write_is_bound_by_every_rule_a_plain_write_is(self):
        for source in [
            cleandoc("""
                function f {
                  [string]$q = 5
                }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                [string]$q = 5
                Invoke-Expression $code
                $q.substring(0, 1)
            """),
            cleandoc("""
                try {
                  [string]$q = New-Object Net.WebClient
                } catch {}
                ($q | Get-Member)[0].Name
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_constraint_is_the_only_type_a_caller_scope_block_store_can_give_the_read(self):
        self.assertIn(self._type_at(cleandoc("""
            [string]$q = 5
            . { $q = New-Object Net.WebClient }
            ($q | Get-Member)[0].Name
        """)), (None, 'System.String'))

    @opportunity
    def test_a_constraint_converts_what_a_caller_scope_block_stores_under_the_name(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = 5
            . { $q = New-Object Net.WebClient }
            ($q | Get-Member)[0].Name
        """)), 'System.String')


class TestPs1AMultiAssignmentSlotTypesTheNameFromTheElementOppositeIt(TestPs1TypeAt):

    def test_each_slot_carries_the_element_standing_opposite_it(self):
        source = cleandoc("""
            $q, $r, $s = 'abc', 1, (New-Object Net.WebClient)
            $q.substring(0, 1)
            $r.tostring()
            $s.downloadstring('u')
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.String')
        self.assertEqual(self._type_at(source, name='r'), 'System.Int32')
        self.assertEqual(self._type_at(source, name='s'), 'System.Net.WebClient')

    def test_a_slot_whose_element_has_no_type_leaves_the_slot_beside_it_typed(self):
        source = cleandoc("""
            $q, $r = 'abc', $unknown
            $q.substring(0, 1)
            $r.tostring()
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.String')
        self.assertIsNone(self._type_at(source, name='r'))

    def test_a_slot_a_shorter_right_hand_side_leaves_empty_carries_no_type(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $a, $q = 1
            $q.tostring()
        """)))

    def test_a_slot_swallowing_the_rest_of_the_right_hand_side_is_an_array_or_untyped(self):
        self.assertIn(self._type_at(cleandoc("""
            $a, $q = 1, 2, 3
            $q.tostring()
        """)), (None, 'System.Object[]'))

    @opportunity
    def test_a_slot_swallowing_the_rest_of_a_longer_right_hand_side_holds_an_array(self):
        self.assertEqual(self._type_at(cleandoc("""
            $a, $q = 1, 2, 3
            $q.tostring()
        """)), 'System.Object[]')

    @opportunity
    def test_a_slot_with_an_element_opposite_it_is_typed_where_a_later_slot_has_none(self):
        for source in [
            cleandoc("""
                $q, $a = 1
                $q.tostring()
            """),
            cleandoc("""
                $q, $a, $b = 1, 2
                $q.tostring()
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Int32')

    def test_the_two_sides_are_read_through_the_parentheses_around_either_of_them(self):
        for source in [
            cleandoc("""
                ($q, $r) = 'abc', 1
                $q.substring(0, 1)
                $r.tostring()
            """),
            cleandoc("""
                $q, $r = ('abc', 1)
                $q.substring(0, 1)
                $r.tostring()
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source, name='q'), 'System.String')
                self.assertEqual(self._type_at(source, name='r'), 'System.Int32')

    def test_a_constrained_slot_carries_its_constraint_and_the_slot_beside_it_its_element(self):
        source = cleandoc("""
            [string]$q, $r = 5, 6
            $q.substring(0, 1)
            $r.tostring()
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.String')
        self.assertEqual(self._type_at(source, name='r'), 'System.Int32')

    def test_a_slot_and_a_plain_write_agreeing_type_a_read_neither_of_them_reaches(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = 5
            if ($c) {
              $q, $r = 5, 6
            }
            $q.tostring()
        """)), 'System.Int32')

    def test_a_slot_whose_element_is_an_array_carries_the_array_and_not_its_first_item(self):
        source = cleandoc("""
            $q, $r = (1, 2), 3
            $q.Length
            $r.tostring()
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.Object[]')
        self.assertEqual(self._type_at(source, name='r'), 'System.Int32')

    def test_a_right_hand_side_whose_elements_cannot_be_counted_types_no_slot(self):
        for source in [
            cleandoc("""
                $q, $r = $pair
                $q.tostring()
            """),
            cleandoc("""
                $q, $r = Get-Pair
                $q.tostring()
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_each_read_carries_the_slot_of_the_multi_assignment_it_observes(self):
        source = cleandoc("""
            $q, $r = 'abc', 1
            $q.substring(0, 1)
            $q, $r = 1, 'abc'
            $q.tostring()
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.String')
        self.assertEqual(self._type_at(source, read=1), 'System.Int32')

    def test_a_multi_assignment_write_is_bound_by_every_rule_a_plain_write_is(self):
        for source in [
            cleandoc("""
                function f {
                  $q, $r = 'abc', 'd'
                }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q, $r = 'abc', 'd'
                Invoke-Expression $code
                $q.substring(0, 1)
            """),
            cleandoc("""
                ($q | Get-Member)[0].Name
                $q, $r = 'abc', 'd'
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_read_below_a_caller_scope_block_carries_what_it_stored_over_a_slot_or_no_type(self):
        self.assertIn(self._type_at(cleandoc("""
            $q, $r = 'abc', 'd'
            . { $q = 5 }
            ($q | Get-Member)[0].Name
        """)), (None, 'System.Int32'))

    @opportunity
    def test_a_read_below_a_caller_scope_block_carries_what_it_stored_over_a_slot(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q, $r = 'abc', 'd'
            . { $q = 5 }
            ($q | Get-Member)[0].Name
        """)), 'System.Int32')


class TestPs1NeitherNewSpellingDecidesWhichWriteAReadObserves(TestPs1TypeAt):

    def test_a_read_at_the_top_of_a_loop_body_precedes_either_spelling_below_it(self):
        for source in [
            cleandoc("""
                while ($c) {
                  ($q | Get-Member)[0].Name
                  [string]$q = 5
                }
            """),
            cleandoc("""
                while ($c) {
                  ($q | Get-Member)[0].Name
                  $q, $r = 'abc', 'd'
                }
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_either_spelling_before_a_loop_types_the_read_at_the_top_of_its_body(self):
        for source in [
            cleandoc("""
                [string]$q = 5
                while ($c) {
                  $q.substring(0, 1)
                  [string]$q = 6
                }
            """),
            cleandoc("""
                $q, $r = 'abc', 'd'
                while ($c) {
                  $q.substring(0, 1)
                  $q, $r = 'e', 'f'
                }
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.String')


if __name__ == '__main__':
    import unittest
    unittest.main()
