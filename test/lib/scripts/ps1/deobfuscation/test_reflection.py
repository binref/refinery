from __future__ import annotations

import unittest

from test import opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation.reflection import Ps1ReflectionMembers


class TestPs1ReflectionMembers(TestPs1):

    def test_a_reflection_property_read_folds_to_the_direct_member(self):
        self.assertEqual(
            self._apply(
                '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($Null)',
                Ps1ReflectionMembers,
            ),
            '$x = [Text.Encoding]::UTF8',
        )

    def test_the_two_argument_spelling_folds_the_same_way(self):
        self.assertEqual(
            self._apply(
                '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($Null, $Null)',
                Ps1ReflectionMembers,
            ),
            '$x = [Text.Encoding]::UTF8',
        )

    def test_a_read_through_the_whole_unit_folds_the_chain_it_feeds(self):
        self.assertEqual(
            self._deobfuscate(
                '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($Null)'
                '.GetString([Convert]::FromBase64String(\'aGk=\'))'),
            "$x = 'hi'",
        )

    def test_a_reflection_method_call_folds_to_the_direct_method(self):
        self.assertEqual(
            self._apply(
                "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, @('aGk='))",
                Ps1ReflectionMembers,
            ),
            "$x = [Convert]::FromBase64String('aGk=')",
        )

    def test_a_call_through_the_whole_unit_folds_and_evaluates(self):
        self.assertEqual(
            self._deobfuscate(
                "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, @('aGk='))"),
            '$x = @(0x68, 0x69)',
        )

    def test_a_zero_argument_call_folds_to_the_direct_method(self):
        self.assertEqual(
            self._apply(
                "$x = [Guid].GetMethod('NewGuid', [type[]]@()).Invoke($Null, @())",
                Ps1ReflectionMembers,
            ),
            '$x = [Guid]::NewGuid()',
        )

    def test_a_value_type_argument_folds_to_the_direct_method(self):
        self.assertEqual(
            self._apply(
                "$x = [BitConverter].GetMethod('GetBytes', [type[]]@([int32]))"
                ".Invoke($Null, @(65))",
                Ps1ReflectionMembers,
            ),
            "$x = [BitConverter]::GetBytes(65)",
        )

    def test_two_arguments_separated_by_a_semicolon_fold_to_the_direct_method(self):
        self.assertEqual(
            self._apply(
                "$x = [Math].GetMethod('Max', [type[]]@([int32], [int32]))"
                ".Invoke($Null, @(5; 7))",
                Ps1ReflectionMembers,
            ),
            '$x = [Math]::Max(5, 7)',
        )

    def test_an_argument_from_a_vouched_member_call_folds(self):
        self.assertEqual(
            self._apply(
                "$sb = New-Object Text.StringBuilder\n"
                "$x = $sb.ToString()\n"
                "$y = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, @($x))",
                Ps1ReflectionMembers,
            ),
            "$sb = New-Object Text.StringBuilder\n"
            "$x = $sb.ToString()\n"
            "$y = [Convert]::FromBase64String($x)",
        )

    def test_an_argument_from_a_constrained_write_folds(self):
        self.assertEqual(
            self._apply(
                "[string]$q = 5\n"
                "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, @($q))",
                Ps1ReflectionMembers,
            ),
            "[string]$q = 5\n"
            "$x = [Convert]::FromBase64String($q)",
        )

    def test_a_folded_call_with_a_variable_argument_is_not_junk(self):
        self.assertEqual(
            self._deobfuscate(
                "$sb = New-Object Text.StringBuilder\n"
                "$x = $sb.ToString()\n"
                "$u = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, @($x))"),
            "$sb = New-Object Text.StringBuilder\n"
            "$x = $sb.ToString()\n"
            "$u = [Convert]::FromBase64String($x)",
        )

    def test_an_uncollected_type_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Zzqnope].GetProperty(\'UTF8\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_target_other_than_null_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($x)', Ps1ReflectionMembers)

    def test_a_member_the_type_does_not_carry_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Text.Encoding].GetProperty(\'Zzqnope\').GetValue($Null)', Ps1ReflectionMembers)

    def test_an_instance_member_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Diagnostics.Process].GetProperty(\'ProcessName\').GetValue($Null)',
            Ps1ReflectionMembers)

    def test_a_member_outside_the_cannot_throw_table_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Console].GetProperty(\'KeyAvailable\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_property_spelled_in_another_case_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Text.Encoding].GetProperty(\'utf8\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_field_read_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Math].GetProperty(\'PI\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_method_spelled_in_another_case_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Convert].GetMethod('frombase64string', [type[]]@([string]))"
            ".Invoke($Null, @('aGk='))", Ps1ReflectionMembers)

    def test_a_name_only_getmethod_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Convert].GetMethod('FromBase64String')"
            ".Invoke($Null, @('aGk='))", Ps1ReflectionMembers)

    def test_an_overload_the_binder_could_reselect_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Console].GetMethod('Write', [type[]]@([object]))"
            ".Invoke($Null, @('x'))", Ps1ReflectionMembers)

    def test_a_void_method_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Console].GetMethod('Clear', [type[]]@()).Invoke($Null, @())",
            Ps1ReflectionMembers)

    def test_a_generic_method_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Array].GetMethod('Empty', [type[]]@()).Invoke($Null, @())",
            Ps1ReflectionMembers)

    def test_a_generic_method_with_a_concrete_signature_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Runtime.InteropServices.Marshal].GetMethod('OffsetOf', [type[]]@([string]))"
            ".Invoke($Null, @('x'))", Ps1ReflectionMembers)

    def test_a_null_literal_argument_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, @($Null))", Ps1ReflectionMembers)

    def test_a_discarded_write_to_null_does_not_vouch_the_null_argument(self):
        self._assertUnchanged(
            "$null = 'aGk='\n"
            "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, @($Null))", Ps1ReflectionMembers)

    def test_a_constrained_multi_assignment_slot_is_left_standing(self):
        self._assertUnchanged(
            "[string]$q = 'x'\n"
            "$q, $r = 5, 6\n"
            "$x = [BitConverter].GetMethod('GetBytes', [type[]]@([int32]))"
            ".Invoke($Null, @($q))", Ps1ReflectionMembers)

    def test_an_empty_decoding_folds_to_the_empty_array(self):
        self.assertEqual(
            self._deobfuscate(
                "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, @(''))"),
            '$x = @()',
        )

    def test_a_type_array_matching_an_instance_overload_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Text.StringBuilder].GetMethod('Append', [type[]]@([string]))"
            ".Invoke($Null, @('x'))", Ps1ReflectionMembers)

    def test_an_unvouched_member_call_argument_is_left_standing(self):
        self._assertUnchanged(
            "$x = 'abc'.ToUpper()\n"
            "$y = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, @($x))", Ps1ReflectionMembers)

    def test_a_chase_cycle_in_assigned_values_terminates_and_stands(self):
        self._assertUnchanged(
            "$a = $b\n"
            "$b = $a\n"
            "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, @($a))", Ps1ReflectionMembers)

    def test_an_array_literal_argument_is_left_standing(self):
        self._assertUnchanged(
            "$x = [IO.File].GetMethod('AppendAllText', [type[]]@([string], [string]))"
            ".Invoke($Null, @('a', 'b'))", Ps1ReflectionMembers)

    @opportunity
    def test_a_comma_list_without_the_array_wrapper_folds_like_the_wrapped_one(self):
        self.assertEqual(
            self._apply(
                "$x = [Math].GetMethod('Max', [type[]]@([int32], [int32]))"
                ".Invoke($Null, (5, 7))",
                Ps1ReflectionMembers,
            ),
            '$x = [Math]::Max(5, 7)',
        )

    def test_a_bare_comma_list_is_left_alone_or_folds_like_the_wrapped_one(self):
        source = "$x = [Math].GetMethod('Max', [type[]]@([int32], [int32])).Invoke($Null, (5, 7))"
        self.assertIn(self._apply(source, Ps1ReflectionMembers), (source, '$x = [Math]::Max(5, 7)'))

    @opportunity
    def test_a_scalar_argument_folds_like_a_one_element_array(self):
        self.assertEqual(
            self._apply(
                "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
                ".Invoke($Null, 'aGk=')",
                Ps1ReflectionMembers,
            ),
            "$x = [Convert]::FromBase64String('aGk=')",
        )

    def test_a_scalar_argument_is_left_alone_or_folds_like_a_one_element_array(self):
        source = (
            "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, 'aGk=')"
        )
        self.assertIn(
            self._apply(source, Ps1ReflectionMembers),
            (source, "$x = [Convert]::FromBase64String('aGk=')"),
        )


if __name__ == '__main__':
    unittest.main()
