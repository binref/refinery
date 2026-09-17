from __future__ import annotations

import unittest

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
        # Measured on 5.1: a non-indexed property accepts the two-argument `GetValue` and answers
        # the same instance the one-argument one does.
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
            "$x = @(0x68, 0x69)",
        )

    def test_a_zero_argument_call_folds_to_the_direct_method(self):
        self.assertEqual(
            self._apply(
                "$x = [Guid].GetMethod('NewGuid', [type[]]@()).Invoke($Null, @())",
                Ps1ReflectionMembers,
            ),
            "$x = [Guid]::NewGuid()",
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
            "$x = [Math]::Max(5, 7)",
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
        # Measured on 5.1: `[string]$q = 5` stores the String `5`, so the argument is judged a
        # String rather than the Int32 that was written.
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
        # A literal argument makes the folded statement pure, and the cleanup passes evaluate it
        # away; a variable argument is a read the script decides, so the statement stays.
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
        # `KeyAvailable` throws on a redirected stdin, and a getter that throws surfaces through
        # `GetValue` wrapped in a `MethodInvocationException` where the direct read throws as
        # itself — measured — so the member is not curated and the read stays as written.
        self._assertUnchanged(
            '$x = [Console].GetProperty(\'KeyAvailable\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_property_spelled_in_another_case_is_left_standing(self):
        # `Type.GetProperty(String)` is case-sensitive, so `GetProperty('utf8')` finds nothing on
        # 5.1 and `GetValue($Null)` throws, where the case-insensitive member `[T]::utf8` is a
        # value: rewriting the throw to the value is a different program.
        self._assertUnchanged(
            '$x = [Text.Encoding].GetProperty(\'utf8\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_field_read_is_left_standing(self):
        # `GetProperty` does not find a field: the read the script spells throws on 5.1, and the
        # direct member it would resolve to is a different program. No `GetField` arm exists until
        # a sample needs one.
        self._assertUnchanged(
            '$x = [Math].GetProperty(\'PI\').GetValue($Null)', Ps1ReflectionMembers)

    def test_a_method_spelled_in_another_case_is_left_standing(self):
        # `Type.GetMethod(String, Type[])` is case-sensitive, so `GetMethod('frombase64string')`
        # finds nothing on 5.1 and `Invoke` throws, where the case-insensitive member
        # `[Convert]::FromBase64String` is a call: rewriting the throw to the call is a different
        # program.
        self._assertUnchanged(
            "$x = [Convert].GetMethod('frombase64string', [type[]]@([string]))"
            ".Invoke($Null, @('aGk='))", Ps1ReflectionMembers)

    def test_a_name_only_getmethod_is_left_standing(self):
        # Measured on 5.1: `GetMethod(String)` on an overloaded name throws
        # `AmbiguousMatchException` before any `Invoke` happens, so the spelling selects nothing
        # this could re-spell.
        self._assertUnchanged(
            "$x = [Convert].GetMethod('FromBase64String')"
            ".Invoke($Null, @('aGk='))", Ps1ReflectionMembers)

    def test_an_overload_the_binder_could_reselect_is_left_standing(self):
        # Measured on 5.1: a type array of `@([object])` selects `Write(Object)`, and a String
        # argument re-binds the direct call to `Write(String)` — the binder selects again, and a
        # different overload is a different program.
        self._assertUnchanged(
            "$x = [Console].GetMethod('Write', [type[]]@([object]))"
            ".Invoke($Null, @('x'))", Ps1ReflectionMembers)

    def test_a_void_method_is_left_standing(self):
        # Measured on 5.1: a void method called directly emits no pipeline item where `Invoke`
        # emits one `$null`, so the two spellings differ by an output.
        self._assertUnchanged(
            "$x = [IO.File].GetMethod('AppendAllText', [type[]]@([string], [string]))"
            ".Invoke($Null, @('a', 'b'))", Ps1ReflectionMembers)

    def test_a_generic_method_is_left_standing(self):
        # Measured on 5.1: `Invoke` on a generic method definition throws
        # `InvalidOperationException` where the direct spelling throws a bare `MethodException`.
        # `Array.Empty`'s return spelling names nothing this resolves, so the genericity is seen
        # from the signature.
        self._assertUnchanged(
            "$x = [Array].GetMethod('Empty', [type[]]@()).Invoke($Null, @())",
            Ps1ReflectionMembers)

    def test_a_generic_method_with_a_concrete_signature_is_left_standing(self):
        # Measured on 5.1: `Marshal.OffsetOf` is generic although every type in its signature is
        # concrete, so no spelling guard can see it and the curated deny-table is what refuses it.
        self._assertUnchanged(
            "$x = [Runtime.InteropServices.Marshal].GetMethod('OffsetOf', [type[]]@([string]))"
            ".Invoke($Null, @('x'))", Ps1ReflectionMembers)

    def test_a_null_literal_argument_is_left_standing(self):
        # Measured on 5.1: `Invoke` hands the method raw null where the direct call converts it
        # (`[Convert]::FromBase64String($Null)` reads the empty string), so a `$null` argument is
        # a different program.
        self._assertUnchanged(
            "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, @($Null))", Ps1ReflectionMembers)

    def test_a_type_array_matching_an_instance_overload_is_left_standing(self):
        # Measured on 5.1: `Type.GetMethod(String, Type[])` finds instance methods as well as
        # static ones, and `Invoke` ignores its target for a static — but the direct spelling of
        # an instance method on a type literal is a call 5.1 cannot make.
        self._assertUnchanged(
            "$x = [Text.StringBuilder].GetMethod('Append', [type[]]@([string]))"
            ".Invoke($Null, @('x'))", Ps1ReflectionMembers)

    def test_an_unvouched_member_call_argument_is_left_standing(self):
        # `String.ToUpper` is not in the curated non-null table, so the judgment refuses.
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

    def test_a_comma_list_without_the_array_wrapper_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Math].GetMethod('Max', [type[]]@([int32], [int32]))"
            ".Invoke($Null, (5, 7))", Ps1ReflectionMembers)

    def test_a_scalar_argument_is_left_standing(self):
        self._assertUnchanged(
            "$x = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, 'aGk=')", Ps1ReflectionMembers)


if __name__ == '__main__':
    unittest.main()
