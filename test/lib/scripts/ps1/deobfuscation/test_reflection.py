from __future__ import annotations

import unittest

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation.reflection import Ps1ReflectionReads


class TestPs1ReflectionReads(TestPs1):

    def test_a_reflection_property_read_folds_to_the_direct_member(self):
        self.assertEqual(
            self._apply(
                '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($Null)',
                Ps1ReflectionReads,
            ),
            '$x = [Text.Encoding]::UTF8',
        )

    def test_the_two_argument_spelling_folds_the_same_way(self):
        # Measured on 5.1: a non-indexed property accepts the two-argument `GetValue` and answers
        # the same instance the one-argument one does.
        self.assertEqual(
            self._apply(
                '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($Null, $Null)',
                Ps1ReflectionReads,
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

    def test_an_uncollected_type_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Zzqnope].GetProperty(\'UTF8\').GetValue($Null)', Ps1ReflectionReads)

    def test_a_target_other_than_null_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Text.Encoding].GetProperty(\'UTF8\').GetValue($x)', Ps1ReflectionReads)

    def test_a_member_the_type_does_not_carry_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Text.Encoding].GetProperty(\'Zzqnope\').GetValue($Null)', Ps1ReflectionReads)

    def test_an_instance_member_is_left_standing(self):
        self._assertUnchanged(
            '$x = [Diagnostics.Process].GetProperty(\'ProcessName\').GetValue($Null)',
            Ps1ReflectionReads)

    def test_a_member_outside_the_cannot_throw_table_is_left_standing(self):
        # `KeyAvailable` throws on a redirected stdin, and a getter that throws surfaces through
        # `GetValue` wrapped in a `MethodInvocationException` where the direct read throws as
        # itself — measured — so the member is not curated and the read stays as written.
        self._assertUnchanged(
            '$x = [Console].GetProperty(\'KeyAvailable\').GetValue($Null)', Ps1ReflectionReads)

    def test_a_field_read_is_left_standing(self):
        # `GetProperty` does not find a field: the read the script spells throws on 5.1, and the
        # direct member it would resolve to is a different program. No `GetField` arm exists until
        # a sample needs one.
        self._assertUnchanged(
            '$x = [Math].GetProperty(\'PI\').GetValue($Null)', Ps1ReflectionReads)

    def test_a_method_invocation_is_left_standing(self):
        self._assertUnchanged(
            "$x = [System.Convert].GetMethod('FromBase64String', [type[]]@([string]))"
            ".Invoke($Null, @('aGk='))", Ps1ReflectionReads)


if __name__ == '__main__':
    unittest.main()
