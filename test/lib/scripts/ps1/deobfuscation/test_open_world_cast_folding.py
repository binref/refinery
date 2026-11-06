from __future__ import annotations

from test import opportunity, wontfix
from test.lib.scripts.ps1.corpus import (
    CAST_AFTER_A_REPOINTED_ACCELERATOR,
    CAST_OF_A_CONSTANT_AFTER_A_PLANTED_CONVERTER,
    CAST_OF_A_VALUE_AFTER_A_PLANTED_CONVERTER,
    CAST_TO_AN_ACCELERATOR_A_PAYLOAD_ADDED,
)
from test.lib.scripts.ps1.deobfuscation import TestPs1
from test.lib.scripts.ps1.test_oracle import CLAIM_TRANSCRIPTS

from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.effects import is_side_effect_free
from refinery.lib.scripts.ps1.model import Ps1AssignmentExpression, Ps1ExpressionStatement
from refinery.lib.scripts.ps1.parser import Ps1Parser

_LEAK = 'Invoke-Expression $payload'

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"


class TestPs1ACastToABuiltInTypeBelowCodeNobodyCanRead(TestPs1):

    @staticmethod
    def _runs_no_code(source: str) -> bool:
        tree = Ps1Parser(source).parse()
        statement = tree.body[-1]
        assert isinstance(statement, Ps1ExpressionStatement)
        assert isinstance(statement.expression, Ps1AssignmentExpression)
        return is_side_effect_free(statement.expression.value, Ps1ModelCache(tree).world_reach)

    def test_a_payload_changes_a_cast_of_a_value_but_not_of_a_constant_to_a_built_in_type(self):
        self.assertEqual(CLAIM_TRANSCRIPTS[CAST_AFTER_A_REPOINTED_ACCELERATOR], ('INFO\t50',))
        self.assertEqual(CLAIM_TRANSCRIPTS[CAST_TO_AN_ACCELERATOR_A_PAYLOAD_ADDED], ('INFO\t455',))
        self.assertEqual(
            CLAIM_TRANSCRIPTS[CAST_OF_A_CONSTANT_AFTER_A_PLANTED_CONVERTER], ('INFO\t50',)
        )
        self.assertEqual(
            CLAIM_TRANSCRIPTS[CAST_OF_A_VALUE_AFTER_A_PLANTED_CONVERTER][0],
            'ERROR\tnullToObjectInvalidCast\tSystem.Management.Automation.RuntimeException',
        )

    @opportunity
    def test_a_cast_of_a_constant_after_a_leak_runs_no_code(self):
        self.assertTrue(self._runs_no_code(F'{_LEAK}\n$Null = [Int]"45" + 5'))

    def test_a_cast_of_a_value_after_a_leak_may_run_code(self):
        self.assertFalse(self._runs_no_code(F'{_LEAK}\n$Null = [Int]$env:X + 5'))

    def test_a_cast_after_a_leak_may_be_folded(self):
        self.assertEqual(
            self._deobfuscate(F'{_LEAK}\n$q = [Int]"45" + 5\nWrite-Host $q'),
            F'{_LEAK}\n$q = 50\nWrite-Host 50',
        )

    def test_a_discarded_cast_after_a_leak_is_removed(self):
        self.assertEqual(
            self._deobfuscate(F'{_LEAK}\n$Null = [Int]"45" + 5\n{_ANCHOR}'),
            F'{_LEAK}\n{_ANCHOR}',
        )


class TestPs1TheWorldGateHoldsForEverythingButTheCast(TestPs1):

    def test_a_static_call_after_a_leak_is_kept(self):
        source = F'{_LEAK}\n$Null = [Math]::Sqrt(36)\n{_ANCHOR}'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_parsing_cast_after_a_leak_is_kept(self):
        source = F'{_LEAK}\n$q = [Xml]"<r/>"\nWrite-Host $q'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_cast_with_no_leak_anywhere_is_folded(self):
        self.assertEqual(
            self._deobfuscate(F'$q = [Int]"45" + 5\nWrite-Host $q'),
            'Write-Host 50')

_RETYPE = (
    "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty"
    " -Value { Write-Host 'S' }")

_REPOINT_LENGTH = (
    "Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty"
    " -Value { 99 }")


class TestPs1AMemberReadOnALiteralIsNotAskedAboutTheWorld(TestPs1):

    def test_a_discarded_read_of_a_re_pointed_member_is_kept(self):
        source = F"{_RETYPE}\n$Null = 'abc'.Zq\n{_ANCHOR}"
        self._assertKept(source)

    @wontfix(
        'no obfuscator or script overrides the Length property of System.String through '
        'Update-TypeData'
    )
    def test_a_read_of_a_re_pointed_member_is_not_folded(self):
        source = F"{_REPOINT_LENGTH}\nWrite-Host 'abc'.Length"
        self._assertKept(source)

    def test_a_discarded_read_with_no_mutation_anywhere_is_removed(self):
        self._assertDeobfuscatesTo(F"$Null = 'abc'.Length\n{_ANCHOR}", _ANCHOR)

    def test_a_read_with_no_mutation_anywhere_is_folded(self):
        self._assertDeobfuscatesTo("Write-Host 'abc'.Length", 'Write-Host 3')
