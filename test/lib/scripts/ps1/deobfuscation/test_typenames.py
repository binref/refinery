from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1


class TestPs1TypeSystemSimplifications(TestPs1):

    def test_get_member_index_name_resolved(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[6].Name')
        self.assertIn('InvokeCommand', result)
        self.assertNotIn('[6]', result)

    def test_get_member_index_unknown_type_preserved(self):
        result = self._deobfuscate('($unknown | Get-Member)[6].Name')
        self.assertIn('[6].Name', result)

    def test_get_member_index_out_of_range_preserved(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[999].Name')
        self.assertIn('[999].Name', result)

    def test_name_on_string_literal_stripped(self):
        result = self._deobfuscate("$x.('GetCmdlets'.Name)('*w-*ct')")
        self.assertNotIn('.Name', result)
        self.assertIn('New-Object', result)
