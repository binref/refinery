from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1


class TestPs1AliasInlining(TestPs1):

    def test_user_function_not_aliased(self):
        data = (
            "Function R ([String]$s){"
            "$r = '';"
            "ForEach($c in $s.ToCharArray()){$r = $c + $r};"
            "$r;}"
            "$x = R 'olleH'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertNotIn('Invoke-History', result)

    def test_user_function_not_case_normalized_to_alias(self):
        result = self._deobfuscate("Function gc { 'test' }\ngc")
        self.assertNotIn('Get-Content', result)

    def test_digit_starting_alias_inlined(self):
        data = "Set-Alias 1abc Invoke-Expression\n1abc 'Write-Host hello'"
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('1abc', result.split('\n')[-1])

    def test_obfuscated_alias_target_resolved_after_folding(self):
        data = (
            "Set-Alias myalias $([char]73+[char]69+[char]88)\n"
            "myalias 'Write-Host hi'"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('myalias', result.split('\n')[-1])

    def test_self_alias_terminates(self):
        # A self-resolving alias must reach a fixpoint (no infinite mark_changed loop) and leave
        # the script unchanged.
        result = self._deobfuscate(cleandoc("""
            Set-Alias foo foo
            foo bar
        """))
        self.assertEqual(result, cleandoc("""
            Set-Alias foo foo
            foo bar
        """))
