from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1ExpandableStringHoist


class TestPs1ExpandableStringFolding(TestPs1):

    def test_expandable_constant_subexpr(self):
        result = self._deobfuscate("\"\"\"$('hello')\"\"\"")
        self.assertIn('"hello"', result)
        self.assertNotIn('$(', result)

    def test_expandable_pipeline_chain(self):
        result = self._deobfuscate_iterative(
            "\"\"\"$($((312,348,348)|%{[char]($_/3)})-join'')\"\"\"")
        self.assertIn('"htt"', result)
        self.assertNotIn('$(', result)

    def test_expandable_variable_not_folded(self):
        result = self._deobfuscate("\"\"\"$($x)\"\"\"", remove_junk=False)
        self.assertIn('$(', result)

    def test_expandable_full_chain_with_iex(self):
        result = self._deobfuscate_iterative(
            "$(\"\"\"$($((312,348,348)|%{[char]($_/3)})-join'')\"\"\")"
            " | Invoke-Expression")
        self.assertIn('htt', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('$(', result)


class TestPs1ExpandableExtra(TestPs1):

    def test_variable_string_concat_becomes_expandable(self):
        result = self._deobfuscate("$env:temp + '\\foo.exe'")
        self.assertIn('"${env:Temp}\\foo.exe"', result)

    def test_expandable_string_value_subexpr_kept(self):
        result = self._deobfuscate('''"prefix$( 1 + 2 )suffix"''', remove_junk=False)
        self.assertIn('prefix$(', result)

    def test_expandable_command_subexpr_not_dropped(self):
        # A command inside an interpolating string contributes its output, so the hoist leaves it.
        result = self._apply(
            '$result = "Value: $(Write-Output 42)"', Ps1ExpandableStringHoist)
        self.assertEqual(result, '$result = "Value: $(Write-Output 42)"')

    def test_expandable_hoist_preserves_assignment_order(self):
        # Void subexpressions hoisted out of expandable strings must keep source execution order;
        # reversing them would make `$b` read `$a` before it is assigned.
        result = self._apply(
            '$z = 1 + "$($a = 1)" + "$($b = $a)"', Ps1ExpandableStringHoist)
        self.assertLess(result.index('$a = 1'), result.index('$b = $a'))
