from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1JunkStatementRemoval,
    Ps1UnusedVariableRemoval,
)


class TestPs1UnusedVariableRemoval(TestPs1):

    def test_unused_constant_assignment_removed(self):
        result = self._deobfuscate("$x = 'hello'; Write-Host done")
        self.assertNotIn('$x', result)
        self.assertNotIn('hello', result)
        self.assertIn('done', result)

    def test_multiple_unused_removed(self):
        result = self._deobfuscate("$a = 1; $b = 2; Write-Host done")
        self.assertNotIn('$a', result)
        self.assertNotIn('$b', result)
        self.assertIn('done', result)

    def test_used_variable_kept(self):
        result = self._deobfuscate("$x = 'hello'; Write-Host $x")
        self.assertIn('hello', result)

    def test_side_effect_rhs_preserved(self):
        result = self._deobfuscate("$x = Start-Process notepad; Write-Host done")
        self.assertNotIn('$x', result)
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_increment_removed(self):
        result = self._deobfuscate("$x = 0; $x++; Write-Host done")
        self.assertNotIn('$x', result)
        self.assertIn('done', result)

    def test_foreach_variable_preserved(self):
        result = self._deobfuscate(
            "foreach ($item in @(1,2,3)) { Write-Host 'hi' }")
        self.assertIn('foreach', result.lower())

    def test_scoped_variable_preserved(self):
        result = self._deobfuscate("$script:x = 42; Write-Host done")
        self.assertIn('$script:x', result)

    def test_parameter_preserved(self):
        result = self._deobfuscate(
            "function Test { Param($x); Write-Host done }; Test")
        self.assertIn('$x', result)

    def test_compound_assignment_removed(self):
        result = self._deobfuscate("$x = 0; $x += 1; Write-Host done")
        self.assertNotIn('$x', result)
        self.assertIn('done', result)

    def test_self_referential_folded(self):
        result = self._deobfuscate("$x = 0; $x = $x + 1; Write-Host $x")
        self.assertNotIn('$x', result)
        self.assertIn('1', result)


class TestPs1JunkStatementRemoval(TestPs1):

    def test_void_cast_removed(self):
        result = self._deobfuscate('[Void]([Math]::Sqrt(144)); Write-Host done')
        self.assertNotIn('Sqrt', result)
        self.assertIn('done', result)

    def test_out_null_pipeline_removed(self):
        result = self._deobfuscate('[Math]::Pow(2, 8) | Out-Null; Write-Host done')
        self.assertNotIn('Pow', result)
        self.assertIn('done', result)

    def test_pure_static_method_removed(self):
        result = self._deobfuscate('[Math]::Sqrt(36); Write-Host done')
        self.assertNotIn('Sqrt', result)
        self.assertIn('done', result)

    def test_pure_cmdlet_removed(self):
        result = self._deobfuscate('Get-Random -Minimum 1 -Maximum 100; Write-Host done')
        self.assertNotIn('Get-Random', result)
        self.assertIn('done', result)

    def test_pure_instance_method_removed(self):
        result = self._deobfuscate('(Get-Date).ToString("yyyy"); Write-Host done')
        self.assertNotIn('ToString', result)
        self.assertIn('done', result)

    def test_side_effect_command_preserved(self):
        result = self._deobfuscate('Start-Sleep -s 1; Write-Host done')
        self.assertIn('Start-Sleep', result)
        self.assertIn('done', result)

    def test_uncalled_function_removed(self):
        result = self._deobfuscate(
            'function Junk { Get-Random }; Write-Host done')
        self.assertNotIn('Junk', result)
        self.assertIn('done', result)

    def test_called_function_preserved(self):
        result = self._deobfuscate(
            'function Helper { Get-Random }; Helper; Write-Host done')
        self.assertIn('Helper', result)

    def test_expandable_string_removed(self):
        result = self._deobfuscate('"noise ${x} text"; Write-Host done')
        self.assertNotIn('noise', result)
        self.assertIn('done', result)

    def test_string_literal_removed(self):
        result = self._deobfuscate("'junk string'; Write-Host done")
        self.assertNotIn('junk', result)
        self.assertIn('done', result)

    def test_pure_pipeline_removed(self):
        result = self._deobfuscate(
            'Get-Date | Out-String; Write-Host done')
        self.assertNotIn('Get-Date', result)
        self.assertIn('done', result)

    def test_empty_body_guard(self):
        result = self._deobfuscate('[Math]::Sqrt(36)')
        self.assertIn('Sqrt', result)

    def test_nested_body_junk_removed(self):
        result = self._deobfuscate(
            'while ($True) { [Void]"noise"; Write-Host running; break }')
        self.assertNotIn('noise', result)
        self.assertIn('running', result)

    def test_subexpression_body_preserved(self):
        result = self._deobfuscate("$x = $($a.Name + '.' + $a.Extension)")
        self.assertIn('.Name', result)
        self.assertIn('.Extension', result)

    def test_scriptblock_body_preserved(self):
        result = self._deobfuscate('1,2,3 | ForEach-Object { $_.ToString() }')
        self.assertIn('.ToString()', result)

    def test_transitive_function_calls_preserved(self):
        result = self._deobfuscate(
            'function Inner { Get-Date }\n'
            'function Outer { Inner }\n'
            'Outer\n'
        )
        self.assertIn('Inner', result)
        self.assertIn('Get-Date', result)


class TestPs1UnusedExtra(TestPs1):

    def test_junk_removal_keeps_indirectly_called_function(self):
        # A function reachable only through the call operator on a variable (`& $f`) must survive,
        # because the dynamic target cannot be proven different from it.
        result = self._apply(
            "function Invoke-Payload { Write-Host 'x' }\n& $f", Ps1JunkStatementRemoval)
        self.assertIn('Invoke-Payload', result)

    def test_junk_removal_keeps_collection_mutation(self):
        # `.Remove` mutates a collection in place, so a discarded `$list.Remove(...)` is not junk.
        result = self._apply(
            "$list = [System.Collections.ArrayList]@(1, 2, 3)\n$list.Remove(2)",
            Ps1JunkStatementRemoval)
        self.assertIn('.Remove(2)', result)

    def test_unused_variable_read_in_function_is_kept(self):
        # The read inside Run keeps the assignment alive (PowerShell dynamic scoping).
        result = self._apply(
            "$x = 'payload'; function Run { iex $x }; Run", Ps1UnusedVariableRemoval)
        self.assertEqual(result, cleandoc("""
            $x = 'payload'
            function Run {
              iex $x
            }
            Run
        """))

    def test_unused_variable_scoped_read_is_kept(self):
        # The $script:x read keeps the $x assignment alive.
        result = self._apply(
            "$x = 'keepme'; function f { Write-Host $script:x }; f", Ps1UnusedVariableRemoval)
        self.assertEqual(result, cleandoc("""
            $x = 'keepme'
            function f {
              Write-Host $script:x
            }
            f
        """))
