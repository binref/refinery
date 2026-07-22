from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1DeadStoreElimination,
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

    def test_dead_multiassign_all_targets_removed(self):
        # Every target of `$a, $b, $c = 1, 2, 3` is unread, so the whole multi-assignment is dead.
        result = self._apply(
            "$a, $b, $c = 1, 2, 3\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_live_multiassign_cotarget_keeps_statement(self):
        # `$b` is read, so the multi-assignment survives even though its co-target `$a` is dead.
        result = self._apply(
            '$a, $b = 1, 2\nWrite-Output $b', Ps1UnusedVariableRemoval)
        self.assertEqual(result, '$a, $b = 1, 2\nWrite-Output $b')

    def test_pure_new_object_dead_store_removed(self):
        # `New-Object System.Object` has no side effect, so an unread store of it is removable.
        result = self._apply(
            "$x = New-Object System.Object\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_impure_new_object_store_kept(self):
        # `New-Object System.Net.WebClient` is not proven pure, so its RHS must be preserved.
        result = self._apply(
            "$x = New-Object System.Net.WebClient\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "New-Object System.Net.WebClient\nWrite-Host 'keep'")

    def test_null_discard_pure_removed(self):
        # `$null = <pure>` is PowerShell's discard idiom; with a side-effect-free RHS it is junk.
        result = self._apply(
            "$null = [Environment]::UserName\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_null_discard_side_effect_kept(self):
        # A `$null =` discard whose RHS is a command call has a side effect and must be preserved.
        result = self._apply(
            "$null = Remove-Item C:\\x\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "$null = Remove-Item C:\\x\nWrite-Host 'keep'")


class TestPs1InertFunctionRemoval(TestPs1):

    def test_inert_function_and_call_removed(self):
        result = self._apply(
            "function j { $Null = 915 }\nj\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_inert_function_multiple_calls_removed(self):
        result = self._apply(
            "function j { $Null = 915 }\nj\nj\nj\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_emitting_function_kept(self):
        result = self._apply(
            "function f { 42 }\nf\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertIn('function f', result)
        self.assertIn('42', result)

    def test_effectful_function_kept(self):
        result = self._apply(
            "function f { Write-Host 'real' }\nf", Ps1JunkStatementRemoval)
        self.assertIn('function f', result)
        self.assertIn('Write-Host', result)

    def test_dynamic_dispatch_preserves_all_functions(self):
        result = self._apply(
            "function j { $Null = 1 }\nj\n& $name\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertIn('function j', result)

    def test_function_with_argful_call_kept(self):
        result = self._apply(
            "function j { $Null = 1 }\nj 'arg'\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertIn('function j', result)

    def test_function_captured_result_kept(self):
        result = self._apply(
            "function j { $Null = 1 }\n$x = j\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertIn('function j', result)

    def test_param_block_function_module_preserved(self):
        result = self._apply(cleandoc("""
            function Ge {
              [CmdletBinding()]
              param (
                [parameter(ValueFromPipeline=$true)]
                $frk=$env:ComputerName
              )
              Write-Host $frk
            }
        """), Ps1JunkStatementRemoval)
        self.assertIn('function Ge', result)
        self.assertIn('Write-Host', result)


class TestPs1DiscardedObjectRemoval(TestPs1):

    def test_bare_hash_literal_removed(self):
        result = self._apply(
            "@{ a = 1; b = 2 }\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_pscustomobject_hash_removed(self):
        result = self._apply(
            "[pscustomobject]@{ Name = 'x'; Value = 42 }\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_synchronized_hashtable_removed(self):
        result = self._apply(
            "[Collections.Hashtable]::Synchronized(@{})\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_void_foreach_pipeline_removed(self):
        result = self._apply(
            "(1, 2, 3) | ForEach-Object { [Void]$_ }\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_null_assign_foreach_pipeline_removed(self):
        result = self._apply(
            "(1, 2, 3) | ForEach-Object { $Null = $_ }\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_hash_with_impure_value_kept(self):
        result = self._apply(
            "@{ x = (Start-Process notepad) }", Ps1JunkStatementRemoval)
        self.assertIn('Start-Process', result)

    def test_emitting_foreach_kept(self):
        result = self._apply(
            "(1, 2, 3) | ForEach-Object { $_ }", Ps1JunkStatementRemoval)
        self.assertIn('ForEach-Object', result)

    def test_null_assign_foreach_side_effect_kept(self):
        result = self._apply(
            "(1, 2, 3) | ForEach-Object { $Null = Remove-Item $_ }",
            Ps1JunkStatementRemoval)
        self.assertIn('Remove-Item', result)


class TestPs1DeadStoreElimination(TestPs1):

    def test_overwritten_store_removed(self):
        result = self._apply("$x = 1\n$x = 2\nWrite-Host $x", Ps1DeadStoreElimination)
        self.assertEqual(result, '$x = 2\nWrite-Host $x')

    def test_chain_all_but_last_removed(self):
        result = self._apply("$x = 1\n$x = 2\n$x = 3\nWrite-Host $x", Ps1DeadStoreElimination)
        self.assertEqual(result, '$x = 3\nWrite-Host $x')

    def test_dead_store_before_for_removed(self):
        result = self._apply(
            "$i = 33\nfor ($i = 0; $i -LT 5; $i++) { Write-Host $i }",
            Ps1DeadStoreElimination)
        self.assertNotIn('$i = 33', result)
        self.assertIn('for', result)

    def test_multiple_dead_stores_before_for_removed(self):
        result = self._apply(
            "$i = 33\n$i = 44\n$i = 55\nfor ($i = 0; $i -LT 5; $i++) { Write-Host $i }",
            Ps1DeadStoreElimination)
        self.assertNotIn('$i = 33', result)
        self.assertNotIn('$i = 44', result)
        self.assertNotIn('$i = 55', result)
        self.assertIn('for', result)

    def test_intervening_read_keeps_store(self):
        result = self._apply(
            "$x = 1\nWrite-Host $x\n$x = 2\nWrite-Host $x", Ps1DeadStoreElimination)
        self.assertIn('$x = 1', result)
        self.assertIn('$x = 2', result)

    def test_impure_rhs_preserved_as_standalone(self):
        result = self._apply(
            "$x = Remove-Item foo\n$x = 5\nWrite-Host $x", Ps1DeadStoreElimination)
        self.assertIn('Remove-Item', result)
        self.assertNotIn('$x = Remove-Item', result)
        self.assertIn('$x = 5', result)

    def test_different_variables_independent(self):
        result = self._apply(
            "$x = 1\n$y = 2\n$x = 3\nWrite-Host $x $y", Ps1DeadStoreElimination)
        self.assertNotIn('$x = 1', result)
        self.assertIn('$y = 2', result)
        self.assertIn('$x = 3', result)

    def test_scoped_variable_not_killed(self):
        result = self._apply(
            "$script:x = 1\n$script:x = 2\nWrite-Host $script:x", Ps1DeadStoreElimination)
        self.assertIn('$script:x = 1', result)

    def test_control_flow_flushes_pending(self):
        result = self._apply(
            "$x = 1\nif ($c) { Write-Host $x }\n$x = 2\nWrite-Host $x",
            Ps1DeadStoreElimination)
        self.assertIn('$x = 1', result)
        self.assertIn('$x = 2', result)

    def test_dead_store_inside_nested_function_removed(self):
        result = self._apply(
            'function f { $i = 5\n$i = 3\nWrite-Host $i }',
            Ps1DeadStoreElimination)
        self.assertNotIn('$i = 5', result)
        self.assertIn('$i = 3', result)

    def test_dead_store_scriptblock_local_does_not_flush_outer(self):
        result = self._apply(cleandoc(
            """
            $inner = 1
            $cb = {
              $inner = 99
            }
            $inner = 2
            Write-Host $inner
            """
        ), Ps1DeadStoreElimination)
        self.assertNotIn('$inner = 1', result)
        self.assertIn('$inner = 2', result)
        self.assertIn('$cb', result)
