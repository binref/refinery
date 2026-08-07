from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis.model import build_semantic_model
from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1DeadStoreElimination,
    Ps1JunkStatementRemoval,
    Ps1UnusedVariableRemoval,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


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

    def test_a_script_reduced_to_this_passs_own_discards_is_left_alone(self):
        # Every store here is dead and every value acts, so the batch would leave a script of
        # nothing but `$Null = ...` husks. Those are this pass's own residue and not evidence the
        # script still says something, so the batch is abandoned and the stores stand as written.
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

    def test_a_store_a_callee_writes_through_a_reference_is_kept(self):
        """
        Nothing in the script reads `$n`, and `[Int]::TryParse` assigns it through the reference —
        so the assignment is the storage the call writes into, and removing it removes the write.

        Asserted as exact output: `assertIn('$n', ...)` is satisfied by the `[ref]$n` of the
        surviving call while the assignment it stores into has already been deleted.
        """
        self._assertUnchanged(
            "$n = 0\n[void][int]::TryParse('7', [ref]$n)\nWrite-Host done",
            Ps1UnusedVariableRemoval)

    def test_a_reference_is_not_a_mutation_this_pass_can_remove(self):
        """
        The store happens inside the callee, so there is no assignment here to delete — which is
        also what makes the reference a use that nothing discounts. `_removable_mutations` yielding
        one would offer the enclosing call up for removal.
        """
        model = build_semantic_model(
            Ps1Parser("$n = 0\n[void][int]::TryParse('7', [ref]$n)").parse())
        binding = model.script_scope.bindings['n']
        references = [
            write for write in binding.writes
            if Ps1UnusedVariableRemoval._mutation_of(write.node) is None
        ]
        self.assertEqual(len(references), 1)
        self.assertEqual(len(Ps1UnusedVariableRemoval._removable_mutations(binding)), 1)


class TestPs1JunkStatementRemoval(TestPs1):

    def test_void_cast_removed(self):
        result = self._deobfuscate('[Void]([Math]::Sqrt(144)); Write-Host done')
        self.assertNotIn('Sqrt', result)
        self.assertIn('done', result)

    def test_void_cast_around_a_call_preserved(self):
        # A `[Void]` wrapper discards the value of the call, not the call. Treating the cast alone
        # as a discard deleted the payload out of a script whose whole point is to reveal it.
        result = self._deobfuscate('[Void](Start-Process notepad); Write-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_void_cast_around_a_call_preserved_inside_a_function(self):
        result = self._deobfuscate(
            'function f { Write-Host hi; [Void](Remove-Item C:\\important) }\nf')
        self.assertIn('Remove-Item', result)

    def test_an_advanced_function_is_not_junk(self):
        # A `process` block is a body like any other; reading the empty unnamed body as an inert
        # function deleted the definition and every call to it.
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
        # `-MemberName Kill` runs on every input item whatever the block beside it does with `$_`,
        # so a visible discard may not vouch for it.
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
        # The member name is a string whichever way it is quoted, and a table of literal forms that
        # names only the single-quoted one hands the here-string spelling back to the junk pass.
        for source in (
            "Get-ChildItem C:\\ | ForEach-Object { $Null = $_ } -MemberName @'\nDelete\n'@",
            "Get-Process | ForEach-Object { [Void]$_ } @'\nKill\n'@",
        ):
            with self.subTest(source):
                self.assertIn('ForEach-Object', self._deobfuscate(F'{source}\nWrite-Host done'))

    def test_a_foreach_body_hidden_in_a_named_or_param_block_is_kept(self):
        # The parser fills either `body` or the named blocks, so a block that carries its work in
        # `end { ... }` or in a parameter default reports an empty statement list. Reading that as
        # "this body discards everything" deleted the recursive removal along with the statement.
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
        # A bare parameter declaration evaluates nothing, so the pruned body is still inert.
        result = self._deobfuscate('function j($x) { $Null = 915 }\nj\nWrite-Host done')
        self.assertNotIn('function', result)
        self.assertIn('done', result)

    def test_a_foreach_block_held_in_a_variable_is_kept(self):
        # `-End $sb` runs whatever scriptblock the variable holds; nothing in the source says what,
        # so the discarding process block proves nothing about the statement as a whole.
        for source in (
            'Param($sb)\n1..3 | ForEach-Object -Process { [Void]$_ } -End $sb\nWrite-Host done',
            '1..3 | ForEach-Object { [Void]$_ } $Global:sb\nWrite-Host done',
        ):
            with self.subTest(source):
                self.assertIn('ForEach-Object', self._deobfuscate(source))

    def test_a_parameter_default_that_runs_a_command_keeps_the_function(self):
        # The default is evaluated on every call that omits the argument, so neither the definition
        # nor the call site is a no-op.
        result = self._deobfuscate(
            'function f { param($x = (Start-Process notepad)) }\nf\nWrite-Host done')
        self.assertIn('Start-Process', result)
        self.assertIn('done', result)

    def test_a_splatted_argument_keeps_the_command(self):
        # `@options` supplies parameters that are nowhere in the source, `-OutVariable` among them.
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
        # The statement is what fills `$n`; deleting it leaves the read below with nothing.
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
        # `-OutVariable d` is what sets `$d`. The parsed parameter name keeps its leading dash and
        # PowerShell binds abbreviations, so a name table consulted by exact match matches nothing.
        for source, marker in (
            ('Get-Date -OutVariable d\nWrite-Host $d', 'OutVariable'),
            ('Get-Date -OutVar d\nWrite-Host $d', 'OutVar'),
            ('Get-Date -ov d\nWrite-Host $d', '-ov'),
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

    def test_a_pure_statement_that_writes_to_the_output_stream_is_kept(self):
        # Purity is not silence. Each of these was deleted for being side-effect free, and each one
        # prints on PowerShell 5.1 — `6`, a number in 1..100, `2026`, the formatted date.
        for source, marker in (
            ('[Math]::Sqrt(36); Write-Host done'               , 'Sqrt'),        # noqa
            ('Get-Random -Minimum 1 -Maximum 100; Write-Host done', 'Get-Random'),  # noqa
            ('(Get-Date).ToString("yyyy"); Write-Host done'    , 'ToString'),    # noqa
            ('Get-Date | Out-String; Write-Host done'          , 'Get-Date'),    # noqa
        ):
            with self.subTest(source):
                result = self._deobfuscate(source)
                self.assertIn(marker, result)
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

    def test_an_expandable_string_is_kept_however_much_it_looks_like_noise(self):
        # `"noise ${x} text"` prints `noise  text`, and what the text says is not a question this
        # pipeline asks. It is kept for the reason a plain `'junk string'` is not: expanding one
        # runs whatever the parts hold, so it can raise, and nothing here can rule that out.
        result = self._deobfuscate('"noise ${x} text"; Write-Host done')
        self.assertIn('noise', result)
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
        # `New-Object System.Net.WebClient` is not proven pure, so its RHS must be preserved — as a
        # discard, not as a bare statement. The construction returns the client, which the dead
        # store swallowed and a bare expression would write to the output stream instead.
        result = self._apply(
            "$x = New-Object System.Net.WebClient\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
        self.assertEqual(result, "$Null = New-Object System.Net.WebClient\nWrite-Host 'keep'")

    def test_dropping_a_dead_store_does_not_start_emitting_its_value(self):
        # A bare expression statement writes its value to the output stream; the assignment being
        # removed swallowed it. Rewriting the store to the value alone therefore made the
        # deobfuscated script print what the sample never printed, and inside a function body it
        # changed the return value — a deobfuscator has to preserve what the script does.
        for source in (
            "$unused = [Loader]'payload'",
            '$unused = New-Object System.Net.WebClient',
        ):
            with self.subTest(source):
                result = self._apply(
                    F"{source}\nWrite-Host 'keep'", Ps1UnusedVariableRemoval)
                self.assertTrue(result.startswith('$Null = '), result)

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
            "function f { Get-Random }\nf\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "function f {\n  Get-Random\n}\nf\nWrite-Host 'keep'")

    def test_effectful_function_kept(self):
        result = self._apply(
            "function f { Write-Host 'real' }\nf", Ps1JunkStatementRemoval)
        self.assertEqual(result, "function f {\n  Write-Host 'real'\n}\nf")

    def test_dynamic_dispatch_preserves_all_functions(self):
        result = self._apply(
            "function j { $Null = 1 }\nj\n& $name\nWrite-Host 'keep'",
            Ps1JunkStatementRemoval)
        self.assertEqual(result, "function j {}\nj\n& $name\nWrite-Host 'keep'")

    def test_a_call_to_an_inert_function_that_opens_a_file_is_kept(self):
        # Regression: an inert function's call sites were found by shape alone, so `j > out.txt`
        # read as a bare call and went with the definition — taking with it the file the redirection
        # creates. PowerShell opens the target as it sets the redirection up, whatever the command
        # writes, so the stream named does not matter and every file spelling is one of these.
        for redirection in (r'> C:\out.txt', r'>> C:\out.txt', r'2> C:\err.txt', r'3>> C:\v.txt'):
            with self.subTest(redirection):
                source = F"function j {{ $Null = 1 }}\nj {redirection}\nWrite-Host 'keep'"
                self.assertEqual(
                    self._apply(source, Ps1JunkStatementRemoval),
                    F"function j {{}}\nj {redirection}\nWrite-Host 'keep'")

    def test_a_call_to_an_inert_function_that_only_merges_streams_is_removed(self):
        # A merge names no file and moves nothing an inert command never wrote, so `j 2>&1` really
        # is the no-op it looks like. Pinned beside the case above because the two redirection
        # questions are separate and a gate that answered both the same way would be wrong at one.
        self.assertEqual(
            self._apply(
                "function j { $Null = 1 }\nj 2>&1\nWrite-Host 'keep'", Ps1JunkStatementRemoval),
            "Write-Host 'keep'")

    def test_function_with_argful_call_kept(self):
        result = self._apply(
            "function j { $Null = 1 }\nj 'arg'\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "function j {}\nj 'arg'\nWrite-Host 'keep'")

    def test_function_captured_result_kept(self):
        result = self._apply(
            "function j { $Null = 1 }\n$x = j\nWrite-Host 'keep'", Ps1JunkStatementRemoval)
        self.assertEqual(result, "function j {}\n$x = j\nWrite-Host 'keep'")

    def test_a_scope_qualified_definition_is_reached_by_an_unqualified_call(self):
        # `function global:f` defines what a later bare `f` runs. Keying the definition under the
        # qualified spelling left the callgraph unable to enter the body, so nothing inside it
        # counted as reachable and the definition itself read as never called.
        for definition in ('global:f', 'script:f', 'local:f', 'private:f'):
            with self.subTest(definition):
                result = self._apply(
                    F"function {definition} {{ Start-Process calc }}\nf\nWrite-Host 'keep'",
                    Ps1JunkStatementRemoval)
                self.assertIn('Start-Process', result)

    def test_a_script_of_nothing_but_definitions_is_not_emptied(self):
        # Dot-sourcing is how a definition-only script is used, so the call sites that would prove
        # its functions live sit in a caller this walk never reads. Every definition then reads as
        # both unreachable and inert, which is the same evidence that says "this is a module" —
        # and one removal site already refuses to act on it while this one did not.
        for script in ('function f { }', 'function f { }\nfunction g { }'):
            with self.subTest(script):
                result = self._apply(script, Ps1JunkStatementRemoval)
                self.assertIn('function f', result)

    def test_a_script_that_calls_its_own_inert_functions_is_still_emptied(self):
        # The counterpart, and the reason the guard weighs only the definitions. A script holding a
        # call site of its own is not the dot-sourced module the guard protects — it uses the
        # function here — so the whole thing goes. Weighing the call sites too kept every one of
        # these alive.
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


#: A statement that acts, so it is never a candidate for either model and its survival says only
#: that the script was not emptied.
_ANCHOR = "Write-Host 'ANCHOR'"

#: The bare-output shapes whose value provably reaches the console and cannot raise, each with a
#: marker that is present in the source and absent once it is deleted. Written as a table because
#: the two models are asked exactly the same question about exactly the same shapes, and a table
#: neither of them can edit privately is what makes them comparable.
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
    """
    A statement whose only effect is to write a value to the success output stream is deleted when
    the value provably reaches the console and nothing else, and when evaluating it cannot raise.
    Each test names why a shape qualifies rather than pinning a rendering.
    """

    def _assertStripped(self, junk: str, marker: str) -> None:
        result = self._deobfuscate(F'{junk}\n{_ANCHOR}')
        self.assertNotIn(marker, result)
        self.assertIn('ANCHOR', result)

    def test_a_bare_literal_at_the_root_is_stripped(self):
        for kind in ('string literal', 'integer', 'negated integer', 'real', 'boolean'):
            with self.subTest(kind):
                self._assertStripped(*_STRIPPABLE[kind])

    def test_an_expression_that_folds_to_a_literal_is_stripped(self):
        # Folding runs first, so what the removal is shown is a literal like any other. Both of
        # these print on PowerShell 5.1 — `Xtjbnwqm` and `True`.
        for kind in ('string sum', 'comparison'):
            with self.subTest(kind):
                self._assertStripped(*_STRIPPABLE[kind])

    def test_a_container_built_only_out_of_literals_is_stripped(self):
        # Constructing an array or a hash table cannot fail when nothing inside it can, so these
        # join the literals rather than needing a rule of their own. A range is not one of them —
        # the operator converts both endpoints and then allocates the span, so it is weighed
        # separately and only a short range of `Int32` bounds qualifies.
        for kind in ('array literal', 'hash literal', 'range'):
            with self.subTest(kind):
                self._assertStripped(*_STRIPPABLE[kind])

    def test_a_range_the_operator_cannot_build_is_not_stripped(self):
        # Regression: `4242424242..4242424245` raises the same `Int32` conversion error `[Int]'x'`
        # raises, so it is a guard that already stopped the script and deleting it resumes
        # execution. Folding expanded it into an array of literals before anything asked, and an
        # array of literals is granted unconditionally.
        for junk in ('4242424242..4242424245', '1..2147483648', '0..2147483647'):
            with self.subTest(junk):
                self.assertIn('ANCHOR', (result := self._deobfuscate(F'{junk}\n{_ANCHOR}')))
                self.assertIn('4242424242' if junk.startswith('42') else '2147483', result)

    def test_a_bare_value_in_a_function_every_call_site_only_prints_is_stripped(self):
        # The direction that needs the call graph: position alone says only that the value leaves
        # the body, and a bare call is what makes the console the one thing that reads it. Measured
        # on PowerShell 5.1 — a bare call to a two-value function writes both to the console and
        # leaves nothing for anything else to read.
        result = self._deobfuscate(F"function Qzmr {{ 'Xtjbnwqm' }}\nQzmr\n{_ANCHOR}")
        self.assertNotIn('Xtjbnwqm', result)
        self.assertIn('ANCHOR', result)


class TestPs1BareOutputIsKeptWhenAsked(TestPs1):
    """
    The same shapes with `preserve_bare_output` on, which is what a caller passes for a module, for
    a fragment of a larger script, or whenever the printed output is itself the artifact.
    """

    def _assertKept(self, junk: str, marker: str) -> None:
        result = self._deobfuscate(F'{junk}\n{_ANCHOR}', preserve_bare_output=True)
        self.assertIn(marker, result)
        self.assertIn('ANCHOR', result)

    def test_a_bare_literal_at_the_root_is_kept(self):
        for kind in ('string literal', 'integer', 'negated integer', 'real', 'boolean'):
            with self.subTest(kind):
                self._assertKept(*_STRIPPABLE[kind])

    def test_a_folded_literal_is_kept(self):
        for kind in ('string sum', 'comparison'):
            with self.subTest(kind):
                self._assertKept(*_STRIPPABLE[kind])

    def test_a_container_built_only_out_of_literals_is_kept(self):
        for kind in ('array literal', 'hash literal', 'range'):
            with self.subTest(kind):
                self._assertKept(*_STRIPPABLE[kind])

    def test_a_bare_value_in_a_function_every_call_site_only_prints_is_kept(self):
        result = self._deobfuscate(
            F"function Qzmr {{ 'Xtjbnwqm' }}\nQzmr\n{_ANCHOR}", preserve_bare_output=True)
        self.assertIn('Xtjbnwqm', result)
        self.assertIn('ANCHOR', result)


class TestPs1OutputSomethingElseHoldsIsKeptEitherWay(TestPs1):
    """
    The claim here *is* mode-invariance, which is why every case runs under both models and asserts
    they agree. A value anything but the console could read is not the switch's to give away, so a
    model that keeps these only when asked has put them behind the wrong gate.
    """

    #: A function whose body writes the payload to the output stream, carrying a `Write-Host` so the
    #: function evaluator cannot fold a call to it into that payload. Folding is not wrong, but it
    #: takes the call site out of the tree, and the call site is the whole subject here: without it
    #: these tests pass with the destination analysis removed entirely.
    _QZMR = "function Qzmr { Write-Host 'inner'; 'Xtjbnwqm' }\n"

    def _assertKeptEitherWay(self, source: str, marker: str) -> None:
        default = self._deobfuscate(source)
        preserved = self._deobfuscate(source, preserve_bare_output=True)
        self.assertEqual(default, preserved)
        self.assertIn(marker, default)

    def test_a_value_a_caller_stores_is_kept(self):
        # `@(f)` and `$(f)` hold whole statements, so a model that reads "is this call a statement?"
        # as "is its value discarded?" lets both of these through while `$r` receives what f wrote.
        # Measured on PowerShell 5.1 with a two-value body: `$r = @(f)`, `$r = $(f)` and `$r = f`
        # all give `$r` two elements, while the bare call writes both to the console instead.
        for call in ('$r = Qzmr', '$r = @(Qzmr)', '$r = $(Qzmr)'):
            with self.subTest(call):
                self._assertKeptEitherWay(
                    F'{self._QZMR}{call}\nWrite-Host $r', 'Xtjbnwqm')

    def test_a_value_a_redirection_moves_elsewhere_is_kept(self):
        # `>` writes the values to a file and `1>&2` sends them to the error stream; neither reaches
        # the console, so neither is text the switch is about. Measured: `f > out.txt` leaves the
        # console empty and the file holding both values.
        for call in (r'Qzmr > C:\out.txt', 'Qzmr 1>&2'):
            with self.subTest(call):
                self._assertKeptEitherWay(F'{self._QZMR}{call}\n{_ANCHOR}', 'Xtjbnwqm')

    def test_a_value_a_call_site_hands_to_anything_at_all_is_kept(self):
        # Regression: the outward walk enumerated the positions that *consume* a value and walked
        # past everything else, so every slot the enumeration did not name read as the console. Each
        # of these hands the value to something other than the console, which is the whole claim —
        # what the value then decides varies by row and is not what is being pinned.
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
        # A default runs on every call that omits the argument, and a `param` declaration is not a
        # position the allow-list names — so the walk out of one answers `CAPTURED` and the value is
        # kept, which no arm added for an argument position would have covered.
        self._assertKeptEitherWay(
            F'{self._QZMR}function Ldkr {{ param($p = (Qzmr)) Write-Host $p }}\nLdkr\n{_ANCHOR}',
            'Xtjbnwqm')

    def test_a_value_a_pipeline_consumes_is_kept_though_nothing_could_tell(self):
        """
        This one is a policy choice and not a semantic requirement, which is why it is named for the
        choice. `f | Out-Null` prints nothing whether or not `f` still writes anything, so deleting
        the write is unobservable and no measurement can settle it. It is kept because the pass
        reasons about where a value goes and not about what the command downstream will do with it,
        and a model that started making exceptions for known sinks would be back to keying deletions
        on a table of command names.
        """
        self._assertKeptEitherWay(F'{self._QZMR}Qzmr | Out-Null\n{_ANCHOR}', 'Xtjbnwqm')

    def test_a_statement_that_can_raise_is_kept(self):
        # Each of these terminates the script where it stands, so deleting one resumes execution
        # that had stopped. Both classify as output like `42` does, and only the fault gate parts
        # them from it.
        for junk in ("[Int]'Xtjbnwqm'", '4242424242 / $zero'):
            with self.subTest(junk):
                self._assertKeptEitherWay(F'{junk}\n{_ANCHOR}', 'Xtjbnwqm' if "'" in junk else '/')

    def test_a_fault_inside_a_function_a_handler_catches_is_kept(self):
        # The fault gate has to hold across a call, where the veto that reads a `try` body cannot
        # see: deleting the throw makes the handler dead code.
        self._assertKeptEitherWay(
            "function Qzmr { [Int]'Xtjbnwqm' }\n"
            "try { Qzmr } catch { Write-Host 'CAUGHT' }", 'CAUGHT')

    def test_a_value_in_a_function_nothing_calls_is_kept(self):
        # No call site is no evidence, and the answer has to be the same one an unreachable cycle
        # gets. A nested definition is the shape that makes it visible: `Inner` is written into the
        # enclosing scope and still nothing names it.
        self._assertKeptEitherWay(
            F"function Outer {{ function Inner {{ 'Xtjbnwqm' }} }}\nOuter\n{_ANCHOR}", 'Xtjbnwqm')

    def test_one_captured_call_site_captures_every_definition_of_the_name(self):
        # Calls are attributed to the name, not to one of its definitions, so the join has to be
        # pessimistic across the whole name, or the definition the bare call reaches is the wrong
        # one.
        self._assertKeptEitherWay(
            "function Qzmr { 'Xtjbnwqm' }\n"
            "function Qzmr { 'Ldkrpwsz' }\n"
            F"Qzmr\n$r = Qzmr\nWrite-Host $r\n{_ANCHOR}", 'Xtjbnwqm')

    def test_a_recursion_no_call_grounds_is_kept(self):
        # `Qzmr` and `Vbxl` call each other and nothing else calls either, so the only evidence
        # available is the evidence an uncalled function has: none. Reading their calls to each
        # other as grounding would hand a cycle a licence a single uncalled function is refused.
        # Nested inside a function that *is* called, because a definition standing at the root with
        # no call site is deleted outright and the cycle would never be weighed.
        self._assertKeptEitherWay(
            'function Outer {\n'
            "  function Qzmr { 'Xtjbnwqm'; Vbxl }\n"
            '  function Vbxl { Qzmr }\n'
            F'}}\nOuter\n{_ANCHOR}', 'Xtjbnwqm')

    def test_a_grounded_recursion_one_caller_captures_is_kept(self):
        # The same cycle reached from the root, so it is grounded, with one call site that stores
        # what it receives. Grounded is not enough on its own.
        self._assertKeptEitherWay(
            "function Qzmr { 'Xtjbnwqm'; Vbxl }\n"
            'function Vbxl { Qzmr }\n'
            F'Qzmr\n$r = Vbxl\nWrite-Host $r\n{_ANCHOR}', 'Xtjbnwqm')


#: Every way a name in this tree can be bound or reached from somewhere the walk cannot read. Listed
#: once, because the properties below say the same thing about all of them and a row that goes
#: missing from the analysis should fail here without anyone having thought to name it.
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
    """
    Properties rather than cases. Each says something about *every* unknown at once, so an analysis
    that learns a new way to bind a name and forgets to fail closed on it is caught here without a
    test having to name the row.
    """

    #: A function whose body only prints, called once, beside a bare value at the root. Under a
    #: closed world every part of this is removable; under any unknown none of it is.
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
        # The subset property above holds vacuously while `known` is the anchor alone — every
        # statement it could report missing has already been stripped from `known` — so it is not
        # what says the removal fails closed. This is: under every unknown the definition and the
        # value its body writes both have to be standing, because the name could be bound or reached
        # from a file this walk never read. The bare `'Ldkrpwsz'` at the root is deliberately not
        # asserted — an unknown says nothing about who reads the root, which is the console under
        # the default model whatever else the script imports, and `preserve_bare_output` is the
        # switch that keeps it.
        #
        # Asked of the pass, because that is the scope on which it holds for every unknown.
        # `Ps1FunctionEvaluator` folds a call into its value and then deletes the definition, and it
        # declines that deletion for an export alone — the other unknowns are risks it takes
        # deliberately, in exchange for resolving `iex` trampolines. The export case, where the
        # property does reach the whole pipeline, is pinned separately below.
        for opener in _UNKNOWNS:
            with self.subTest(opener):
                result = self._apply(F'{opener}\n{self._SCRIPT}', Ps1JunkStatementRemoval)
                self.assertIn('function Qzmr', result)
                self.assertIn('Xtjbnwqm', result)

    def test_an_exported_name_keeps_what_it_writes_through_the_whole_pipeline(self):
        # Regression: an export says in as many words that a caller outside the file reaches this
        # name, and the junk pass honoured it while the function evaluator did not — it folded the
        # internal call, deleted the definition, and left a bare literal at the root that the junk
        # pass then stripped as console text. A `.psm1`'s whole payload went, under the default.
        for export in (
            'Export-ModuleMember -Function Qzmr',
            "& 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function Qzmr",
        ):
            with self.subTest(export):
                result = self._deobfuscate(F'{export}\n{self._SCRIPT}')
                self.assertIn('function Qzmr', result)
                self.assertIn('Xtjbnwqm', result)

    def test_the_default_removes_whole_statements_and_never_rewrites_one(self):
        # Whatever the switch is worth, turning it off may only *delete*. A default output holding a
        # line the preserving one does not is a rewrite wearing a deletion's clothes, and it is how
        # a value would come to be altered rather than dropped.
        for source in (
            self._SCRIPT,
            F"@(1, 2, 3)\n@{{ a = 1 }}\n'Xtjbnwqm'\n{_ANCHOR}",
            F"function Qzmr {{ 42; Write-Host 'inner' }}\nQzmr\n{_ANCHOR}",
        ):
            with self.subTest(source):
                self.assertLessEqual(
                    _statements(self._deobfuscate(source)),
                    _statements(self._deobfuscate(source, preserve_bare_output=True)))

    def test_one_readability_verdict_governs_both_name_keyed_removals(self):
        # An inert function and a bare-output function stand side by side, and the two removals that
        # would take them read the same predicate. An unknown that reached one and not the other
        # would be a second copy of the verdict, drifting.
        #
        # `Qzmr` carries a `Write-Host` so that the function evaluator cannot fold the call into its
        # value: a folded call leaves the payload standing at the root, where nothing about a name
        # is being asked and the property would be measuring another pass.
        script = (
            'function Ldkr { $Null = 1 }\n'
            "function Qzmr { Write-Host 'inner'; 'Xtjbnwqm' }\n"
            F'Ldkr\nQzmr\n{_ANCHOR}'
        )
        for opener in ('', *_UNKNOWNS):
            with self.subTest(opener or 'closed world'):
                result = self._deobfuscate(F'{opener}\n{script}' if opener else script)
                self.assertEqual('Ldkr' in result, 'Xtjbnwqm' in result)


class TestPs1DiscardedObjectRemoval(TestPs1):

    def test_a_bare_object_a_cast_or_a_call_produces_is_kept(self):
        # Each of these writes one object to the output stream on PowerShell 5.1, and each is kept
        # because building it runs code that could raise: a cast converts by calling into the target
        # type, and the synchronized table is a call like any other. The plain `@{ a = 1 }` beside
        # them is not, which is why it is stripped and these are not.
        for source in (
            "[pscustomobject]@{\n  Name = 'x'\n  Value = 42\n}",
            '[Collections.Hashtable]::Synchronized(@{})',
        ):
            with self.subTest(source):
                self._assertUnchanged(
                    F"{source}\nWrite-Host 'keep'", Ps1JunkStatementRemoval)

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

    def test_scoped_variable_not_killed(self):
        result = self._apply(
            "$script:x = 1\n$script:x = 2\nWrite-Host $script:x", Ps1DeadStoreElimination)
        self.assertEqual(result, '$script:x = 1\n$script:x = 2\nWrite-Host $script:x')

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

    def test_dead_store_read_in_captured_scriptblock_is_kept(self):
        # Regression: $x = 1 is read only through a captured (stored, never invoked) scriptblock
        # nested inside an array expression. The block could observe that value when later invoked,
        # so the store is live and must not be removed. The former per-body walk skipped nested
        # scriptblocks and deleted it; sourcing reads from the shared model closes that path.
        result = self._apply(cleandoc(
            """
            $x = 1
            $arr = @( { Write-Host $x } )
            $x = 2
            Write-Host $x
            """
        ), Ps1DeadStoreElimination)
        self.assertEqual(
            result, '$x = 1\n$arr = @({\n  Write-Host $x\n})\n$x = 2\nWrite-Host $x')

    def test_dead_store_read_by_compound_assignment_is_kept(self):
        # Regression: the target of `$x += 1` reads the variable before writing it, so the store it
        # observes is live. Excluding every assignment target from the read set — rather than only
        # the target of a plain `=`, which replaces the value unread — deleted `$x = 1`.
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


class TestPs1PayloadRetention(TestPs1):
    """
    Each test asserts the payload survives rather than pinning a rendering: keeping junk costs
    nothing and deleting a call that runs is the failure.
    """

    def test_a_nested_redefinition_keeps_the_name_from_being_inert(self):
        # Regression: `acting` was collected from top-level statements while call sites were
        # collected tree-wide, so the empty definition made the name inert and the call that reaches
        # the payload definition — an `if` body is not a new scope in PowerShell — was removed.
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
        # Regression: an assignment whose value is a statement (`$x = if (...) { ... }`, and the
        # switch/foreach/try forms beside it) has no expression statement to be rewritten into, and
        # the branch that could not rewrite it deleted the statement along with the branch bodies.
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
        # The shape that carried a whole family of losses: a payload inside a function was deleted
        # because something beside it read as carrying the body's output. Nothing beside it is
        # consulted any more — where the value goes is decided at the call sites — so the same body
        # answers differently only when the *call* does. Every junk shape here was one of the
        # reported covers.
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
                self.assertNotIn('TVqQAAMA', self._deobfuscate(F'{definition}f'))
                self.assertIn(
                    'TVqQAAMA', self._deobfuscate(F'{definition}$r = f\nWrite-Host $r'))

    def test_a_void_foreach_sink_is_a_discard_under_both_spellings(self):
        # `%` and `ForEach-Object` are the same command, and only one of them is what the discard
        # idiom is written against. A body that writes is not a discard under either.
        for sink in ('ForEach-Object', '%'):
            with self.subTest(sink):
                result = self._deobfuscate(
                    F"1..3 | {sink} {{ Write-Host $_ }}\nWrite-Output 'keep'")
                self.assertIn('Write-Host', result)

    def test_a_redefined_command_keeps_the_body_the_script_gave_it(self):
        # A script that takes a built-in name over makes every table keyed on that name wrong, so
        # nothing may be concluded from the name alone — least of all a deletion.
        result = self._deobfuscate(
            "function Write-Host { Start-Process calc }\n"
            "function f { Write-Host 'x'; Get-Random }\nf")
        self.assertIn('Get-Random', result)
        self.assertIn('Start-Process calc', result)


class TestPs1NameRemovalNeedsTheWholeStory(TestPs1):
    """
    Each test asserts the payload path survives rather than pinning a rendering, because what is
    missing from the tree is exactly what the removal cannot see.
    """

    def test_an_open_world_keeps_the_call_to_an_apparently_inert_function(self):
        # Regression: the empty `j` standing here is not the `j` the dot-sourced file defines, so
        # the call reaches code this tree does not contain.
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
        # Regression: the `iex` is exactly what calls it, and its call site is not in this tree.
        result = self._deobfuscate(cleandoc(
            """
            function Payload { Start-Process calc }
            Invoke-Expression $code
            Write-Host 'keep'
            """
        ))
        self.assertIn('Start-Process calc', result)

    def test_an_identity_assignment_keeps_the_names_it_could_bind(self):
        # `${function:j} = { ... }` is a definition of `j` the definition scan does not read, and
        # `${alias:q} = 'j'` is a call to `j` the call scan does not read.
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
        # Regression: a call site was credited to the innermost function around it, so the call to
        # `Payload` counted as `Inner`'s and `Inner` is named by nothing. `Payload` then read as
        # reached from nowhere and was deleted — while `Inner`, which no pass removes because only a
        # top-level definition is removable, stayed behind calling a name the script no longer
        # defines. A call is credited to the enclosing scope for exactly this reason.
        result = self._deobfuscate(
            'function Outer { function Inner { Payload } }\n'
            'Outer\n'
            'function Payload { Start-Process calc }')
        self.assertIn('Start-Process calc', result)

    def test_a_call_inside_a_method_of_a_nested_class_keeps_the_definition_it_names(self):
        # Crediting a call to the outermost enclosing function has to stop at a class method, or the
        # method's calls become conditional on a name that reaches the *class*, which nothing here
        # can prove. A method is reached through `$object.Method()` and never through a bare name,
        # so its calls are the ones that must stay unconditional.
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
        self._assertUnchanged(cleandoc(
            """
            $payload = 'x'
            try {
              $q = 'seed' + $payload
            } catch {
              Write-Host 'err'
            }
            Write-Host 'go'
            """
        ), Ps1UnusedVariableRemoval)

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
        # An `if` condition sits in a tuple inside `clauses`: no list to splice, no field to take.
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
    """
    `& 'MyModule\\Qzmr'` keys as `mymodule\\qzmr` while `function Qzmr` keys as `qzmr`, so nothing
    matched, the definition read as uncalled, and the emitted script called a name it no longer
    defined.

    Real PowerShell errors on such a call rather than reaching the local definition, so keeping the
    definition is not what the language says: it is the internal invariant that no removal leaves a
    dangling reference, plus a decision to fail closed in front of the lexer's qualified-name hole.
    """

    def test_a_quoted_module_qualified_call_keeps_the_definition_it_resolves_onto(self):
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\n& 'MyModule\\Qzmr'")
        self.assertIn('function Qzmr', result)

    def test_a_bare_module_qualified_call_keeps_the_definition_it_resolves_onto(self):
        # The call operator is what makes the name arrive whole, not the quoting; both spellings
        # reach the graph as one token and have to be answered the same way.
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\n& MyModule\\Qzmr")
        self.assertIn('function Qzmr', result)

    def test_a_scope_qualified_call_still_reaches_the_definition_by_key(self):
        result = self._deobfuscate(
            "function Qzmr { Write-Host 'P' }\n& 'global:Qzmr'")
        self.assertIn('function Qzmr', result)

    def test_an_executable_invoked_by_path_does_not_switch_the_analysis_off(self):
        # Reading the backslash itself as the signal would make every script that runs an
        # executable by path unreadable, and this inert function would survive with it.
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
    """
    A binding whose only reader addresses it by name. Nothing in the script reads `$a`, so a pass
    counting `$`-occurrences alone finds the assignment unread and deletes the value the command
    goes on to read.
    """

    def test_an_assignment_read_only_by_name_is_kept(self):
        self._assertUnchanged("$a = 'x'\nGet-Variable a", Ps1UnusedVariableRemoval)

    def test_an_assignment_nothing_reads_at_all_is_still_removed(self):
        """
        The floor under the case above: without the named read the assignment really is dead, so a
        guard that keeps every assignment would satisfy the first test while doing nothing.
        """
        result = self._deobfuscate("$a = 'x'\nWrite-Host done")
        self.assertNotIn('$a', result)
