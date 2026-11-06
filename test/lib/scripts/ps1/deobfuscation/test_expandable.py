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
        self.assertIn('$x', result)

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

    def test_a_value_producing_subexpression_is_written_into_the_string_and_not_dropped(self):
        self.assertEqual(
            self._deobfuscate('''"prefix$( 1 + 2 )suffix"''', remove_junk=False),
            "'prefix3suffix'")

    def test_expandable_command_subexpr_not_dropped(self):
        result = self._apply(
            '$result = "Value: $(Write-Output 42)"', Ps1ExpandableStringHoist)
        self.assertEqual(result, '$result = "Value: $(Write-Output 42)"')

    def test_expandable_hoist_preserves_assignment_order(self):
        result = self._apply(
            '$z = 1 + "$($a = 1)" + "$($b = $a)"', Ps1ExpandableStringHoist)
        self.assertLess(result.index('$a = 1'), result.index('$b = $a'))

    def test_a_hoisted_subexpression_takes_its_redirection_with_it(self):
        self.assertEqual(
            self._apply('$m = "a$($z = Get-Date > C:\\o.txt)b"', Ps1ExpandableStringHoist),
            "$z = Get-Date > C:\\o.txt\n$m = 'ab'")


class TestPs1ASubexpressionOfThePipelineInputRunsBeforeTheCommand(TestPs1):

    def test_a_separator_the_payload_text_restores_is_in_place_when_the_payload_runs(self):
        source = (
            '''"$( Set-Variable 'OFS' '' )" + 'Write-Host "$(1,2)"' + '''
            '''"$( Set-Variable 'OFS' ' ' )" | Invoke-Expression'''
        )
        self._assertDeobfuscatesToOneOf(source, source, "$OFS = ''\n$OFS = ' '\nWrite-Host '1 2'")

    def test_a_payload_reads_what_a_subexpression_after_its_text_assigns(self):
        source = '''\'Write-Host $x\' + "$( $x = 'b' )" | Invoke-Expression'''
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'b'")

    def test_a_pipeline_body_reads_what_a_subexpression_after_a_variable_assigns(self):
        source = '''$x = 'a'; $x + "$( $x = 'b' )" | ForEach-Object { Write-Host $x }'''
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            "'a' | ForEach-Object {\n  Write-Host 'b'\n}",
            "Write-Host 'b'",
        )


class TestPs1ASubexpressionAStatementMayNotEvaluateStaysWhereItRuns(TestPs1):

    def test_an_operand_a_false_and_skips_assigns_nothing(self):
        source = """
            $x = 'a'
            $Null = $False -and "$($x = 'b')"
            Write-Host $x
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'a'")

    def test_an_operand_a_true_or_skips_assigns_nothing(self):
        source = """
            $x = 'a'
            $Null = $True -or "$($x = 'b')"
            Write-Host $x
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'a'")

    def test_a_branch_that_is_not_taken_assigns_nothing(self):
        source = """
            $x = 'a'
            $c = Read-Host
            if ($c) { Write-Host "$($x = 'b')" }
            Write-Host $x
        """
        self._assertDeobfuscatesToOneOf(source, source, """
            $x = 'a'
            $c = Read-Host
            if ($c) {
              $x = 'b'
              Write-Host ''
            }
            Write-Host $x
        """)

    def test_a_block_that_never_runs_assigns_nothing(self):
        source = """
            $x = 'a'
            $Null = { Write-Host "$($x = 'b')" }
            Write-Host $x
        """
        self._assertDeobfuscatesToOneOf(source, source, """
            $x = 'a'
            $Null = {
              $x = 'b'
              Write-Host ''
            }
            Write-Host $x
        """, "Write-Host 'a'")

    def test_an_argument_ahead_of_the_string_reads_the_value_before_the_assignment(self):
        source = """
            $x = Read-Host
            Write-Host $x "$($x = 'b')"
        """
        self._assertDeobfuscatesToOneOf(source, source, """
            $x = Read-Host
            Write-Host $x ''
        """)
