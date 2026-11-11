from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis.values import make_string_literal
from refinery.lib.scripts.ps1.deobfuscation.substitution import (
    carried_redirections,
    may_substitute,
    substitute_statement,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1Substitution(TestPs1):

    @staticmethod
    def _statement(source: str):
        return Ps1Parser(source).parse().body[0]

    def test_a_redirection_written_below_the_replaced_node_is_still_its_own(self):
        statement = self._statement("Invoke-Expression 'x' > C:\\o.txt")
        self.assertEqual(len(carried_redirections(statement)), 1)
        self.assertFalse(may_substitute(statement, make_string_literal('x')))

    def test_a_replacement_reusing_the_redirected_node_is_allowed(self):
        statement = self._statement("Invoke-Expression 'x' > C:\\o.txt")
        self.assertTrue(may_substitute(statement, [statement]))

    def test_a_node_the_caller_moves_elsewhere_does_not_count_as_lost(self):
        statement = self._statement("Invoke-Expression 'x' > C:\\o.txt")
        self.assertTrue(may_substitute(
            statement, make_string_literal('x'), moved=[statement.expression]))

    def test_a_rebuilt_redirection_does_not_stand_in_for_the_one_it_copies(self):
        one = self._statement("Invoke-Expression 'x' > C:\\o.txt")
        other = self._statement("Invoke-Expression 'x' > C:\\o.txt")
        self.assertFalse(may_substitute(one, other))

    def test_a_merge_is_refused_although_it_neither_moves_output_nor_opens_a_file(self):
        statement = self._statement("Invoke-Expression 'x' 2>&1")
        self.assertFalse(may_substitute(statement, make_string_literal('x')))

    def test_a_statement_carrying_nothing_may_be_replaced(self):
        statement = self._statement("Invoke-Expression 'x'")
        self.assertTrue(may_substitute(statement, make_string_literal('x')))

    def test_an_empty_replacement_is_refused_rather_than_performed_as_a_removal(self):
        script = Ps1Parser("Write-Host 'x'").parse()
        with self.assertRaises(ValueError):
            substitute_statement(script, script.body[0], [])
        self.assertEqual(len(script.body), 1)


class TestPs1ASubstitutionKeepsTheBindingErrorsItReplaces(TestPs1):

    @staticmethod
    def _statement(source: str):
        return Ps1Parser(source).parse().body[0]

    def test_a_replacement_dropping_an_invocation_the_binder_rejects_is_refused(self):
        for source in (
            'Write-Output (Get-Variable x -Bogus).Value',
            'Write-Output (Get-Variable x zzq -ValueOnly)',
            "Set-Variable x 'a' 'b'",
        ):
            with self.subTest(source):
                self.assertFalse(may_substitute(self._statement(source), make_string_literal('x')))

    def test_a_replacement_keeping_the_rejected_invocation_is_allowed(self):
        statement = self._statement('Write-Output (Get-Variable x -Bogus).Value')
        self.assertTrue(may_substitute(statement, [statement]))

    def test_a_replacement_dropping_an_invocation_the_binder_accepts_is_allowed(self):
        statement = self._statement('Write-Output (Get-Variable x -ValueOnly)')
        self.assertTrue(may_substitute(statement, make_string_literal('x')))

    def test_every_pass_keeps_the_binding_error_a_fold_would_drop(self):
        for source in (
            "Set-Item -P 'Variable:x' 5\nWrite-Output $x",
            '$x = 1\nWrite-Output (Get-Variable x -Bogus).Value',
            '$x = 1\nWrite-Output (Get-Variable x zzq -ValueOnly)',
            "Set-Item Variable:x 'a' 'b'\nWrite-Output $x",
            "Set-Variable x 'a' 'b'\nWrite-Output $x",
            "(Get-Command -N 'wr?te').Name",
        ):
            with self.subTest(source):
                self._assertKept(source)
