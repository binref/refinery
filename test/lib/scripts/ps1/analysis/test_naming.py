from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.analysis.naming import (
    Ps1NameRole,
    Ps1NameTarget,
    addresses_unreadable_name,
    named_references,
)
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1NameCensus(TestBase):
    """
    Which names a command addresses as a string, and what it does to each. A name reached only this
    way has no variable occurrence anywhere, so a layer that reasons about occurrences alone sees a
    value that never changes and folds straight across the command that changed it.

    Every expectation is what PowerShell does, measured on 5.1 where the documentation and our own
    code are not evidence — see `temp/ps1/census_measurements.md`.
    """

    @staticmethod
    def _command(source: str) -> Ps1CommandInvocation:
        for node in Ps1Parser(source).parse().walk():
            if isinstance(node, Ps1CommandInvocation):
                return node
        raise AssertionError(F'no command in {source!r}')

    def _refs(self, source: str) -> list[tuple[str, str, str]]:
        return [
            (ref.key, ref.role.name, ref.target.name)
            for ref in named_references(self._command(source))
        ]

    def test_the_variable_commands_are_recognized_through_their_aliases(self):
        for source, role in (
            ('Set-Variable x 5', 'WRITES'),
            ('sv x 5', 'WRITES'),
            ('SET-VARIABLE x 5', 'WRITES'),
            ('New-Variable x 5', 'WRITES'),
            ('nv x 5', 'WRITES'),
            ('Clear-Variable x', 'WRITES'),
            ('clv x', 'WRITES'),
            ('Get-Variable x', 'READS'),
            ('gv x', 'READS'),
            ('Remove-Variable x', 'UNBINDS'),
            ('rv x', 'UNBINDS'),
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', role, 'LOCAL')])

    def test_the_name_is_found_however_the_argument_is_written(self):
        for source in (
            'Set-Variable x 5',
            'Set-Variable -Name x -Value 5',
            'Set-Variable -Name:x -Value:5',
            'Set-Variable -Na x -Va 5',
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'WRITES', 'LOCAL')])

    def test_a_named_argument_before_the_name_does_not_become_the_name(self):
        """
        `-Scope Global` is a switch followed by a positional as far as the parser can tell, so a
        reading that takes the first positional as the name calls this variable `Global`.
        """
        self.assertEqual(
            self._refs('Set-Variable -Scope Global x 5'), [('x', 'WRITES', 'SCRIPT')])

    def test_a_bare_write_lands_in_the_scope_the_command_is_written_in(self):
        """
        Measured: `Set-Variable d 'INNER'` inside a function writes that function's scope and leaves
        the caller's `$d` alone, so the default is local and not script.
        """
        self.assertEqual(self._refs('Set-Variable x 5'), [('x', 'WRITES', 'LOCAL')])

    def test_an_explicit_script_or_global_scope_is_placed_at_the_script(self):
        for source in (
            'Set-Variable x 5 -Scope Global',
            'Set-Variable x 5 -Scope Script',
            'Set-Variable global:x 5',
            'Set-Variable script:x 5',
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'WRITES', 'SCRIPT')])

    def test_a_numeric_scope_names_a_scope_the_lexical_chain_cannot_reach(self):
        """
        Measured: `-Scope 1` writes the *caller's* scope, which is not a lexical ancestor of the
        command, so no walk up the scope chain finds it.

        The quoted spelling is the one that matters to the lookup: `-Scope 1` is an integer literal
        and never reaches a table of scope *names* at all, so only `-Scope '1'` shows whether an
        unrecognised name falls to the safe side.
        """
        for source in (
            'Set-Variable x 5 -Scope 1',
            "Set-Variable x 5 -Scope '1'",
            'Set-Variable x 5 -Scope Foo',
            'Set-Variable x 5 -Scope $s',
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'WRITES', 'UNREADABLE')])

    def test_an_item_command_on_a_name_drive_addresses_that_name(self):
        self.assertEqual(self._refs('Set-Item Variable:x 5'), [('x', 'WRITES', 'LOCAL')])
        self.assertEqual(
            self._refs("Set-Item Env:ComSpec 'evil'"), [('env:comspec', 'WRITES', 'SCRIPT')])
        self.assertEqual(self._refs('del variable:x'), [('x', 'UNBINDS', 'LOCAL')])

    def test_a_bare_noun_reaching_a_variable_reader_reads_the_same_name(self):
        """
        Nothing on a 5.1 host claims `variable` or `item`, so the implicit `Get-` retry runs
        `Get-Variable` and `Get-Item`. A census keyed on the written spelling alone finds no
        reference here and leaves the read of `$x` unaccounted for.
        """
        for source in ('Get-Variable x -ValueOnly', 'variable x -ValueOnly'):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'READS', 'LOCAL')])
        for source in ('Get-Item variable:x', 'item variable:x'):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'READS', 'LOCAL')])

    def test_an_item_command_on_any_other_drive_addresses_no_name(self):
        for source in ("Set-Item C:\\file 5", "Set-Item Function:f 5", "Get-Item HKLM:\\Key"):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [])

    def test_an_out_variable_parameter_writes_the_name_it_binds(self):
        for source in (
            'Get-Process -OutVariable p',
            'Get-Process -ov p',
            'Get-Process -OutVariable:p',
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('p', 'WRITES', 'LOCAL')])

    def test_the_append_form_of_an_out_variable_reads_the_name_as_well(self):
        """
        Measured: with `$a = 'PRE'`, `-OutVariable +a` leaves `PRE` in place and appends the output,
        where `-OutVariable a` replaces it. The append form therefore observes the previous value.
        """
        self.assertEqual(self._refs('Get-Process -OutVariable +p'), [('p', 'APPENDS', 'LOCAL')])

    def test_one_command_may_address_several_names(self):
        self.assertEqual(
            sorted(self._refs('Get-Variable x -OutVariable y')),
            [('x', 'READS', 'LOCAL'), ('y', 'WRITES', 'LOCAL')])

    def test_a_command_that_addresses_no_name_reports_none(self):
        for source in (
            'Write-Host x',
            'Get-ChildItem -Recurse C:\\',
            'Get-Process',
            'Set-Content out.txt x',
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [])

    def test_a_qualified_command_name_does_not_consume_the_name_it_writes(self):
        """
        A scope or module qualifier belongs to the command name, so the first argument is still the
        name the command addresses. Both spellings used to arrive with the qualifier and the command
        split apart, which handed the resolver the *argument* as the command and left the write
        unattributed.
        """
        for source in (
            'global:sv x 5',
            'Microsoft.PowerShell.Utility\\Set-Variable x 5',
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'WRITES', 'LOCAL')])
                self.assertFalse(addresses_unreadable_name(self._command(source)))


class TestPs1UnreadableNames(TestBase):
    """
    A write whose name is computed. Nothing can say which binding it lands on, so the fact belongs
    to the scope rather than to any binding, and a consumer has to hold every name in that scope in
    doubt.
    """

    @staticmethod
    def _command(source: str) -> Ps1CommandInvocation:
        for node in Ps1Parser(source).parse().walk():
            if isinstance(node, Ps1CommandInvocation):
                return node
        raise AssertionError(F'no command in {source!r}')

    def test_a_computed_name_on_a_variable_write_is_unreadable(self):
        for source in (
            "Set-Variable $n 'v'",
            "Set-Variable -Name $n -Value 'v'",
            "New-Variable $n 'v'",
            'Remove-Variable $n',
            "Set-Variable ('x' + $i) 'v'",
        ):
            with self.subTest(source):
                self.assertTrue(addresses_unreadable_name(self._command(source)))
                self.assertEqual(named_references(self._command(source)), [])

    def test_a_literal_name_is_never_unreadable(self):
        for source in ("Set-Variable x 'v'", 'Remove-Variable x', 'Set-Variable global:x 5'):
            with self.subTest(source):
                self.assertFalse(addresses_unreadable_name(self._command(source)))

    def test_a_computed_name_on_a_read_costs_nothing(self):
        """
        Not knowing which name was read loses nothing: a read changes no value, so no later fold
        depends on having identified it.
        """
        self.assertFalse(addresses_unreadable_name(self._command('Get-Variable $n')))

    def test_a_command_that_addresses_no_variable_is_not_unreadable(self):
        for source in ('Write-Host $n', 'Get-Process', "Set-Item $path 'v'"):
            with self.subTest(source):
                self.assertFalse(addresses_unreadable_name(self._command(source)))
