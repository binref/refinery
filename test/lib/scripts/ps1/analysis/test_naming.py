from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.naming import (
    Ps1NameTarget,
    addresses_unreadable_name,
    named_references,
    reads_unreadable_name,
    unreadable_name_target,
)
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1InvokeMember, Ps1Variable
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
        name the command addresses.
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

    def test_a_computed_name_on_a_read_of_values_writes_nothing(self):
        """
        Not knowing which value was read changes no value, so no later fold depends on having
        identified it — where only values are read and no variable is handed out.
        """
        for source in ('Get-Variable $n -ValueOnly', 'Write-Host (Get-Variable $n).Value'):
            with self.subTest(source):
                self.assertFalse(addresses_unreadable_name(self._command(source)))

    def test_a_pattern_on_a_variable_write_is_unreadable(self):
        for source in ('Remove-Variable x*', "Set-Variable -Name x? -Value 'v'"):
            with self.subTest(source):
                self.assertTrue(addresses_unreadable_name(self._command(source)))
                self.assertEqual(named_references(self._command(source)), [])

    def test_a_variable_of_a_name_nobody_can_read_handed_out_is_written_anywhere(self):
        """
        Measured: a store into the `Value` of a variable picked out of `Get-Variable` rebinds it,
        and which scope it belongs to is whichever scope the command could see.
        """
        for source in (
            '$v = Get-Variable',
            '$v = Get-Variable $n',
            '$v = Get-ChildItem variable:',
        ):
            with self.subTest(source):
                self.assertIs(
                    unreadable_name_target(self._command(source)), Ps1NameTarget.UNREADABLE)

    def test_a_command_that_addresses_no_variable_is_not_unreadable(self):
        for source in ('Write-Host $n', 'Get-Process', "Set-Item $path 'v'"):
            with self.subTest(source):
                self.assertFalse(addresses_unreadable_name(self._command(source)))

    def test_a_name_computed_after_the_variable_drive_is_spelled_is_unreadable(self):
        for source, target in (
            ('$v = Get-Item "variable:$n"', Ps1NameTarget.UNREADABLE),
            ("$v = Get-ChildItem ('Variable:\\' + $n)", Ps1NameTarget.UNREADABLE),
            ("Set-Item \"variable:$n\" 'v'", Ps1NameTarget.LOCAL),
            ("Set-Item ('variable:{0}' -f $n) 'v'", Ps1NameTarget.LOCAL),
        ):
            with self.subTest(source):
                self.assertIs(unreadable_name_target(self._command(source)), target)

    def test_a_name_computed_after_another_drive_is_spelled_is_no_variable(self):
        for source in ("Set-Item \"function:$n\" { 'v' }", "Set-Item ('alias:' + $n) 'v'"):
            with self.subTest(source):
                self.assertFalse(addresses_unreadable_name(self._command(source)))


def _first(source: str, kind: type, name: str | None = None) -> Node:
    """
    The first node of *kind* in *source*, in source order; a variable is picked by its *name*.
    """
    for node in Ps1Parser(source).parse().walk_in_order():
        if isinstance(node, kind) and (name is None or getattr(node, 'name', None) == name):
            return node
    raise AssertionError(F'no {kind.__name__} in {source!r}')


class TestPs1AVariableHandedOut(TestBase):
    """
    Which commands hand out the variable itself rather than its value. A store into the `Value` of
    one rebinds the name from wherever the variable has gone: each script measured on 5.1 in
    `corpus.BEHAVIOURS` writes the value stored through the variable.
    """

    @staticmethod
    def _handed_out(source: str, kind: type = Ps1CommandInvocation) -> list[tuple[str, bool]]:
        return [(ref.key, ref.hands_out) for ref in named_references(_first(source, kind))]

    def test_a_variable_a_command_writes_out_is_handed_out(self):
        for source in (
            "$v = Get-Variable b; $v.Value = 'b'",
            "Get-Variable b | ForEach-Object { $_.Value = 'b' }",
            "(Get-Variable b).set_Value('b')",
            "(Get-Variable b).Value = 'b'",
            "$v = Get-ChildItem variable:b; $v.Value = 'b'",
            '$v = New-Variable b 1 -PassThru; $v.Value = 5',
        ):
            with self.subTest(source):
                self.assertEqual(self._handed_out(source), [('b', True)])

    def test_a_value_read_where_it_stands_hands_out_nothing(self):
        for source in (
            '$v = Get-Variable b -ValueOnly',
            '$x = (Get-Variable b).Value',
            '$x = $(Get-Variable b).Value',
            'New-Variable b 1',
        ):
            with self.subTest(source):
                self.assertEqual(self._handed_out(source), [('b', False)])

    def test_a_variable_the_session_state_writes_out_is_handed_out(self):
        self.assertEqual(
            self._handed_out(
                "$ExecutionContext.SessionState.PSVariable.Get('b').Value = 'b'", Ps1InvokeMember),
            [('b', True)],
        )

    def test_a_variable_on_a_path_rooted_at_the_drive_is_handed_out(self):
        for source in (
            "$v = Get-Item variable:\\b; $v.Value = 'b'",
            "$v = Get-Item variable:/b; $v.Value = 'b'",
            "$v = Get-Item variable::b; $v.Value = 'b'",
            "$v = Get-ChildItem Variable:\\b; $v.Value = 'b'",
        ):
            with self.subTest(source):
                self.assertEqual(self._handed_out(source), [('b', True)])

    def test_a_value_only_switch_bound_to_false_hands_the_variable_out(self):
        for source, handed_out in (
            ("$v = Get-Variable b -ValueOnly:$false; $v.Value = 'b'", True),
            ("$v = Get-Variable b -ValueOnly:$c; $v.Value = 'b'", True),
            ('$v = Get-Variable b -ValueOnly:$true', False),
        ):
            with self.subTest(source):
                self.assertEqual(self._handed_out(source), [('b', handed_out)])

    def test_a_store_into_the_value_in_a_slot_of_a_multi_assignment_hands_the_variable_out(self):
        self.assertEqual(self._handed_out('$a, (Get-Variable b).Value = 1, 2'), [('b', True)])
        self.assertEqual(
            self._handed_out(
                "$a, $ExecutionContext.SessionState.PSVariable.Get('b').Value = 1, 2",
                Ps1InvokeMember,
            ),
            [('b', True)],
        )

    def test_a_variable_an_output_variable_keeps_is_handed_out(self):
        """
        What a command writes out also lands in the variable its `-OutVariable` names, so the
        variable object leaves in `$o` whatever is read of it where the command stands.
        """
        self.assertEqual(
            self._handed_out('$n = (Get-Variable b -OutVariable o).Name'),
            [('b', True), ('o', False)],
        )

    def test_a_reference_kept_hands_out_the_variable_it_is_spelled_around(self):
        referenced = _first("$r = [ref]$b; $r.Value = 'b'", Ps1Variable, 'b')
        self.assertEqual(
            [(ref.key, ref.hands_out) for ref in named_references(referenced)],
            [('b', True)],
        )

    def test_a_reference_handed_to_a_call_is_the_parameter_it_fills(self):
        referenced = _first("[int]::TryParse('5', [ref]$b)", Ps1Variable, 'b')
        self.assertEqual(named_references(referenced), [])


class TestPs1TheSessionStateAddressesVariablesByName(TestBase):
    """
    The session state's `PSVariable` reads, writes and removes a variable by the name it is
    handed. Measured on 5.1 in `corpus.BEHAVIOURS`: `GetValue('x')` writes the value of `$x`,
    `Set('b', 'b')` leaves `$b` holding `b`, and `Remove('b')` leaves it holding nothing.
    """

    @staticmethod
    def _refs(source: str) -> list[tuple[str, str, str]]:
        return [
            (ref.key, ref.role.name, ref.target.name)
            for ref in named_references(_first(source, Ps1InvokeMember))
        ]

    def test_each_method_addresses_the_name_it_is_handed(self):
        for source, role in (
            ("$ExecutionContext.SessionState.PSVariable.GetValue('x')", 'READS'),
            ("$ExecutionContext.SessionState.PSVariable.Set('x', 'b')", 'WRITES'),
            ("$ExecutionContext.SessionState.PSVariable.Remove('x')", 'UNBINDS'),
            ("$PSCmdlet.SessionState.PSVariable.Set('x', 'b')", 'WRITES'),
            ("$PSCmdlet.GetVariableValue('x')", 'READS'),
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', role, 'LOCAL')])

    def test_a_qualified_name_is_resolved_against_its_scope(self):
        self.assertEqual(
            self._refs("$ExecutionContext.SessionState.PSVariable.Set('script:x', 'b')"),
            [('x', 'WRITES', 'SCRIPT')],
        )

    def test_the_session_state_is_reached_through_any_qualifier_of_its_holder(self):
        """
        `$ExecutionContext` is a constant every scope carries, so a qualified spelling of it is the
        same engine intrinsics the bare one is.
        """
        for source in (
            "$global:ExecutionContext.SessionState.PSVariable.Set('x', 'b')",
            "$script:ExecutionContext.SessionState.PSVariable.Set('x', 'b')",
        ):
            with self.subTest(source):
                self.assertEqual(self._refs(source), [('x', 'WRITES', 'LOCAL')])

    def test_a_computed_name_is_unreadable_where_the_call_runs(self):
        call = _first("$ExecutionContext.SessionState.PSVariable.Set($n, 'b')", Ps1InvokeMember)
        self.assertIs(unreadable_name_target(call), Ps1NameTarget.LOCAL)
        self.assertEqual(named_references(call), [])

    def test_the_session_state_kept_reads_and_writes_every_name(self):
        """
        Measured: `$p = $ExecutionContext.SessionState.PSVariable; $p.Set('b', 'b')` leaves `$b`
        holding `b`, and nothing at the call says which variable the kept table is asked for.
        """
        for source in (
            '$p = $ExecutionContext.SessionState.PSVariable',
            '$s = $ExecutionContext.SessionState',
            '$e = $ExecutionContext',
            "$ExecutionContext.SessionState.InvokeProvider.Item.Set('variable:b', 'b')",
        ):
            with self.subTest(source):
                holder = _first(source, Ps1Variable, 'ExecutionContext')
                self.assertTrue(reads_unreadable_name(holder))
                self.assertIs(unreadable_name_target(holder), Ps1NameTarget.UNREADABLE)

    def test_a_member_that_reaches_no_variable_leaks_nothing(self):
        for source in (
            "$ExecutionContext.InvokeCommand.GetCommand('x', 'Cmdlet')",
            "$ExecutionContext.SessionState.InvokeCommand.GetCommand('x', 'Cmdlet')",
            '$ExecutionContext.SessionState.LanguageMode',
            "$ExecutionContext.SessionState.PSVariable.GetValue('x')",
        ):
            with self.subTest(source):
                holder = _first(source, Ps1Variable, 'ExecutionContext')
                self.assertFalse(reads_unreadable_name(holder))
                self.assertIsNone(unreadable_name_target(holder))


class TestPs1AReadOfNamesNobodyCanRead(TestBase):
    """
    A read that may observe every variable. Measured on 5.1 in `corpus.BEHAVIOURS`: a store into
    the variable picked out of `Get-Variable` by its name reaches it, and a pattern reads each
    variable it matches.
    """

    def test_every_variable_a_command_lists_is_read(self):
        for source in (
            '$v = Get-Variable',
            'Get-Variable x* | ForEach-Object Value',
            'Get-Variable $n -ValueOnly',
            'Get-ChildItem variable:',
            'Get-ChildItem variable:\\',
            'dir variable:/',
            'dir variable:x*',
        ):
            with self.subTest(source):
                self.assertTrue(reads_unreadable_name(_first(source, Ps1CommandInvocation)))

    def test_a_name_computed_after_the_drive_is_spelled_may_be_any_name(self):
        for source in (
            '(Get-Item "variable:$n").Value',
            "(Get-ChildItem ('variable:' + $n)).Value",
        ):
            with self.subTest(source):
                self.assertTrue(reads_unreadable_name(_first(source, Ps1CommandInvocation)))

    def test_only_the_names_of_the_listed_variables_read_no_value(self):
        self.assertFalse(reads_unreadable_name(
            _first("(Get-Variable '*mdr*').Name[3, 11, 2] -join ''", Ps1CommandInvocation)))

    def test_a_named_read_is_a_reference_and_not_every_name(self):
        for source in ('Get-Variable x', 'Get-Item variable:x'):
            with self.subTest(source):
                self.assertFalse(reads_unreadable_name(_first(source, Ps1CommandInvocation)))
