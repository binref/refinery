from __future__ import annotations

from inspect import cleandoc

from test import TestBase, opportunity

from refinery.lib.scripts import Statement
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.effects import (
    Contribution,
    OutputSink,
    StatementEffect,
    _reflection_read_is_pure,
    body_is_inert,
    is_a_library,
    is_fault_free,
    is_side_effect_free,
    output_path,
    output_sink,
    runs_something,
    script_contribution,
    statement_effect,
    unconsumed_statement,
)
from refinery.lib.scripts.ps1.analysis.raising import expression_cannot_fault
from refinery.lib.scripts.ps1.analysis.values import certainly_throws
from refinery.lib.scripts.ps1.analysis.faults import build_fault_reach
from refinery.lib.scripts.ps1.analysis.world import Ps1TypeWorld, measure_world
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach, build_world_reach
from refinery.lib.scripts.ps1.ast import get_body, get_command_name
from refinery.lib.scripts.ps1.data import resolve_type
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1CatchClause,
    Ps1CommandInvocation,
    Ps1DataSection,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1InvokeMember,
    Ps1ScriptBlock,
    Ps1SubExpression,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1UnaryExpression,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


_CLOSED_WORLD = Ps1WorldReach(Ps1TypeWorld(True, frozenset()))

_NO_WORLD = Ps1WorldReach(Ps1TypeWorld(False, frozenset()))


class Ps1EffectsTest(TestBase):

    @staticmethod
    def _pure(node) -> bool:
        return is_side_effect_free(node, _CLOSED_WORLD)

    @staticmethod
    def _effect(stmt) -> StatementEffect:
        return statement_effect(stmt, _CLOSED_WORLD)

    @staticmethod
    def _inert(node) -> bool:
        return body_is_inert(node, _CLOSED_WORLD)

    @staticmethod
    def _parse(source: str):
        return Ps1Parser(source).parse()

    @classmethod
    def _statement(cls, source: str):
        return cls._parse(source).body[0]

    @classmethod
    def _expression(cls, source: str):
        statement = cls._statement(source)
        assert isinstance(statement, Ps1ExpressionStatement)
        assert statement.expression is not None
        return statement.expression

    @classmethod
    def _first(cls, source: str, kind):
        return next(node for node in cls._parse(source).walk() if isinstance(node, kind))


class TestPs1Purity(Ps1EffectsTest):

    def test_effect_free_expressions(self):
        for source in (
            "'a' + 'b'",
            '[Math]::Abs(-3)',
            '[Convert]::ToBase64String($b)',
            '$s.Substring(0, 2)',
            'Get-Date',
            'New-Object System.Text.StringBuilder',
        ):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_expressions_that_change_the_world(self):
        for source in (
            'Start-Process notepad',
            'Remove-Item x',
            "[System.IO.File]::WriteAllText('a', 'b')",
            '$x++',
            '$s.Invoke()',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_an_unrecognized_construct_is_assumed_impure(self):
        for source in ('New-Object System.Net.WebClient', '& $f', '$obj.Frobnicate()'):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_pipeline_cmdlet_is_as_pure_as_the_body_it_runs(self):
        for source, pure in (
            ('1..3 | ForEach-Object { $_ }', True),
            ('1..3 | ForEach-Object { $Null = $_ }', True),
            ('1..3 | ForEach-Object { [Void]$_ }', True),
            ('1..3 | Where-Object { $Null = $_ }', True),
            ('1..3 | ForEach-Object { $x = $_ }', False),
            ('1..3 | ForEach-Object { Write-Host $_ }', False),
            ('1..3 | ForEach-Object { [Void](Start-Process notepad) }', False),
        ):
            with self.subTest(source):
                self.assertIs(self._pure(self._expression(source)), pure)

    def test_a_pipeline_cmdlet_body_is_read_for_every_such_cmdlet(self):
        for source in (
            'Where-Object { Start-Process notepad }',
            'Select-Object { Start-Process notepad }',
            'Sort-Object { Start-Process notepad }',
            '1..3 | ForEach-Object { Start-Process notepad }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_scriptblock_argument_is_read_through_every_block_it_owns(self):
        for source in (
            'Get-Process | Where-Object { begin { Start-Process notepad } process { $_ } }',
            '1..3 | ForEach-Object { end { Start-Process notepad } }',
            '1..3 | ForEach-Object { param($p = (Start-Process notepad)) [Void]$_ }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_computed_member_name_is_an_expression_the_read_evaluates(self):
        for source in (
            '$x.$(Start-Process notepad)',
            '[IO.Path]::$(Start-Process notepad)',
            '$x.$(Remove-Item C:\\important).Length',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_provable_pure_member_read_is_removable(self):
        for source in (
            '[Diagnostics.Process]::GetCurrentProcess().ProcessName',
            '(Get-Date).Ticks',
            '[Environment]::UserName',
            '[Threading.Thread]::CurrentThread.ManagedThreadId',
            '[Math]::PI',
            '[Int]::MaxValue',
            '[String]::Empty',
        ):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_cast_to_a_type_the_metadata_cannot_resolve_is_kept(self):
        for source in ("[Loader]'payload'", '[Some.Unknown.Type]$x', '[NotAType]42'):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_cast_to_a_collected_type_is_still_removable(self):
        for source in ("[Int]'42'", '[Void]1', '[String]42', '[Char[]]$s', '[ordered]@{ a = 1 }'):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_quoted_member_name_reads_the_same_member_as_a_bare_one(self):
        self.assertTrue(self._pure(self._expression("(Get-Date).'Ticks'")))
        self.assertFalse(self._pure(self._expression("(Get-Process).'Path'")))
        self.assertFalse(self._pure(self._expression('(Get-Date).$($x)')))

    def test_a_member_read_is_kept_unless_the_getter_is_proven_inert(self):
        for source in (
            '(Get-Process).Path',
            '[Diagnostics.Process]::GetCurrentProcess().ExitCode',
            "([ipaddress]'::1').Address",
            '([object]$x).Path',
            '$Host.UI',
            '$reader.EndOfStream',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_forwarding_cmdlet_result_read_is_kept(self):
        for source in (
            '(Get-Random -InputObject $procs).Path',
            '(Get-Random -InputObject $x).ProcessName',
            '(Get-Content $p).Length',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_static_field_read_is_gated_but_an_instance_field_is_not(self):
        self.assertFalse(self._pure(self._expression('[IO.Path]::DirectorySeparatorChar')))
        self.assertTrue(self._pure(self._expression('[Math]::PI')))
        self.assertTrue(self._pure(self._expression('[Int]::MaxValue')))

    def test_a_hash_literal_evaluates_its_keys_as_well_as_its_values(self):
        for source in (
            '@{ $(Start-Process notepad) = 1 }',
            '@{ 1 = $(Start-Process notepad) }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_cmdlet_is_no_purer_than_the_arguments_it_evaluates(self):
        for source in (
            'Out-String -InputObject (Start-Process notepad)',
            'Measure-Object -InputObject (Start-Process notepad)',
            'Get-Item (Remove-Item C:\\important)',
            'Where-Object -InputObject (Start-Process notepad) { $_ }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_member_invoking_foreach_has_no_body_to_vouch_for_it(self):
        for source in (
            'Get-ChildItem | ForEach-Object -MemberName Delete',
            'Get-Process | ForEach-Object Kill',
            'Get-Process | ForEach-Object $handler',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_an_in_place_mutator_is_pure_only_on_a_temporary(self):
        for source, pure in (
            ("[Array]::Reverse('ab'.ToCharArray())", True),
            ('[Array]::Reverse((1, 2, 3))', True),
            ('[Array]::Reverse($buffer)', False),
            ('[Array]::Sort($buffer)', False),
            ('[Array]::Clear($buffer, 0, 2)', False),
            ('[Array]::Reverse($this.Items)', False),
            ('[Array]::Reverse($pair[0])', False),
        ):
            with self.subTest(source):
                self.assertIs(self._pure(self._expression(source)), pure)

    def test_an_out_parameter_writes_the_callers_storage(self):
        for source in (
            '[Int]::TryParse($s, [ref]$n)',
            '[Int32]::TryParse($s, [ref]$n)',
            '[Int64]::TryParse($s, [ref]$n)',
            '[Double]::TryParse($s, [ref]$n)',
            '[Decimal]::TryParse($s, [ref]$n)',
            '[DateTime]::TryParse($s, [ref]$d)',
            '[TimeSpan]::TryParse($s, [ref]$t)',
            '[IPAddress]::TryParse($s, [ref]$a)',
            '[Guid]::TryParse($s, [ref]$g)',
            '[Version]::TryParse($s, [ref]$v)',
            '[Char]::TryParse($s, [ref]$c)',
            '[Int]::TryParse($s, [ref]$obj.Slot)',
            '$dict.TryGetValue($k, [ref]$v)',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_call_that_only_returns_its_result_stays_pure(self):
        for source in (
            '[Int]::Parse($s)',
            '[Math]::Max($a, $b)',
            "[String]::Join(',', $parts)",
            '[Convert]::ToBase64String($b)',
        ):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_bare_out_argument_is_caught_by_the_signature(self):
        for source, pure in (
            ('[Int]::TryParse($s, $r)', False),
            ('[Int32]::TryParse($s, $r)', False),
            ('[DateTime]::TryParse($s, $d)', False),
            ('[IPAddress]::TryParse($s, $a)', False),
            ('[Int]::TryParse($s, $obj.Slot)', False),
            ('[Int]::TryParse($s, $arr[0])', False),
            ('[Int]::Parse($s)', True),
        ):
            with self.subTest(source):
                self.assertIs(self._pure(self._expression(source)), pure)

    def test_a_types_spelling_does_not_change_its_purity(self):
        for variants in (
            ('[int]::Parse($s)', '[Int32]::Parse($s)', '[System.Int32]::Parse($s)'),
            (
                "New-Object 'Collections.Generic.List[byte]'",
                "New-Object 'System.Collections.Generic.List[byte]'",
            ),
        ):
            with self.subTest(variants):
                verdicts = {self._pure(self._expression(v)) for v in variants}
                self.assertEqual(verdicts, {True})

    def test_a_member_that_writes_whatever_it_is_handed(self):
        self.assertFalse(self._pure(self._expression('[IO.Path]::GetTempFileName()')))
        self.assertTrue(self._pure(self._expression('[IO.Path]::Combine($a, $b)')))
        self.assertTrue(self._pure(self._expression('[IO.Path]::GetFileName($p)')))

    def test_a_parameter_that_names_a_variable_the_command_fills(self):
        for source in (
            'Get-Date -OutVariable d',
            'Get-Date -outvariable d',
            'Get-Date -OutVar d',
            'Get-Date -ov d',
            'Get-Date -ov:$d',
            'Get-Process -ErrorVariable e',
            'Get-ChildItem -PipelineVariable p',
            'Get-Content x -WarningVariable w',
            'Get-Random -SetSeed 5',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_the_write_parameter_derivation_fails_loud_when_data_drops_one(self):
        from refinery.lib.scripts.ps1 import data

        reduced = {
            name: aliases
            for name, aliases in data.COMMON_PARAMETERS.items()
            if name != 'outvariable'
        }
        with self.assertRaises(ValueError):
            data._derive_out_variable_parameters(reduced)

    def test_a_command_that_only_reads_stays_pure(self):
        for source in (
            'Get-Date -Format o',
            'Get-ChildItem -Recurse',
            'Get-Item x -Force',
            'Get-Random -Maximum 5',
            '1..3 | Select-Object -First 2',
        ):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_constructor_is_judged_by_every_argument_it_is_handed(self):
        for source in (
            "New-Object String 'x' (Start-Process notepad)",
            'New-Object Text.StringBuilder (Start-Process notepad)',
            'New-Object Text.StringBuilder ([ref]$n)',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_type_grants_purity_to_its_members_one_by_one(self):
        for source, pure in (
            ("[Environment]::GetFolderPath('Desktop')", True),
            ("[Environment]::GetEnvironmentVariable('PATH')", True),
            ('[Environment]::Exit(0)', False),
            ("[Environment]::SetEnvironmentVariable('k', 'v')", False),
        ):
            with self.subTest(source):
                self.assertIs(self._pure(self._expression(source)), pure)

    def test_a_redirection_writes_a_file_however_pure_the_command_is(self):
        for source in (
            'Get-Date > C:\\out.txt',
            'Get-Content a.txt >> b.txt',
            'Get-Process 2> C:\\err.txt',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_no_combining_form_launders_an_effect(self):
        for source in (
            '1 + (Start-Process notepad)',
            '@(1, (Start-Process notepad))',
            '-(Start-Process notepad)',
            '((Start-Process notepad))',
            '@{ k = (Start-Process notepad) }',
            '$(Start-Process notepad)',
            '1..3 | ForEach-Object { Start-Process notepad }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))


class TestPs1ACallIsJudgedByTheSlotTheOverloadItBindsFills(Ps1EffectsTest):

    @opportunity
    def test_an_arity_no_overload_of_the_member_takes_writes_nothing(self):
        for source in (
            '[Convert]::ToBase64CharArray($a, 0, 2, $b)',
            '[Convert]::ToBase64CharArray($a, 0, 2, $b, 0, 9, 9)',
        ):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_an_arity_the_member_takes_is_judged_by_what_stands_in_the_slot_it_fills(self):
        for source, pure in (
            ('[Convert]::ToBase64CharArray($a, 0, 2, $b, 0)', False),
            ('[Convert]::ToBase64CharArray($a, 0, 2, $b, 0, 1)', False),
            ('[Convert]::ToBase64CharArray($a, 0, 2, (1, 2, 3), 0)', True),
            ('[Buffer]::BlockCopy($s, 0, $d, 0, 3)', False),
            ('[Buffer]::BlockCopy($s, 0, (1, 2, 3), 0, 3)', True),
        ):
            with self.subTest(source):
                self.assertIs(self._pure(self._expression(source)), pure)


class TestPs1MemberGateWorld(Ps1EffectsTest):

    def test_each_grant_is_withheld_when_the_world_is_open(self):
        for source in (
            "'abcdef'.Length",
            '(Get-Date).Ticks',
            '[Environment]::UserName',
            '[Math]::Max(1, 2)',
            '$s.Trim()',
            "[Array]::Reverse('ab'.ToCharArray())",
            'New-Object System.Version(1, 2)',
        ):
            with self.subTest(source):
                self.assertFalse(is_side_effect_free(self._expression(source), _NO_WORLD))
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_denied_read_stays_impure_even_under_a_closed_world(self):
        for source in (
            '(Get-Process).Path',
            '[Diagnostics.Process]::GetCurrentProcess().ExitCode',
            '[Array]::Reverse($buffer)',
            '[IO.Path]::GetTempFileName()',
        ):
            with self.subTest(source):
                self.assertFalse(is_side_effect_free(self._expression(source), _NO_WORLD))
                self.assertFalse(self._pure(self._expression(source)))


class TestPs1CommandShadowing(Ps1EffectsTest):

    @staticmethod
    def _shadowing(*names: str) -> Ps1WorldReach:
        return Ps1WorldReach(Ps1TypeWorld(True, frozenset(names)))

    def test_a_shadowed_commands_read_and_call_are_impure(self):
        world = self._shadowing('get-date', 'new-object')
        for source in ('(Get-Date).Ticks', 'Get-Date', 'New-Object System.Version'):
            with self.subTest(source):
                self.assertFalse(is_side_effect_free(self._expression(source), world))

    def test_a_shadowed_pipeline_sink_does_not_discard(self):
        world = self._shadowing('out-null', 'foreach-object')
        for source in ('1 | Out-Null', '1 | ForEach-Object { [Void]$_ }'):
            with self.subTest(source):
                self.assertIs(
                    statement_effect(self._statement(source), world), StatementEffect.EFFECT)

    def test_an_unshadowed_command_stays_pure_beside_a_shadowed_one(self):
        world = self._shadowing('get-date')
        self.assertTrue(is_side_effect_free(self._expression('Get-ChildItem'), world))
        self.assertTrue(is_side_effect_free(self._expression('New-Object System.Version'), world))


class TestPs1StatementEffect(Ps1EffectsTest):

    def test_a_statement_that_only_yields_a_value_is_output(self):
        for source in ('42', "'hi'", '$x', '1 + 1', 'Get-Date'):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.OUTPUT)

    def test_a_statement_that_does_something_is_an_effect(self):
        for source in ('Write-Host hi', '$x = 1', '$x++', 'if ($a) { }'):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_the_discard_idioms_emit_nothing(self):
        for source in (
            '$Null = 5',
            '[Void]1',
            '1..3 | Out-Null',
            '1..3 | ForEach-Object { [Void]$_ }',
            '1..3 | ForEach-Object { $Null = $_ }',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.DISCARD)

    def test_a_discard_idiom_wrapped_around_an_effect_is_still_an_effect(self):
        for source in (
            '$Null = Start-Process notepad',
            '[Void](Start-Process notepad)',
            '[Void]$(Remove-Item C:\\important)',
            '1..3 | ForEach-Object { [Void](Start-Process notepad) }',
            '1..3 | ForEach-Object { $Null = Start-Process notepad }',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_a_discard_of_a_harmless_value_stays_a_discard(self):
        for source in ('$Null = 5', '[Void]1', '[Void]$x', "[Void]('a' + 'b')"):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.DISCARD)

    def test_a_foreach_is_judged_by_all_of_its_work_not_only_its_blocks(self):
        for source in (
            'Get-Process | ForEach-Object { [Void]$_ } -MemberName Kill',
            'Get-Process | ForEach-Object { [Void]$_ } Kill',
            'Get-ChildItem | ForEach-Object { $Null = $_ } -MemberName Delete',
            '1..3 | ForEach-Object -Process { [Void]$_ } -End $sb',
            '1..3 | ForEach-Object { [Void]$_ } $sb',
            "Get-Process | ForEach-Object { [Void]$_ } -MemberName @'\nKill\n'@",
            "Get-ChildItem | ForEach-Object { $Null = $_ } @'\nDelete\n'@",
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_foreach_body_is_read_through_every_block_it_owns(self):
        for source in (
            '1..3 | ForEach-Object { end { Remove-Item C:\\important } }',
            '1..3 | ForEach-Object { begin { Start-Process notepad } process { [Void]$_ } }',
            '1..3 | ForEach-Object { param($p = (Start-Process notepad)) [Void]$_ }',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_a_foreach_whose_work_is_all_visible_is_still_a_discard(self):
        for source in (
            '1..3 | ForEach-Object { [Void]$_ }',
            '1..3 | ForEach-Object -Process { $Null = $_ }',
            '1..3 | ForEach-Object -Begin { [Void]$_ } -Process { $Null = $_ }',
            '1..3 | ForEach-Object -InputObject 5 -Process { [Void]$_ }',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.DISCARD)

    def test_a_splatted_argument_hides_the_parameters_it_supplies(self):
        for source in ('Get-Date @options', 'Get-ChildItem @options | Out-Null'):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_a_pure_pipeline_cmdlet_still_yields_a_value_a_caller_may_want(self):
        self.assertTrue(self._pure(self._expression('1..3 | Where-Object { $_ }')))
        self.assertIn(
            self._effect(self._statement('1..3 | Where-Object { $_ }')),
            (StatementEffect.EFFECT, StatementEffect.OUTPUT),
        )

    @opportunity
    def test_a_pure_pipeline_cmdlet_yields_its_value_as_output(self):
        self.assertIs(
            self._effect(self._statement('1..3 | Where-Object { $_ }')), StatementEffect.OUTPUT
        )


class TestPs1ACallThatReturnsNothingEmitsNothing(Ps1EffectsTest):

    def test_a_void_static_call_over_a_temporary_writes_nothing(self):
        for source in (
            "[Array]::Reverse('abc'.ToCharArray())",
            "[Array]::Sort('cba'.ToCharArray())",
            "[Array]::Clear('abc'.ToCharArray(), 0, 2)",
            "[Array]::Copy('ab'.ToCharArray(), 'cd'.ToCharArray(), 2)",
            "[Array]::ConstrainedCopy('ab'.ToCharArray(), 0, 'cd'.ToCharArray(), 0, 2)",
            "[System.Array]::Reverse('abc'.ToCharArray())",
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.DISCARD)

    def test_a_static_call_that_produces_a_value_yields_it(self):
        for source in (
            "[Array]::IndexOf('abc'.ToCharArray(), [Char]98)",
            "[Array]::BinarySearch('abc'.ToCharArray(), [Char]98)",
            '[Math]::Sqrt(36)',
            '[Math]::Abs(-3)',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.OUTPUT)

    def test_a_void_call_that_writes_to_the_host_is_an_effect(self):
        for source in ("[Console]::WriteLine('x')", "[Console]::Write('x')", '[Console]::Beep()'):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_a_void_call_over_storage_the_script_reads_back_is_an_effect(self):
        for source in (
            '[Array]::Reverse($buffer)',
            '[Array]::Clear($buffer, 0, 2)',
            '[Array]::Reverse($this.Items)',
            '[Array]::Reverse($pair[0])',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_a_conversion_before_the_slot_does_not_make_the_argument_a_temporary(self):
        for source in (
            '[Array]::Reverse($buffer -as [array])',
            '[Array]::Reverse([int[]]$buffer)',
            '[Array]::Reverse(($buffer))',
        ):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    @opportunity
    def test_a_void_instance_call_over_a_temporary_writes_nothing(self):
        self.assertIs(
            self._effect(self._statement("'abc'.ToCharArray().SetValue([Char]122, 0)")),
            StatementEffect.DISCARD,
        )

    @opportunity
    def test_an_arity_no_overload_binds_writes_nothing(self):
        self.assertIs(
            self._effect(self._statement("[Array]::Reverse('abc'.ToCharArray(), 0)")),
            StatementEffect.DISCARD,
        )


class TestPs1FaultFreedom(Ps1EffectsTest):

    def test_literals_and_builtin_constants_cannot_raise(self):
        for source in ('42', '3.5', "'hi'", '$Null', '$True', '$False', '(7)', '-3', '+9'):
            with self.subTest(source):
                self.assertTrue(is_fault_free(self._expression(source)))

    def test_a_container_of_things_that_cannot_raise_cannot_raise(self):
        for source in (
            '@(1, 2, 3)',
            "@('a', 'b')",
            '@{ a = 1; b = 2 }',
            "@{ 'k' = 'v' }",
            '@{}',
            '1..5',
            '@(1, @(2, @{ c = 3 }))',
        ):
            with self.subTest(source):
                self.assertTrue(is_fault_free(self._expression(source)))

    def test_a_container_is_only_as_safe_as_what_it_holds(self):
        for source in (
            "@(1, [Int]'abc')",
            "@{ a = [Int]'abc' }",
            '@{ a = $x }',
            '$lo..$hi',
            '@($x)',
        ):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_hash_literal_powershell_refuses_to_build_is_not_fault_free(self):
        # 5.1 refuses each of these before the script runs: it compares literal keys as text and
        # ignores case, so `1` and `'1'` are the same key.
        for source in ('@{ a = 1; a = 2 }', '@{ a = 1; A = 2 }', "@{ 1 = 'x'; '1' = 'y' }"):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_key_that_cannot_be_compared_is_not_a_key_proven_distinct(self):
        for source in ('@{ $k = 1 }', "@{ 1.5 = 1; '1.5' = 2 }"):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_an_operator_that_converts_to_int_raises_on_a_string_it_accepts(self):
        for source in ("-'Xtjbnwqm'", "+'Xtjbnwqm'", "'a'..'z'", "1..'z'", "@('a'..'z')"):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_range_bound_that_does_not_fit_in_int32_is_not_fault_free(self):
        for source in ('4242424242..4242424245', '1..4242424242', '1..2147483648'):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_range_whose_bounds_fit_but_whose_span_does_not_is_not_fault_free(self):
        for source in ('0..2147483647', '(-2147483648)..2147483647', '2147483647..0'):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_short_range_of_int32_literals_is_still_fault_free(self):
        for source in (
            '1..5',
            '(-3)..(+9)',
            '(-2147483648)..(-2147483640)',
            '2147483647..2147483640',
        ):
            with self.subTest(source):
                self.assertTrue(is_fault_free(self._expression(source)))

    def test_side_effect_free_is_not_an_answer_to_this_question(self):
        for source in ("[Int]'abc'", '$a / $b', '$a[$i]', '[Math]::Sqrt($x)'):
            with self.subTest(source):
                expression = self._expression(source)
                self.assertTrue(self._pure(expression))
                self.assertFalse(is_fault_free(expression))

    def test_a_call_is_never_granted_however_safe_it_looks(self):
        for source in ('[Math]::Sqrt(36)', 'Get-Random', "[Convert]::ToInt32('x')"):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))


class TestPs1FaultFreedomGrantsWhatPowerShellEvaluates(Ps1EffectsTest):

    def test_an_expression_that_evaluates_to_a_value_is_fault_free(self):
        for source in (
            '6 * 7',
            "[Int]'42'",
            '1 / 1',
            '10 % 3',
            '[Char]65',
            "'ab' + 'cd'",
            '[String]12',
            '3 -band 1',
            "[Bool]'x'",
            '-0.5',
            "'abc'",
            '42',
            '$True',
            '$Null',
            '(42)',
            "'a' -eq 'A'",
            '1 -lt 2',
            '[Long]42',
            '[Double]1',
            "'42' + 1",
        ):
            with self.subTest(source):
                self.assertTrue(is_fault_free(self._expression(source)))


class TestPs1FaultFreedomGrantsWhatCannotFailToBuild(Ps1EffectsTest):

    def test_a_construction_over_safe_parts_is_fault_free(self):
        for source in (
            '1..5',
            '0..0',
            '@{ a = 1 }',
            '@{ a = 1; b = 2 }',
            '@()',
            '@(1, 2, 3)',
            "@('a', @(1, 2))",
        ):
            with self.subTest(source):
                self.assertTrue(is_fault_free(self._expression(source)))


class TestPs1FaultFreedomRefusesWhatPowerShellRaisesOn(Ps1EffectsTest):

    def test_an_expression_that_terminates_the_script_is_not_fault_free(self):
        for source in (
            "[Int]'abc'",
            '1 / 0',
            "[Convert]::ToInt32('x')",
            "'abc'.Substring(5)",
            "'a'..'e'",
            "@{ a = 1; 'a' = 2 }",
            "-'abc'",
        ):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))


class TestPs1FaultFreedomRefusesAnOutcomeItCannotKnow(Ps1EffectsTest):

    def test_an_expression_over_an_unknown_is_not_fault_free(self):
        for source in (
            '$x',
            '$x + 1',
            '[Int]$x',
            '@{ a = $x }',
            '1..$x',
            'Get-Random',
            '[Math]::Sqrt(36)',
            '$a[$i]',
        ):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))


class TestPs1CertainThrowProvesWhatTheHostRaisesOn(Ps1EffectsTest):

    def test_an_expression_the_host_certainly_raises_on_is_a_certain_throw(self):
        for source in (
            "[Int]'abc'",
            "[Int]'1_0'",
            "[Int]'0b10'",
            "[Int]'1kb'",
            '[Byte]999',
            '[Byte]-1',
            '[SByte]200',
            '[Int]2147483648',
            '[Char]65536',
            "[Char]'ab'",
            '1 / 0',
            '7 % 0',
            '1d / 0d',
            "1 + 'abc'",
            "'abc' -band 5",
            '@(1, 2) * 2147483648',
        ):
            with self.subTest(source):
                self.assertTrue(certainly_throws(self._expression(source)))

    @opportunity
    def test_a_throw_a_short_circuit_cannot_skip_is_a_certain_throw(self):
        for source in ('$true -and (1 / 0)', '$false -or (1 / 0)'):
            with self.subTest(source):
                self.assertTrue(certainly_throws(self._expression(source)))

    def test_a_throw_statement_is_a_certain_throw_whatever_it_raises(self):
        for source in ('throw', "throw 'boom'", 'throw (Get-Thing)'):
            with self.subTest(source):
                self.assertTrue(certainly_throws(self._statement(source)))


class TestPs1CertainThrowDeclinesEverythingItCannotProve(Ps1EffectsTest):

    def test_a_value_the_host_converts_is_not_a_certain_throw(self):
        for source in (
            "[Int]'1e3'",
            "[Int]'1,000'",
            "[Int]'3.9'",
            "[Int]''",
            "[Int]'0x10'",
            "1 + '1,000'",
            "1 + '1kb'",
        ):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_a_throw_that_a_path_may_skip_is_not_certain(self):
        for source in (
            '$false -and (1 / 0)',
            "$true -or [Int]'abc'",
        ):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_a_string_that_only_concatenates_or_repeats_is_not_coerced(self):
        for source in ("'abc' + 1", "'abc' * 2"):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_an_index_out_of_range_is_mode_dependent_and_never_certain(self):
        self.assertFalse(certainly_throws(self._expression('@(1, 2)[9]')))

    def test_an_operand_the_domain_does_not_hold_is_not_a_certain_throw(self):
        for source in ("[Int]$x", '1 / $x', '$x + 1', 'Get-Thing', "[DateTime]'x'"):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_an_operator_that_never_reads_its_string_as_a_number_is_not_a_certain_throw(self):
        for source in (
            "$false -and 'abc'",
            "$true -or 'abc'",
            "'abc' -xor $true",
            "'a,b' -split ','",
            "'abc' -like '*b*'",
            "'abc' -match 'b'",
            "'x' -in 1, 2, 3",
            "'abc' -contains 'a'",
            "'{0}' -f 'x'",
        ):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_a_hex_prefixed_or_whitespace_wrapped_cast_string_is_not_a_certain_throw(self):
        # 5.1's integer cast reads `&h`, `#` and `0x` as hex prefixes and trims Unicode whitespace
        # first, so each of these converts.
        sources = ["[Int]'&hFF'", "[Int]'#FF'", "[Int]'0xFF'"]
        sources += [F"[Int]'{pad}5'" for pad in (chr(0x0B), chr(0x0C), chr(0xA0))]
        for source in sources:
            with self.subTest(repr(source)):
                self.assertFalse(certainly_throws(self._expression(source)))


class TestPs1FaultFreedomAndSideEffectFreedomAreIndependent(Ps1EffectsTest):

    def test_a_pure_expression_may_still_raise(self):
        for source, side_effect_free, fault_free in (
            ('42', True, True),
            ("[Int]'42'", True, True),
            ('[Int]$x', True, False),
            ('$a / $b', True, False),
            ('$a[$i]', True, False),
        ):
            with self.subTest(source):
                expression = self._expression(source)
                self.assertEqual(
                    (self._pure(expression), is_fault_free(expression)),
                    (side_effect_free, fault_free),
                )


class TestPs1ReadingThePipelineEnumeratorIsNotAPureRead(Ps1EffectsTest):

    def test_a_bare_read_of_the_enumerator_is_not_pure(self):
        self.assertFalse(self._pure(self._expression('$input')))

    def test_the_spelling_does_not_decide_it(self):
        for source in ('$input', '${input}', '$INPUT'):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_every_other_bare_read_stays_pure(self):
        for source in ('$x', '$inputs', '$myinput', '$args', '$_'):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_the_statement_acts_where_the_same_statement_over_any_other_name_only_writes(self):
        self.assertEqual(
            {
                source: self._effect(self._statement(source))
                for source in ('$input', '$x')
            },
            {'$input': StatementEffect.EFFECT, '$x': StatementEffect.OUTPUT},
        )


class TestPs1EffectInvariant(Ps1EffectsTest):

    def _violations(self, source: str):
        script = self._parse(source)
        found = []
        for node in script.walk():
            if not isinstance(node, Statement):
                continue
            if self._effect(node) is StatementEffect.EFFECT:
                continue
            for sub in node.walk():
                if sub is node:
                    continue
                if isinstance(sub, (Ps1CommandInvocation, Ps1InvokeMember)):
                    if not self._pure(sub):
                        found.append(sub)
                elif isinstance(sub, Ps1UnaryExpression) and sub.operator in ('++', '--'):
                    found.append(sub)
        return found

    def test_a_removable_statement_never_hides_work(self):
        for source in (
            '[Void](Start-Process notepad)',
            '$Null = Start-Process notepad',
            '$Null = 5',
            '[Void]1',
            '1 | Out-Null -InputObject (Start-Process notepad)',
            '1..3 | ForEach-Object { [Void](Start-Process notepad) }',
            '1..3 | ForEach-Object { $_ } | Out-Null',
            '1..3 | ForEach-Object { $Null = $_ }',
            'Get-Process | ForEach-Object -MemberName Kill',
            'Get-Date > C:\\out.txt',
            'Get-Date -OutVariable d',
            '[Environment]::Exit(0)',
            '[Array]::Reverse($buffer)',
            '[Int]::TryParse($s, [ref]$n)',
            '[Int]::TryParse($s, $n)',
            '[IO.Path]::GetTempFileName()',
            "New-Object String 'x' (Start-Process notepad)",
            '[Void]$a[$i++]',
            '$Null = $x++',
            "$Null = 'a' + $(Start-Process notepad)",
            "@(1, 2) | Where-Object { $_ -GT 1 } | ForEach-Object { [Void](Remove-Item $_) }",
        ):
            with self.subTest(source):
                self.assertEqual(self._violations(source), [])


_PROPAGATING_BODIES = cleandoc(
    """
    if ($a) { 1 } else { 2 }
    while ($a) { 3 }
    do { 4 } while ($a)
    for ($i = 0; $i -lt 3; $i++) { 5 }
    foreach ($i in $x) { 6 }
    switch ($a) { 1 { 7 } default { 8 } }
    try { 9 } catch { 10 } finally { 11 }
    trap { 12 }
    &{ 13 }
    . { 14 }
    """
)

class TestPs1OutputSink(Ps1EffectsTest):

    @staticmethod
    def _owning_body(node):
        cursor = node.parent
        while cursor is not None:
            if get_body(cursor) is not None:
                return cursor
            cursor = cursor.parent
        return None

    def test_the_script_root_writes_to_the_host(self):
        self.assertIs(output_sink(self._parse('42')), OutputSink.HOST)

    def test_only_a_function_body_is_a_caller_boundary(self):
        for source in ('function f { 42 }', 'filter f { 42 }'):
            with self.subTest(source):
                block = self._first(source, Ps1ScriptBlock)
                self.assertIs(output_sink(block), OutputSink.CALLER)
        method = self._first('class C { [Int] m() { return 42 } }', Ps1ScriptBlock)
        self.assertIs(output_sink(method), OutputSink.CALLER)

    def test_a_scriptblock_run_in_statement_position_writes_through_to_the_host(self):
        for source in ('&{ 42 }', '. { 42 }'):
            with self.subTest(source):
                block = self._first(source, Ps1ScriptBlock)
                self.assertIs(output_sink(block), OutputSink.HOST)

    def test_a_scriptblock_run_in_statement_position_inside_a_function_reaches_its_caller(self):
        block = self._first('function f { &{ 42 } }', Ps1CommandInvocation).name
        self.assertIs(output_sink(block), OutputSink.CALLER)

    def test_a_captured_body_is_never_pruned(self):
        for source in (
            '$cb = { 42 }',
            '&{ 42 } | Out-Null',
            'Foo-Bar { 42 }',
            'Get-Item | ForEach-Object { 42 }',
        ):
            with self.subTest(source):
                block = self._first(source, Ps1ScriptBlock)
                self.assertIs(output_sink(block), OutputSink.CAPTURED)

    def test_a_subexpression_is_captured(self):
        self.assertIs(
            output_sink(self._first('$x = $( 42 )', Ps1SubExpression)), OutputSink.CAPTURED)

    def test_an_array_expression_owns_no_prunable_body(self):
        self.assertIsNone(output_sink(self._first('$x = @( 42 )', Ps1ArrayExpression)))

    def test_a_node_that_owns_no_body_has_no_sink(self):
        self.assertIsNone(output_sink(self._expression('42')))

    def _call_to_f(self, source: str) -> Ps1CommandInvocation:
        return next(
            node for node in self._parse(source).walk_in_order()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'f'
        )

    def test_a_value_position_the_walk_cannot_read_is_captured(self):
        for source in (
            "[IO.File]::WriteAllText('C:\\x', (f))",
            'Write-Host (f)',
            'if (f) { 1 }',
            'while (f) { 1 }',
            'foreach ($i in f) { 1 }',
            'switch (f) { 1 { 2 } }',
            'for (; f; ) { 1 }',
            'do { 1 } while (f)',
            'function g { param($p = (f)) 1 }',
            '$a = @(1, 2)[(f)]',
            'throw (f)',
            '[Int](f)',
            '-not (f)',
            "(f) -join ','",
            '$o.M((f))',
        ):
            with self.subTest(source):
                self.assertIs(output_path(self._call_to_f(source)).sink, OutputSink.CAPTURED)

    def test_a_call_the_walk_does_read_still_reaches_its_reader(self):
        for source, expected in (
            ('f'                    , OutputSink.HOST),      # noqa
            ('if ($x) { f }'        , OutputSink.HOST),      # noqa
            ('&{ f }'               , OutputSink.HOST),      # noqa
            ('try { f } catch { 1 }', OutputSink.HOST),      # noqa
            ('Get-Item | f'         , OutputSink.HOST),      # noqa
            ('return f'             , OutputSink.HOST),      # noqa
            ('exit (f)'             , OutputSink.CAPTURED),  # noqa
            ('f | Out-Null'         , OutputSink.CAPTURED),  # noqa
            ('$r = f'               , OutputSink.CAPTURED),  # noqa
            ('$r = $( f )'          , OutputSink.CAPTURED),  # noqa
            ('function g { f }'     , OutputSink.CALLER),    # noqa
            ('function g { return f }', OutputSink.CALLER),  # noqa
        ):
            with self.subTest(source):
                self.assertIs(output_path(self._call_to_f(source)).sink, expected)

    def test_a_nested_block_answers_with_whoever_reads_the_body_holding_it(self):
        for source in ('if ($x) { 1 }', 'function f { if ($x) { 1 } }', '&{ if ($x) { 1 } }'):
            with self.subTest(source):
                block = self._first(source, Ps1IfStatement).clauses[0][1]
                self.assertIs(output_sink(block), output_sink(self._owning_body(block)))

    def test_a_block_inside_a_captured_body_is_captured(self):
        for source in (
            '$cb = { if ($x) { 1 } }',
            '$y = $( if ($x) { 1 } )',
            '$z = @( if ($x) { 1 } )',
            'data d { if ($x) { 1 } }',
        ):
            with self.subTest(source):
                block = self._first(source, Ps1IfStatement).clauses[0][1]
                self.assertIs(output_sink(block), OutputSink.CAPTURED)

    def test_a_propagating_body_answers_with_whoever_reads_the_body_holding_it(self):
        for wrap, expected in (
            ('%s', OutputSink.HOST),
            ('function outer {\n%s\n}', OutputSink.CALLER),
        ):
            script = self._parse(wrap % _PROPAGATING_BODIES)
            walked = 0
            for node in script.walk():
                if get_body(node) is None or node is script:
                    continue
                if isinstance(node.parent, Ps1FunctionDefinition) and node.parent.body is node:
                    continue
                holder = self._owning_body(node)
                if holder is None:
                    continue
                with self.subTest(F'{expected.name} {node!r}'):
                    walked += 1
                    self.assertIs(output_sink(node), output_sink(holder))
                    self.assertIs(output_sink(node), expected)
            self.assertGreater(walked, 10)


class TestPs1WhatAScriptAddsToARun(Ps1EffectsTest):

    @classmethod
    def _contribution(cls, source: str) -> Contribution:
        script = cls._parse(source)
        return script_contribution(script, Ps1ModelCache(script).world_reach)

    def _assert_contributions(self, *cases: tuple[str, Contribution]):
        for source, expected in cases:
            with self.subTest(source):
                self.assertEqual(self._contribution(source), expected)

    def test_commands_calls_and_throws_act(self):
        self._assert_contributions(
            ('Start-Process calc', Contribution.ACTS),
            ("Write-Verbose 'debug'", Contribution.ACTS),
            ('function f { 1 }\nf', Contribution.ACTS),
            ("throw 'x'", Contribution.ACTS),
            ('throw', Contribution.ACTS),
            ('$Null = Start-Process calc', Contribution.ACTS),
            ('[Void](Start-Process calc)', Contribution.ACTS),
        )

    def test_a_store_of_a_value_that_does_something_stores_a_run(self):
        self._assert_contributions(
            ('$x = Start-Process calc', Contribution.STORES_A_RUN),
            ('$x = $y = Start-Process calc', Contribution.STORES_A_RUN),
            ('$a, $b = Start-Process calc', Contribution.STORES_A_RUN),
        )

    def test_bare_values_print(self):
        self._assert_contributions(
            ("'a'", Contribution.PRINTS),
            ("'a' + 'b'", Contribution.PRINTS),
            ("return 'a'", Contribution.PRINTS | Contribution.ENDS),
        )

    def test_exit_and_return_end_the_run(self):
        self._assert_contributions(
            ('exit', Contribution.ENDS),
            ('exit 1', Contribution.ENDS),
            ('return', Contribution.ENDS),
            ('exit (Start-Process calc)', Contribution.ENDS | Contribution.ACTS),
        )

    def test_definitions_add_nothing(self):
        self._assert_contributions(
            ('function f { Start-Process calc }', Contribution.NOTHING),
            ('filter f { Start-Process calc }', Contribution.NOTHING),
            ('class C { [void] m() { Start-Process calc } }', Contribution.NOTHING),
            ('enum E { A; B }', Contribution.NOTHING),
            ('using namespace System', Contribution.NOTHING),
            ('trap { Start-Process calc; continue }', Contribution.NOTHING),
            ("data { 'a' }", Contribution.NOTHING),
        )

    def test_jumps_add_nothing(self):
        self._assert_contributions(
            ('break', Contribution.NOTHING),
            ('continue', Contribution.NOTHING),
        )

    def test_stores_and_discards_of_values_that_do_nothing_add_nothing(self):
        self._assert_contributions(
            ("$x = 'a'", Contribution.NOTHING),
            ("$ErrorActionPreference = 'Stop'", Contribution.NOTHING),
            ('$x++', Contribution.NOTHING),
            ('--$x', Contribution.NOTHING),
            ('$Null = 1', Contribution.NOTHING),
            ('[Void]1', Contribution.NOTHING),
            ("'a' | Out-Null", Contribution.NOTHING),
        )

    def test_a_script_block_does_nothing_until_it_is_called(self):
        self._assert_contributions(
            ('$sb = { Start-Process calc }', Contribution.NOTHING),
            ('$Null = { Start-Process calc }', Contribution.NOTHING),
            ('$sb = { Start-Process calc }\n& $sb', Contribution.ACTS),
        )

    def test_a_compound_statement_adds_what_its_conditions_and_bodies_add(self):
        self._assert_contributions(
            ("if ($x) { 'a' } else { $y = 1 }", Contribution.PRINTS),
            ("if (Start-Process calc) { 'a' }", Contribution.ACTS | Contribution.PRINTS),
            ('while ($i -lt 3) { $i++ }', Contribution.NOTHING),
            ("do { 'a' } while ($false)", Contribution.PRINTS),
            ('for ($i = 0; $i -lt 2; $i++) { Start-Process calc }', Contribution.ACTS),
            ('for ($i = 0; (Start-Process calc); $i++) { }', Contribution.ACTS),
            ("foreach ($i in 1..3) { 'a' }", Contribution.PRINTS),
            ('foreach ($i in (Start-Process calc)) { }', Contribution.ACTS),
            ("switch ($a) { 1 { 'x' } default { return } }", Contribution.PRINTS | Contribution.ENDS),
            ("switch ((Start-Process calc)) { 1 { 'x' } }", Contribution.ACTS | Contribution.PRINTS),
            ("if ($x) { if ($y) { while ($z) { 'deep' } } }", Contribution.PRINTS),
        )

    def test_a_script_block_run_where_it_stands_adds_what_its_body_adds(self):
        self._assert_contributions(
            ("& { 'a' }", Contribution.PRINTS),
            ('. { $x = 1 }', Contribution.NOTHING),
            ('& { Start-Process calc }', Contribution.ACTS),
            ("& { end { 'a' } }", Contribution.PRINTS),
            ('& { param($p = (Start-Process calc)) }', Contribution.ACTS),
            ("& { & { 'a' } }", Contribution.PRINTS),
            ('& { exit }', Contribution.ENDS),
            ("& { 'a' } > out.txt", Contribution.ACTS),
        )

    def test_a_return_leaves_the_script_block_and_not_the_run(self):
        self._assert_contributions(
            ("& { return 'a' }", Contribution.PRINTS),
            ('. { return }', Contribution.NOTHING),
        )

    def test_a_switch_over_a_file_reads_the_file(self):
        self._assert_contributions(
            ("switch -file x.txt { 'a' { 1 } }", Contribution.ACTS),
        )

    def test_a_try_adds_its_try_and_finally_bodies_but_not_its_handlers(self):
        self._assert_contributions(
            ("try { 'a' } catch { Start-Process calc }", Contribution.PRINTS),
            ('try { } finally { Start-Process calc }', Contribution.ACTS),
            ("try { exit } catch { 'b' } finally { $x = 1 }", Contribution.ENDS),
        )

    def test_named_blocks_add_what_they_hold(self):
        self._assert_contributions(
            ('begin { $x = 1 } end { Start-Process calc }', Contribution.ACTS),
            ("end { 'a' }", Contribution.PRINTS),
            ('process { function f { 1 } }', Contribution.NOTHING),
        )

    def test_a_parameter_default_that_does_something_acts(self):
        self._assert_contributions(
            ('param($p = (Start-Process calc))', Contribution.ACTS),
            ("param($p = 1)\n'a'", Contribution.PRINTS),
        )

    def test_a_script_adds_the_union_of_its_statements(self):
        self._assert_contributions(
            ("function f { 1 }\n$x = 'a'\n'b'\nexit", Contribution.PRINTS | Contribution.ENDS),
            ("Start-Process calc\n'b'", Contribution.ACTS | Contribution.PRINTS),
            ('', Contribution.NOTHING),
        )


class TestPs1WhatAScriptIs(Ps1EffectsTest):

    @classmethod
    def _decide(cls, source: str) -> tuple[bool, bool]:
        script = cls._parse(source)
        world = Ps1ModelCache(script).world_reach
        return runs_something(script, world), is_a_library(script, world)

    def test_a_script_that_runs_something_is_not_a_library(self):
        for source in (
            "Start-Process calc\nfunction f { 'a' }",
            'function f { 1 }\nf',
            "throw 'x'",
        ):
            with self.subTest(source):
                self.assertEqual(self._decide(source), (True, False))

    def test_a_file_that_only_defines_and_stores_is_a_library_whatever_it_stores(self):
        for source in (
            "$Version = '1.0'\nfunction Invoke-Thing { Write-Host $Version }",
            'function A { Write-Host 1 }\nfunction B { Write-Host 2 }',
            '',
        ):
            with self.subTest(source):
                self.assertEqual(self._decide(source), (False, True))
        self.assertEqual(self._decide('$p = Start-Process calc\nfunction f { $p }'), (True, True))

    def test_a_file_that_prints_or_ends_its_run_is_not_a_library(self):
        for source in (
            "function f { Write-Host 1 }\n'a'",
            '$p = 1\nfunction f { Write-Host 1 }\nreturn',
            "class C {}\n'a'",
        ):
            with self.subTest(source):
                self.assertEqual(self._decide(source), (False, False))


class TestPs1EmitSafety(Ps1EffectsTest):

    def test_a_sink_that_licenses_deletion_does_not_follow_an_alias(self):
        from refinery.lib.scripts.ps1.analysis import effects
        from refinery.lib.scripts.ps1.analysis.world import build_closed_world

        source = 'function foreach { Start-Process calc }\n1..3 | foreach { $Null = $_ }'
        tree = self._parse(source)
        world = Ps1WorldReach(build_closed_world(tree))
        statement = tree.body[-1]
        self.assertFalse(effects._pipeline_ends_with_void_foreach(statement.expression, world))
        self.assertIsNot(effects.statement_effect(statement, world), StatementEffect.DISCARD)

    def test_a_named_block_body_is_never_inert(self):
        for source in (
            'function f { process { Start-Process notepad } }',
            'function f { begin { Start-Process notepad } }',
            'function f { end { Start-Process notepad } }',
            'function f { param($a) process { Write-Host $a } }',
        ):
            with self.subTest(source):
                self.assertFalse(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_parameter_block_is_code_the_call_runs(self):
        for source in (
            'function f { param($x = (Start-Process notepad)) }',
            'function f { param($x = $(Remove-Item C:\\important)) }',
            'function f { param([ValidateScript({ Start-Process notepad })]$x) }',
            'function f { param([Parameter(Mandatory)]$x) }',
        ):
            with self.subTest(source):
                self.assertFalse(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_parameter_block_that_only_declares_names_runs_nothing(self):
        for source in (
            'function f($a) { }',
            'function j($x) { $Null = 915 }',
            'function f { param($x, $y = 1) }',
            'function f { param([String]$x) }',
        ):
            with self.subTest(source):
                self.assertTrue(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_data_section_captures_the_block_it_binds(self):
        block = self._first('data d { 42 }', Ps1DataSection).body
        self.assertIs(output_sink(block), OutputSink.CAPTURED)

    def test_a_body_of_pure_discards_is_inert(self):
        for source in ('function j { $Null = 915 }', 'function j { }', 'function j { [Void]1 }'):
            with self.subTest(source):
                self.assertTrue(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_body_that_emits_or_acts_is_not_inert(self):
        for source in ('function j { Write-Host hi }', 'function j { 42 }', 'function j { $x++ }'):
            with self.subTest(source):
                self.assertFalse(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_definition_without_a_body_is_inert(self):
        self.assertTrue(self._inert(None))


class TestPs1OpenWorldNameTrust(Ps1EffectsTest):

    OPEN = Ps1WorldReach(Ps1TypeWorld(False, frozenset()))

    def test_an_open_world_grants_no_command_purity(self):
        for source in ('Get-Date', 'New-Object System.Version', '(Get-Date)'):
            with self.subTest(source):
                self.assertTrue(is_side_effect_free(self._expression(source), _CLOSED_WORLD))
                self.assertFalse(is_side_effect_free(self._expression(source), self.OPEN))

    def test_an_open_world_has_no_discarding_pipeline_sink(self):
        for source in ('1 | Out-Null', '1 | ForEach-Object { [Void]$_ }'):
            with self.subTest(source):
                self.assertIs(
                    statement_effect(self._statement(source), _CLOSED_WORLD),
                    StatementEffect.DISCARD)
                self.assertIs(
                    statement_effect(self._statement(source), self.OPEN), StatementEffect.EFFECT)

    def test_an_oracle_without_a_world_withholds_name_trust_too(self):
        self.assertFalse(is_side_effect_free(self._expression('Get-Date'), _NO_WORLD))


class TestPs1OutputPathMarksAHandlerBodyGuarded(Ps1EffectsTest):

    def test_a_trap_body_is_guarded(self):
        trap = self._first("trap { 'h' }; 1", Ps1TrapStatement)
        assert isinstance(trap, Ps1TrapStatement)
        self.assertTrue(output_path(trap.body).guarded)

    def test_a_catch_body_is_guarded(self):
        clause = self._first("try { 1 } catch { 'h' }", Ps1CatchClause)
        assert isinstance(clause, Ps1CatchClause)
        self.assertTrue(output_path(clause.body).guarded)

    def test_a_catch_body_inside_a_function_stays_guarded_across_the_boundary(self):
        clause = self._first("function f { try { 1 } catch { 'h' } }", Ps1CatchClause)
        assert isinstance(clause, Ps1CatchClause)
        path = output_path(clause.body)
        self.assertIs(path.sink, OutputSink.CALLER)
        self.assertTrue(path.guarded)

    def test_a_finally_body_is_not_guarded(self):
        construct = self._first("try { 1 } finally { 'h' }", Ps1TryCatchFinally)
        assert isinstance(construct, Ps1TryCatchFinally)
        self.assertFalse(output_path(construct.finally_block).guarded)

    def test_a_try_body_is_not_guarded(self):
        construct = self._first("try { 'h' } catch { 1 }", Ps1TryCatchFinally)
        assert isinstance(construct, Ps1TryCatchFinally)
        self.assertFalse(output_path(construct.try_block).guarded)

    def test_a_statement_reached_by_ordinary_flow_is_not_guarded(self):
        self.assertFalse(output_path(self._statement("'h'")).guarded)


class TestPs1WhetherAnExpressionCanFaultIsDecidedByTheScriptToo(Ps1EffectsTest):

    @staticmethod
    def _cannot_fault(expression: str, above: str = '', below: str = '') -> bool:
        tree = Ps1Parser(cleandoc(F'{above}{expression}{below}')).parse()
        control_flow = build_control_flow_model(tree)
        world = build_world_reach(measure_world(tree), lambda: control_flow)
        statement = tree.body[above.count(chr(10))]
        calls = Ps1ModelCache(tree).call_graph
        return expression_cannot_fault(
            statement.expression, statement, build_fault_reach(control_flow, lambda: calls), world)

    def _verdicts(self, expressions: list[str], above: str = '') -> dict[str, bool]:
        return {
            expression: self._cannot_fault(expression, above)
            for expression in expressions
        }

    _BARE = ['$x', '${x}', '$Undefined']

    def test_a_bare_variable_read_cannot_fault_where_nothing_arms_strict_mode(self):
        self.assertEqual(self._verdicts(self._BARE), dict.fromkeys(self._BARE, True))

    def test_the_same_reads_can_fault_where_the_script_arms_strict_mode(self):
        self.assertEqual(
            self._verdicts(self._BARE, 'Set-StrictMode -Version 1\n'),
            dict.fromkeys(self._BARE, False),
        )

    def test_the_same_reads_can_fault_below_a_payload_the_analysis_cannot_read(self):
        self.assertEqual(
            self._verdicts(self._BARE, 'Invoke-Expression $env:ZZQ\n'),
            dict.fromkeys(self._BARE, False),
        )

    def test_the_same_reads_cannot_fault_above_that_payload(self):
        self.assertEqual(
            {
                expression: self._cannot_fault(
                    expression, below='\nInvoke-Expression $env:ZZQ')
                for expression in self._BARE
            },
            dict.fromkeys(self._BARE, True),
        )

    @opportunity
    def test_a_qualified_or_member_read_cannot_fault_where_nothing_arms_strict_mode(self):
        expressions = ['$global:x', '$script:x', '$env:x', '$x.Foo']
        self.assertEqual(self._verdicts(expressions), dict.fromkeys(expressions, True))

    def test_no_read_that_is_more_than_a_bare_name_is_granted(self):
        expressions = ['@x', '${zzqdrive:x}', '$x[0]', 'Get-Thing']
        self.assertEqual(self._verdicts(expressions), dict.fromkeys(expressions, False))

    def test_a_member_read_can_fault_below_strict_mode_or_a_payload_the_analysis_cannot_read(self):
        for above in (
            'Set-StrictMode -Version 2\n$x = 1\n',
            '$x = 1\nInvoke-Expression $env:ZZQ\n',
        ):
            with self.subTest(above=above):
                self.assertFalse(self._cannot_fault('$x.Foo', above))

    def test_what_cannot_raise_under_any_semantics_is_granted_under_all_of_them(self):
        expressions = ["'abc'", '42', '6 * 7', "[Int]'42'", '@(1, 2)']
        for above in ('', 'Set-StrictMode -Version 1\n', 'Invoke-Expression $env:ZZQ\n'):
            with self.subTest(above=above):
                self.assertEqual(
                    self._verdicts(expressions, above), dict.fromkeys(expressions, True))

    def test_a_bare_variable_read_is_never_fault_free_on_its_own(self):
        self.assertEqual(
            {e: is_fault_free(self._expression(e)) for e in self._BARE},
            dict.fromkeys(self._BARE, False),
        )

    def test_a_caller_with_no_world_gets_the_context_free_answer_alone(self):
        tree = Ps1Parser('$x').parse()
        statement = tree.body[0]
        calls = Ps1ModelCache(tree).call_graph
        faults = build_fault_reach(build_control_flow_model(tree), lambda: calls)
        self.assertFalse(expression_cannot_fault(statement.expression, statement, faults, None))


class TestPs1AnAdapterMemberIsReadOffTheAdapterAndNotOffTheType(Ps1EffectsTest):

    def test_the_adapter_count_on_a_sealed_type_that_does_not_carry_one_is_pure(self):
        self.assertTrue(_reflection_read_is_pure(
            resolve_type('Microsoft.PowerShell.Commands.TextMeasureInfo'), 'Count'))

    def test_the_adapter_count_on_an_unsealed_type_is_not(self):
        self.assertTrue(_reflection_read_is_pure(
            resolve_type('System.Diagnostics.Process'), 'ProcessName'))
        self.assertFalse(_reflection_read_is_pure(
            resolve_type('System.Diagnostics.Process'), 'PSTypeNames'))

    def test_a_member_the_type_really_carries_is_not_read_off_the_adapter(self):
        self.assertFalse(_reflection_read_is_pure(resolve_type('System.Array'), 'Length'))

    def test_a_member_no_collected_type_carries_stays_refused_on_a_sealed_reference_type(self):
        self.assertFalse(_reflection_read_is_pure(
            resolve_type('Microsoft.PowerShell.Commands.TextMeasureInfo'), 'Nonesuch'))


class TestPs1ADiscardedMeasurementReadsItsCountWithoutRunningCode(Ps1EffectsTest):

    def test_the_whole_pipeline_is_side_effect_free(self):
        self.assertTrue(self._pure(
            self._expression("@('a', 'b') | Measure-Object | ForEach-Object { $_.Count }")))

    @opportunity
    def test_a_length_read_off_the_measurement_runs_no_code(self):
        self.assertTrue(self._pure(
            self._expression("@('a', 'b') | Measure-Object | ForEach-Object { $_.Length }")
        ))

    @opportunity
    def test_a_count_read_off_an_integer_runs_no_code(self):
        self.assertTrue(self._pure(self._expression('1, 2 | ForEach-Object { $_.Count }')))

    def test_a_member_read_on_an_untyped_current_object_is_refused(self):
        self.assertFalse(self._pure(self._expression('$x | ForEach-Object { $_.Count }')))
