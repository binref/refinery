from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts import Statement, _remove_from_parent
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.effects import (
    OutputSink,
    StatementEffect,
    _reflection_read_is_pure,
    body_is_inert,
    certainly_throws,
    expression_cannot_fault,
    is_fault_free,
    is_side_effect_free,
    output_path,
    output_sink,
    pruning_erases_body,
    statement_effect,
    unconsumed_statement,
)
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


#: A type world with no mutation or capability leak, the context in which the member gate performs
#: its full type reasoning. `TestPs1Purity` asserts type facts (this member read is a plain .NET
#: property) against it, because Position A makes a present-member grant conditional on the world
#: being closed; the open-world behaviour it guards is exercised in `TestPs1ClosedWorld`.
_CLOSED_WORLD = Ps1WorldReach(Ps1TypeWorld(True, frozenset()))

#: An open world, which is what a caller holds before anything has been measured. Every
#: present-member grant is withheld, so a read this module proves pure is still kept. Named rather
#: than defaulted: a test asserting open-world behaviour has to say so, and the effect layer no
#: longer lets a call site acquire this answer by omission.
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
        # The allow-list is the whole safety argument: anything it does not name has to come back
        # impure, however harmless it looks.
        for source in ('New-Object System.Net.WebClient', '& $f', '$obj.Frobnicate()'):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_pipeline_cmdlet_is_as_pure_as_the_body_it_runs(self):
        # A scriptblock body is a sequence of statements, so purity of the cmdlet has to be decided
        # at the statement layer: a body of discards is as harmless as one of bare pure expressions.
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
        # Three of the four pipeline cmdlets also name a plain pure cmdlet, so an allow-list that
        # answers on the name alone never reaches the body and calls every one of these pure.
        for source in (
            'Where-Object { Start-Process notepad }',
            'Select-Object { Start-Process notepad }',
            'Sort-Object { Start-Process notepad }',
            '1..3 | ForEach-Object { Start-Process notepad }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_scriptblock_argument_is_read_through_every_block_it_owns(self):
        # The parser fills either `body` or the named blocks, so a block that carries its work in
        # `begin`/`process`/`end` or in a parameter default reports an empty statement list. Judging
        # the cmdlet by that list calls a command that runs on every input item pure.
        for source in (
            'Get-Process | Where-Object { begin { Start-Process notepad } process { $_ } }',
            '1..3 | ForEach-Object { end { Start-Process notepad } }',
            '1..3 | ForEach-Object { param($p = (Start-Process notepad)) [Void]$_ }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_computed_member_name_is_an_expression_the_read_evaluates(self):
        # `$x.$(...)` runs the subexpression to decide which member to read, before any read.
        for source in (
            '$x.$(Start-Process notepad)',
            '[IO.Path]::$(Start-Process notepad)',
            '$x.$(Remove-Item C:\\important).Length',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_provable_pure_member_read_is_removable(self):
        # The object is pure to evaluate and the member read runs no code: a curated reflection
        # property (`Process.ProcessName`, resolved through the static call's return type), any read
        # on a sealed value type (`DateTime.Ticks`), or a reflection field, which is a bare memory
        # slot with no getter (`Math.PI`, `Int32.MaxValue`). The chained read resolves the receiver
        # of `.ManagedThreadId` through `CurrentThread`, itself a curated pure read.
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
        # Converting a string to a custom type runs that type's constructor, and `Add-Type`, a
        # PowerShell `class` and `[Reflection.Assembly]::Load` each make such a name denote code the
        # metadata never saw. Granting on the operand alone deleted the conversion — and the call
        # inside it — even under a closed world, which is where the name is most trusted.
        for source in ("[Loader]'payload'", '[Some.Unknown.Type]$x', '[NotAType]42'):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_cast_to_a_collected_type_is_still_removable(self):
        # The guard above is a resolution check, not a blanket denial: the ordinary casts an
        # obfuscator emits by the dozen have to keep pruning.
        for source in ("[Int]'42'", '[Void]1', '[String]42', '[Char[]]$s', '[ordered]@{ a = 1 }'):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_quoted_member_name_reads_the_same_member_as_a_bare_one(self):
        # A quoted member name (`.'Ticks'`) is one spelling of a literal member, not a computed one,
        # so the gate resolves it to the same member and reaches the same verdict as the bare form:
        # the sealed-value read is removable and the Extended Type System getter is kept. Only a
        # name the engine computes at runtime (`.$(...)`) leaves the member unknown and stays
        # impure.
        self.assertTrue(self._pure(self._expression("(Get-Date).'Ticks'")))
        self.assertFalse(self._pure(self._expression("(Get-Process).'Path'")))
        self.assertFalse(self._pure(self._expression('(Get-Date).$($x)')))

    def test_a_member_read_is_kept_unless_the_getter_is_proven_inert(self):
        # The soundness core: a property getter may run code or throw, and a read is removed only
        # when it is proven not to. Returning the object's own purity — which this gate replaces —
        # deleted every one of these. `Process.Path` is an Extended Type System member that shells
        # out; `Process.ExitCode` throws until the process exits; `IPAddress.Address` throws by
        # address family, which is why that type is not a whole-surface grant; casting to the
        # supertype `object` leaves the runtime type free to carry an effectful member the supertype
        # lacks; and an object whose type is not resolved could be anything at all.
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
        # A cmdlet's [OutputType] is only a lower bound: one that forwards its input emits types it
        # never declares. `Get-Random -InputObject $x` returns an element of $x -- a Process if $x
        # holds processes -- so proving `.Path` pure over its declared numeric outputs would delete
        # a live ETS getter. A declaration is trusted only for a curated closed set, so a
        # read on any forwarding command's result is left unresolved and kept.
        for source in (
            '(Get-Random -InputObject $procs).Path',
            '(Get-Random -InputObject $x).ProcessName',
            '(Get-Content $p).Length',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_static_field_read_is_gated_but_an_instance_field_is_not(self):
        # Reading a static field runs the declaring type's static constructor on first touch, so it
        # is not unconditionally pure the way an instance field is; it is removable only when the
        # type or the read is granted. `Math.PI` and `Int32.MaxValue` are granted; `IO.Path`'s
        # separator fields are not, and its cctor could do anything, so they are kept.
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
        # Being a pure transform says nothing about what the operands cost to produce: the cmdlet
        # runs whatever it is handed before it transforms anything.
        for source in (
            'Out-String -InputObject (Start-Process notepad)',
            'Measure-Object -InputObject (Start-Process notepad)',
            'Get-Item (Remove-Item C:\\important)',
            'Where-Object -InputObject (Start-Process notepad) { $_ }',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_member_invoking_foreach_has_no_body_to_vouch_for_it(self):
        # `ForEach-Object -MemberName Delete` calls that member on every input item. A body check
        # that proves a property of the scriptblocks it saw proves nothing when there are none.
        for source in (
            'Get-ChildItem | ForEach-Object -MemberName Delete',
            'Get-Process | ForEach-Object Kill',
            'Get-Process | ForEach-Object $handler',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_an_in_place_mutator_is_pure_only_on_a_temporary(self):
        # `[Array]::Reverse` rewrites what it is given. Reversing a value nothing else can reach is
        # unobservable; reversing a variable is the mutation the rest of the script reads back.
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
        # `[ref]$x` hands the callee somewhere to put its result. Every `TryParse` on the numeric,
        # date and network types takes one, so a whole-type grant on its own calls them all pure and
        # the deobfuscator drops the statement that produced the value the script goes on to read.
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
        # The rule is about being handed writable storage, not about the call having arguments.
        for source in (
            '[Int]::Parse($s)',
            '[Math]::Max($a, $b)',
            "[String]::Join(',', $parts)",
            '[Convert]::ToBase64String($b)',
        ):
            with self.subTest(source):
                self.assertTrue(self._pure(self._expression(source)))

    def test_a_bare_out_argument_is_caught_by_the_signature(self):
        # `TryParse` binds its second parameter by reference, and PowerShell lets the caller pass
        # the target without a `[ref]` cast. The syntactic check sees only `[ref]$n`; the collected
        # signature is what tells the effect layer that a bare `$r` in that position is written, so
        # a call filling a live variable is not mistaken for a pure transform and dropped. Only a
        # storage location can be written back through, so a temporary in that slot stays pure.
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
        # `int`, `Int32` and the qualified name are one type, and a generic is one type however its
        # argument is spelled; resolving every spelling through the collected data lands them on a
        # single canonical key, so the verdict cannot depend on which an obfuscated script chose.
        # This is the property that retired the dual-spelling allow-list entries.
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
        # A whole-type grant asserts that no member of the type writes. `[IO.Path]` is pure apart
        # from the one member that creates a file on disk, and that one takes no arguments to be
        # judged by.
        self.assertFalse(self._pure(self._expression('[IO.Path]::GetTempFileName()')))
        self.assertTrue(self._pure(self._expression('[IO.Path]::Combine($a, $b)')))
        self.assertTrue(self._pure(self._expression('[IO.Path]::GetFileName($p)')))

    def test_a_parameter_that_names_a_variable_the_command_fills(self):
        # `-OutVariable d` sets `$d`. The parsed parameter name carries its leading dash and
        # PowerShell binds any unambiguous abbreviation, so matching the documented spelling alone
        # recognizes none of these and the deobfuscator drops the statement that fills the variable.
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
        # The out-variable parameters are derived from the collected common parameters. If a
        # regenerated surface stopped flagging one, the set would silently shrink and a real
        # `-OutVariable` write would be judged pure and dropped; the derivation floors itself
        # against that and refuses to build rather than failing open in the deletion direction.
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
        # `New-Object` binds two positional parameters. An accessor that reports the first two and
        # drops the rest leaves the trailing argument unexamined, and a call it runs is deleted.
        for source in (
            "New-Object String 'x' (Start-Process notepad)",
            'New-Object Text.StringBuilder (Start-Process notepad)',
            'New-Object Text.StringBuilder ([ref]$n)',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_a_type_grants_purity_to_its_members_one_by_one(self):
        # A type whose static surface mixes readers with process- and environment-level writers
        # cannot be trusted wholesale, so membership is per method.
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
        # Purity is compositional: an impure operand must poison every expression built over it,
        # otherwise a pass could delete the effect by wrapping it.
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


class TestPs1ACallBindingNoOverloadIsWorkTheScriptStillPerforms(Ps1EffectsTest):
    """
    `[Convert]::ToBase64CharArray` takes five arguments or six, so a call at any other count binds
    none of them: 5.1 fills nothing and writes a `MethodException` the pipeline carries on. Purity
    would delete the statement and the error record with it.

    `System.Convert` is the type where a miss is felt, because the rest of its static surface is
    trusted wholesale: an arity the written-slot table does not cover reaches that grant unless the
    miss is reported as doubt rather than as the claim that this call writes nothing.
    """

    def test_an_arity_no_overload_of_the_member_takes_is_not_pure(self):
        for source in (
            '[Convert]::ToBase64CharArray($a, 0, 2, $b)',
            '[Convert]::ToBase64CharArray($a, 0, 2, $b, 0, 9, 9)',
        ):
            with self.subTest(source):
                self.assertFalse(self._pure(self._expression(source)))

    def test_an_arity_the_member_takes_is_judged_by_what_stands_in_the_slot_it_fills(self):
        for source, pure in (
            ('[Convert]::ToBase64CharArray($a, 0, 2, $b, 0)', False),
            ('[Convert]::ToBase64CharArray($a, 0, 2, $b, 0, 9)', False),
            ('[Convert]::ToBase64CharArray($a, 0, 2, (1, 2, 3), 0)', True),
            ('[Buffer]::BlockCopy($s, 0, $d, 0, 3)', False),
            ('[Buffer]::BlockCopy($s, 0, (1, 2, 3), 0, 3)', True),
        ):
            with self.subTest(source):
                self.assertIs(self._pure(self._expression(source)), pure)


class TestPs1MemberGateWorld(Ps1EffectsTest):
    """
    Position A: a present-member purity grant — a property read, a static or instance method call, a
    constructor — is trusted only under a closed type world. The type reasoning that proves the read
    inert is the same whether the world is open or closed; what the world decides is whether that
    proof may be acted on, because an Extended Type System mutation the script could run would make
    the read effectful. Each read below is one the type layer proves pure, withheld under a world
    carrying no world and granted only under a closed one.
    """

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
        # The world gates grants, never denies: a getter that runs code or throws, an in-place
        # mutator on shared storage, or an out-parameter is kept whether the world is open or
        # closed.
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
    """
    A command the script redefines as a function is not the built-in the metadata describes, so —
    even under a closed type world — the type layer must not type its result and the gate must not grant
    its purity or read it as a discarding sink. A command the script does not redefine is unaffected.
    """

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
        # A discard idiom throws away a value, never the work that produced it. Obfuscated scripts
        # wrap real calls in exactly these idioms, so a discard that skips the operand check makes
        # the deobfuscator delete the payload it is supposed to surface.
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
        # `ForEach-Object` takes its work through its arguments, and a discarding block sitting
        # beside that work says nothing about it: `-MemberName Delete` invokes a member on every
        # input item and `-End $sb` runs whatever scriptblock the variable holds. Reading the
        # question off "a block was seen" let the visible discard vouch for both.
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
        # A discarding `body` says nothing about work the same block carries in a named or `param`
        # block, and the parser fills only one of the two.
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
        # `@options` can carry `-OutVariable` as easily as `-Format`, and none of it is in the
        # source, so there is nothing to judge the command by.
        for source in ('Get-Date @options', 'Get-ChildItem @options | Out-Null'):
            with self.subTest(source):
                self.assertIs(self._effect(self._statement(source)), StatementEffect.EFFECT)

    def test_a_pure_pipeline_cmdlet_still_yields_a_value_a_caller_may_want(self):
        # Purity and emission answer different questions: `Where-Object` performs no side effect,
        # yet the filtered value it puts on the pipeline is not junk.
        statement = self._statement('1..3 | Where-Object { $_ }')
        self.assertTrue(self._pure(self._expression('1..3 | Where-Object { $_ }')))
        self.assertIs(self._effect(statement), StatementEffect.EFFECT)


class TestPs1ACallThatReturnsNothingEmitsNothing(Ps1EffectsTest):
    """
    A bare expression statement writes what its expression produces, so a call to a static method
    declared `System.Void` writes nothing at all: `[Array]::Reverse` turns its argument around and
    yields no value, while `[Array]::IndexOf` on the same type yields the `System.Int32` its reader
    receives.

    Emission is the last question asked and never the only one. A call that acts is an `EFFECT`
    whatever it returns, and so is one that rewrites storage the script reads back — including
    through a conversion, because whether `[int[]]$x` or `$x -as [array]` builds a fresh array is a
    question about the operand's runtime type that nothing reading the source can answer.
    """

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

    def test_a_void_member_reached_as_an_instance_call_is_not_read_for_emission(self):
        self.assertIs(
            self._effect(self._statement("'abc'.ToCharArray().SetValue([Char]122, 0)")),
            StatementEffect.EFFECT,
        )

    def test_an_arity_no_overload_binds_emits_an_error_rather_than_nothing(self):
        self.assertIs(
            self._effect(self._statement("[Array]::Reverse('abc'.ToCharArray(), 0)")),
            StatementEffect.EFFECT,
        )


class TestPs1FaultFreedom(Ps1EffectsTest):
    """
    `is_fault_free` decides whether an expression may be moved out of a `try` whose `catch` is
    empty, and whether a statement that only writes it to the output stream may be deleted. What it
    accepts therefore has to be everything that cannot raise and nothing else.
    """

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
        # PowerShell rejects a duplicate key outright, so a script carrying one never runs at all
        # and deleting the literal would make the rest of it run.
        for source in ('@{ a = 1; a = 2 }', '@{ a = 1; A = 2 }', "@{ 1 = 'x'; '1' = 'y' }"):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_key_that_cannot_be_compared_is_not_a_key_proven_distinct(self):
        for source in ('@{ $k = 1 }', '@{ 1.5 = 1 }'):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_an_operator_that_converts_to_int_raises_on_a_string_it_accepts(self):
        # A string literal cannot raise by being evaluated, which is why the plain arm grants it,
        # and both of these read their operands through `Int32` — so each raises exactly what
        # `[Int]'abc'` raises. Inheriting the string grant is what deleted a guard that had already
        # terminated the script.
        for source in ("-'Xtjbnwqm'", "+'Xtjbnwqm'", "'a'..'z'", "1..'z'", "@('a'..'z')"):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_range_bound_that_does_not_fit_in_int32_is_not_fault_free(self):
        # `4242424242` is a perfectly good integer literal and still too large for the conversion
        # the range operator performs, so the endpoints are weighed rather than counted.
        for source in ('4242424242..4242424245', '1..4242424242', '1..2147483648'):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_range_whose_bounds_fit_but_whose_span_does_not_is_not_fault_free(self):
        # Both endpoints convert cleanly and PowerShell still dies building the array they span:
        # `0..2147483647` raises `OutOfMemoryException`, which an enclosing handler may be catching.
        for source in ('0..2147483647', '(-2147483648)..2147483647', '2147483647..0'):
            with self.subTest(source):
                self.assertFalse(is_fault_free(self._expression(source)))

    def test_a_short_range_of_int32_literals_is_still_fault_free(self):
        # `-2147483648` is the narrowest `Int32` there is and parses as a sign over a literal that
        # is not one, so the sign has to be applied rather than walked past.
        for source in (
            '1..5',
            '(-3)..(+9)',
            '(-2147483648)..(-2147483640)',
            '2147483647..2147483640',
        ):
            with self.subTest(source):
                self.assertTrue(is_fault_free(self._expression(source)))

    def test_side_effect_free_is_not_an_answer_to_this_question(self):
        # Each of these was hoisted out of its `try` on a purity argument, and each one raises on
        # the wrong operand.
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
    """
    Every row here runs to completion on a 5.1 host, and the predicate reaches it by computing the
    value: carrying out the conversion, the arithmetic or the comparison is what proves it succeeds.
    A refusal costs only recall, but these are the rows the pruning passes live on.
    """

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
    """
    A range, a hash literal and an array literal are built rather than computed, so evaluating one
    hands back no value to reason from. Fault freedom is not the folder's verdict: a construction
    assembled from parts that cannot raise has to be granted without one.
    """

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
    """
    Each row terminates on a 5.1 host, so granting one is a soundness defect: a pass would delete or
    relocate a statement whose error an enclosing handler was catching.
    """

    def test_an_expression_that_terminates_the_script_is_not_fault_free(self):
        # A 5.1 range reads both ends through `Int32`, and `'a'` has no conversion to it. A hash
        # literal with a duplicate key is refused before the script runs at all, and its keys are
        # compared case-insensitively and across the string/integer divide.
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
    """
    Whether these raise depends on a value the analysis does not hold, or on .NET semantics it never
    models. `[Math]::Sqrt(36)` raises on no host at all and still has to be refused, because the
    grant would be a claim about a method body this layer does not read.
    """

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
    """
    `certainly_throws` is the must-throw dual of `is_fault_free`: every row here terminates on a 5.1
    host, and the domain reaches that throw value-precisely on the operand in hand. Being a certain
    throw is a strong claim a code-deleting transform acts on, so a row is granted only where the
    host was observed to raise — the value-domain oracle in `test_value_facts` pins each of these
    throws against a captured transcript.
    """

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

    def test_a_throw_statement_is_a_certain_throw_whatever_it_raises(self):
        for source in ('throw', "throw 'boom'", 'throw (Get-Thing)'):
            with self.subTest(source):
                self.assertTrue(certainly_throws(self._statement(source)))


class TestPs1CertainThrowDeclinesEverythingItCannotProve(Ps1EffectsTest):
    """
    The load-bearing property is no false positive: where an expression can ever not throw, or the
    domain cannot prove it must, `certainly_throws` answers `False`. That covers a value the host
    converts, a throw guarded by short-circuit or by strict-mode, an operand the domain does not
    hold, and an operator that never reads its String operand as a number — and each `False` is a
    fold declined, never a wrong deletion.
    """

    def test_a_value_the_host_converts_is_not_a_certain_throw(self):
        # 5.1 reads all of these rather than throwing: an exponent, a thousands separator, a
        # fraction, a hex pattern, the empty string, and a thousands-separated arithmetic operand.
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
        # `-and`/`-or` may never evaluate the right operand, so a certain throw parked there is not
        # certain for the whole expression: 5.1 answers `$false -and (1 / 0)` with `$false`. The
        # right operand is capped unconditionally, so a left that *forces* the right to run
        # (`$true -and`, `$false -or`) is declined too rather than proven — a sound under-claim
        # this pass does not refine with left-value analysis; 5.1 does end the script on those two.
        for source in (
            '$false -and (1 / 0)',
            "$true -or [Int]'abc'",
            '$true -and (1 / 0)',
            '$false -or (1 / 0)',
        ):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_a_string_that_only_concatenates_or_repeats_is_not_coerced(self):
        # A String on the left of `+` or `*` joins or repeats and is never read as a number, so it
        # cannot be the numeric-coercion throw the same text is on the right of an operator.
        for source in ("'abc' + 1", "'abc' * 2"):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_an_index_out_of_range_is_mode_dependent_and_never_certain(self):
        # `@(1, 2)[9]` is `$null` in the default mode and throws only under Set-StrictMode 3, so a
        # certain throw would be a claim about a mode the script may not be in.
        self.assertFalse(certainly_throws(self._expression('@(1, 2)[9]')))

    def test_an_operand_the_domain_does_not_hold_is_not_a_certain_throw(self):
        for source in ("[Int]$x", '1 / $x', '$x + 1', 'Get-Thing', "[DateTime]'x'"):
            with self.subTest(source):
                self.assertFalse(certainly_throws(self._expression(source)))

    def test_an_operator_that_never_reads_its_string_as_a_number_is_not_a_certain_throw(self):
        # A String no number can be read out of is a certain throw only where the operator coerces
        # it to one; a logical, pattern, membership, split or format operator never does, so 5.1
        # answers each of these with a value rather than ending the script.
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
        # 5.1's integer cast reads a `&h`, `#` or `0x` hex pattern, and trims a String of Unicode
        # whitespace before reading it, so a bit pattern or a number wrapped in a vertical tab, a
        # form feed or a non-breaking space converts rather than throwing.
        sources = ["[Int]'&hFF'", "[Int]'#FF'", "[Int]'0xFF'"]
        sources += [F"[Int]'{pad}5'" for pad in (chr(0x0B), chr(0x0C), chr(0xA0))]
        for source in sources:
            with self.subTest(repr(source)):
                self.assertFalse(certainly_throws(self._expression(source)))


class TestPs1FaultFreedomAndSideEffectFreedomAreIndependent(Ps1EffectsTest):
    """
    Purity says an expression changes nothing, fault freedom says it cannot raise, and neither
    answer decides the other. The rows that agree on the first while disagreeing on the second are
    what stops a later change from serving both questions out of a single verdict.
    """

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
    """
    Every other variable read yields a value and changes nothing, which is why purity grants a bare
    name unconditionally. `$input` is the enumerator over a function's pipeline input, and
    enumerating it advances it, so a statement whose whole content is that read still decides what
    the statement below it writes. Measured on 5.1 in `test.lib.scripts.ps1.corpus.BEHAVIOURS`:
    `function f { $input; $input | ForEach-Object { Write-Host "seen:$_" } }` fed `1, 2` writes the
    two values once and nothing after them.
    """

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
    """
    A regression list of shapes that were each, at some point, deleted along with real work: a
    statement the passes are allowed to drop must not contain a call the expression layer rejects.

    Read this as a list, not as a property. Sweeping the same check over every PowerShell snippet in
    the test tree reports nothing at all, including on shapes confirmed to be live data-loss bugs at
    the time — because it asks `is_side_effect_free` about the sub-expressions of a statement whose
    classification already consulted it, so the two layers sharing one wrong belief looks like
    agreement. `ForEach-Object { $Null = $_ } -MemberName Delete` was exactly that: `DISCARD` at the
    statement layer, pure at the expression layer, silently deleted, and invisible here.

    A check that would have caught it has to ask a source of truth this module does not supply — real
    PowerShell, or a corpus labelled by hand with what each statement actually does.
    """

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


#: Every construct that owns a body and merely propagates what it writes. Nothing here is a
#: boundary, so each of these must answer with whatever reads the body holding it.
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

#: The same constructs plus every boundary, for the guards that weigh a body without asking who
#: reads it.
_EVERY_KIND_OF_BODY = F"""{_PROPAGATING_BODIES}
function f {{ 15 }}
filter g {{ 16 }}
class C {{ [Int] m() {{ return 17 }} }}
$cb = {{ 18 }}
$y = $( 19 )
$z = @( 20 )
data d {{ 21 }}"""


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
        # `&{ 42 }` and `. { 42 }` print 42; nothing captures what they yield, so the reader is
        # whoever reads the body they stand in.
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
        # `@( ... )` holds a captured value and is kept out of the pruning walks by having no sink
        # at all. Teaching the body accessor about it would silently make its contents prunable.
        self.assertIsNone(output_sink(self._first('$x = @( 42 )', Ps1ArrayExpression)))

    def test_a_node_that_owns_no_body_has_no_sink(self):
        self.assertIsNone(output_sink(self._expression('42')))

    def _call_to_f(self, source: str) -> Ps1CommandInvocation:
        return next(
            node for node in self._parse(source).walk_in_order()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'f'
        )

    def test_a_value_position_the_walk_cannot_read_is_captured(self):
        # A body owner sits in a handful of positions; a call site sits in every position an
        # expression can, and the walk answers for both. Reading an unrecognized position as
        # propagating reported all of these as HOST, which is the answer that deletes what the
        # callee wrote.
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
        # The other half of the same claim: inverting the allow-list may not cost the positions it
        # was already right about, or the answer is conservative by being useless.
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
        # The relation, not the three values: a block writes through to its holder, so any model
        # that answers these two separately is answering one of them wrongly.
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
        # Enumerated by walking one script rather than by listing node types, so a construct the
        # parser learns later is covered here without anyone remembering to add it. Run at both
        # boundaries: the same block has to follow its holder to the host and to a caller alike.
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


class TestPs1EmitSafety(Ps1EffectsTest):

    def test_only_the_script_root_may_not_be_emptied(self):
        script = self._parse(_EVERY_KIND_OF_BODY)
        owners = [node for node in script.walk() if get_body(node) is not None]
        guarded = [node for node in owners if pruning_erases_body(node, [])]
        self.assertEqual(guarded, [script])

    def test_a_surviving_statement_never_trips_the_erasure_guard(self):
        script = self._parse(_EVERY_KIND_OF_BODY)
        survivors = list(self._parse('Write-Host hi').body)
        for node in script.walk():
            if get_body(node) is None:
                continue
            with self.subTest(repr(node)):
                self.assertFalse(pruning_erases_body(node, survivors))

    def test_the_erasure_guard_reads_only_the_sequence_it_is_given(self):
        # The contract that used to be broken: a caller holds statements hoisted out of a block it
        # just pruned, whose `parent` still points at the block they came from, and statements that
        # are not parented into any body yet. The verdict has to be the same either way.
        for source in (
            'function f { Write-Host hi; 42 }',
            'function f { function g { Write-Host hi } }',
            'function f { }',
            '&{ if ($true) { Write-Host hi }; 42 }',
        ):
            with self.subTest(source):
                script = self._parse(source)
                block = self._first(source, Ps1ScriptBlock)
                survivors = list(block.body)
                before = pruning_erases_body(script, survivors)
                for statement in survivors:
                    _remove_from_parent(statement)
                self.assertEqual(before, pruning_erases_body(script, survivors))

    def test_the_erasure_guard_answers_per_candidate_set(self):
        # `[Void]1; 42` at script root. One shared guard, two candidate sets, two answers: dropping
        # only the discard leaves `42` standing, and dropping everything the junk pass would take
        # leaves nothing, which it must decline. Pinned so that unifying the passes is a decision.
        script = self._parse('[Void]1\n42')
        discards = {
            statement for statement in script.body
            if self._effect(statement) is StatementEffect.DISCARD
        }
        junk = {
            statement for statement in script.body
            if self._effect(statement) is not StatementEffect.EFFECT
        }
        self.assertEqual(len(discards), 1)
        self.assertEqual(len(junk), 2)
        self.assertFalse(pruning_erases_body(
            script, [s for s in script.body if s not in discards]))
        self.assertTrue(pruning_erases_body(
            script, [s for s in script.body if s not in junk]))

    def test_a_sink_that_licenses_deletion_does_not_follow_an_alias(self):
        # The `ForEach-Object` discard sink *deletes*, so it matches the written spelling and clears
        # it with `may_trust_command_name('foreach-object')` — a script defining `function foreach`
        # shadows the spelling `foreach`, which a question about `foreach-object` cannot see.
        # Resolving aliases here would delete a call reaching the payload below.
        from refinery.lib.scripts.ps1.analysis import effects
        from refinery.lib.scripts.ps1.analysis.world import build_closed_world

        source = 'function foreach { Start-Process calc }\n1..3 | foreach { $Null = $_ }'
        tree = self._parse(source)
        world = Ps1WorldReach(build_closed_world(tree))
        statement = tree.body[-1]
        self.assertFalse(effects._pipeline_ends_with_void_foreach(statement.expression, world))
        self.assertIsNot(effects.statement_effect(statement, world), StatementEffect.DISCARD)

    def test_a_named_block_body_is_never_inert(self):
        # The parser fills either `body` or the named blocks, so an advanced function reports an
        # empty statement list. Reading that as "nothing happens here" deletes the function.
        for source in (
            'function f { process { Start-Process notepad } }',
            'function f { begin { Start-Process notepad } }',
            'function f { end { Start-Process notepad } }',
            'function f { param($a) process { Write-Host $a } }',
        ):
            with self.subTest(source):
                self.assertFalse(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_parameter_block_is_code_the_call_runs(self):
        # A parameter default is evaluated on every call that omits the argument, and `get_body`
        # reports none of it. Reading the empty statement list as "nothing happens here" deletes the
        # function together with the call that runs the command in its default.
        for source in (
            'function f { param($x = (Start-Process notepad)) }',
            'function f { param($x = $(Remove-Item C:\\important)) }',
            'function f { param([ValidateScript({ Start-Process notepad })]$x) }',
            'function f { param([Parameter(Mandatory)]$x) }',
        ):
            with self.subTest(source):
                self.assertFalse(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_parameter_block_that_only_declares_names_runs_nothing(self):
        # Declaring a parameter binds storage and evaluates nothing, so a junk function keeps being
        # removable once its body is pruned away. Only a default value or an attribute is code.
        for source in (
            'function f($a) { }',
            'function j($x) { $Null = 915 }',
            'function f { param($x, $y = 1) }',
            'function f { param([String]$x) }',
        ):
            with self.subTest(source):
                self.assertTrue(self._inert(self._first(source, Ps1FunctionDefinition).body))

    def test_a_data_section_captures_the_block_it_binds(self):
        # `data d { 42 }` binds the block's value to `$d`, so pruning into it is as destructive as
        # pruning into `$(...)`.
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
    """
    A world that is open is not merely a statement about the type system: every opener — a
    dot-sourced file, an imported module, an `iex`, an item cmdlet writing the `function:` provider,
    an opaque dispatch — can bind an arbitrary command name to code this tree does not contain. The
    shadow set holds only the redefinitions written where the classifier can see them, so an open
    world has to withdraw name trust wholesale or the two facts contradict each other: the world
    reports that any name may have been rebound while the gate keeps granting the built-in's purity.
    """

    #: A world nothing was proven to redefine, but in which something can redefine anything.
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
        # The two questions the world answers must fail in the same direction, or a caller that
        # forgets the world gets a member grant refused and a name grant handed to it.
        self.assertFalse(is_side_effect_free(self._expression('Get-Date'), _NO_WORLD))


class TestPs1OutputPathMarksAHandlerBodyGuarded(Ps1EffectsTest):
    """
    A `trap` or `catch` body runs only when the region it guards faults, so a value it writes is
    console output on the fault path and not the normal one. `output_path` marks such a body
    `guarded`, which is what keeps the junk strip from taking its bare output for normal-path noise.
    A `finally` body always runs and a `try` body runs before anything faults, so neither is guarded,
    and a value written by ordinary flow is not either.
    """

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
    """
    `expression_cannot_fault` is the whole question a removal site asks, and `is_fault_free` is only
    its context-free half. The half added on top is one fault the operands cannot decide: reading a
    variable that was never set yields `$null` under the default semantics and raises only where
    strict mode is armed. Measured on 5.1 in `test.lib.scripts.ps1.corpus.BEHAVIOURS`.

    Two models answer it and both may refuse. The script may arm strict mode itself, and a payload
    the analysis cannot read may arm it before the position — so a read below an opaque
    `Invoke-Expression` is refused where the same read above it is granted.

    A variable is not fault-free and stays that way, so the two predicates disagree about `$x` on
    purpose: one says what holds under any semantics, the other what holds in this script here.
    """

    @staticmethod
    def _cannot_fault(expression: str, above: str = '', below: str = '') -> bool:
        tree = Ps1Parser(cleandoc(F'{above}{expression}{below}')).parse()
        control_flow = build_control_flow_model(tree)
        world = build_world_reach(measure_world(tree), lambda: control_flow)
        statement = tree.body[above.count(chr(10))]
        return expression_cannot_fault(
            statement.expression, statement, build_fault_reach(control_flow), world)

    def _verdicts(self, expressions: list[str], above: str = '') -> dict[str, bool]:
        return {
            expression: self._cannot_fault(expression, above)
            for expression in expressions
        }

    #: Three spellings of the one shape the added half is about, so that no row below rests on how
    #: the name happens to be written.
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

    def test_no_read_that_is_more_than_a_bare_name_is_granted(self):
        expressions = ['@x', '$env:x', '$global:x', '${zzqdrive:x}', '$x.Foo', '$x[0]', 'Get-Thing']
        self.assertEqual(self._verdicts(expressions), dict.fromkeys(expressions, False))

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
        faults = build_fault_reach(build_control_flow_model(tree))
        self.assertFalse(expression_cannot_fault(statement.expression, statement, faults, None))


class TestPs1AnAdapterMemberIsReadOffTheAdapterAndNotOffTheType(Ps1EffectsTest):
    """
    The object adapter answers `Count`, `PSTypeNames` and `PSObject` for any value that carries no
    member of that name, so reading one runs no getter the type declares. What could still make it
    run one is the runtime value being a subtype with a real member of that name — which a sealed
    type rules out, and an unsealed one does not.

    Measured on 5.1: `(@('one', 'two', 'three') | Measure-Object).GetType().FullName` is the sealed
    `Microsoft.PowerShell.Commands.TextMeasureInfo`'s sibling `GenericMeasureInfo`, and the whole
    family carries no `Count` of its own on the text variant, where the adapter supplies it.
    """

    def test_the_adapter_count_on_a_sealed_type_that_does_not_carry_one_is_pure(self):
        self.assertTrue(_reflection_read_is_pure(
            resolve_type('Microsoft.PowerShell.Commands.TextMeasureInfo'), 'Count'))

    def test_the_adapter_count_on_an_unsealed_type_is_not(self):
        self.assertTrue(_reflection_read_is_pure(
            resolve_type('System.Diagnostics.Process'), 'ProcessName'))
        self.assertFalse(_reflection_read_is_pure(
            resolve_type('System.Diagnostics.Process'), 'PSTypeNames'))

    def test_a_member_the_type_really_carries_is_not_read_off_the_adapter(self):
        """
        `System.Array` declares its own `Length`, and the collected record wins over the adapter, so
        the sealedness of the type says nothing about it.
        """
        self.assertFalse(_reflection_read_is_pure(resolve_type('System.Array'), 'Length'))

    def test_a_member_no_collected_type_carries_stays_refused_on_a_sealed_reference_type(self):
        self.assertFalse(_reflection_read_is_pure(
            resolve_type('Microsoft.PowerShell.Commands.TextMeasureInfo'), 'Nonesuch'))


class TestPs1ADiscardedMeasurementReadsItsCountWithoutRunningCode(Ps1EffectsTest):
    """
    `@('a', 'b') | Measure-Object | ForEach-Object { $_.Count }` writes `2` on 5.1 and does nothing
    else, so a script that throws the value away has said nothing. Every type `Measure-Object`
    declares has to answer for the read, since which one a call yields depends on its switches.
    """

    def test_the_whole_pipeline_is_side_effect_free(self):
        self.assertTrue(self._pure(
            self._expression("@('a', 'b') | Measure-Object | ForEach-Object { $_.Count }")))

    def test_a_member_the_measurement_does_not_carry_is_still_refused(self):
        self.assertFalse(self._pure(
            self._expression("@('a', 'b') | Measure-Object | ForEach-Object { $_.Length }")))

    def test_a_member_read_on_an_untyped_current_object_is_refused(self):
        self.assertFalse(self._pure(self._expression("1, 2 | ForEach-Object { $_.Count }")))
