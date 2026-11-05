from __future__ import annotations

import re

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1
from test.lib.scripts.ps1.test_oracle import TYPE_TRANSCRIPTS

from refinery.lib.scripts.pipeline import DeobfuscationTimeout
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1ParserModeRescan(TestPs1):

    def test_paren_command_static_member_resolved(self):
        result = self._deobfuscate(
            '$Y = [Net.SecurityProtocolType];'
            ' [Net.ServicePointManager]::SecurityProtocol = (Get-Variable Y -ValueOnly)::Tls'
        )
        self.assertIn('::Tls', result)
        self.assertIn('SecurityProtocolType', result)
        self.assertNotIn('Get-Variable', result)

    def test_paren_command_invoke_member_resolved(self):
        result = self._deobfuscate(
            '$X = [Convert];'
            ' (Get-Variable X -ValueOnly)::FromBase64String("AAAA")'
        )
        self.assertIn('0x00', result)
        self.assertNotIn('Get-Variable', result)
        self.assertNotIn('FromBase64String', result)

    def test_member_name_case_normalization(self):
        result = self._deobfuscate(
            '[Net.ServicePointManager]::sEcUrItYpRoToCoL'
        )
        self.assertIn('SecurityProtocol', result)
        self.assertNotIn('sEcUrItYpRoToCoL', result)

    def test_member_name_default_credentials(self):
        result = self._deobfuscate(
            '[Net.CredentialCache]::dEfAuLtCrEdEnTiAlS'
        )
        self.assertIn('DefaultCredentials', result)

    def test_invocation_operator_type_literal_in_method_args(self):
        result = self._deobfuscate(
            '(. $a."B"($c."D"($x,$y,$z),[int]::Max) Arg); $z=1'
        )
        self.assertIn('($x, $y, $z), [int]::Max) Arg', result)

    def test_dotted_command_name(self):
        result = self._deobfuscate(
            'deVICEcREdEnTiaLDEPlOYmENt.eXe ; Write-Host hello'
        )
        self.assertIn('deVICEcREdEnTiaLDEPlOYmENt.eXe', result)

    def test_wildcard_argument_not_split(self):
        ast = Ps1Parser("gcm ???t?")
        result = Ps1Synthesizer().convert(ast.parse())
        self.assertEqual(result, 'gcm ???t?')

    def test_member_dash_operator_not_absorbed(self):
        ast = Ps1Parser("$_.Name-like'*test*'")
        result = Ps1Synthesizer().convert(ast.parse())
        self.assertIn('-like', result)
        self.assertNotIn('Name-like', result)

    def test_array_type_in_param_block(self):
        result = self._deobfuscate(
            'function f { Param([byte[]]$x, [string]$y) ; $x }'
        )
        self.assertIn('[byte[]]', result)
        self.assertIn('[string]', result)

    def test_digit_starting_token_does_not_break_expression(self):
        result = self._deobfuscate('$x = 1 + 2')
        self.assertIn('3', result)

    def test_a_payload_in_a_typed_catch_after_a_command_try_body_survives(self):
        result = self._deobfuscate_iterative(
            "try { Get-Process } catch [System.Exception] { Start-Process calc }\n"
            "Write-Host 'keep'")
        self.assertEqual(result, cleandoc(
            '''
            try {
              Get-Process
            } catch [System.Exception] {
              Start-Process calc
            }
            Write-Host 'keep'
            '''
        ))

    def test_an_empty_typed_catch_after_a_command_try_body_keeps_the_script_below_it(self):
        result = self._deobfuscate_iterative("try { foo =5 } catch [A] {}\nWrite-Host 'keep'")
        self.assertEqual(result, cleandoc(
            """
            try {
              foo =5
            } catch [A] {}
            Write-Host 'keep'
            """
        ))


class TestPs1ClassEnum(TestPs1):

    def test_class_basic_round_trip(self):
        result = self._deobfuscate('class Foo { [string]$Name }')
        self.assertIn('class Foo', result)
        self.assertIn('$Name', result)

    def test_class_with_inheritance(self):
        result = self._deobfuscate('class Derived : Base { [int]$X }')
        self.assertIn('class Derived : Base', result)
        self.assertIn('$X', result)

    def test_class_static_method(self):
        result = self._deobfuscate_iterative(
            'class B { static [int] A([string]$xWdH){return $xWdH[0]}}'
        )
        self.assertIn('class B', result)
        self.assertIn('static', result)
        self.assertIn('[int]', result)
        self.assertIn('A(', result)
        self.assertIn('$xWdH', result)

    def test_class_method_with_body(self):
        result = self._deobfuscate(
            'class Foo : Bar { [void] Greet() { Write-Host "hello" } }'
        )
        self.assertIn('class Foo : Bar', result)
        self.assertIn('Greet()', result)
        self.assertIn('Write-Host', result)

    def test_class_hidden_property(self):
        result = self._deobfuscate('class H { hidden [int]$Secret = 42 }')
        self.assertIn('hidden', result)
        self.assertIn('$Secret', result)
        self.assertIn('42', result)

    def test_class_constructor(self):
        result = self._deobfuscate(
            'class C { C([int]$n) { $this.N = $n } ; [int]$N }'
        )
        self.assertIn('class C', result)
        self.assertIn('$n', result)
        self.assertIn('$This.N', result)

    def test_class_method_params_not_null_inlined(self):
        result = self._deobfuscate_iterative(
            'class B { static [int] A([string]$xWdH){return $xWdH[0]}}'
        )
        self.assertNotIn('$Null', result)
        self.assertIn('$xWdH[0]', result)

    def test_a_class_is_preserved_while_the_outer_code_folds(self):
        result = self._deobfuscate_iterative(
            '$x = 1; class C { [int]$N }; Write-Host $x'
        )
        self.assertEqual(result, cleandoc(
            """
            class C {
              [int]$N
            }
            Write-Host 1
            """
        ))

    def test_enum_basic(self):
        result = self._deobfuscate('enum Color { Red; Green; Blue }')
        self.assertIn('enum Color', result)
        self.assertIn('Red', result)
        self.assertIn('Green', result)
        self.assertIn('Blue', result)

    def test_enum_with_values(self):
        result = self._deobfuscate('enum Flags { None = 0; Read = 1; Write = 2 }')
        self.assertIn('enum Flags', result)
        self.assertIn('Read = 1', result)
        self.assertIn('Write = 2', result)

    def test_enum_with_underlying_type(self):
        result = self._deobfuscate('enum Size : byte { Small; Large }')
        self.assertIn('enum Size : byte', result)
        self.assertIn('Small', result)
        self.assertIn('Large', result)


class TestPs1Integration(TestPs1):

    def test_type_variable_inlined(self):
        result = self._deobfuscate(
            "$x = [Type]'Convert'; $x::FromBase64String('dGVzdA==')"
        )
        self.assertNotIn("'Convert'", result)
        self.assertIn('0x74', result)

    def test_gcm_unwrap(self):
        data = "& (gcm 'Set-Variable') foo 42"
        result = self._deobfuscate(data)
        self.assertIn('$foo', result)
        self.assertIn('42', result)
        self.assertNotIn('gcm', result)

    def test_method_argument_binary_expressions(self):
        result = self._deobfuscate(
            "$x=$a.GetType('Sys'+'tem.Int32');"
            "$y=$b.Replace('#','');"
            "$z=$c.Foo('A'+'B','C'+'D')"
        )
        self.assertIn("GetType('System.Int32')", result)
        self.assertIn("Replace('#', '')", result)
        self.assertIn("Foo('AB', 'CD')", result)

    def test_tostring_multiindex_join(self):
        data = "& ('SilentlyContinue'.ToString()[1, 3] + 'x' -Join '')"
        result = self._deobfuscate(data)
        self.assertIn('invoke-expression', result.lower())

    def test_index_in_method_arg(self):
        result = self._deobfuscate('$x.Method($a[0,1])')
        self.assertIn('[0, 1]', result)

    def test_scriptblock_comma_in_method_arg(self):
        result = self._deobfuscate('$x.Where({$_ -in 1,2,3})', remove_junk=False)
        self.assertIn('1, 2, 3', result)

    def test_shl_operator(self):
        result = self._deobfuscate('$y = $env:V\n$x = $y -shl 2')
        self.assertIn('-shl', result.lower())

    def test_shr_operator(self):
        result = self._deobfuscate('$y = $env:V\n$x = $y -shr 3')
        self.assertIn('-shr', result.lower())

    def test_exit_negative_literal(self):
        result = self._deobfuscate('exit -65536')
        self.assertIn(' -65536', result)

    def test_range_expression_chained(self):
        result = self._deobfuscate('$x = 1..5..2')
        self.assertIn('1..5..2', result)

    def test_dash_operator_as_parameter_in_command(self):
        code = '$x = ((gwmi win32_process -F ProcessId=${PID}).CommandLine) -split [char]34'
        result = self._deobfuscate(code)
        self.assertIn('-split', result.lower())
        self.assertIn('.commandline', result.lower())
        for line in result.strip().splitlines():
            self.assertNotEqual(line.strip(), ')')

    def test_binary_expression_in_command_argument(self):
        result = self._deobfuscate("Set-Item Variable:x ($env:temp + '\\foo.exe')")
        self.assertIn('${env:Temp}', result)
        self.assertIn('\\foo.exe', result)

    def test_semicolons_are_statement_separators(self):
        result = self._deobfuscate('; Get-Item foo ;; Get-Item bar ;')
        self.assertNotIn(';', result)
        self.assertIn('Get-Item foo', result)
        self.assertIn('Get-Item bar', result)

    def test_assignment_if_expression(self):
        result = self._deobfuscate('$d = if ($x) { 1 } else { 2 }')
        self.assertIn('$d = if', result)

    def test_assignment_for_expression(self):
        result = self._deobfuscate('$r = for ($i = 0; $i -LT 5; $i++) { $i }')
        self.assertIn('$r = for', result)

    def test_expandable_here_string_inlining_not_stale(self):
        result = self._deobfuscate_iterative(cleandoc("""
            $v = 'SECRET'
            $h = @"
            value: $v end
            "@
            Write-Host $h
        """))
        self.assertEqual(result, 'Write-Host "value: SECRET end"')

    def test_step_budget_enforced_across_phases(self):
        source = cleandoc("""
            $a = 1 + 2
            $b = 'x' + 'y'
            $unused = 'dead'
            Write-Host $a $b
        """)
        ast = Ps1Parser(source).parse()
        with self.assertRaises(DeobfuscationTimeout):
            deobfuscate(ast, max_steps=1)

    def test_a_group_that_cannot_settle_within_the_budget_raises_instead_of_hanging(self):
        ast = Ps1Parser(cleandoc("""
            $a = 1 + 2 + 3 + 4 + 5
            $b = 'x' + 'y' + 'z'
            $c = $a
            Write-Host $a $b $c
        """)).parse()
        with self.assertRaises(DeobfuscationTimeout):
            deobfuscate(ast, max_steps=2)

    def test_string_equality_guard_prunes_dead_branch(self):
        result = self._deobfuscate(
            "if ('m' -eq 'z') { Write-Output 'dead' } else { Write-Output 'live' }")
        self.assertEqual(result, "Write-Output 'live'")

    def test_logical_guard_prunes_dead_branch(self):
        result = self._deobfuscate(
            "if ($true -and $false) { Write-Output 'dead' } else { Write-Output 'live' }")
        self.assertEqual(result, "Write-Output 'live'")

    def test_junk_function_cascade(self):
        result = self._deobfuscate(
            "function j { $Null = 915 }\nj\nWrite-Host 'payload'")
        self.assertEqual(result, "Write-Host 'payload'")

    def test_empty_for_dead_variable_cascade(self):
        result = self._deobfuscate(
            "for ($i = 0; $i -LT 41; $i++) {}\nWrite-Host 'payload'")
        self.assertEqual(result, "Write-Host 'payload'")

    def test_empty_for_live_variable_terminal_kept(self):
        result = self._deobfuscate(
            'for ($i = 0; $i -LT 41; $i++) {}\nWrite-Host $i')
        self.assertEqual(result, 'Write-Host 41')

    def test_tier2_full_cascade(self):
        src = cleandoc("""
            for ($i = 0; $i -LT 41; $i++) {}
            function j { $Null = 915 }
            j
            trap { continue }
            try {} catch {}
            Write-Host 'payload'
        """)
        result = self._deobfuscate(src)
        self.assertEqual(result, "Write-Host 'payload'")

    def test_tier3_try_bareword_cascade(self):
        src = cleandoc("""
            try { foo =5 } catch {}
            try { bar =3 } catch {}
            Write-Host 'payload'
        """)
        result = self._deobfuscate(src)
        self.assertEqual(result, "Write-Host 'payload'")

    def test_tier3_dead_store_cascade(self):
        src = "$i = 33\n$i = 44\nfor ($i = 0; $i -LT 3; $i++) { Write-Host $i }"
        result = self._deobfuscate(src)
        self.assertNotIn('$i = 33', result)
        self.assertNotIn('$i = 44', result)
        self.assertIn('for', result)

    def test_tier3_full(self):
        src = cleandoc("""
            try { MEI26Qtd2AKx =9188720 } catch {}
            $i = 33
            try { kfkeJNjkCnmbK =3750696 } catch {}
            $i = 44
            Write-Host 'payload'
        """)
        result = self._deobfuscate(src)
        self.assertEqual(result, "Write-Host 'payload'")


class TestPs1ClosedWorld(TestPs1):

    def test_a_pure_read_is_deleted_only_in_a_closed_world(self):
        anchor = "$Null = [Environment]::UserName\nWrite-Output 'anchor'\n"
        self.assertNotIn('UserName', self._deobfuscate_iterative(anchor))
        self.assertIn('UserName', self._deobfuscate_iterative(F'iex $x\n{anchor}'))

    def test_a_temporary_mutator_is_deleted_only_in_a_closed_world(self):
        anchor = "$Null = [Array]::Reverse('ab'.ToCharArray())\nWrite-Output 'anchor'\n"
        self.assertNotIn('Reverse', self._deobfuscate_iterative(anchor))
        self.assertIn('Reverse', self._deobfuscate_iterative(F'iex $x\n{anchor}'))


class TestPs1CommandRedefinition(TestPs1):

    def test_a_shadowed_commands_effect_survives_every_deletion_form(self):
        anchor = "\nWrite-Output 'keep'\n"
        forms = {
            'member-read': "function Get-Date { Start-Process calc }\n$Null = (Get-Date).Ticks",
            'bare-discard': "function Get-Date { Start-Process calc }\n$Null = Get-Date",
            'out-null-sink': "function Out-Null { Start-Process calc }\n1 | Out-Null",
            'foreach-void-sink':
                "function ForEach-Object { Start-Process calc }\n1 | ForEach-Object { [Void]$_ }",
            'noise-bareword-try': "function Zzz { Start-Process calc }\ntry { Zzz =5 } catch {}",
            'function-scope-assign':
                "${function:Get-Date} = { Start-Process calc }\n$Null = Get-Date",
            'new-object': "function New-Object { Start-Process calc }\n$Null = New-Object Version",
            'global-function':
                "function global:Get-Date { Start-Process calc }\n$Null = (Get-Date).Ticks",
            'private-filter': "filter private:Out-Null { Start-Process calc }\n1 | Out-Null",
        }
        for name, body in forms.items():
            with self.subTest(name):
                self.assertIn('Start-Process', self._deobfuscate_iterative(body + anchor))

    def test_a_bareword_written_above_the_definition_that_shadows_it_is_still_removed(self):
        self.assertEqual(
            self._deobfuscate_iterative(
                'try { Zzz =5 } catch {}\n'
                'function Zzz { Start-Process calc }\n'
                'Zzz\n'
                "Write-Output 'keep'\n"),
            cleandoc("""
                function Zzz {
                  Start-Process calc
                }
                Zzz
                Write-Output 'keep'
            """))

    def test_a_multi_assignment_redefinition_keeps_the_call_it_shadows(self):
        out = self._deobfuscate_iterative(
            "${function:Get-Date}, $y = { Start-Process calc }, 2\n"
            "$Null = (Get-Date).Ticks\n"
            "Write-Output 'keep'\n")
        self.assertIn('Ticks', out)
        self.assertIn('Start-Process', out)

    def test_an_unshadowed_pure_read_is_still_deleted(self):
        out = self._deobfuscate_iterative(
            "function Helper { 'x' }\n$Null = (Get-Date).Ticks\nWrite-Output 'keep'\n")
        self.assertNotIn('Get-Date', out)

    def test_a_cast_to_a_script_defined_type_keeps_the_constructor_it_runs(self):
        out = self._deobfuscate_iterative(cleandoc(
            """
            class Loader { Loader([String]$s) { [IO.File]::WriteAllText('C:\\p.txt', $s) } }
            $Null = [Loader]'payload'
            Write-Host 'keep'
            """
        ))
        self.assertIn('[Loader]', out)

    def test_a_name_is_inert_only_when_every_definition_of_it_is(self):
        for second in ('function f { }', 'function global:f { }'):
            with self.subTest(second):
                out = self._deobfuscate_iterative(
                    F"function f {{ Start-Process calc }}\n{second}\nf\nWrite-Host 'keep'")
                self.assertIn('Start-Process', out)


class TestPs1ErrorHandlerSurvival(TestPs1):

    def test_a_payload_in_a_catch_survives_a_throwing_try_body(self):
        for body in ("$Null = [Int]'abc'", "$x = [Int]'abc'", "[Int]'abc'", "[Guid]'nope'"):
            with self.subTest(body):
                out = self._deobfuscate_iterative(
                    F"try {{ {body} }} catch {{ Start-Process calc }}\nWrite-Host 'keep'")
                self.assertIn('Start-Process', out)

    def test_a_payload_in_a_catch_survives_a_try_body_another_pass_emptied(self):
        scripts = (
            "function f { $Null = [Int]'abc' }\ntry { f } catch { Start-Process calc }",
            "try { function g { 'z' } } catch { Start-Process calc }\nWrite-Host (g)",
            "try { if ($false) { 1 } } catch { Start-Process calc }",
            "try { 42 } catch { Start-Process calc }",
            "try { trap { continue } } catch { Start-Process calc }",
            "try { do { } while ($false) } catch { Start-Process calc }",
        )
        for script in scripts:
            with self.subTest(script):
                out = self._deobfuscate_iterative(F"{script}\nWrite-Host 'keep'")
                self.assertIn('Start-Process', out)

    def test_an_empty_catch_lets_a_noise_bareword_and_a_cast_it_swallows_go(self):
        out = self._deobfuscate_iterative(
            "try { foo =5 } catch {}\ntry { [Int]$env:FOO } catch {}\nWrite-Host 'keep'")
        self.assertEqual(out, "Write-Host 'keep'")


class TestPs1NameTrustSurvivesRewriting(TestPs1):

    def test_a_dot_source_of_a_script_keeps_its_operator(self):
        out = self._deobfuscate_iterative(cleandoc(
            """
            . 'profile-loader'
            $Null = (Get-Date).Ticks
            Write-Host 'keep'
            """
        ))
        self.assertIn('. profile-loader', out)
        self.assertIn('Get-Date', out)

    def test_a_dot_on_a_cmdlet_is_still_dropped(self):
        out = self._deobfuscate_iterative("$c = . New-Object 'Net.WebClient'\nWrite-Host $c")
        self.assertNotIn('. New-Object', out)

    def test_a_provider_redefinition_is_kept_while_the_bare_call_resolves_to_the_alias(self):
        out = self._deobfuscate_iterative(cleandoc(
            """
            ${function:gci} = { Start-Process calc }
            Write-Host (gci)
            Write-Host done
            """
        ))
        self.assertIn('Start-Process calc', out)
        self.assertIn('Get-ChildItem', out)

    def test_a_regex_match_stays_while_a_read_of_matches_needs_it(self):
        out = self._deobfuscate_iterative(cleandoc(
            """
            $c = 'aaa<<calc>>bbb'
            $z = $c -match '<<(.*)>>'
            Invoke-Expression $Matches[1]
            """
        )).lower()
        self.assertTrue('-match' in out or '$matches' not in out)

    def test_a_scope_qualified_redefinition_is_not_constant_folded(self):
        out = self._deobfuscate_iterative(cleandoc(
            """
            function F { 'A' }
            function global:F { Start-Process calc; 'B' }
            Write-Host (F)
            """
        ))
        self.assertIn('Start-Process calc', out)


_BRANCH_ROW = re.compile(
    r"\$t = (?P<script>if \(.+\) \{ 'yes' \} else \{ 'no' \})"
    r'; Write-Output \(,\$t\); Write-Output \$t'
)


def _measured_line(expression: str) -> str:
    row = F'$t = {expression}; Write-Output (,$t); Write-Output $t'
    kind, _, rendered = TYPE_TRANSCRIPTS[row][0].split('\t')
    assert kind == 'OUT', row
    return rendered


def _branch_rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    for row in TYPE_TRANSCRIPTS:
        match = _BRANCH_ROW.fullmatch(row)
        if match is not None:
            script = match.group('script')
            rows[script] = _measured_line(script)
    return rows


BRANCHES: dict[str, str] = _branch_rows()


class TestPs1MeasuredBranch(TestPs1):

    def test_every_measured_if_reduces_to_the_branch_the_host_printed(self):
        self.assertEqual(len(BRANCHES), 6, 'a measured branch was added or withdrawn')
        self.assertEqual(
            {
                script: self._deobfuscate_iterative(script, remove_junk=False)
                for script in BRANCHES
            },
            {script: F"'{branch}'" for script, branch in BRANCHES.items()},
        )


UNSETTLED_SOURCES: tuple[str, ...] = (
    cleandoc("""
        if ($Null * [int]'abc') {
          'A'
        } else {
          'B'
        }
    """),
    cleandoc("""
        while (@() + (0 -Shl $True)) {
          'A'
        }
    """),
    "$x = -Not ($Null * [int]'abc')",
    '$x = (@() + (0 -Shl $True)) -and $True',
)


class TestPs1UnsettledConditionIsLeftStanding(TestPs1):

    def test_a_condition_the_domain_cannot_settle_is_left_where_it_stands(self):
        for source in UNSETTLED_SOURCES:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate_iterative(source, remove_junk=False), source)


THROWING_NEGATIONS: tuple[str, ...] = (
    cleandoc("""
        if (-'abc') {
          'A'
        } else {
          'B'
        }
    """),
    "$x = (-'abc') -or $False",
)

NEGATED_ZERO_FOLDS: dict[str, str] = {
    "$x = -Not (-'0')"       : "-not (- '0')",
    "$x = (-'0') -and $True" : "(- '0') -and $true",
}


class TestPs1NegatedStringTruth(TestPs1):

    def test_a_negated_string_the_host_threw_on_is_left_where_it_stands(self):
        for source in THROWING_NEGATIONS:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate_iterative(source, remove_junk=False), source)

    def test_a_negated_zero_is_folded_to_the_value_the_host_printed_for_it(self):
        self.assertEqual(
            {
                source: self._deobfuscate_iterative(source, remove_junk=False)
                for source in NEGATED_ZERO_FOLDS
            },
            {
                source: F'$x = ${_measured_line(row)}'
                for source, row in NEGATED_ZERO_FOLDS.items()
            },
        )

    def test_a_loop_whose_condition_is_never_met_is_kept_with_its_body(self):
        self.assertEqual(_measured_line("- '0'"), '0')
        self.assertEqual(
            self._deobfuscate_iterative(cleandoc("""
                do {
                  'A'
                } until (-'0')
            """), remove_junk=False),
            cleandoc("""
                do {
                  'A'
                } until (0)
            """),
        )


class TestPs1ABlockAShadowedIteratorReceivesRunsWhereThatIteratorRunsIt(TestPs1):

    _SCRIPT = """
        function ForEach-Object { param($s) $script:store = $s }
        $x = 'a'
        1..2 | ForEach-Object { Write-Output $x }
        $x = 'b'
        & $script:store
        """

    def test_the_read_inside_the_stored_block_is_not_folded(self):
        result = self._deobfuscate(cleandoc(self._SCRIPT))
        self.assertIn('Write-Output $x', result)
        self.assertNotIn("Write-Output 'a'", result)

    def test_the_write_after_the_pipeline_is_kept_alive_by_the_stored_read(self):
        result = self._deobfuscate(cleandoc(self._SCRIPT))
        self.assertIn("$x = 'b'", result)
