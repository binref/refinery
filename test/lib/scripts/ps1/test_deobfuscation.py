from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

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
        self.assertIn('Max', result)
        self.assertIn('Arg', result)

    def test_dotted_command_name(self):
        result = self._deobfuscate(
            'deVICEcREdEnTiaLDEPlOYmENt.eXe ; Write-Host hello'
        )
        self.assertIn('deVICEcREdEnTiaLDEPlOYmENt.eXe', result)

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
        self.assertIn('String', result)

    def test_digit_starting_token_does_not_break_expression(self):
        result = self._deobfuscate('$x = 1 + 2')
        self.assertIn('3', result)


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

    def test_class_preserved_alongside_outer_code(self):
        result = self._deobfuscate_iterative(
            '$x = 1; class C { [int]$N }; Write-Host $x'
        )
        self.assertIn('class C', result)
        self.assertIn('Write-Host', result)

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
        # The constant inlined into the expandable here-string must reach the output, and the
        # source assignment is then removed cleanly (no dangling $v).
        result = self._deobfuscate_iterative(cleandoc("""
            $v = 'SECRET'
            $h = @"
            value: $v end
            "@
            Write-Host $h
        """))
        self.assertEqual(result, cleandoc("""
            $h = "value: SECRET end"
            Write-Host $h
        """))

    def test_step_budget_enforced_across_phases(self):
        # A step budget smaller than the total work must raise rather than letting phase 2 run
        # unbounded once phase 1 has consumed the budget.
        source = cleandoc("""
            $a = 1 + 2
            $b = 'x' + 'y'
            $unused = 'dead'
            Write-Host $a $b
        """)
        ast = Ps1Parser(source).parse()
        with self.assertRaises(DeobfuscationTimeout):
            deobfuscate(ast, max_steps=1)
