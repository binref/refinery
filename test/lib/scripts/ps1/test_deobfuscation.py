from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1(TestBase):

    def _deobfuscate(self, source: str) -> str:
        ast = Ps1Parser(source).parse()
        deobfuscate(ast)
        return Ps1Synthesizer().convert(ast)

    def _deobfuscate_iterative(self, source: str, iterations: int = 100) -> str:
        ast = Ps1Parser(source).parse()
        for _ in range(iterations):
            if not deobfuscate(ast):
                break
        return Ps1Synthesizer().convert(ast)


class TestPs1Deobfuscator(TestPs1):

    def test_format_string_basic(self):
        data = '"{0}{2}{1}" -f "signa","ures","t"'
        result = self._deobfuscate(data)
        self.assertIn('signatures', result)

    def test_format_string_in_parens(self):
        data = '("{0}{2}{1}"-f "signa","ures","t")'
        result = self._deobfuscate(data)
        self.assertIn('signatures', result)

    def test_format_string_single_quotes(self):
        data = "('{2}{0}{1}'-f'c','m','g')"
        result = self._deobfuscate(data)
        self.assertIn('gcm', result)

    def test_bracket_removal_string(self):
        data = '("hello")'
        result = self._deobfuscate(data)
        self.assertNotIn('(', result)
        self.assertIn('hello', result)

    def test_bracket_removal_integer(self):
        data = '(42)'
        result = self._deobfuscate(data)
        self.assertEqual(result.strip(), '42')

    def test_typecast_char(self):
        data = '[char]120'
        result = self._deobfuscate(data)
        self.assertIn('x', result)

    def test_typecast_char_hex(self):
        data = '[char]0x41'
        result = self._deobfuscate(data)
        self.assertIn('A', result)

    def test_typecast_string_strip(self):
        data = '[string]"foo"'
        result = self._deobfuscate(data)
        self.assertIn('foo', result)
        self.assertNotIn('[string]', result)

    def test_typecast_char_array(self):
        data = '[char[]](72,101,108,108,111)'
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_as_char_cast(self):
        result = self._deobfuscate('(45 -As [Char])')
        self.assertIn("'-'", result)
        self.assertNotIn('-As', result)

    def test_type_cast_string_to_type_expression(self):
        result = self._deobfuscate("[Type]'Convert'")
        self.assertIn('[Convert]', result)
        self.assertNotIn("'Convert'", result)

    def test_type_variable_inlined(self):
        result = self._deobfuscate(
            "$x = [Type]'Convert'; $x::FromBase64String('dGVzdA==')"
        )
        self.assertIn('[Convert]', result)
        self.assertNotIn("'Convert'", result)

    def test_uncurly_variable(self):
        data = '${variable}'
        result = self._deobfuscate(data)
        self.assertEqual(result.strip(), '$variable')

    def test_case_normalize_invoke_expression(self):
        data = "iNVokE-exPreSSion"
        result = self._deobfuscate(data)
        self.assertIn('Invoke-Expression', result)

    def test_case_normalize_get_variable(self):
        data = 'gEt-VaRIAblE'
        result = self._deobfuscate(data)
        self.assertIn('Get-Variable', result)

    def test_case_normalize_set_variable(self):
        data = 'sEt-VarIAbLE'
        result = self._deobfuscate(data)
        self.assertIn('Set-Variable', result)

    def test_invoke_simplification_member(self):
        data = '$x.ToString.Invoke()'
        result = self._deobfuscate(data)
        self.assertIn('$x.ToString()', result)

    def test_invoke_simplification_quoted_member(self):
        data = '$x."ToString"()'
        result = self._deobfuscate(data)
        self.assertIn('$x.ToString()', result)

    def test_command_invocation_ampersand(self):
        data = '& ("Invoke-Expression")'
        result = self._deobfuscate(data)
        self.assertIn('Invoke-Expression', result)
        self.assertNotIn('&', result)

    def test_command_invocation_dot(self):
        data = ". ('Set-Variable') foo 42"
        result = self._deobfuscate(data)
        self.assertIn('$foo', result)
        self.assertIn('42', result)

    def test_b64convert(self):
        data = '[System.Convert]::FromBase64String("AQID")'
        result = self._deobfuscate(data)
        self.assertIn('0x01', result)
        self.assertIn('0x02', result)
        self.assertIn('0x03', result)

    def test_encoding_utf8(self):
        data = '[System.Text.Encoding]::UTF8.GetString(@(72, 101, 108, 108, 111))'
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_gcm_unwrap(self):
        data = "& (gcm 'Set-Variable') foo 42"
        result = self._deobfuscate(data)
        self.assertIn('$foo', result)
        self.assertIn('42', result)
        self.assertNotIn('gcm', result)

    def test_useless_string_cast(self):
        result = self._deobfuscate('''$snug.replAce(("M0I"),[strIng]"'")''')
        self.assertIn("'", result)
        self.assertNotIn('[strIng]', result)

    def test_method_argument_binary_expressions(self):
        result = self._deobfuscate(
            "$x=$a.GetType('Sys'+'tem.Int32');"
            "$y=$b.Replace('#','');"
            "$z=$c.Foo('A'+'B','C'+'D')"
        )
        self.assertIn("GetType('System.Int32')", result)
        self.assertIn("Replace('#', '')", result)
        self.assertIn("Foo('AB', 'CD')", result)

    def test_param_block(self):
        result = self._deobfuscate('param($qu, $sec=0, $iv=0)')
        self.assertIn('Param($qu, $sec = 0, $iv = 0)', result)

    def test_arithmetic_constant_folding(self):
        result = self._deobfuscate(
            '$foo=36665-36663\n'
            '$bar=345-BXor21\n'
            '$baz=744-BAND(3254-1221)*99-BXor743\n'
        ).lower()
        self.assertNotIn('36665', result)
        self.assertIn('$foo = 2', result)
        self.assertNotIn('bxor', result)
        self.assertIn('$bar = 332', result)
        self.assertNotIn('band', result)
        self.assertIn('$baz = 199', result)

    def test_preference_variable_indexing(self):
        result = self._deobfuscate("Write-Output ($VerbosePreference[0] + $VerbosePreference[1])")
        self.assertNotIn('VerbosePreference', result)

    def test_preference_variable_not_substituted_when_assigned(self):
        result = self._deobfuscate("$VerbosePreference = 'Custom'\nWrite-Output $VerbosePreference[1]")
        self.assertIn("$VerbosePreference", result)

    def test_tostring_multiindex_join(self):
        data = "& ('SilentlyContinue'.ToString()[1, 3] + 'x' -Join '')"
        result = self._deobfuscate(data)
        self.assertIn('invoke-expression', result.lower())

    def test_split_constant_string(self):
        result = self._deobfuscate("'aXbYcZd'.Split('XYZ')")
        self.assertIn("'a'", result)
        self.assertIn("'b'", result)
        self.assertIn("'c'", result)
        self.assertIn("'d'", result)

    def test_join_scalar_string_is_noop(self):
        result = self._deobfuscate("-Join 'hello'")
        self.assertNotIn('-Join', result)
        self.assertNotIn('-join', result)
        self.assertIn('hello', result)

    def test_binary_split_single(self):
        result = self._deobfuscate("'aXbXc' -Split 'X'")
        self.assertIn("'a'", result)
        self.assertIn("'b'", result)
        self.assertIn("'c'", result)

    def test_binary_split_chained(self):
        result = self._deobfuscate("'aXbYc' -Split 'X' -Split 'Y'")
        self.assertIn("'a'", result)
        self.assertIn("'b'", result)
        self.assertIn("'c'", result)

    def test_backtick_removal_in_variable(self):
        result = self._deobfuscate('${ex`ecu`tion}')
        self.assertNotIn('`', result)
        self.assertNotIn('{', result)
        self.assertEqual(result.strip(), '$execution')

    def test_backtick_variable_with_known_name(self):
        result = self._deobfuscate('${eXeC`uTi`oNCon`tEXt}')
        self.assertNotIn('`', result)
        self.assertNotIn('{', result)
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_normalize_true_false(self):
        result = self._deobfuscate('$tRUe, $fAlSE')
        self.assertIn('$True', result)
        self.assertIn('$False', result)

    def test_backtick_member_access(self):
        result = self._deobfuscate('$x."me`Th`od"')
        self.assertNotIn('`', result)
        self.assertIn('.Method', result)

    def test_backtick_function_name_stripped(self):
        result = self._deobfuscate("function tR`iomE { Param($x); return $x }")
        self.assertNotIn('`', result)
        self.assertIn('function tRiomE', result)

    def test_backtick_in_command_name(self):
        result = self._deobfuscate("i`EX 'Write-Host hello'")
        self.assertNotIn('`', result)
        self.assertIn('Write-Host', result)

    def test_backtick_in_parameter_name(self):
        result = self._deobfuscate("Get-WmiObject -w`mI`InS`tAnCe foo")
        self.assertNotIn('`', result)

    def test_cast_wrapped_array_pipeline(self):
        result = self._deobfuscate(
            "[String]([Char[]] (72,101,108,108,111) | "
            "ForEach-Object { [Char]($_ -BXor 0) })")
        self.assertIn('Hello', result)

    def test_char_array_xor_pipeline(self):
        result = self._deobfuscate("[String]([Char[]] (127,78,88,95) | % { [Char]($_ -BXor 0x2B) })")
        self.assertIn('Test', result)

    def test_shift_operations(self):
        result = self._deobfuscate("$x = 1 -Shl 4; $y = 256 -Shr 3")
        self.assertIn('16', result)
        self.assertIn('32', result)


class TestPS1BracketRemoval(TestPs1):

    def test_string_literal_01(self):
        result = self._deobfuscate('("{0}{2}{1}")')
        self.assertIn('"{0}{2}{1}"', result)

    def test_string_literal_02(self):
        result = self._deobfuscate('( ((    \n( "Test")))')
        self.assertIn('"Test"', result)

    def test_string_literal_03(self):
        result = self._deobfuscate('(((\n( "Tes""t")\n)) )')
        self.assertIn('"Tes""t"', result)

    def test_numeric_literal_01(self):
        result = self._deobfuscate('(0x12)')
        self.assertIn('0x12', result)

    def test_numeric_literal_02(self):
        result = self._deobfuscate('( ((    \n( 0x12)  ))')
        self.assertIn('0x12', result)

    def test_numeric_literal_03(self):
        result = self._deobfuscate('((31337) )')
        self.assertIn('31337', result)


class TestPS1StringConcatenations(TestPs1):

    def test_concat_basic(self):
        data = "'foo' + 'bar'"
        result = self._deobfuscate(data)
        self.assertIn('foobar', result)

    def test_concat_double_quotes(self):
        data = '"hel" + "lo"'
        result = self._deobfuscate(data)
        self.assertIn('hello', result)

    def test_uneven(self):
        result = self._deobfuscate("'T'+'b'+'c'")
        self.assertIn('Tbc', result)

    def test_concatenation(self):
        result = self._deobfuscate('"bla" + "foo" +"bar"')
        self.assertIn('blafoobar', result)

    def test_uneven_special_chars(self):
        result = self._deobfuscate('$t = "bla " + "\\foo" + "bar baz"')
        self.assertIn('bla \\foobar baz', result)

    def test_not_inside_string(self):
        result = self._deobfuscate('''$t="'bla ' + '\\foo'"; $t = $t + 'bar' + "baz"''')
        self.assertIn("'bla ' + '\\foo'", result)
        self.assertIn('barbaz', result)

    def test_variable_substitution(self):
        result = self._deobfuscate('''$y = "$y"+'$z';''')
        self.assertIn('$z', result)

    def test_split_format_string(self):
        result = self._deobfuscate(R'''"{0}$SEP{1}"-f 'Hello',"World"''')
        self.assertIn('Hello', result)
        self.assertIn('World', result)

    def test_invalid_format(self):
        result = self._deobfuscate(R'''"{0}{2}{1}"-f 'Hello',"World"''')
        self.assertIn('Hello', result)

    def test_all_single_quotes(self):
        result = self._deobfuscate(R"""'{0}{2}{1}'-f 'signa','ures','t'""")
        self.assertIn('signatures', result)

    def test_mixed_quotes(self):
        result = self._deobfuscate(R'''"{0}{2}{1}"-f 'signa','ures',"t"''')
        self.assertIn('signatures', result)

    def test_format_string_with_chars(self):
        result = self._deobfuscate('("{0}na{2}{1}"-f \'sig\',\'ures\',\'t\')')
        self.assertIn('signatures', result)

    def test_multiple_occurrences(self):
        result = self._deobfuscate(
            '"{10}{1}{0}{5}{9}{7}{8}{7}{3}{6}{2}{7}{4}{4}{10}{5}{1}"'
            "-f'v','n','r','x','s','o','p','e','-','k','i'"
        )
        self.assertIn('invoke-expression', result)

    def test_format_string_escaped_braces(self):
        result = self._deobfuscate('"{0} {{literal}}" -f "test"')
        self.assertIn('test {literal}', result)

    def test_format_string_only_escaped_braces(self):
        result = self._deobfuscate('"{{hello}}" -f "unused"')
        self.assertEqual(result, "'{hello}'")

    def test_string_concat_static_method(self):
        result = self._deobfuscate("[String]::Concat('a', 'b', 'c')")
        self.assertEqual(result, "'abc'")

    def test_join_single_string(self):
        result = self._deobfuscate("-Join @('hello')")
        self.assertEqual(result, "'hello'")

    def test_replace_after_concat(self):
        result = self._deobfuscate("$([String]::Concat('h_llo')).Replace('_', 'e')")
        self.assertEqual(result, "'hello'")


class TestPS1StringReplace(TestPs1):

    def test_real_world_01(self):
        data = '''-RepLaCe"UVL",""""-CrePLAcE "MQo","``" -RepLaCe ("0"+"N"+"R"),"'"-CrePLAcE'eV5',"`$"-CrePLAcE  '31V',"|")'''
        result = self._deobfuscate(data)
        self.assertIn('0NR', result)

    def test_real_world_02(self):
        result = self._deobfuscate(
            '''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"))''')
        self.assertIn("'", result)

    def test_string_replace_method(self):
        data = '"haystack".Replace("hay","needle")'
        result = self._deobfuscate(data)
        self.assertIn('needlestack', result)

    def test_string_replace_operator(self):
        data = '"Hello World" -replace "World","Earth"'
        result = self._deobfuscate(data)
        self.assertIn('Hello Earth', result)

    def test_chained_replace_operator(self):
        data = '"ABCDEF" -replace \'AB\',\'ab\' -replace \'CD\',\'cd\' -replace \'EF\',\'ef\''
        result = self._deobfuscate(data)
        self.assertIn('abcdef', result)

    def test_replace_with_backslash_replacement(self):
        data = "'MarkXPath' -Replace 'X', '\\'"
        result = self._deobfuscate(data)
        self.assertIn('Mark\\Path', result)
        self.assertNotIn('-Replace', result)

    def test_chained_replace_on_herestring(self):
        data = (
            "(@'\n"
            "aXb cYd\n"
            "'@ -Replace 'X', '1' -Replace 'Y', '2')"
        )
        result = self._deobfuscate_iterative(data)
        self.assertIn('a1b', result)
        self.assertIn('c2d', result)
        self.assertNotIn('-Replace', result)

    def test_trivial(self):
        result = self._deobfuscate('''"Hello World".replace('l', "FOO")''')
        self.assertIn('HeFOOFOOo WorFOOd', result)

    def test_variable_substitution_01(self):
        result = self._deobfuscate(
            '''Write-Output "The $product costs `$100 for the average person." -replace '$', "\u20ac";''')
        self.assertIn('\u20ac', result)

    def test_variable_substitution_02(self):
        result = self._deobfuscate(
            '''Write-Output "The $product costs `$100 for the average person." -replace '$', "$currency";''')
        self.assertIn('currency', result)


class TestPS1Regressions(TestPs1):
    def test_index_in_method_arg(self):
        result = self._deobfuscate('$x.Method($a[0,1])')
        self.assertIn('[0, 1]', result)

    def test_scriptblock_comma_in_method_arg(self):
        result = self._deobfuscate('$x.Where({$_ -in 1,2,3})')
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

    def test_format_expression_chained(self):
        result = self._deobfuscate('$x = "{0}" -f "a" -f "b"')
        self.assertIn("'a'", result)

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

    def test_pipeline_index_member_access(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[6].Name')
        self.assertIn('InvokeCommand', result)
        self.assertNotIn('[6]', result)

    def test_user_function_not_aliased(self):
        data = (
            "Function R ([String]$s){"
            "$r = '';"
            "ForEach($c in $s.ToCharArray()){$r = $c + $r};"
            "$r;}"
            "$x = R 'olleH'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertNotIn('Invoke-History', result)

    def test_user_function_not_case_normalized_to_alias(self):
        result = self._deobfuscate("Function gc { 'test' }\ngc")
        self.assertNotIn('Get-Content', result)

    def test_where_object_wildcard_not_over_resolved(self):
        data = "$obj.PSObject.Methods | ? { $_.Name -ilike '*ts' }"
        result = self._deobfuscate(data)
        self.assertNotIn('Exists', result)
        self.assertIn("'*ts'", result)

    def test_binary_expression_in_command_argument(self):
        result = self._deobfuscate("Set-Item Variable:x ($env:temp + '\\foo.exe')")
        self.assertIn('${env:Temp}', result)
        self.assertIn('\\foo.exe', result)

    def test_variable_string_concat_becomes_expandable(self):
        result = self._deobfuscate("$env:temp + '\\foo.exe'")
        self.assertIn('"${env:Temp}\\foo.exe"', result)

    def test_expandable_string_value_subexpr_kept(self):
        result = self._deobfuscate('''"prefix$( 1 + 2 )suffix"''')
        self.assertIn('prefix$(', result)

    def test_semicolons_are_statement_separators(self):
        result = self._deobfuscate('; Get-Item foo ;; Get-Item bar ;')
        self.assertNotIn(';', result)
        self.assertIn('Get-Item foo', result)
        self.assertIn('Get-Item bar', result)

    def test_digit_starting_alias_inlined(self):
        data = "Set-Alias 1abc Invoke-Expression\n1abc 'Write-Host hello'"
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('1abc', result.split('\n')[-1])

    def test_obfuscated_alias_target_resolved_after_folding(self):
        data = (
            "Set-Alias myalias $([char]73+[char]69+[char]88)\n"
            "myalias 'Write-Host hi'"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('myalias', result.split('\n')[-1])

    def test_assignment_if_expression(self):
        result = self._deobfuscate('$d = if ($x) { 1 } else { 2 }')
        self.assertIn('$d = if', result)

    def test_assignment_for_expression(self):
        result = self._deobfuscate('$r = for ($i = 0; $i -LT 5; $i++) { $i }')
        self.assertIn('$r = for', result)


class TestPs1VariableDriveResolution(TestPs1):

    def test_get_item_variable_value_resolved(self):
        result = self._deobfuscate("(Get-Item 'Variable:E*t').Value.InvokeCommand")
        self.assertEqual(result.strip(), '$ExecutionContext.InvokeCommand')

    def test_get_variable_value_resolved(self):
        result = self._deobfuscate('(Get-Variable ExecutionContext).Value')
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_get_item_variable_without_value_preserved(self):
        result = self._deobfuscate("(Get-Item 'Variable:E*t')")
        self.assertNotIn('$ExecutionContext', result)

    def test_member_alias_resolved(self):
        result = self._deobfuscate('$x | Member')
        self.assertIn('Get-Member', result)

    def test_variable_alias_resolved(self):
        result = self._deobfuscate('Variable ExecutionContext')
        self.assertIn('Get-Variable', result)

    def test_variable_drive_path_separator_stripped(self):
        result = self._deobfuscate('(Get-Item Variable:/hb).Value')
        self.assertIn('$hb', result)
        self.assertNotIn('/', result)

    def test_set_item_variable_becomes_assignment(self):
        result = self._deobfuscate("Set-Item Variable:/G7E 'hello'")
        self.assertEqual(result.strip(), "$G7E = 'hello'")

    def test_set_item_variable_multi_value(self):
        result = self._deobfuscate(
            "Set-Item Variable:/G7E $env:Temp '\\NGLClient.exe'"
        )
        self.assertIn('$G7E', result)
        self.assertIn('=', result)
        self.assertIn('env:Temp', result)
        self.assertIn('NGLClient', result)

    def test_set_variable_becomes_assignment(self):
        result = self._deobfuscate("Set-Variable foo 42")
        self.assertEqual(result.strip(), '$foo = 42')

    def test_set_variable_named_params(self):
        result = self._deobfuscate("Set-Variable -Name foo -Value 'bar'")
        self.assertEqual(result.strip(), "$foo = 'bar'")

    def test_set_variable_with_integer_name(self):
        result = self._deobfuscate("Set-Variable 0 'hello'\n$0")
        self.assertIn('hello', result)
        self.assertNotIn('Set-Variable', result)

    def test_get_variable_value_only_resolved(self):
        result = self._deobfuscate('Get-Variable ExecutionContext -ValueOnly')
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_get_variable_value_only_abbreviated(self):
        result = self._deobfuscate('Get-Variable Cf -ValueO')
        self.assertEqual(result.strip(), '$Cf')

    def test_get_variable_value_abbreviated_short(self):
        for switch in ('-V', '-Va', '-Val', '-Valu', '-Value', '-ValueO', '-ValueOn', '-ValueOnl', '-ValueOnly'):
            with self.subTest(switch=switch):
                result = self._deobfuscate(F'Get-Variable Cf {switch}')
                self.assertEqual(result.strip(), '$Cf')

    def test_get_childitem_variable_drive_resolved(self):
        result = self._deobfuscate("(Get-ChildItem 'Variable:ExecutionContext').Value")
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_gci_variable_drive_resolved(self):
        result = self._deobfuscate("(gci 'Variable:X').Value")
        self.assertIn('$X', result)
        self.assertNotIn('gci', result)

    def test_get_variable_value_only_member_access(self):
        result = self._deobfuscate(
            '(Get-Variable ExecutionContext -ValueOnly).InvokeCommand'
        )
        self.assertIn('$ExecutionContext', result)
        self.assertIn('InvokeCommand', result)
        self.assertNotIn('Get-Variable', result)

    def test_where_object_wildcard_paren_wrapped_pipeline(self):
        result = self._deobfuscate(
            '((New-Object Net.WebClient) | Get-Member) | ? { $_.Name -ilike \'Do*e\' }'
        )
        self.assertIn('DownloadFile', result)
        self.assertNotIn('Do*e', result)

    def test_new_object_type_resolution_in_pipeline(self):
        result = self._deobfuscate(
            '(New-Object Net.WebClient | Get-Member)[6].Name'
        )
        self.assertNotIn('[6].Name', result)

    def test_where_object_wildcard_variable_type_inferred(self):
        code = (
            "$x = New-Object Net.WebClient;"
            " ($x | Get-Member) | ? { $_.Name -ilike 'Do*e' }"
        )
        result = self._deobfuscate(code)
        self.assertIn('DownloadFile', result)
        self.assertNotIn('Do*e', result)


class TestPs1TypeSystemSimplifications(TestPs1):

    def test_get_member_index_name_resolved(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[6].Name')
        self.assertIn('InvokeCommand', result)
        self.assertNotIn('[6]', result)

    def test_get_member_index_unknown_type_preserved(self):
        result = self._deobfuscate('($unknown | Get-Member)[6].Name')
        self.assertIn('[6].Name', result)

    def test_get_member_index_out_of_range_preserved(self):
        result = self._deobfuscate('($ExecutionContext | Get-Member)[999].Name')
        self.assertIn('[999].Name', result)

    def test_name_on_string_literal_stripped(self):
        result = self._deobfuscate("$x.('GetCmdlets'.Name)('*w-*ct')")
        self.assertNotIn('.Name', result)
        self.assertIn('New-Object', result)


class TestPs1ConstantInlining(TestPs1):

    def test_scalar_string_inlining(self):
        result = self._deobfuscate("$x = 'hello'; Write-Output $x")
        self.assertIn("'hello'", result)
        self.assertNotIn('$x', result)

    def test_scalar_integer_inlining(self):
        result = self._deobfuscate('$x = 42; Write-Output $x')
        self.assertIn('42', result)
        self.assertNotIn('$x', result)

    def test_array_index_inlining(self):
        result = self._deobfuscate("$a = @('foo','bar','baz'); Write-Output $a[1]")
        self.assertIn("'bar'", result)
        self.assertNotIn('$a', result)

    def test_array_multiple_indices(self):
        result = self._deobfuscate(
            "$a = @('X','Y','Z'); $r = $a[0] + $a[2]")
        self.assertIn('XZ', result)
        self.assertNotIn('$a', result)

    def test_double_assignment_not_inlined(self):
        result = self._deobfuscate("$x = 'a'; $x = 'b'; Write-Output $x")
        self.assertIn('$x', result)

    def test_compound_assignment_disqualifies(self):
        result = self._deobfuscate("$x = 'a'; $x += 'b'; Write-Output $x")
        self.assertIn('$x', result)

    def test_same_value_multiple_assignments_inlined(self):
        result = self._deobfuscate(
            "$x = 'hello'; Write-Host $x; $x = 'hello'; Write-Host $x")
        self.assertNotIn('$x', result)
        self.assertEqual(result.count("'hello'"), 2)

    def test_same_value_integer_multiple_assignments_folded(self):
        result = self._deobfuscate_iterative(
            '$x = 150; $y = ($x + 1); $x = 150; $z = ($x + 2)')
        self.assertNotIn('$x', result)
        self.assertIn('151', result)
        self.assertIn('152', result)

    def test_mixed_constant_and_nonconst_not_inlined(self):
        result = self._deobfuscate("$x = 'a'; $x = $y; Write-Output $x")
        self.assertIn('$x', result)

    def test_variable_index_skipped(self):
        result = self._deobfuscate("$a = @('x','y'); Write-Output $a[$i]")
        self.assertIn('$a', result)
        self.assertIn('$i', result)

    def test_try_body_skipped(self):
        result = self._deobfuscate(
            "$x = 'val'; try { Write-Output $x } catch { }")
        self.assertIn('$x', result)

    def test_catch_body_inlined(self):
        result = self._deobfuscate(
            "$x = 'val'; try { foo } catch { Write-Output $x }")
        self.assertIn("'val'", result)

    def test_foreach_variable_not_candidate(self):
        result = self._deobfuscate(
            "foreach ($item in @('a','b')) { Write-Output $item }")
        self.assertIn('$item', result)

    def test_param_variable_not_candidate(self):
        result = self._deobfuscate(
            "param($x); Write-Output $x")
        self.assertIn('$x', result)

    def test_assignment_removed_when_all_refs_substituted(self):
        result = self._deobfuscate("$x = 'hello'; Write-Output $x")
        self.assertNotIn("$x = 'hello'", result)
        self.assertNotIn('$x', result)

    def test_assignment_kept_when_some_refs_remain(self):
        result = self._deobfuscate(
            "$a = @('x','y'); Write-Output $a[0]; Write-Output $a[$i]")
        self.assertIn('$a', result)
        self.assertIn("'x'", result)
        self.assertIn('$i', result)

    def test_case_insensitive_matching(self):
        result = self._deobfuscate("$Foo = 'bar'; Write-Output $foo")
        self.assertIn("'bar'", result)
        self.assertNotIn('$foo', result)
        self.assertNotIn('$Foo', result)

    def test_scoped_variable_not_inlined(self):
        result = self._deobfuscate("$script:x = 'val'; Write-Output $script:x")
        self.assertIn('$script:x', result)

    def test_increment_not_inlined(self):
        result = self._deobfuscate("$i = 0; $i++; Write-Output $i")
        self.assertIn('$i', result)
        self.assertNotIn('0++', result)

    def test_nonconst_value_not_inlined(self):
        result = self._deobfuscate("$x = Get-Date; Write-Output $x")
        self.assertIn('$x', result)

    def test_zero_ref_constant_not_pruned(self):
        result = self._deobfuscate("$url = 'http://evil.com'; Write-Host done")
        self.assertIn('$url', result)
        self.assertIn('http://evil.com', result)

    def test_env_comspec_inlined(self):
        result = self._deobfuscate("$x = $env:ComSpec[4]")
        self.assertNotIn('ComSpec', result)
        self.assertIn("'I'", result)

    def test_null_variable_inlined(self):
        result = self._deobfuscate_iterative(
            '$x = $Null; Write-Host (5 + $x)')
        self.assertIn('5', result)
        self.assertNotIn('$x', result)

    def test_null_assigned_variable_folds(self):
        result = self._deobfuscate_iterative(
            '$x = $Null; $y = 10 - $x; Write-Host $y')
        self.assertIn('10', result)
        self.assertNotIn('$x', result)
        self.assertNotIn('$y', result)


class TestPs1FunctionEvaluator(TestPs1):

    def test_stride_extraction(self):
        data = (
            "Function F ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$x = F 'HaEbLcLdOeX'"
            "\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('abcde', result)
        self.assertNotIn('function', result.lower())

    def test_multiple_call_sites(self):
        data = (
            "Function D ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$a = D 'XaYbZcX'\n"
            "$b = D 'P1Q2R3X'\n"
            "Write-Output $a\nWrite-Output $b"
        )
        result = self._deobfuscate(data)
        self.assertIn('abc', result)
        self.assertIn('123', result)
        self.assertNotIn('function', result.lower())

    def test_nonconstant_arg_preserved(self):
        data = (
            "Function D ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$y = D $input"
        )
        result = self._deobfuscate(data)
        self.assertIn('$input', result)
        self.assertIn('function', result.lower())

    def test_while_loop_variant(self):
        data = (
            "Function W ([String]$s){"
            "$i=0; $r=''; "
            "While($i -lt $s.Length){$r=$r+$s.Substring($i, 1); $i+=2};"
            "$r;}"
            "$x = W 'HEeLlLlOo'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_foreach_tochararray(self):
        data = (
            "Function R ([String]$s){"
            "$a = $s.ToCharArray(); $r = '';"
            "ForEach($c in $a){$r = $c + $r};"
            "$r;}"
            "$x = R 'olleH'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_if_inside_function(self):
        data = (
            "Function C ([String]$s){"
            "$r = '';"
            "For($i=0; $i -lt $s.Length; $i+=1){"
            "If ($i % 2 -eq 0){$r = $r + $s.Substring($i, 1)}"
            "}; $r;}"
            "$x = C 'HxExLxLxO'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('HELLO', result)

    def test_function_definition_kept_when_not_all_resolved(self):
        data = (
            "Function D ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$a = D 'XaYbX'\n"
            "$b = D $var"
        )
        result = self._deobfuscate(data)
        self.assertIn('ab', result)
        self.assertIn('function', result.lower())

    def test_return_statement(self):
        data = (
            "Function R ([String]$s){"
            "$r = '';"
            "For($i=0; $i -lt $s.Length; $i+=2){"
            "$r = $r + $s.Substring($i, 1)"
            "}; return $r;}"
            "$x = R 'HxExLxLxOx'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('HELLO', result)

    def test_do_while_loop(self):
        data = (
            "Function D ([String]$s){"
            "$i = 0; $r = '';"
            "Do{$r = $r + $s.Substring($i, 1); $i += 2}"
            "While($i -lt $s.Length);"
            "$r;}"
            "$x = D 'HxExLxLxOx'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('HELLO', result)

    def test_new_object_byte_array(self):
        data = (
            "Function F ([Int]$n){"
            "$a = New-Object byte[] $n;"
            "$r = '';"
            "For($i=0; $i -lt $n; $i+=1){$r = $r + $a[$i]};"
            "$r;}"
            "$x = F 3\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('000', result)

    def test_convert_tobyte_static(self):
        data = (
            "Function F ([String]$s){"
            "$r = [convert]::ToByte($s, 16);"
            "$r;}"
            "$x = F 'FF'\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('255', result)

    def test_encoding_getstring(self):
        data = (
            "Function F {"
            "$a = New-Object byte[] 3;"
            "$a[0] = 72; $a[1] = 105; $a[2] = 33;"
            "[System.Text.Encoding]::ASCII.GetString($a);}"
            "$x = F\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hi!', result)

    def test_hex_xor_decode_function(self):
        data = (
            "Function F ([String]$s){\n"
            "$a = New-Object byte[] ($s.Length / 2)\n"
            "For($i=0; $i -lt $s.Length; $i+=2){\n"
            "$a[$i/2] = [convert]::ToByte($s.Substring($i, 2), 16)\n"
            "$a[$i/2] = ($a[$i/2] -bxor 128)\n"
            "}\n"
            "[String][System.Text.Encoding]::ASCII.GetString($a)\n"
            "}\n"
            "$x = F 'C8E5ECECEF'\n"
            "Write-Output $x\n"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)
        self.assertNotIn('function', result.lower())

    def test_base64_xor_decode_function(self):
        data = (
            "Function F ([String]$s, [Byte]$k) {\n"
            "$a = [System.Convert]::FromBase64String($s)\n"
            "For ($i = 0; $i -lt $a.Length; $i++) {\n"
            "$a[$i] = $a[$i] -bxor $k\n"
            "}\n"
            "return [System.Text.Encoding]::ASCII.GetString($a)\n"
            "}\n"
            "$x = F 'aEVMTE8=' 0x20\n"
            "Write-Output $x\n"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)
        self.assertNotIn('function', result.lower())


class TestPs1IexInlining(TestPs1):

    def test_iex_single_statement(self):
        result = self._deobfuscate("IEX 'Write-Host hello'")
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result.upper().split('WRITE')[0])

    def test_iex_multi_statement(self):
        result = self._deobfuscate("IEX '$a = 1; $b = 2'")
        self.assertIn('$a = 1', result)
        self.assertIn('$b = 2', result)
        self.assertNotIn('IEX', result)

    def test_iex_variable_not_inlined(self):
        result = self._deobfuscate('IEX $var')
        self.assertIn('Invoke-Expression', result)
        self.assertIn('$var', result)

    def test_iex_after_constant_inlining(self):
        result = self._deobfuscate("$x = 'Write-Host hi'; IEX $x")
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result)
        self.assertNotIn('$x', result)

    def test_iex_inside_function_body(self):
        data = (
            "function F {\n"
            "IEX '$y = 42'\n"
            "}\n"
        )
        result = self._deobfuscate(data)
        self.assertIn('$y = 42', result)
        self.assertNotIn('IEX', result)

    def test_invoke_expression_long_form(self):
        result = self._deobfuscate("Invoke-Expression 'Write-Host hello'")
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_piped_string(self):
        result = self._deobfuscate("'Write-Host hello' | IEX")
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result)
        self.assertNotIn('|', result)

    def test_iex_piped_variable_not_inlined(self):
        result = self._deobfuscate('$var | IEX')
        self.assertIn('Invoke-Expression', result)
        self.assertIn('$var', result)

    def test_invoke_expression_piped_long_form(self):
        result = self._deobfuscate("'Write-Host hello' | Invoke-Expression")
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('|', result)

    def test_iex_piped_deflate_pipeline(self):
        # Base64-encoded raw deflate of "Write-Host hello"
        b64 = 'Cy/KLEnV9cgvLlHISM3JyQcA'
        data = (
            "(New-Object IO.Compression.DeflateStream("
            F"[IO.MemoryStream][Convert]::FromBase64String('{b64}'),"
            " [IO.Compression.CompressionMode]::Decompress)"
            " | %{ New-Object System.IO.StreamReader($_, [Text.Encoding]::ASCII) }"
            " | %{ $_.ReadToEnd() })"
            " | Invoke-Expression"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('FromBase64String', result)

    def test_iex_expression_position_inlined(self):
        result = self._deobfuscate("$x = Invoke-Expression \"'hello'\"")
        self.assertIn("$x = 'hello'", result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_expression_multi_statement_not_inlined(self):
        result = self._deobfuscate("$x = Invoke-Expression \"'a'; 'b'\"")
        self.assertIn('Invoke-Expression', result)

    def test_iex_via_env_comspec_indexing(self):
        data = "& ($env:ComSpec[4,26,25] -Join '') 'Write-Host hello'"
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('ComSpec', result)

    def test_iex_piped_via_env_comspec(self):
        data = "'Write-Host hello' | & ($env:ComSpec[4,26,25] -Join '')"
        result = self._deobfuscate(data)
        self.assertNotIn('ComSpec', result)
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)

    def test_iex_deflate_byte_array(self):
        data = (
            "(New-Object IO.StreamReader("
            "(New-Object IO.Compression.DeflateStream("
            "[IO.MemoryStream]@("
            "0x0B, 0x2F, 0xCA, 0x2C, 0x49, 0xD5, 0xF5, 0xC8,"
            " 0x2F, 0x2E, 0x51, 0xC8, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00),"
            " [IO.Compression.CompressionMode]::Decompress)),"
            " [Text.Encoding]::ASCII)).ReadToEnd() | IEX"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result)
        self.assertNotIn('DeflateStream', result)

    def test_scriptblock_create_ampersand(self):
        result = self._deobfuscate("&([scriptblock]::Create('Write-Host hello'))")
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_scriptblock_create_invoke(self):
        result = self._deobfuscate("[scriptblock]::Create('Write-Host hello').Invoke()")
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_scriptblock_create_fqn(self):
        result = self._deobfuscate(
            "&([System.Management.Automation.ScriptBlock]::Create('Write-Host hello'))"
        )
        self.assertIn('Write-Host', result)
        self.assertNotIn('ScriptBlock', result)

    def test_scriptblock_create_deflate(self):
        b64 = 'Cy/KLEnV9cgvLlHISM3JyQcA'
        data = (
            "&([scriptblock]::Create("
            "(New-Object IO.StreamReader("
            "(New-Object IO.Compression.DeflateStream("
            F"[IO.MemoryStream][Convert]::FromBase64String('{b64}'),"
            " [IO.Compression.CompressionMode]::Decompress)),"
            " [Text.Encoding]::ASCII)).ReadToEnd()))"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())
        self.assertNotIn('FromBase64String', result)

    def test_scriptblock_create_gzip_new_object_memorystream(self):
        b64 = 'H4sIAP7802kC/wsvyixJ1fXILy5RyEjNyckHAA2QLxEQAAAA'
        data = (
            "&([scriptblock]::Create("
            "(New-Object IO.StreamReader("
            "(New-Object IO.Compression.GzipStream("
            "(New-Object IO.MemoryStream(,"
            F"[Convert]::FromBase64String('{b64}'))),"
            " [IO.Compression.CompressionMode]::Decompress)))"
            ".ReadToEnd()))"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())
        self.assertNotIn('FromBase64String', result)

    def test_scriptblock_create_variable_not_inlined(self):
        result = self._deobfuscate('&([scriptblock]::Create($var))')
        self.assertIn('scriptblock', result.lower())
        self.assertIn('$var', result)

    def test_scriptblock_create_multi_statement(self):
        result = self._deobfuscate("&([scriptblock]::Create('$a = 1; $b = 2'))")
        self.assertIn('$a = 1', result)
        self.assertIn('$b = 2', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_scriptblock_create_invoke_return_as_is(self):
        result = self._deobfuscate("[scriptblock]::Create('Write-Host hello').InvokeReturnAsIs()")
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_iex_inside_subexpression(self):
        result = self._deobfuscate_iterative("$('\"hello\"' | Invoke-Expression)")
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_piped_inside_assignment(self):
        result = self._deobfuscate("$x = 'Write-Host hello' | Invoke-Expression")
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('|', result)

    def test_multiline_string_emitted_as_here_string(self):
        from refinery.lib.scripts.ps1.deobfuscation._helpers import _make_string_literal
        from refinery.lib.scripts.ps1.model import Ps1HereString, Ps1StringLiteral
        node = _make_string_literal('line1\nline2')
        self.assertIsInstance(node, Ps1HereString)
        self.assertEqual(node.value, 'line1\nline2')
        self.assertIn("@'\n", node.raw)
        node2 = _make_string_literal('no newlines')
        self.assertIsInstance(node2, Ps1StringLiteral)


class TestPs1ForEachPipeline(TestPs1):

    def test_foreach_pipeline_char_convert(self):
        data = "'72z101z108z108z111'.Split('z') | %{ ([Char]([Convert]::ToInt16(($_.ToString()), 10))) }"
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_foreach_pipeline_negative_integers(self):
        data = "((-83,-71,-65,-75,-107,-70,-75,-64,-110,-83,-75,-72,-79,-80) | %{ [char]($_ + 180) }) -join ''"
        result = self._deobfuscate(data)
        self.assertIn('amsiInitFailed', result)

    def test_foreach_pipeline_mixed_sign_integers(self):
        data = "(-4, 1, -17) | %{ [char]($_ + 104) }"
        result = self._deobfuscate(data)
        self.assertIn('d', result)
        self.assertIn('i', result)
        self.assertIn('W', result)

    def test_foreach_pipeline_expandable_string_hex_decode(self):
        data = "'46 75 6E' -split ' ' | %{[char][byte]\"0x$_\"}"
        result = self._deobfuscate(data)
        self.assertIn('Fun', result)

    def test_foreach_pipeline_expandable_string_with_subexpr(self):
        data = "@('A','B','C') | %{\"item: $( $_ )\"}"
        result = self._deobfuscate(data)
        self.assertIn('item: A', result)

    def test_foreach_pipeline_split_join_chain(self):
        data = (
            "$s = '48 65 6C 6C 6F'\n"
            "$r = $s -split ' ' | ForEach-Object {[char][byte]\"0x$_\"}\n"
            "$r -join ''"
        )
        result = self._deobfuscate_iterative(data)
        self.assertIn('Hello', result)

    def test_foreach_pipeline_replace_operator(self):
        data = "@('Hello','World') | %{$_ -replace 'o','0'}"
        result = self._deobfuscate(data)
        self.assertIn('Hell0', result)
        self.assertIn('W0rld', result)

    def test_foreach_pipeline_array_expression(self):
        data = "@(65,66,67) | %{[char]$_}"
        result = self._deobfuscate(data)
        self.assertIn('A', result)
        self.assertIn('B', result)

    def test_foreach_pipeline_string_join_static(self):
        data = "[String]::Join(',', @('a','b','c'))"
        result = self._deobfuscate(data)
        self.assertIn('a,b,c', result)


class TestPs1WildcardResolution(TestPs1):

    def test_wildcard_variable_get_item(self):
        result = self._deobfuscate("(Get-Item Variable:E*t).Value")
        self.assertIn('$ExecutionContext', result)
        self.assertNotIn('Variable:', result)

    def test_wildcard_variable_ambiguous(self):
        result = self._deobfuscate("Get-Item Variable:P*")
        self.assertIn('Variable:P*', result)

    def test_wildcard_cmdlet_getcmdlets(self):
        result = self._deobfuscate("$x.GetCmdlets('*w-*ct')")
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCmdlets', result)

    def test_wildcard_cmdlet_invoke(self):
        result = self._deobfuscate("$x.Invoke('*w-*ct')")
        self.assertIn('New-Object', result)

    def test_wildcard_member_filter(self):
        result = self._deobfuscate("[IO.StreamReader] | Get-Member | ? { $_.Name -ilike 'ReadT*d' }")
        self.assertIn('ReadToEnd', result)

    def test_wildcard_member_filter_no_space_before_operator(self):
        result = self._deobfuscate("[IO.StreamReader] | Get-Member | ? { $_.Name-ilike'ReadT*d' }")
        self.assertIn('ReadToEnd', result)

    def test_wildcard_where_get_command(self):
        result = self._deobfuscate("Get-Command | ? { $_.Name -ilike '*w-*ct' }")
        self.assertIn('New-Object', result)

    def test_wildcard_where_unknown_source(self):
        result = self._deobfuscate("$obj | ? { $_.Name -ilike '*ts' }")
        self.assertNotIn('Exists', result)
        self.assertIn("'*ts'", result)

    def test_getcommandname_wildcard_resolved(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', $True, $True)"
        )
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCommandName', result)

    def test_getcommand_wildcard_resolved(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.GetCommand('*w-*ct', 'All')"
        )
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCommand', result)

    def test_getcommand_exact_name_resolved(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.GetCommand('New-Object', 'Cmdlet')"
        )
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCommand', result)

    def test_childitem_variable_resolved(self):
        result = self._deobfuscate(
            "$Y = 'hello'; (ChildItem Variable:\\Y).Value"
        )
        self.assertNotIn('ChildItem', result)
        self.assertNotIn('Variable:', result)

    def test_get_variable_name_wildcard(self):
        result = self._deobfuscate("(Get-Variable '*mdr*').Name")
        self.assertIn('MaximumDriveCount', result)
        self.assertNotIn('Get-Variable', result)

    def test_get_variable_name_wildcard_indexed_join(self):
        result = self._deobfuscate_iterative(
            "(Get-Variable '*mdr*').Name[3, 11, 2] -Join ''"
        )
        self.assertIn('iex', result.lower())
        self.assertNotIn('Get-Variable', result)


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
        self.assertIn('::FromBase64String', result)
        self.assertIn('Convert', result)
        self.assertNotIn('Get-Variable', result)

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


class TestPs1NameNormalization(TestPs1):

    def test_wmi_class_name_normalized(self):
        result = self._deobfuscate(
            'Get-WmiObject wIn32_oPErATinGsYsteM'
        )
        self.assertIn('Win32_OperatingSystem', result)
        self.assertNotIn('wIn32_oPErATinGsYsteM', result)

    def test_env_variable_name_normalized(self):
        result = self._deobfuscate('${env:aPpdatA}')
        self.assertIn('AppData', result)
        self.assertNotIn('aPpdatA', result)


class TestPs1SubExpressionSimplification(TestPs1):

    def test_subexpression_scalar_simplified(self):
        result = self._deobfuscate("$('hello')")
        self.assertEqual(result.strip(), "'hello'")

    def test_replace_on_subexpression(self):
        result = self._deobfuscate("$('hello world').Replace('world', 'there')")
        self.assertIn('hello there', result)
        self.assertNotIn('$(', result)

    def test_subexpression_member_access(self):
        result = self._deobfuscate('$K[$i % $K.$($p) * $f]')
        self.assertIn('$K.$p', result)
        self.assertNotIn('\n*\n', result)

    def test_chained_replace_across_subexpression(self):
        result = self._deobfuscate(
            "$('aXb'.Replace('X', 'Y')).Replace('Y', 'Z')"
        )
        self.assertNotIn('aXb', result)
        self.assertIn('aZb', result)


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
        result = self._deobfuscate("\"\"\"$($x)\"\"\"")
        self.assertIn('$(', result)

    def test_expandable_full_chain_with_iex(self):
        result = self._deobfuscate_iterative(
            "$(\"\"\"$($((312,348,348)|%{[char]($_/3)})-join'')\"\"\")"
            " | Invoke-Expression")
        self.assertIn('htt', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('$(', result)


class TestPs1ComparisonFolding(TestPs1):

    def test_eq_true(self):
        result = self._deobfuscate('(3 -eq 3)')
        self.assertIn('$True', result)

    def test_eq_false(self):
        result = self._deobfuscate('(3 -eq 4)')
        self.assertIn('$False', result)

    def test_lt_true(self):
        result = self._deobfuscate('(1 -lt 2)')
        self.assertIn('$True', result)

    def test_ge_false(self):
        result = self._deobfuscate('(-296 -ge 44)')
        self.assertIn('$False', result)

    def test_le_negative(self):
        result = self._deobfuscate('(81 -le -230)')
        self.assertIn('$False', result)

    def test_parenthesized_operands(self):
        result = self._deobfuscate('((5) -gt (3))')
        self.assertIn('$True', result)

    def test_non_constant_unchanged(self):
        result = self._deobfuscate('$x = $env:V\n($x -eq 3)')
        self.assertIn('-Eq', result)


class TestPs1DeadCodeElimination(TestPs1):

    def test_while_false_removed(self):
        result = self._deobfuscate("while ($False) { Write-Host 'dead' }; Write-Host 'live'")
        self.assertNotIn('dead', result)
        self.assertIn('live', result)

    def test_if_true_keeps_then(self):
        result = self._deobfuscate("if ($True) { Write-Host 'yes' } else { Write-Host 'no' }")
        self.assertIn('yes', result)
        self.assertNotIn("'no'", result)

    def test_if_false_keeps_else(self):
        result = self._deobfuscate("if ($False) { Write-Host 'a' } else { Write-Host 'b' }")
        self.assertNotIn("'a'", result)
        self.assertIn('b', result)

    def test_if_false_then_true_elseif(self):
        result = self._deobfuscate("if ($False) {} elseif ($True) { Write-Host 'second' }")
        self.assertIn('second', result)

    def test_all_false_keeps_else(self):
        result = self._deobfuscate("if ($False) {} elseif ($False) {} else { Write-Host 'else' }")
        self.assertIn('else', result)

    def test_non_static_stops_pruning(self):
        result = self._deobfuscate("$x = $env:V\nif ($False) {} elseif ($x) { Write-Host 'kept' }")
        self.assertNotIn('$False', result)
        self.assertIn('$x', result)
        self.assertIn('kept', result)

    def test_switch_constant_match(self):
        result = self._deobfuscate("switch (5) { 3 { 'a' } 5 { 'b' } default { 'c' } }")
        self.assertIn('b', result)
        self.assertNotIn("'a'", result)
        self.assertNotIn("'c'", result)

    def test_switch_constant_default(self):
        result = self._deobfuscate("switch (99) { 1 { 'a' } default { 'd' } }")
        self.assertIn('d', result)
        self.assertNotIn("'a'", result)

    def test_switch_constant_no_match(self):
        result = self._deobfuscate("switch (99) { 1 { 'a' } 2 { 'b' } }")
        self.assertNotIn("'a'", result)
        self.assertNotIn("'b'", result)

    def test_do_while_false_executes_once(self):
        result = self._deobfuscate("do { Write-Host 'once' } while ($False)")
        self.assertIn('once', result)
        self.assertNotIn('while', result.lower())

    def test_if_false_no_else_removed(self):
        result = self._deobfuscate("if ($False) { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_true_empty_then(self):
        result = self._deobfuscate("if ($True) {} else { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_nonzero_integer_truthy(self):
        result = self._deobfuscate("if (99) { Write-Host 'yes' } else { Write-Host 'no' }")
        self.assertIn('yes', result)
        self.assertNotIn("'no'", result)

    def test_if_zero_integer_falsy(self):
        result = self._deobfuscate("if (0) { Write-Host 'dead' } else { Write-Host 'live' }")
        self.assertNotIn('dead', result)
        self.assertIn('live', result)

    def test_while_zero_removed(self):
        result = self._deobfuscate("while (0) { Write-Host 'dead' }; Write-Host 'live'")
        self.assertNotIn('dead', result)
        self.assertIn('live', result)

    def test_if_nonempty_string_truthy(self):
        result = self._deobfuscate("if ('x') { Write-Host 'yes' }")
        self.assertIn('yes', result)
        self.assertNotIn('if', result.lower().split('write')[0])

    def test_if_empty_string_falsy(self):
        result = self._deobfuscate("if ('') { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_negative_integer_truthy(self):
        result = self._deobfuscate("if (-12) { Write-Host 'yes' }")
        self.assertIn('yes', result)
        self.assertNotIn('-12', result)

    def test_if_null_falsy(self):
        result = self._deobfuscate("if ($Null) { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_zero_real_falsy(self):
        result = self._deobfuscate("if (0.0) { Write-Host 'dead' }")
        self.assertNotIn('dead', result)

    def test_if_nonzero_real_truthy(self):
        result = self._deobfuscate("if (3.14) { Write-Host 'yes' }")
        self.assertIn('yes', result)
        self.assertNotIn('3.14', result)

    def test_dead_for_loop_false_eq(self):
        result = self._deobfuscate(
            "for($x=175;$x-Eq437;$x++){Write-Host 'hi'}")
        self.assertIn('$x', result)
        self.assertIn('175', result)
        self.assertNotIn('for', result.lower())
        self.assertNotIn('Write-Host', result)

    def test_dead_for_loop_true_condition(self):
        result = self._deobfuscate(
            "for($x=10;$x-Eq10;$x++){Write-Host 'hi'}")
        self.assertIn('for', result.lower())

    def test_dead_for_loop_no_initializer(self):
        result = self._deobfuscate(
            "for(;$False;){Write-Host 'hi'}")
        self.assertNotIn('Write-Host', result)

    def test_for_break_unrolled(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 10;$i++){$x = 1; $y = 2; break}")
        self.assertNotIn('for', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('$x', result)
        self.assertIn('$y', result)
        self.assertIn('$i', result)

    def test_for_break_labeled_preserved(self):
        result = self._deobfuscate(
            ":outer for($i=0;$i -lt 5;$i++){$x = 1; break :outer}")
        self.assertIn('for', result.lower())

    def test_for_break_with_continue_preserved(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 5;$i++){if($i -eq 3){continue}; $x = 1; break}")
        self.assertIn('for', result.lower())

    def test_for_break_not_last_preserved(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 5;$i++){break; $x = 1}")
        self.assertIn('for', result.lower())

    def test_for_break_only(self):
        result = self._deobfuscate(
            "for($i=0;$i -lt 5;$i++){break}")
        self.assertNotIn('for', result.lower())
        self.assertIn('$i', result)

    def test_while_break_unrolled(self):
        result = self._deobfuscate(
            "while($True){$x = 42; break}")
        self.assertNotIn('while', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('42', result)

    def test_do_while_break_unrolled(self):
        result = self._deobfuscate(
            "do{$x = 42; break}while($True)")
        self.assertNotIn('do', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('42', result)

    def test_do_until_break_unrolled(self):
        result = self._deobfuscate(
            "do{$x = 42; break}until($False)")
        self.assertNotIn('until', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('42', result)

    def test_while_break_false_condition_removed(self):
        result = self._deobfuscate_iterative(
            "while($False){$x = 42; break}")
        self.assertNotIn('42', result)

    def test_while_break_unknown_condition_guarded(self):
        result = self._deobfuscate(
            "while(Get-Random){$x = 42; break}")
        self.assertNotIn('while', result.lower())
        self.assertNotIn('break', result.lower())
        self.assertIn('if', result.lower())
        self.assertIn('42', result)

    def test_for_break_false_condition_preserves_init(self):
        result = self._deobfuscate_iterative(
            "for($i=0; $False; $i++){$x = 42; break}")
        self.assertNotIn('42', result)
        self.assertIn('$i', result)

    def test_while_dead_loop_no_incorrect_inline(self):
        result = self._deobfuscate_iterative(
            '$a = 10\n'
            'while((-9 + $a) -GE (44)) { $b = $a; break }\n'
            '$c = $b - 200\n'
            '$d = [Char][int]$c'
        )
        self.assertNotIn('[Char]-', result.lower())

    def test_bare_integer_statements_pruned(self):
        result = self._deobfuscate_iterative(
            '$x = Get-Process\n'
            '42\n'
            'Write-Host $x\n'
            '(-7)\n'
        )
        self.assertNotIn('42', result)
        self.assertNotIn('-7', result)
        self.assertIn('Get-Process', result)

    def test_bare_integer_only_script_preserved(self):
        result = self._deobfuscate('42')
        self.assertIn('42', result)

    def test_string_statement_preserved(self):
        result = self._deobfuscate_iterative(
            '$x = Get-Process\n'
            "'hello'\n"
            'Write-Host $x\n'
        )
        self.assertIn('hello', result)

    def test_constant_in_switch_case_pruned(self):
        result = self._deobfuscate_iterative(
            'switch ($action) {\n'
            '  1 { 99 }\n'
            '  2 { Write-Host "ok" }\n'
            '}\n'
        )
        self.assertNotIn('99', result)
        self.assertIn('Write-Host', result)

    def test_constant_in_subexpression_preserved(self):
        result = self._deobfuscate('"prefix$( 1 + 2 )suffix"')
        self.assertIn('prefix', result)
        self.assertIn('suffix', result)
        self.assertNotIn('prefix""suffix', result.replace(' ', ''))


class TestPs1CharIntFolding(TestPs1):

    def test_char_int_literal(self):
        result = self._deobfuscate('[Char][int]83')
        self.assertEqual(result.strip(), "'S'")

    def test_char_literal_regression(self):
        result = self._deobfuscate('[Char]65')
        self.assertEqual(result.strip(), "'A'")

    def test_char_int_concat(self):
        result = self._deobfuscate_iterative('([Char][int]72 + [Char][int]105)')
        self.assertEqual(result.strip(), "'Hi'")

    def test_char_int_negative_not_folded(self):
        result = self._deobfuscate('[Char][int](-65)')
        self.assertNotIn("'", result)

    def test_int_identity_cast_stripped(self):
        result = self._deobfuscate('[int]42')
        self.assertEqual(result.strip(), '42')

    def test_char_int_multi_concat(self):
        result = self._deobfuscate_iterative(
            '([Char][int]83 + [Char][int]116 + [Char][int]111 + [Char][int]112)')
        self.assertEqual(result.strip(), "'Stop'")

    def test_char_int_partial_with_variable(self):
        result = self._deobfuscate_iterative(
            '([Char][int]83 + [Char][int]$x + [Char][int]112)')
        self.assertIn('Sp', result)


class TestPs1DeadBranchInlining(TestPs1):

    def test_conditional_only_variable_not_inlined(self):
        result = self._deobfuscate_iterative(
            '$x = 1\n'
            'if (0 -GE 1) { $x = 999 }\n'
            'Write-Host $x'
        )
        self.assertIn('1', result)
        self.assertNotIn('999', result)

    def test_dead_branch_arithmetic_not_evaluated(self):
        result = self._deobfuscate_iterative(
            'if (0 -GT 1) { $a = 500 }\n'
            '$b = $a - 200\n'
            '$c = [Char][int]$b'
        )
        self.assertNotIn('[Char][int]-', result)

    def test_unconditional_assignment_still_inlined(self):
        result = self._deobfuscate_iterative(
            '$x = 42\n'
            'if (1 -GT 0) { $x = 42 }\n'
            'Write-Host $x'
        )
        self.assertIn('42', result)

    def test_conditional_only_not_inlined_nonconstant_condition(self):
        result = self._deobfuscate_iterative(
            'if ($env:OS -eq "Windows_NT") { $x = 42 }\n'
            'Write-Host $x'
        )
        self.assertIn('$x', result)

    def test_char_cast_no_negative(self):
        result = self._deobfuscate_iterative(
            'if ($y -GE 100) { $a = 500 }\n'
            '$b = $a - 700\n'
            '$c = [Char][int]$b'
        )
        self.assertNotIn('$y', result)
        self.assertNotIn('$a', result)
        self.assertIn('-700', result)


class TestPs1NullVariableInlining(TestPs1):

    def test_null_arithmetic(self):
        result = self._deobfuscate_iterative(
            '$x = 5 + $unset\n'
            'Write-Host $x'
        )
        self.assertIn('5', result)
        self.assertNotIn('$unset', result)

    def test_null_if_branch_elimination(self):
        result = self._deobfuscate_iterative(
            'if ($undefined) {\n'
            "    Write-Host 'dead'\n"
            '} else {\n'
            "    Write-Host 'live'\n"
            '}'
        )
        self.assertIn('live', result)
        self.assertNotIn('dead', result)

    def test_null_complex_arithmetic(self):
        result = self._deobfuscate_iterative(
            '$x = (10 - $a + 3)\n'
            'Write-Host $x'
        )
        self.assertIn('13', result)
        self.assertNotIn('$a', result)

    def test_no_inlining_for_assigned_variable(self):
        result = self._deobfuscate_iterative(
            '$y = 5\n'
            '$x = $y + 1\n'
            'Write-Host $x'
        )
        self.assertIn('6', result)

    def test_no_inlining_for_known_variable(self):
        result = self._deobfuscate_iterative(
            'Write-Host $Host'
        )
        self.assertIn('$Host', result)

    def test_no_inlining_for_automatic_variable(self):
        result = self._deobfuscate_iterative(
            '$_ | Write-Host'
        )
        self.assertIn('$_', result)

    def test_no_inlining_for_parameter_variable(self):
        result = self._deobfuscate_iterative(
            'function f {\n'
            '    Param($x)\n'
            '    $x + 1\n'
            '}'
        )
        self.assertIn('$x', result)

    def test_no_inlining_for_foreach_variable(self):
        result = self._deobfuscate_iterative(
            'foreach ($item in @(1, 2, 3)) {\n'
            '    $item\n'
            '}'
        )
        self.assertIn('$item', result)

    def test_no_inlining_for_typed_assignment(self):
        result = self._deobfuscate_iterative(
            '[Byte[]]$data = Get-Content -Encoding Byte "test.bin"\n'
            'Write-Host $data.Length'
        )
        self.assertNotIn('$Null', result)
        self.assertIn('$data', result)


class TestPs1RegexFolding(TestPs1):

    def test_regex_matches_simple(self):
        result = self._deobfuscate("[Regex]::Matches('abc123def', '\\d+').Groups.Captures.Groups.Value")
        self.assertIn("'123'", result)

    def test_regex_without_value_access_not_inlined(self):
        result = self._deobfuscate(
            """
            [Regex]::Matches('REFINERY', '[RF]') | Write-Output;
            """
        )
        self.assertIn('REFINERY', result)

    def test_regex_matches_dot_righttoleft(self):
        result = self._deobfuscate_iterative(
            "(-Join [Regex]::Matches('dlroW olleH', '.', 'RightToLeft'))")
        self.assertIn('Hello World', result)

    def test_regex_matches_dot_righttoleft_mapped(self):
        result = self._deobfuscate_iterative(
            "-Join([Regex]::Matches('dlroW olleH', '.', 'RightToLeft')|%{$_.Groups.Value})")
        self.assertIn('Hello World', result)

    def test_regex_matches_integer_option(self):
        result = self._deobfuscate_iterative(
            "(-Join [Regex]::Matches('olleH', '.', 64))")
        self.assertIn('Hello', result)

    def test_regression_props_of_constant_are_null(self):
        self.assertEqual(self._deobfuscate("'a'.Value"), '$Null')
        self.assertEqual(self._deobfuscate("'a'.fLaBu"), '$Null')

    def test_regex_matches_combined_options(self):
        result = self._deobfuscate(
            "[Regex]::Matches('aAbBcC', '[a-c]', 'IgnoreCase, RightToLeft').Value")
        self.assertIn("'C'", result)
        self.assertIn("'c'", result)
        self.assertNotIn('Value', result)

    def test_regex_match_single(self):
        result = self._deobfuscate("[Regex]::Match('abc123def456', '\\d+').Value")
        self.assertIn("'123'", result)
        self.assertNotIn('456', result)

    def test_regex_match_no_match(self):
        result = self._deobfuscate("[Regex]::Match('hello', '\\d+')|%{$_.Value}")
        self.assertIn("''", result)
        self.assertNotIn("Value", result)

    def test_regex_replace_static(self):
        result = self._deobfuscate("[Regex]::Replace('Hello World', 'World', 'Earth')")
        self.assertIn('Hello Earth', result)

    def test_regex_replace_with_pattern(self):
        result = self._deobfuscate("[Regex]::Replace('abc123def456', '\\d+', 'X')")
        self.assertIn('abcXdefX', result)

    def test_regex_matches_fully_qualified_type(self):
        result = self._deobfuscate(
            "[Text.RegularExpressions.Regex]::Matches('abc', '.')|%{$_.Value}")
        self.assertIn("'a'", result)
        self.assertIn("'b'", result)
        self.assertIn("'c'", result)
        self.assertNotIn("Value", result)

    def test_regex_join_chain(self):
        result = self._deobfuscate_iterative(
            "-Join [Regex]::Matches('!o!l!l!e!H', '[^!]', 'RightToLeft')")
        self.assertIn('Hello', result)


class TestPs1SubstringFolding(TestPs1):

    def test_substring_one_arg(self):
        result = self._deobfuscate("'Hello World'.Substring(6)")
        self.assertIn("'World'", result)
        self.assertNotIn('Substring', result)

    def test_substring_two_args(self):
        result = self._deobfuscate("'Hello World'.Substring(0, 5)")
        self.assertIn("'Hello'", result)
        self.assertNotIn('Substring', result)

    def test_substring_out_of_bounds(self):
        result = self._deobfuscate("'abc'.Substring(0, 10)")
        self.assertIn('Substring', result)


class TestPs1StringInsertRemoveFolding(TestPs1):

    def test_string_insert(self):
        result = self._deobfuscate("'hello'.Insert(0, 'X')")
        self.assertEqual(result, "'Xhello'")

    def test_string_insert_middle(self):
        result = self._deobfuscate("'hello'.Insert(2, 'XY')")
        self.assertEqual(result, "'heXYllo'")

    def test_string_insert_end(self):
        result = self._deobfuscate("'hello'.Insert(5, '!')")
        self.assertEqual(result, "'hello!'")

    def test_string_remove_one_arg(self):
        result = self._deobfuscate("'hello'.Remove(3)")
        self.assertEqual(result, "'hel'")

    def test_string_remove_two_args(self):
        result = self._deobfuscate("'hello'.Remove(1, 2)")
        self.assertEqual(result, "'hlo'")

    def test_string_insert_remove_chain(self):
        result = self._deobfuscate("'abcdef'.Remove(2, 1).Insert(0, 'X')")
        self.assertEqual(result, "'Xabdef'")


class TestPs1LengthFolding(TestPs1):

    def test_string_length(self):
        self.assertEqual(self._deobfuscate("'Hello'.Length"), '5')

    def test_array_length(self):
        self.assertEqual(self._deobfuscate('@(1, 2, 3).Length'), '3')

    def test_array_count(self):
        self.assertEqual(self._deobfuscate('@(1, 2, 3).Count'), '3')

    def test_string_length_via_variable(self):
        result = self._deobfuscate("$x = 'Hello'; Write-Host $x.Length")
        self.assertIn('5', result)


class TestPs1ArrayInliningGuard(TestPs1):

    def test_small_array_inlined_with_parens(self):
        result = self._deobfuscate('$x = @(1, 2, 3); Write-Host $x')
        self.assertIn('(1, 2, 3)', result)

    def test_large_array_not_inlined(self):
        elements = ', '.join(str(i) for i in range(100))
        code = F'$x = @({elements}); Write-Host $x; Write-Host $x'
        result = self._deobfuscate(code)
        self.assertIn('$x', result)


class TestPs1ControlCharStringLiteral(TestPs1):

    def test_format_newline_only_produces_here_string(self):
        code = '"{0}`n{1}" -f "hello","world"'
        result = self._deobfuscate(code)
        self.assertIn("@'", result)
        self.assertIn('hello', result)
        self.assertIn('world', result)

    def test_tab_in_format_produces_backtick_escape(self):
        code = '"{0}`t{1}" -f "a","b"'
        result = self._deobfuscate(code)
        self.assertIn('`t', result)
        self.assertNotIn('\t', result)

    def test_mixed_newline_and_control_chars_produces_dq_string(self):
        code = '"{0}`n`t{1}" -f "a","b"'
        result = self._deobfuscate(code)
        self.assertNotIn("@'", result)
        self.assertIn('`n', result)
        self.assertIn('`t', result)

    def test_concat_with_control_chars_no_raw_embedding(self):
        code = "'hello' + \"`tworld\""
        result = self._deobfuscate(code)
        self.assertNotIn('\t', result)
        self.assertIn('hello', result)
        self.assertIn('world', result)

