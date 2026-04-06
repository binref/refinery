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
        self.assertIn('iex', result.lower())

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
        result = self._deobfuscate('$x = $y -shl 2')
        self.assertIn('-shl', result.lower())

    def test_shr_operator(self):
        result = self._deobfuscate('$x = $y -shr 3')
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
        self.assertIn('${env:temp}', result)
        self.assertIn('\\foo.exe', result)

    def test_variable_string_concat_becomes_expandable(self):
        result = self._deobfuscate("$env:temp + '\\foo.exe'")
        self.assertIn('"${env:temp}\\foo.exe"', result)


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
            "Set-Item Variable:/G7E $env:temp '\\NGLClient.exe'"
        )
        self.assertIn('$G7E', result)
        self.assertIn('=', result)
        self.assertIn('env:temp', result)
        self.assertIn('NGLClient', result)

    def test_set_variable_becomes_assignment(self):
        result = self._deobfuscate("Set-Variable foo 42")
        self.assertEqual(result.strip(), '$foo = 42')

    def test_set_variable_named_params(self):
        result = self._deobfuscate("Set-Variable -Name foo -Value 'bar'")
        self.assertEqual(result.strip(), "$foo = 'bar'")

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
        self.assertIn('GetCmdlets', result)


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


class TestPs1ForEachPipeline(TestPs1):

    def test_foreach_pipeline_char_convert(self):
        data = "'72z101z108z108z111'.Split('z') | %{ ([Char]([Convert]::ToInt16(($_.ToString()), 10))) }"
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)


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

    def test_wildcard_where_get_command(self):
        result = self._deobfuscate("Get-Command | ? { $_.Name -ilike '*w-*ct' }")
        self.assertIn('New-Object', result)

    def test_wildcard_where_unknown_source(self):
        result = self._deobfuscate("$obj | ? { $_.Name -ilike '*ts' }")
        self.assertNotIn('Exists', result)
        self.assertIn("'*ts'", result)


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
