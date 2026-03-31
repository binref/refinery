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

    def test_concat_basic(self):
        data = "'foo' + 'bar'"
        result = self._deobfuscate(data)
        self.assertIn('foobar', result)

    def test_concat_double_quotes(self):
        data = '"hel" + "lo"'
        result = self._deobfuscate(data)
        self.assertIn('hello', result)

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
        self.assertIn('Set-Variable', result)

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
        self.assertIn('Set-Variable', result)
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
        result = self._deobfuscate('param($qu, $sec=0, $iv=0)').lower()
        self.assertIn('param($qu, $sec = 0, $iv = 0)', result)


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


class TestPS1Concat(TestPs1):

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

    def test_real_world_01(self):
        data = '''-RepLaCe"UVL",""""-CrePLAcE "MQo","``" -RepLaCe ("0"+"N"+"R"),"'"-CrePLAcE'eV5',"`$"-CrePLAcE  '31V',"|")'''
        result = self._deobfuscate(data)
        self.assertIn('0NR', result)

    def test_variable_substitution(self):
        result = self._deobfuscate('''$y = "$y"+'$z';''')
        self.assertIn('$z', result)


class TestPS1FormatString(TestPs1):

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


class TestPS1StringReplace(TestPs1):

    def test_trivial(self):
        result = self._deobfuscate('''"Hello World".replace('l', "FOO")''')
        self.assertIn('HeFOOFOOo WorFOOd', result)

    def test_real_world_01(self):
        result = self._deobfuscate(
            '''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"))''')
        self.assertIn("'", result)

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
        result = self._deobfuscate('$x = 1 -shl 2')
        self.assertIn('1 -shl 2', result)

    def test_shr_operator(self):
        result = self._deobfuscate('$x = 1 -shr 3')
        self.assertIn('1 -shr 3', result)

    def test_format_expression_chained(self):
        result = self._deobfuscate('$x = "{0}" -f "a" -f "b"')
        self.assertIn("'a'", result)

    def test_range_expression_chained(self):
        result = self._deobfuscate('$x = 1..5..2')
        self.assertIn('1..5..2', result)
