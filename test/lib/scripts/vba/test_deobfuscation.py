from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.vba.deobfuscation import VbaSimplifications, deobfuscate
from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer


class TestVbaDeobfuscation(TestBase):

    def _fold(self, source: str) -> str:
        ast = VbaParser(source).parse()
        VbaSimplifications().visit(ast)
        return VbaSynthesizer().convert(ast)

    def _deobfuscate(self, source: str) -> str:
        ast = VbaParser(source).parse()
        VbaSimplifications().deobfuscate(ast)
        return VbaSynthesizer().convert(ast)

    def _full_deobfuscate(self, source: str, max_rounds: int = 20) -> str:
        ast = VbaParser(source).parse()
        for _ in range(max_rounds):
            if not deobfuscate(ast):
                break
        return VbaSynthesizer().convert(ast)

    def test_string_concat_ampersand(self):
        code = 'Sub T()\nx = "hel" & "lo"\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"hello"', result)

    def test_string_concat_plus(self):
        code = 'Sub T()\nx = "hel" + "lo"\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"hello"', result)

    def test_chr_resolution(self):
        code = 'Sub T()\nx = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"Hello"', result)

    def test_chrw_resolution(self):
        code = 'Sub T()\nx = ChrW(65)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"A"', result)

    def test_asc_resolution(self):
        code = 'Sub T()\nx = Asc("A")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('65', result)

    def test_numeric_add(self):
        code = 'Sub T()\nx = 10 + 20\nEnd Sub'
        result = self._fold(code)
        self.assertIn('30', result)

    def test_numeric_subtract(self):
        code = 'Sub T()\nx = 50 - 15\nEnd Sub'
        result = self._fold(code)
        self.assertIn('35', result)

    def test_numeric_multiply(self):
        code = 'Sub T()\nx = 6 * 7\nEnd Sub'
        result = self._fold(code)
        self.assertIn('42', result)

    def test_integer_division(self):
        code = 'Sub T()\nx = 10 \\ 3\nEnd Sub'
        result = self._fold(code)
        self.assertIn('3', result)

    def test_mod_operation(self):
        code = 'Sub T()\nx = 10 Mod 3\nEnd Sub'
        result = self._fold(code)
        self.assertIn('1', result)

    def test_exponentiation(self):
        code = 'Sub T()\nx = 2 ^ 3\nEnd Sub'
        result = self._fold(code)
        self.assertIn('8', result)

    def test_unary_minus(self):
        code = 'Sub T()\nx = -42\nEnd Sub'
        result = self._fold(code)
        self.assertIn('-42', result)

    def test_not_boolean(self):
        code = 'Sub T()\nx = Not True\nEnd Sub'
        result = self._fold(code)
        self.assertIn('False', result)

    def test_not_integer(self):
        code = 'Sub T()\nx = Not 0\nEnd Sub'
        result = self._fold(code)
        self.assertIn('-1', result)

    def test_mid_function(self):
        code = 'Sub T()\nx = Mid("Hello", 2, 3)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"ell"', result)

    def test_left_function(self):
        code = 'Sub T()\nx = Left("Hello", 3)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"Hel"', result)

    def test_right_function(self):
        code = 'Sub T()\nx = Right("Hello", 3)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"llo"', result)

    def test_strreverse(self):
        code = 'Sub T()\nx = StrReverse("Hello")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"olleH"', result)

    def test_lcase(self):
        code = 'Sub T()\nx = LCase("HELLO")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"hello"', result)

    def test_ucase(self):
        code = 'Sub T()\nx = UCase("hello")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"HELLO"', result)

    def test_len_function(self):
        code = 'Sub T()\nx = Len("Hello")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('5', result)

    def test_paren_removal(self):
        code = 'Sub T()\nx = (42)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('42', result)
        self.assertNotIn('(42)', result)

    def test_combined_chr_concat(self):
        code = 'Sub T()\nx = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"WScript"', result)

    def test_nested_concat(self):
        code = 'Sub T()\nx = ("a" & "b") & "c"\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"abc"', result)

    def test_division_by_zero_safe(self):
        code = 'Sub T()\nx = 1 / 0\nEnd Sub'
        result = self._fold(code)
        self.assertIn('1 / 0', result)

    def test_space_function(self):
        code = 'Sub T()\nx = Space(5)\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"     "', result)

    def test_replace_function(self):
        code = 'Sub T()\nx = Replace("abc", "b", "x")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"axc"', result)

    def test_replace_empty_insert(self):
        code = 'Sub T()\nx = Replace("aXbXc", "X", "")\nEnd Sub'
        result = self._fold(code)
        self.assertIn('"abc"', result)

    def test_constant_inlining(self):
        code = 'Sub T()\nConst K = "val"\nF K\nEnd Sub'
        result = self._deobfuscate(code)
        self.assertIn('"val"', result)
        self.assertNotIn('Const', result)

    def test_constant_inline_let(self):
        code = 'Sub T()\ny = 42\nx = y + 1\nF x\nEnd Sub'
        result = self._deobfuscate(code)
        self.assertIn('43', result)
        self.assertNotIn('y =', result)

    def test_constant_multi_assign(self):
        code = 'Sub T()\ny = 1\ny = 2\nx = y\nEnd Sub'
        result = self._deobfuscate(code)
        self.assertIn('y = 1', result)
        self.assertIn('y = 2', result)

    def test_dead_variable_removal(self):
        code = 'Sub T()\nx = 1\nEnd Sub'
        result = self._deobfuscate(code)
        self.assertNotIn('x = 1', result)

    def test_dead_variable_keep_calls(self):
        code = 'Sub T()\nx = Foo()\nEnd Sub'
        result = self._deobfuscate(code)
        self.assertIn('Foo()', result)

    def test_dead_variable_keep_used(self):
        code = 'Sub T()\nx = Foo()\ny = x\nEnd Sub'
        result = self._deobfuscate(code)
        self.assertIn('x = Foo()', result)
        self.assertNotIn('y =', result)

    def test_xor_operator(self):
        result = self._deobfuscate('CLng((0 Xor 0))')
        self.assertEqual(result, 'CLng((0 Xor 0))')

    def test_remove_comments(self):
        result = self._deobfuscate('''
            ' Test
            b = a
            ' Test''')
        self.assertIn('b = a', result)
        self.assertNotIn("' Test", result)

    def test_regression_matchgroup(self):
        result = self._deobfuscate(r'''
            const a = "\3"
            b = a
        ''')
        self.assertIn(r'b = "\3"', result)

    def test_regression_overeager_removal(self):
        data = 'a.Close\nb = z.function(x)\n'
        result = self._deobfuscate(data)
        self.assertIn('a.Close', result)
        self.assertIn('b = z.function(x)', result)

    def test_regression_multi_assign_no_inline(self):
        code = (
            'Function dtiss()\n'
            '  dtiss = "cellvalue"\n'
            '  dtiss = dtiss + "if"\n'
            'End Function\n'
            'Sub T()\n'
            '  melb = dtiss\n'
            '  F melb\n'
            'End Sub'
        )
        result = self._deobfuscate(code)
        self.assertIn('melb = dtiss', result)
        self.assertNotIn('melb = "cellvalue"', result)

    def test_emulator_simple_return(self):
        code = (
            'Function F()\n'
            '  F = "hello"\n'
            'End Function\n'
            'Sub T()\n'
            '  x = F()\n'
            '  G x\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('"hello"', result)
        self.assertNotIn('Function F()', result)

    def test_emulator_self_referential_return(self):
        code = (
            'Function dtiss()\n'
            '  dtiss = "cellvalue"\n'
            '  dtiss = dtiss + "if"\n'
            'End Function\n'
            'Sub T()\n'
            '  melb = dtiss\n'
            '  F melb\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('"cellvalueif"', result)

    def test_emulator_with_params(self):
        code = (
            'Function XorKey(s As String, k As Integer) As String\n'
            '  XorKey = s & Chr(k)\n'
            'End Function\n'
            'Sub T()\n'
            '  x = XorKey("AB", 67)\n'
            '  G x\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('"ABC"', result)

    def test_emulator_nonconstant_arg_preserved(self):
        code = (
            'Function F(x)\n'
            '  F = x & "!"\n'
            'End Function\n'
            'Sub T()\n'
            '  G F(y)\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('F(y)', result)

    def test_emulator_loop(self):
        code = (
            'Function Build()\n'
            '  For i = 1 To 3\n'
            '    Build = Build & "x"\n'
            '  Next\n'
            'End Function\n'
            'Sub T()\n'
            '  G Build()\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('"xxx"', result)

    def test_emulator_impure_not_inlined(self):
        code = (
            'Function F()\n'
            '  F = Application.Name\n'
            'End Function\n'
            'Sub T()\n'
            '  G F()\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('F()', result)

    def test_emulator_do_while_false_skips_body(self):
        code = (
            'Function F()\n'
            '  F = "before"\n'
            '  Do While False\n'
            '    F = "inside"\n'
            '  Loop\n'
            'End Function\n'
            'Sub T()\n'
            '  G F()\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('"before"', result)
        self.assertNotIn('"inside"', result)

    def test_emulator_do_until_true_skips_body(self):
        code = (
            'Function F()\n'
            '  F = "before"\n'
            '  Do Until True\n'
            '    F = "inside"\n'
            '  Loop\n'
            'End Function\n'
            'Sub T()\n'
            '  G F()\n'
            'End Sub'
        )
        result = self._full_deobfuscate(code)
        self.assertIn('"before"', result)
        self.assertNotIn('"inside"', result)
