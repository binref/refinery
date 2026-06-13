from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts.vba.deobfuscation import deobfuscate
from refinery.lib.scripts.vba.deobfuscation.simplify import VbaSimplifications
from refinery.lib.scripts.vba.parser import VbaParser
from refinery.lib.scripts.vba.synth import VbaSynthesizer


class TestVbaDeobfuscation(TestBase):

    def _fold(self, source: str) -> str:
        ast = VbaParser(source).parse()
        VbaSimplifications().visit(ast)
        return VbaSynthesizer().convert(ast)

    def _deobfuscate(self, source: str) -> str:
        ast = VbaParser(source).parse()
        deobfuscate(ast)
        return VbaSynthesizer().convert(ast)

    def _full_deobfuscate(self, source: str, max_rounds: int = 20) -> str:
        ast = VbaParser(source).parse()
        for _ in range(max_rounds):
            if not deobfuscate(ast):
                break
        return VbaSynthesizer().convert(ast)

    def test_string_concat_ampersand(self):
        code = cleandoc("""
            Sub T()
              x = "hel" & "lo"
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"hello"', result)

    def test_string_concat_plus(self):
        code = cleandoc("""
            Sub T()
              x = "hel" + "lo"
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"hello"', result)

    def test_chr_resolution(self):
        code = cleandoc("""
            Sub T()
              x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"Hello"', result)

    def test_chrw_resolution(self):
        code = cleandoc("""
            Sub T()
              x = ChrW(65)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"A"', result)

    def test_asc_resolution(self):
        code = cleandoc("""
            Sub T()
              x = Asc("A")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('65', result)

    def test_numeric_add(self):
        code = cleandoc("""
            Sub T()
              x = 10 + 20
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('30', result)

    def test_numeric_subtract(self):
        code = cleandoc("""
            Sub T()
              x = 50 - 15
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('35', result)

    def test_numeric_multiply(self):
        code = cleandoc("""
            Sub T()
              x = 6 * 7
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('42', result)

    def test_integer_division(self):
        code = cleandoc("""
            Sub T()
              x = 10 \\ 3
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('3', result)

    def test_mod_operation(self):
        code = cleandoc("""
            Sub T()
              x = 10 Mod 3
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('1', result)

    def test_exponentiation(self):
        code = cleandoc("""
            Sub T()
              x = 2 ^ 3
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('8', result)

    def test_unary_minus(self):
        code = cleandoc("""
            Sub T()
              x = -42
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('-42', result)

    def test_not_boolean(self):
        code = cleandoc("""
            Sub T()
              x = Not True
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('False', result)

    def test_not_integer(self):
        code = cleandoc("""
            Sub T()
              x = Not 0
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('-1', result)

    def test_mid_function(self):
        code = cleandoc("""
            Sub T()
              x = Mid("Hello", 2, 3)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"ell"', result)

    def test_left_function(self):
        code = cleandoc("""
            Sub T()
              x = Left("Hello", 3)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"Hel"', result)

    def test_right_function(self):
        code = cleandoc("""
            Sub T()
              x = Right("Hello", 3)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"llo"', result)

    def test_strreverse(self):
        code = cleandoc("""
            Sub T()
              x = StrReverse("Hello")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"olleH"', result)

    def test_lcase(self):
        code = cleandoc("""
            Sub T()
              x = LCase("HELLO")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"hello"', result)

    def test_ucase(self):
        code = cleandoc("""
            Sub T()
              x = UCase("hello")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"HELLO"', result)

    def test_len_function(self):
        code = cleandoc("""
            Sub T()
              x = Len("Hello")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('5', result)

    def test_paren_removal(self):
        code = cleandoc("""
            Sub T()
              x = (42)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('42', result)
        self.assertNotIn('(42)', result)

    def test_combined_chr_concat(self):
        code = cleandoc("""
            Sub T()
              x = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"WScript"', result)

    def test_nested_concat(self):
        code = cleandoc("""
            Sub T()
              x = ("a" & "b") & "c"
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"abc"', result)

    def test_division_by_zero_safe(self):
        code = cleandoc("""
            Sub T()
              x = 1 / 0
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('1 / 0', result)

    def test_space_function(self):
        code = cleandoc("""
            Sub T()
              x = Space(5)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"     "', result)

    def test_replace_function(self):
        code = cleandoc("""
            Sub T()
              x = Replace("abc", "b", "x")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"axc"', result)

    def test_replace_empty_insert(self):
        code = cleandoc("""
            Sub T()
              x = Replace("aXbXc", "X", "")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"abc"', result)

    def test_constant_inlining(self):
        code = cleandoc("""
            Sub T()
              Const K = "val"
              F K
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('"val"', result)
        self.assertNotIn('Const', result)

    def test_constant_inline_let(self):
        code = cleandoc("""
            Sub T()
              y = 42
              x = y + 1
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('43', result)
        self.assertNotIn('y =', result)

    def test_constant_multi_assign(self):
        code = cleandoc("""
            Sub T()
              y = 1
              y = 2
              x = y
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('x = 1', result)
        self.assertNotIn('x = 2', result)
        self.assertIn('x = y', result)

    def test_negative_constant_inlining(self):
        code = cleandoc("""
            Sub T()
              Const X = -1
              y = X + 5
              F y
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('4', result)
        self.assertNotIn('Const', result)

    def test_dead_variable_removal(self):
        code = cleandoc("""
            Sub T()
              x = 1
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('x = 1', result)

    def test_dead_variable_keep_calls(self):
        code = cleandoc("""
            Sub T()
              x = Foo()
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('Foo()', result)

    def test_dead_variable_keep_used(self):
        code = cleandoc("""
            Sub T()
              x = Foo()
              y = x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('x = Foo()', result)
        self.assertNotIn('y =', result)

    def test_xor_operator(self):
        result = self._deobfuscate('CLng((0 Xor 0))')
        self.assertEqual(result, 'CLng((0 Xor 0))')

    def test_remove_comments(self):
        result = self._deobfuscate(cleandoc("""
            ' Test
            b = a
            ' Test
        """))
        self.assertIn('b = a', result)
        self.assertNotIn("' Test", result)

    def test_regression_matchgroup(self):
        result = self._deobfuscate(cleandoc(r"""
            const a = "\3"
            b = a
        """))
        self.assertIn(r'b = "\3"', result)

    def test_regression_overeager_removal(self):
        data = cleandoc("""
            a.Close
            b = z.function(x)
        """)
        result = self._deobfuscate(data)
        self.assertIn('a.Close', result)
        self.assertIn('b = z.function(x)', result)

    def test_regression_multi_assign_no_inline(self):
        code = cleandoc("""
            Function dtiss()
              dtiss = "cellvalue"
              dtiss = dtiss + "if"
            End Function
            Sub T()
              melb = dtiss
              F melb
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('melb = "cellvalue"', result)
        self.assertIn('cellvalueif', result)

    def test_emulator_simple_return(self):
        code = cleandoc("""
            Function F()
              F = "hello"
            End Function
            Sub T()
              x = F()
              G x
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"hello"', result)
        self.assertNotIn('Function F()', result)

    def test_emulator_self_referential_return(self):
        code = cleandoc("""
            Function dtiss()
              dtiss = "cellvalue"
              dtiss = dtiss + "if"
            End Function
            Sub T()
              melb = dtiss
              F melb
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"cellvalueif"', result)

    def test_emulator_with_params(self):
        code = cleandoc("""
            Function XorKey(s As String, k As Integer) As String
              XorKey = s & Chr(k)
            End Function
            Sub T()
              x = XorKey("AB", 67)
              G x
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"ABC"', result)

    def test_emulator_nonconstant_arg_preserved(self):
        code = cleandoc("""
            Function F(x)
              F = x & "!"
            End Function
            Sub T()
              G F(y)
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('F(y)', result)

    def test_emulator_loop(self):
        code = cleandoc("""
            Function Build()
              For i = 1 To 3
                Build = Build & "x"
              Next
            End Function
            Sub T()
              G Build()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"xxx"', result)

    def test_emulator_impure_not_inlined(self):
        code = cleandoc("""
            Function F()
              F = Application.Name
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('F()', result)

    def test_emulator_do_while_false_skips_body(self):
        code = cleandoc("""
            Function F()
              F = "before"
              Do While False
                F = "inside"
              Loop
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"before"', result)
        self.assertNotIn('"inside"', result)

    def test_emulator_do_until_true_skips_body(self):
        code = cleandoc("""
            Function F()
              F = "before"
              Do Until True
                F = "inside"
              Loop
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"before"', result)
        self.assertNotIn('"inside"', result)

    def test_emulator_preserves_side_effecting_function(self):
        code = cleandoc("""
            Function Builder()
              On Error Resume Next
              Builder = "payload"
              Shell "cmd " & Chr(80) & Builder, 0
            End Function
            Sub Autoopen()
              On Error Resume Next
              Builder
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('Shell', result)
        self.assertIn('Function Builder()', result)
        self.assertIn('"cmd Ppayload"', result)

    def test_chr_non_printable_preserved(self):
        code = cleandoc("""
            Sub T()
              x = Chr(13)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('Chr(13)', result)

    def test_builtin_constant_in_chr(self):
        code = cleandoc("""
            Sub T()
              x = Chr(vbKeyA)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"A"', result)

    def test_builtin_constant_vbobjecterror(self):
        code = cleandoc("""
            Sub T()
              x = vbObjectError
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('-2147221504', result)

    def test_builtin_constant_vbcrlf_not_inlined(self):
        code = cleandoc("""
            Sub T()
              x = vbCrLf
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('vbCrLf', result)

    def test_undefined_var_eliminated_in_concat(self):
        code = cleandoc("""
            Function F()
              On Error Resume Next
              F = junk + "hello"
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"hello"', result)
        self.assertNotIn('junk', result)

    def test_undefined_var_kept_without_oern(self):
        code = cleandoc("""
            Sub T()
              x = junk + "hello"
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('junk', result)

    def test_return_variable_inlined(self):
        code = cleandoc("""
            Function F()
              F = "hello"
              Shell "cmd " & F, 0
            End Function
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"cmd hello"', result)

    def test_emulator_refuses_nonprintable_result(self):
        code = cleandoc("""
            Function F()
              F = "a" & Chr(13) & "b"
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertNotIn('F()', result)
        self.assertIn('"a" & Chr(13) & "b"', result)

    def test_chr_inlining_in_concat(self):
        code = cleandoc("""
            Sub T()
              On Error Resume Next
              x = Chr(13)
              y = "a" + x + "b"
              F y
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertNotIn('x =', result)
        self.assertIn('Chr(13)', result)
        self.assertIn('"a"', result)
        self.assertIn('"b"', result)

    def test_emulator_nonprintable_result_synthesized(self):
        code = cleandoc("""
            Function F()
              F = Chr(13) & "payload" & Chr(10)
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertNotIn('F()', result)
        self.assertIn('Chr(13)', result)
        self.assertIn('"payload"', result)
        self.assertIn('Chr(10)', result)

    def test_empty_sub_removed(self):
        code = cleandoc("""
            Sub Junk()
            End Sub
            Sub T()
              G 1
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('Junk', result)
        self.assertIn('Sub T()', result)

    def test_empty_function_removed(self):
        code = cleandoc("""
            Function Junk()
            End Function
            Sub T()
              G 1
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('Junk', result)
        self.assertIn('Sub T()', result)

    def test_empty_property_removed(self):
        code = cleandoc("""
            Property Get Junk()
            End Property
            Sub T()
              G 1
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertNotIn('Junk', result)
        self.assertIn('Sub T()', result)

    def test_empty_sub_called_preserved(self):
        code = cleandoc("""
            Sub Junk()
            End Sub
            Sub T()
              Junk
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('Sub Junk()', result)

    def test_nonempty_sub_uncalled_preserved(self):
        code = cleandoc("""
            Sub Junk()
              MsgBox "hi"
            End Sub
            Sub T()
              G 1
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('Sub Junk()', result)

    def test_mixed_empty_procedures(self):
        code = cleandoc("""
            Sub A()
            End Sub
            Sub B()
            End Sub
            Sub T()
              A
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('Sub A()', result)
        self.assertNotIn('Sub B()', result)

    def test_empty_sub_called_from_other_preserved(self):
        code = cleandoc("""
            Sub Junk()
            End Sub
            Sub Helper()
              Junk
            End Sub
            Sub T()
              G 1
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('Sub Junk()', result)

    def test_instr_two_args(self):
        code = cleandoc("""
            Sub T()
              x = InStr("abcabc", "bc")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 2', result)

    def test_instr_three_args(self):
        code = cleandoc("""
            Sub T()
              x = InStr(3, "abcabc", "bc")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 5', result)

    def test_instr_not_found(self):
        code = cleandoc("""
            Sub T()
              x = InStr("abc", "z")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 0', result)

    def test_instrrev_two_args(self):
        code = cleandoc("""
            Sub T()
              x = InStrRev("abcabc", "bc")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 5', result)

    def test_instrrev_three_args(self):
        code = cleandoc("""
            Sub T()
              x = InStrRev("abcabc", "bc", 4)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 2', result)

    def test_strcomp_equal(self):
        code = cleandoc("""
            Sub T()
              x = StrComp("abc", "abc")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 0', result)

    def test_strcomp_less(self):
        code = cleandoc("""
            Sub T()
              x = StrComp("abc", "def")
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = -1', result)

    def test_strcomp_case_insensitive(self):
        code = cleandoc("""
            Sub T()
              x = StrComp("ABC", "abc", 1)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 0', result)

    def test_emulator_instr(self):
        code = cleandoc("""
            Function F()
              F = InStr("hello world", "world")
            End Function
            Sub T()
              x = F()
              G x
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('7', result)

    def test_emulator_instrrev(self):
        code = cleandoc("""
            Function F()
              F = InStrRev("abcabc", "abc")
            End Function
            Sub T()
              x = F()
              G x
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('4', result)

    def test_accumulator_basic_concat(self):
        code = cleandoc("""
            Sub T()
              x = "hello"
              x = x & " world"
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "hello world"
            End Sub
        """))

    def test_accumulator_long_chain(self):
        lines = ['Sub T()']
        lines.append('  x = "a"')
        for _ in range(50):
            lines.append('  x = x & "b"')
        lines.append('  F x')
        lines.append('End Sub')
        code = '\n'.join(lines)
        result = self._deobfuscate(code)
        self.assertEqual(result, F'Sub T()\n  F "a{"b" * 50}"\nEnd Sub')

    def test_accumulator_with_replace(self):
        code = cleandoc("""
            Sub T()
              x = "aXbXc"
              x = x & "dXe"
              x = Replace(x, "X", "")
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "abcde"
            End Sub
        """))

    def test_accumulator_prepend(self):
        code = cleandoc("""
            Sub T()
              x = "world"
              x = "hello " & x
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "hello world"
            End Sub
        """))

    def test_accumulator_chain_breaks_on_non_assignment(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              F x
              x = x & "b"
              G x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              x = "a"
              F x
              x = x & "b"
              G x
            End Sub
        """))

    def test_accumulator_chain_breaks_on_different_variable(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              y = "z"
              x = x & "b"
              F x, y
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "ab", "z"
            End Sub
        """))

    def test_accumulator_multi_concat_single_stmt(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              x = x & "b" & "c"
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "abc"
            End Sub
        """))

    def test_accumulator_replace_then_concat(self):
        code = cleandoc("""
            Sub T()
              x = "aXb"
              x = Replace(x, "X", "")
              x = x & "c"
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "abc"
            End Sub
        """))

    def test_accumulator_inlined_after_folding(self):
        code = cleandoc("""
            Sub T()
              x = "hel"
              x = x & "lo"
              F x
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "hello"
            End Sub
        """))

    def test_accumulator_surrogate_recombination(self):
        hi = '\uD83D'
        lo = '\uDCC6'
        combined = '\U0001F4C6'
        code = cleandoc(F"""
            Sub T()
              x = "a{hi}"
              x = x & "{lo}b"
              x = Replace(x, "{combined}", "")
              F x
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertEqual(result, cleandoc("""
            Sub T()
              F "ab"
            End Sub
        """))

    def test_integer_division_truncates_toward_zero(self):
        code = cleandoc("""
            Sub T()
              x = -7 \\ 2
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = -3', result)
        self.assertNotIn('-4', result)

    def test_mod_takes_sign_of_dividend(self):
        code = cleandoc("""
            Sub T()
              x = -7 Mod 2
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = -1', result)

    def test_mod_dividend_sign_positive_divisor_negative(self):
        code = cleandoc("""
            Sub T()
              x = 7 Mod -2
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 1', result)

    def test_emulator_string_compare_is_case_sensitive(self):
        code = cleandoc("""
            Function F()
              If "A" = "a" Then
                F = "same"
              Else
                F = "diff"
              End If
            End Function
            Sub T()
              G F()
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('"diff"', result)
        self.assertNotIn('"same"', result)

    def test_power_of_negative_base_keeps_parentheses(self):
        code = cleandoc("""
            Sub T()
              x = (-4) ^ y
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('(-4) ^ y', result)

    def test_hex_of_positive_folds(self):
        code = cleandoc("""
            Sub T()
              x = Hex(255)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"FF"', result)

    def test_hex_of_negative_not_folded(self):
        code = cleandoc("""
            Sub T()
              x = Hex(-1)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('Hex(-1)', result)

    def test_replace_with_start_position(self):
        code = cleandoc("""
            Sub T()
              x = Replace("hello", "l", "L", 3)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('"LLo"', result)
        self.assertNotIn('"heLLo"', result)

    def test_replace_text_compare_not_folded(self):
        code = cleandoc("""
            Sub T()
              x = Replace("aAa", "a", "X", 1, -1, 1)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('Replace(', result)

    def test_mid_negative_length_not_folded(self):
        code = cleandoc("""
            Sub T()
              x = Mid("hello", 2, -1)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('Mid("hello", 2, -1)', result)

    def test_cbyte_rounds_to_nearest(self):
        code = cleandoc("""
            Sub T()
              x = CByte(2.6)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = 3', result)

    def test_cbyte_overflow_not_folded(self):
        code = cleandoc("""
            Sub T()
              x = CByte(300)
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('CByte(300)', result)

    def test_plus_empty_string_not_dropped(self):
        code = cleandoc("""
            Sub T()
              x = 5 + ""
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('5 + ""', result)

    def test_ampersand_empty_string_dropped(self):
        code = cleandoc("""
            Sub T()
              x = y & ""
            End Sub
        """)
        result = self._fold(code)
        self.assertIn('x = y', result)
        self.assertNotIn('& ""', result)

    def test_function_return_value_not_treated_as_dead(self):
        code = cleandoc("""
            Function GetKey() As String
              GetKey = "secret"
            End Function
            Sub T()
              G 1
            End Sub
        """)
        result = self._full_deobfuscate(code)
        self.assertIn('GetKey = "secret"', result)

    def test_constant_not_inlined_across_procedures(self):
        code = cleandoc("""
            Sub A()
              Const n = 7
              G n
            End Sub
            Sub B(n)
              H n
            End Sub
        """)
        result = self._deobfuscate(code)
        self.assertIn('G 7', result)
        self.assertIn('H n', result)
        self.assertNotIn('H 7', result)
