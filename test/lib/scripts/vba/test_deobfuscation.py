from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts.vba.deobfuscation import deobfuscate
from refinery.lib.scripts.vba.deobfuscation.names import text_compare_safe
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
        self.assertEqual(self._fold('x = "hel" & "lo"'), 'x = "hello"')

    def test_string_concat_plus(self):
        self.assertEqual(self._fold('x = "hel" + "lo"'), 'x = "hello"')

    def test_chr_resolution(self):
        self.assertEqual(
            self._fold('x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)'),
            'x = "Hello"')

    def test_chrw_resolution(self):
        self.assertEqual(self._fold('x = ChrW(65)'), 'x = "A"')

    def test_asc_resolution(self):
        self.assertEqual(self._fold('x = Asc("A")'), 'x = 65')

    def test_numeric_add(self):
        self.assertEqual(self._fold('x = 10 + 20'), 'x = 30')

    def test_numeric_subtract(self):
        self.assertEqual(self._fold('x = 50 - 15'), 'x = 35')

    def test_numeric_multiply(self):
        self.assertEqual(self._fold('x = 6 * 7'), 'x = 42')

    def test_integer_division(self):
        self.assertEqual(self._fold('x = 10 \\ 3'), 'x = 3')

    def test_mod_operation(self):
        self.assertEqual(self._fold('x = 10 Mod 3'), 'x = 1')

    def test_exponentiation(self):
        self.assertEqual(self._fold('x = 2 ^ 3'), 'x = 8')

    def test_unary_minus(self):
        self.assertEqual(self._fold('x = -42'), 'x = -42')

    def test_not_boolean(self):
        self.assertEqual(self._fold('x = Not True'), 'x = False')

    def test_not_integer(self):
        self.assertEqual(self._fold('x = Not 0'), 'x = -1')

    def test_mid_function(self):
        self.assertEqual(self._fold('x = Mid("Hello", 2, 3)'), 'x = "ell"')

    def test_left_function(self):
        self.assertEqual(self._fold('x = Left("Hello", 3)'), 'x = "Hel"')

    def test_right_function(self):
        self.assertEqual(self._fold('x = Right("Hello", 3)'), 'x = "llo"')

    def test_strreverse(self):
        self.assertEqual(self._fold('x = StrReverse("Hello")'), 'x = "olleH"')

    def test_lcase(self):
        self.assertEqual(self._fold('x = LCase("HELLO")'), 'x = "hello"')

    def test_ucase(self):
        self.assertEqual(self._fold('x = UCase("hello")'), 'x = "HELLO"')

    def test_len_function(self):
        self.assertEqual(self._fold('x = Len("Hello")'), 'x = 5')

    def test_paren_removal(self):
        self.assertEqual(self._fold('x = (42)'), 'x = 42')

    def test_combined_chr_concat(self):
        self.assertEqual(
            self._fold('x = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)'),
            'x = "WScript"')

    def test_nested_concat(self):
        self.assertEqual(self._fold('x = ("a" & "b") & "c"'), 'x = "abc"')

    def test_division_by_zero_safe(self):
        self.assertEqual(self._fold('x = 1 / 0'), 'x = 1 / 0')

    def test_space_function(self):
        self.assertEqual(self._fold('x = Space(5)'), 'x = "     "')

    def test_replace_function(self):
        self.assertEqual(self._fold('x = Replace("abc", "b", "x")'), 'x = "axc"')

    def test_replace_empty_insert(self):
        self.assertEqual(self._fold('x = Replace("aXbXc", "X", "")'), 'x = "abc"')

    def test_constant_inlining(self):
        code = cleandoc("""
            Sub T()
              Const K = "val"
              F K
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "val"
            End Sub
        """))

    def test_constant_inline_let(self):
        code = cleandoc("""
            Sub T()
              y = 42
              x = y + 1
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F 43
            End Sub
        """))

    def test_constant_multi_assign(self):
        code = cleandoc("""
            Sub T()
              y = 1
              y = 2
              x = y
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), code)

    def test_negative_constant_inlining(self):
        code = cleandoc("""
            Sub T()
              Const X = -1
              y = X + 5
              F y
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F 4
            End Sub
        """))

    def test_dead_variable_removal(self):
        code = cleandoc("""
            Sub T()
              x = 1
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), '')

    def test_dead_variable_keep_calls(self):
        code = cleandoc("""
            Sub T()
              x = Foo()
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), code)

    def test_dead_variable_keep_used(self):
        code = cleandoc("""
            Sub T()
              x = Foo()
              y = x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              x = Foo()
            End Sub
        """))

    def test_xor_operator(self):
        self.assertEqual(self._deobfuscate('CLng((0 Xor 0))'), 'CLng((0 Xor 0))')

    def test_remove_comments(self):
        code = cleandoc("""
            ' Test
            b = a
            ' Test
        """)
        self.assertEqual(self._deobfuscate(code), 'b = a')

    def test_regression_matchgroup(self):
        code = cleandoc(r"""
            const a = "\3"
            b = a
        """)
        self.assertEqual(self._deobfuscate(code), r'b = "\3"')

    def test_regression_overeager_removal(self):
        code = cleandoc("""
            a.Close
            b = z.function(x)
        """)
        self.assertEqual(self._deobfuscate(code), code)

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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "cellvalueif"
            End Sub
        """))

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "hello"
            End Sub
        """))

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              F "cellvalueif"
            End Sub
        """))

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "ABC"
            End Sub
        """))

    def test_emulator_nonconstant_arg_preserved(self):
        code = cleandoc("""
            Function F(x)
              F = x & "!"
            End Function

            Sub T()
              G F(y)
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), code)

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "xxx"
            End Sub
        """))

    def test_emulator_impure_not_inlined(self):
        code = cleandoc("""
            Function F()
              F = Application.Name
            End Function

            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), code)

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "before"
            End Sub
        """))

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "before"
            End Sub
        """))

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Function Builder()
              On Error Resume Next
              Shell "cmd Ppayload", 0
            End Function

            Sub Autoopen()
              On Error Resume Next
              Builder
            End Sub
        """))

    def test_chr_non_printable_preserved(self):
        self.assertEqual(self._fold('x = Chr(13)'), 'x = Chr(13)')

    def test_builtin_constant_in_chr(self):
        self.assertEqual(self._fold('x = Chr(vbKeyA)'), 'x = "A"')

    def test_builtin_constant_vbobjecterror(self):
        code = cleandoc("""
            Sub T()
              x = vbObjectError
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F -2147221504
            End Sub
        """))

    def test_builtin_constant_vbcrlf_not_inlined(self):
        self.assertEqual(self._fold('x = vbCrLf'), 'x = vbCrLf')

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "hello"
            End Sub
        """))

    def test_undefined_var_kept_without_oern(self):
        self.assertEqual(self._fold('x = junk + "hello"'), 'x = junk + "hello"')

    def test_return_variable_inlined(self):
        code = cleandoc("""
            Function F()
              F = "hello"
              Shell "cmd " & F, 0
            End Function
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Function F()
              Shell "cmd hello", 0
            End Function
        """))

    def test_emulator_refuses_nonprintable_result(self):
        code = cleandoc("""
            Function F()
              F = "a" & Chr(13) & "b"
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "a" & Chr(13) & "b"
            End Sub
        """))

    def test_chr_inlining_in_concat(self):
        code = cleandoc("""
            Sub T()
              On Error Resume Next
              x = Chr(13)
              y = "a" + x + "b"
              F y
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              On Error Resume Next
              F "a" + Chr(13) + "b"
            End Sub
        """))

    def test_emulator_nonprintable_result_synthesized(self):
        code = cleandoc("""
            Function F()
              F = Chr(13) & "payload" & Chr(10)
            End Function
            Sub T()
              G F()
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G Chr(13) & "payload" & Chr(10)
            End Sub
        """))

    def test_empty_sub_removed(self):
        code = cleandoc("""
            Sub Junk()
            End Sub
            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              G 1
            End Sub
        """))

    def test_empty_function_removed(self):
        code = cleandoc("""
            Function Junk()
            End Function
            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              G 1
            End Sub
        """))

    def test_empty_property_removed(self):
        code = cleandoc("""
            Property Get Junk()
            End Property
            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              G 1
            End Sub
        """))

    def test_empty_sub_called_preserved(self):
        code = cleandoc("""
            Sub Junk()
            End Sub

            Sub T()
              Junk
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), code)

    def test_nonempty_sub_uncalled_preserved(self):
        code = cleandoc("""
            Sub Junk()
              MsgBox "hi"
            End Sub

            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), code)

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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub A()
            End Sub

            Sub T()
              A
            End Sub
        """))

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
        self.assertEqual(self._deobfuscate(code), code)

    def test_instr_two_args(self):
        self.assertEqual(self._fold('x = InStr("abcabc", "bc")'), 'x = 2')

    def test_instr_three_args(self):
        self.assertEqual(self._fold('x = InStr(3, "abcabc", "bc")'), 'x = 5')

    def test_instr_not_found(self):
        self.assertEqual(self._fold('x = InStr("abc", "z")'), 'x = 0')

    def test_instrrev_two_args(self):
        self.assertEqual(self._fold('x = InStrRev("abcabc", "bc")'), 'x = 5')

    def test_instrrev_three_args(self):
        self.assertEqual(self._fold('x = InStrRev("abcabc", "bc", 4)'), 'x = 2')

    def test_instrrev_start_bounds_match_end(self):
        # InStrRev's start bounds the END of the match: the match must lie within the first `start`
        # characters, so the "abc" beginning at position 4 is excluded and the result is 1, not 4.
        self.assertEqual(self._fold('x = InStrRev("abcabc", "abc", 4)'), 'x = 1')

    def test_strcomp_equal(self):
        self.assertEqual(self._fold('x = StrComp("abc", "abc")'), 'x = 0')

    def test_strcomp_less(self):
        self.assertEqual(self._fold('x = StrComp("abc", "def")'), 'x = -1')

    def test_strcomp_case_insensitive(self):
        self.assertEqual(self._fold('x = StrComp("ABC", "abc", 1)'), 'x = 0')

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G 7
            End Sub
        """))

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G 4
            End Sub
        """))

    def test_accumulator_basic_concat(self):
        code = cleandoc("""
            Sub T()
              x = "hello"
              x = x & " world"
              F x
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._deobfuscate(code), code)

    def test_accumulator_chain_breaks_on_different_variable(self):
        code = cleandoc("""
            Sub T()
              x = "a"
              y = "z"
              x = x & "b"
              F x, y
            End Sub
        """)
        self.assertEqual(self._deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub T()
              F "ab"
            End Sub
        """))

    def test_integer_division_truncates_toward_zero(self):
        self.assertEqual(self._fold('x = -7 \\ 2'), 'x = -3')

    def test_mod_takes_sign_of_dividend(self):
        self.assertEqual(self._fold('x = -7 Mod 2'), 'x = -1')

    def test_mod_dividend_sign_positive_divisor_negative(self):
        self.assertEqual(self._fold('x = 7 Mod -2'), 'x = 1')

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
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Sub T()
              G "diff"
            End Sub
        """))

    def test_power_of_negative_base_keeps_parentheses(self):
        # VBA binds ^ tighter than unary minus, so "-4 ^ y" would mean -(4 ^ y).
        self.assertEqual(self._fold('x = (-4) ^ y'), 'x = (-4) ^ y')

    def test_hex_of_positive_folds(self):
        self.assertEqual(self._fold('x = Hex(255)'), 'x = "FF"')

    def test_hex_of_negative_not_folded(self):
        self.assertEqual(self._fold('x = Hex(-1)'), 'x = Hex(-1)')

    def test_replace_with_start_position(self):
        self.assertEqual(self._fold('x = Replace("hello", "l", "L", 3)'), 'x = "LLo"')

    def test_replace_explicit_text_compare_folds(self):
        self.assertEqual(self._fold('x = Replace("aAa", "a", "X", 1, -1, 1)'), 'x = "XXX"')

    def test_mid_negative_length_not_folded(self):
        self.assertEqual(self._fold('x = Mid("hello", 2, -1)'), 'x = Mid("hello", 2, -1)')

    def test_cbyte_rounds_to_nearest(self):
        self.assertEqual(self._fold('x = CByte(2.6)'), 'x = 3')

    def test_cbyte_overflow_not_folded(self):
        self.assertEqual(self._fold('x = CByte(300)'), 'x = CByte(300)')

    def test_plus_empty_string_not_dropped(self):
        self.assertEqual(self._fold('x = 5 + ""'), 'x = 5 + ""')

    def test_ampersand_empty_string_dropped(self):
        self.assertEqual(self._fold('x = y & ""'), 'x = y')

    def test_function_return_value_not_treated_as_dead(self):
        code = cleandoc("""
            Function GetKey() As String
              GetKey = "secret"
            End Function

            Sub T()
              G 1
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), code)

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
        self.assertEqual(self._deobfuscate(code), cleandoc("""
            Sub A()
              G 7
            End Sub

            Sub B(n)
              H n
            End Sub
        """))

    def test_text_compare_safe_predicate(self):
        # Case folding is locale-independent only for ASCII digits and ASCII letters other than the
        # Turkic-sensitive I/i; symbols and non-ASCII are unsafe.
        self.assertTrue(text_compare_safe(''))
        self.assertTrue(text_compare_safe('AB12'))
        self.assertFalse(text_compare_safe('FILE'))
        self.assertFalse(text_compare_safe('file'))
        self.assertFalse(text_compare_safe('a-b'))
        self.assertFalse(text_compare_safe('\xe9'))

    def _compare_branch(self, option: str, expr: str) -> str:
        return self._full_deobfuscate(cleandoc(F"""
            {option}
            Function F()
              If {expr} Then
                F = "same"
              Else
                F = "diff"
              End If
            End Function
            Sub T()
              G F()
            End Sub
        """))

    def test_text_equality_folds_for_safe_operands(self):
        self.assertIn('G "same"', self._compare_branch('Option Compare Text', '"AB" = "ab"'))

    def test_binary_equality_is_case_sensitive(self):
        for option in ('Option Compare Binary', "' no option"):
            self.assertIn('G "diff"', self._compare_branch(option, '"AB" = "ab"'), option)

    def test_text_equality_bails_on_turkic_letters(self):
        self.assertIn('G F()', self._compare_branch('Option Compare Text', '"FILE" = "file"'))

    def test_text_ordering_always_bails(self):
        self.assertIn('G F()', self._compare_branch('Option Compare Text', '"b" < "A"'))

    def test_strcomp_text_equal_folds_to_zero(self):
        code = cleandoc("""
            Option Compare Text
            Sub T()
              x = StrComp("AB", "ab")
            End Sub
        """)
        self.assertIn('x = 0', self._fold(code))

    def test_strcomp_binary_folds_to_sign(self):
        code = cleandoc("""
            Option Compare Binary
            Sub T()
              x = StrComp("AB", "ab")
            End Sub
        """)
        self.assertIn('x = -1', self._fold(code))

    def test_strcomp_text_unequal_bails(self):
        code = cleandoc("""
            Option Compare Text

            Sub T()
              x = StrComp("AB", "ac")
            End Sub
        """)
        self.assertEqual(self._fold(code), code)

    def test_strcomp_explicit_text_overrides_binary_module(self):
        code = cleandoc("""
            Option Compare Binary
            Sub T()
              x = StrComp("AB", "ab", 1)
            End Sub
        """)
        self.assertIn('x = 0', self._fold(code))

    def test_instr_text_finds_case_insensitively(self):
        code = cleandoc("""
            Option Compare Text
            Sub T()
              x = InStr(1, "aXbXc", "x")
            End Sub
        """)
        self.assertIn('x = 2', self._fold(code))

    def test_instr_explicit_binary_overrides_text_module(self):
        code = cleandoc("""
            Option Compare Text
            Sub T()
              x = InStr(1, "aXbXc", "x", 0)
            End Sub
        """)
        self.assertIn('x = 0', self._fold(code))

    def test_instr_text_bails_on_turkic_letters(self):
        code = cleandoc("""
            Option Compare Text

            Sub T()
              x = InStr(1, "FILE", "i")
            End Sub
        """)
        self.assertEqual(self._fold(code), code)

    def test_replace_text_module_folds_case_insensitively(self):
        code = cleandoc("""
            Option Compare Text
            Sub T()
              x = Replace("aAa", "a", "X")
            End Sub
        """)
        self.assertIn('"XXX"', self._fold(code))

    def test_replace_binary_module_is_case_sensitive(self):
        code = cleandoc("""
            Option Compare Binary
            Sub T()
              x = Replace("aAa", "a", "X")
            End Sub
        """)
        self.assertIn('"XAX"', self._fold(code))

    def test_replace_text_bails_on_turkic_letters(self):
        code = cleandoc("""
            Option Compare Text

            Sub T()
              x = Replace("FILE", "i", "Y")
            End Sub
        """)
        self.assertEqual(self._fold(code), code)

    def test_replace_text_count_zero_makes_no_replacement(self):
        code = cleandoc("""
            Option Compare Text
            Sub T()
              x = Replace("aAa", "a", "X", 1, 0)
            End Sub
        """)
        self.assertEqual(self._fold(code), cleandoc("""
            Option Compare Text

            Sub T()
              x = "aAa"
            End Sub
        """))

    def test_replace_explicit_text_count_zero_makes_no_replacement(self):
        self.assertEqual(self._fold('x = Replace("aAa", "a", "X", 1, 0, 1)'), 'x = "aAa"')

    def test_database_equality_not_folded(self):
        self.assertIn('G F()', self._compare_branch('Option Compare Database', '"AB" = "ab"'))

    def test_database_numeric_comparison_still_folds(self):
        self.assertIn('G "same"', self._compare_branch('Option Compare Database', '2 > 1'))

    def test_database_strcomp_not_folded(self):
        code = cleandoc("""
            Option Compare Database

            Sub T()
              x = StrComp("AB", "ab")
            End Sub
        """)
        self.assertEqual(self._fold(code), code)

    def test_database_instr_not_folded(self):
        code = cleandoc("""
            Option Compare Database

            Sub T()
              x = InStr(1, "aXbXc", "x")
            End Sub
        """)
        self.assertEqual(self._fold(code), code)

    def test_database_replace_not_folded(self):
        code = cleandoc("""
            Option Compare Database

            Sub T()
              x = Replace("aAa", "a", "X")
            End Sub
        """)
        self.assertEqual(self._fold(code), code)

    def test_database_explicit_binary_overrides(self):
        code = cleandoc("""
            Option Compare Database
            Sub T()
              x = StrComp("AB", "ab", 0)
            End Sub
        """)
        self.assertIn('x = -1', self._fold(code))

    def test_database_explicit_text_overrides(self):
        code = cleandoc("""
            Option Compare Database
            Sub T()
              x = StrComp("AB", "ab", 1)
            End Sub
        """)
        self.assertIn('x = 0', self._fold(code))

    def test_database_replace_count_zero_still_folds(self):
        code = cleandoc("""
            Option Compare Database
            Sub T()
              x = Replace("aAa", "a", "X", 1, 0)
            End Sub
        """)
        self.assertEqual(self._fold(code), cleandoc("""
            Option Compare Database

            Sub T()
              x = "aAa"
            End Sub
        """))

    def test_replace_omitted_start_keeps_count(self):
        self.assertEqual(self._fold('x = Replace("xxxx", "x", "y", , 2)'), 'x = "yyxx"')

    def test_replace_omitted_start_and_count_keeps_text_compare(self):
        self.assertEqual(self._fold('x = Replace("aAa", "a", "X", , , 1)'), 'x = "XXX"')

    def test_instrrev_omitted_start_keeps_text_compare(self):
        self.assertEqual(self._fold('x = InStrRev("aBcaBc", "b", , 1)'), 'x = 5')

    def test_mid_rounds_fractional_start(self):
        self.assertEqual(self._fold('x = Mid("abcdef", 7 / 2)'), 'x = "def"')

    def test_left_rounds_fractional_length(self):
        self.assertEqual(self._fold('x = Left("abcdef", 7 / 2)'), 'x = "abcd"')

    def test_replace_rounds_fractional_count(self):
        self.assertEqual(self._fold('x = Replace("aaaa", "a", "b", 1, 7 / 2)'), 'x = "bbbb"')

    def test_instrrev_negative_one_searches_from_end(self):
        self.assertEqual(self._fold('x = InStrRev("abcabc", "abc", -1)'), 'x = 4')

    def test_dead_variable_removed_despite_same_named_function(self):
        code = cleandoc("""
            Function Total() As Long
              Total = 1
            End Function
            Sub T()
              Total = 5
              G 1
            End Sub
        """)
        self.assertEqual(self._full_deobfuscate(code), cleandoc("""
            Function Total() As Long
              Total = 1
            End Function

            Sub T()
              G 1
            End Sub
        """))

    def test_lcase_of_empty_folds_to_empty_string(self):
        self.assertEqual(self._fold('x = LCase(Empty)'), 'x = ""')

    def test_clng_of_true_folds_to_negative_one(self):
        # VBA coerces Boolean True to the Long -1.
        self.assertEqual(self._fold('x = CLng(True)'), 'x = -1')
