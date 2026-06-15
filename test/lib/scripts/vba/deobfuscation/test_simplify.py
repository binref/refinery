from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.vba.deobfuscation import TestVba


class TestVbaSimplifications(TestVba):

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

    def test_chr_non_printable_preserved(self):
        self.assertEqual(self._fold('x = Chr(13)'), 'x = Chr(13)')

    def test_builtin_constant_in_chr(self):
        self.assertEqual(self._fold('x = Chr(vbKeyA)'), 'x = "A"')

    def test_builtin_constant_vbcrlf_not_inlined(self):
        self.assertEqual(self._fold('x = vbCrLf'), 'x = vbCrLf')

    def test_undefined_var_kept_without_oern(self):
        self.assertEqual(self._fold('x = junk + "hello"'), 'x = junk + "hello"')

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

    def test_integer_division_truncates_toward_zero(self):
        self.assertEqual(self._fold('x = -7 \\ 2'), 'x = -3')

    def test_mod_takes_sign_of_dividend(self):
        self.assertEqual(self._fold('x = -7 Mod 2'), 'x = -1')

    def test_mod_dividend_sign_positive_divisor_negative(self):
        self.assertEqual(self._fold('x = 7 Mod -2'), 'x = 1')

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

    def test_lcase_of_empty_folds_to_empty_string(self):
        self.assertEqual(self._fold('x = LCase(Empty)'), 'x = ""')

    def test_clng_of_true_folds_to_negative_one(self):
        # VBA coerces Boolean True to the Long -1.
        self.assertEqual(self._fold('x = CLng(True)'), 'x = -1')
