from __future__ import annotations

import inspect

from test import backlog, opportunity, todo
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1ConstantFolding, Ps1ConstantInlining


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
        result = self._deobfuscate('''$y = "$y"+'$z'; Write-Output $y''')
        self.assertIn('$z', result)

    def test_a_format_string_around_an_unset_variable_formats_as_if_it_were_empty(self):
        source = '"{0}${SEP}{1}" -f \'Hello\', \'World\''
        self._assertDeobfuscatesToOneOf(source, source, "'HelloWorld'")

    @opportunity
    def test_a_format_string_around_an_unset_variable_folds_to_the_text_without_it(self):
        self.assertEqual(
            self._deobfuscate('"{0}${SEP}{1}" -f \'Hello\', \'World\''), "'HelloWorld'"
        )

    def test_a_format_naming_an_argument_it_lacks_is_kept_or_removed_as_a_failing_line(self):
        source = "'{0}{2}{1}' -f 'Hello', 'World'"
        self._assertDeobfuscatesToOneOf(source, source, '')

    @opportunity
    def test_a_format_naming_an_argument_it_lacks_is_removed_as_a_failing_line(self):
        self.assertEqual(self._deobfuscate("'{0}{2}{1}' -f 'Hello', 'World'"), '')

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

    def test_string_join_variadic_empty_separator(self):
        data = "[String]::Join('', 'Nam', 'e')"
        result = self._deobfuscate(data)
        self.assertIn("'Name'", result)

    def test_string_join_variadic_with_separator(self):
        data = "[String]::Join('-', 'a', 'b', 'c')"
        result = self._deobfuscate(data)
        self.assertIn("'a-b-c'", result)

    def test_replace_after_concat(self):
        result = self._deobfuscate("$([String]::Concat('h_llo')).Replace('_', 'e')")
        self.assertEqual(result, "'hello'")

    def test_string_join_static_with_separator(self):
        data = "[String]::Join(',', @('a','b','c'))"
        result = self._deobfuscate(data)
        self.assertIn('a,b,c', result)


class TestPS1StringReplace(TestPs1):

    def test_real_world_01(self):
        data = '''-RepLaCe"UVL",""""-CrePLAcE "MQo","``" -RepLaCe ("0"+"N"+"R"),"'"-CrePLAcE'eV5',"`$"-CrePLAcE  '31V',"|")'''
        result = self._deobfuscate(data, remove_junk=False)
        self.assertIn('0NR', result)

    def test_a_chain_of_replacements_writing_quote_characters_folds_to_its_text(self):
        result = self._deobfuscate(
            '''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"''',
            remove_junk=False,
        )
        self.assertEqual(result, "'\"'''")

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

    @backlog
    def test_a_replace_in_a_command_argument_reaches_the_command_as_the_text_it_spells(self):
        result = self._deobfuscate(
            '''Write-Output "The $product costs `$100 for the average person." -replace '$', "\u20ac";''')
        self.assertIn(' -replace ', result)


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
        result = self._deobfuscate('$x = $env:V\n($x -eq 3)', remove_junk=False)
        self.assertIn('-Eq', result)


class TestPs1StringEqualityFolding(TestPs1):

    def test_eq_false(self):
        self.assertEqual(self._apply("'m' -eq 'z'", Ps1ConstantFolding), '$False')

    def test_eq_true(self):
        self.assertEqual(self._apply("'abc' -eq 'abc'", Ps1ConstantFolding), '$True')

    def test_ne_true(self):
        self.assertEqual(self._apply("'a' -ne 'b'", Ps1ConstantFolding), '$True')

    def test_ne_false(self):
        self.assertEqual(self._apply("'a' -ne 'a'", Ps1ConstantFolding), '$False')

    def test_eq_case_insensitive_by_default(self):
        self.assertEqual(self._apply("'M' -eq 'm'", Ps1ConstantFolding), '$True')

    def test_ieq_case_insensitive(self):
        self.assertEqual(self._apply("'M' -ieq 'm'", Ps1ConstantFolding), '$True')

    def test_ceq_case_sensitive(self):
        self.assertEqual(self._apply("'M' -ceq 'm'", Ps1ConstantFolding), '$False')

    def test_cne_case_sensitive(self):
        self.assertEqual(self._apply("'M' -cne 'm'", Ps1ConstantFolding), '$True')

    def test_ordering_not_folded(self):
        self.assertEqual(self._apply("'a' -lt 'b'", Ps1ConstantFolding), "'a' -lt 'b'")

    def test_the_sharp_s_equals_a_double_s_under_the_invariant_culture(self):
        self.assertIn(self._apply("'ß' -eq 'SS'", Ps1ConstantFolding), ("'ß' -eq 'SS'", '$True'))
        self.assertIn(self._apply("'ß' -ieq 'ss'", Ps1ConstantFolding), ("'ß' -ieq 'ss'", '$True'))


class TestPs1LogicalFolding(TestPs1):

    def test_and_true_false(self):
        self.assertEqual(self._apply('$true -and $false', Ps1ConstantFolding), '$False')

    def test_or_true_false(self):
        self.assertEqual(self._apply('$true -or $false', Ps1ConstantFolding), '$True')

    def test_xor_true_true(self):
        self.assertEqual(self._apply('$true -xor $true', Ps1ConstantFolding), '$False')

    def test_xor_true_false(self):
        self.assertEqual(self._apply('$true -xor $false', Ps1ConstantFolding), '$True')

    def test_null_operand_is_false(self):
        self.assertEqual(self._apply('$null -and $true', Ps1ConstantFolding), '$False')

    def test_unknown_operand_not_folded(self):
        self.assertEqual(self._apply('$x -and $false', Ps1ConstantFolding), '$x -and $false')


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

    def test_a_substring_out_of_bounds_is_kept_or_removed_as_a_failing_line(self):
        source = "'abc'.Substring(0, 10)"
        self._assertDeobfuscatesToOneOf(source, source, '')

    @opportunity
    def test_a_substring_out_of_bounds_is_removed_as_a_failing_line(self):
        self.assertEqual(self._deobfuscate("'abc'.Substring(0, 10)"), '')


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


class TestPs1ControlCharStringLiteral(TestPs1):

    def test_a_format_with_only_a_newline_folds_only_to_a_literal_that_escapes_the_line_break(self):
        code = '"{0}`n{1}" -f "hello","world"'
        self._assertDeobfuscatesToOneOf(code, code, '"hello`nworld"')

    def test_tab_in_format_produces_backtick_escape(self):
        code = '"{0}`t{1}" -f "a","b"'
        self.assertEqual(self._deobfuscate(code), '"a`tb"')

    def test_mixed_newline_and_control_chars_produces_dq_string(self):
        code = '"{0}`n`t{1}" -f "a","b"'
        self.assertEqual(self._deobfuscate(code), '"a`n`tb"')

    def test_concat_with_control_chars_no_raw_embedding(self):
        code = "'hello' + \"`tworld\""
        self.assertEqual(self._deobfuscate(code), '"hello`tworld"')


class TestPs1StringMultiplicationFolding(TestPs1):

    def test_string_times_int(self):
        result = self._deobfuscate("'x' * 5")
        self.assertIn('xxxxx', result)
        self.assertNotIn('*', result)

    def test_int_times_string(self):
        result = self._deobfuscate("3 * 'ab'")
        self.assertNotIn('ababab', result)

    def test_string_multiply_in_expression(self):
        result = self._deobfuscate("$x = 'A' * 3 + 'B'")
        self.assertIn('AAAB', result)

    def test_string_multiply_zero(self):
        result = self._deobfuscate("'hello' * 0")
        self.assertNotIn('hello', result)
        self.assertNotIn('*', result)


class TestPs1RangeExpressionFolding(TestPs1):

    def test_ascending_range(self):
        result = self._deobfuscate('1..3')
        self.assertIn('1', result)
        self.assertIn('2', result)
        self.assertIn('3', result)

    def test_descending_range(self):
        result = self._deobfuscate('3..1')
        self.assertIn('3', result)
        self.assertIn('2', result)
        self.assertIn('1', result)

    def test_char_array_cast_on_range(self):
        result = self._deobfuscate("[char[]](65..67) -Join ''")
        self.assertIn('ABC', result)

    def test_single_element_range(self):
        result = self._deobfuscate('5..5')
        self.assertIn('5', result)
        self.assertNotIn('..', result)

    def test_range_used_as_index(self):
        result = self._deobfuscate("'ABCDEFG'[1..3] -Join ''")
        self.assertIn('BCD', result)
        self.assertNotIn('..', result)


class TestPs1UnaryOperatorFolding(TestPs1):

    def test_bnot_integer(self):
        self.assertEqual(self._apply('$x = -bnot 0', Ps1ConstantFolding), '$x = -1')

    def test_bnot_hex(self):
        self.assertEqual(self._apply('$x = -bnot 0xFF00', Ps1ConstantFolding), '$x = -65281')

    def test_not_zero(self):
        result = self._deobfuscate('-not 0')
        self.assertIn('$True', result)

    def test_not_nonzero(self):
        result = self._deobfuscate('-not 1')
        self.assertIn('$False', result)

    def test_not_true(self):
        result = self._deobfuscate('-not $True')
        self.assertIn('$False', result)

    def test_bang_false(self):
        result = self._deobfuscate('!$False')
        self.assertIn('$True', result)


class TestPs1ComplementIsFoldedAtTheWidthItsOperandTakes(TestPs1):

    def test_a_narrow_integer_operand_widens_to_an_int32(self):
        self.assertEqual(self._apply('$x = -bnot [byte]5', Ps1ConstantFolding), '$x = -6')

    def test_a_long_operand_stays_a_long(self):
        self.assertEqual(self._apply('$x = -bnot 1L', Ps1ConstantFolding), '$x = -2L')

    def test_an_unsigned_operand_keeps_its_unsigned_width(self):
        self.assertEqual(
            self._apply('$x = -bnot [uint32]7', Ps1ConstantFolding), '$x = [uint32]4294967288')

    def test_an_operand_5_1_converts_to_a_number_is_complemented_at_the_number(self):
        self.assertEqual(self._apply('$x = -bnot $null', Ps1ConstantFolding), '$x = -1')
        self.assertEqual(self._apply('$x = -bnot $true', Ps1ConstantFolding), '$x = -2')
        self.assertEqual(self._apply("$x = -bnot '5'", Ps1ConstantFolding), '$x = -6')
        self.assertEqual(self._apply('$x = -bnot [char]65', Ps1ConstantFolding), '$x = -66')
        self.assertEqual(self._apply('$x = -bnot 1.5', Ps1ConstantFolding), '$x = -3')
        self.assertEqual(self._apply('$x = -bnot 10d', Ps1ConstantFolding), '$x = -11')

    def test_a_complement_folded_to_a_negative_number_in_an_argument_is_parenthesized(self):
        self.assertEqual(
            self._deobfuscate('$t = -bnot 0xFF00; Write-Output $t'), 'Write-Output (-65281)')

    def test_a_string_that_spells_no_number_is_left_where_it_stands(self):
        self._assertUnchanged("$x = -bnot 'abc'", Ps1ConstantFolding)

    def test_a_real_whose_width_no_measurement_covers_is_left_where_it_stands(self):
        self._assertUnchanged('$x = -bnot 3000000000.0', Ps1ConstantFolding)


class TestPs1AHexadecimalLiteralIsNegativeWhereverItsNumberIsRead(TestPs1):

    def test_a_range_counts_from_the_negative_number_the_bound_names(self):
        self.assertEqual(self._apply('$x = 0xFFFFFFFF..1', Ps1ConstantFolding), '$x = -1, 0, 1')

    def test_an_index_into_an_array_counts_from_the_end(self):
        self.assertEqual(
            self._apply('$x = @(10, 20, 30)[0xFFFFFFFF]', Ps1ConstantFolding), '$x = 30')

    def test_an_index_into_a_string_counts_from_the_end(self):
        self.assertEqual(
            self._apply("$x = 'ABCDE'[0xFFFFFFFF]", Ps1ConstantFolding), '$x = [char]69')

    def test_a_conversion_reads_its_argument_as_the_negative_number(self):
        self.assertEqual(
            self._apply('$x = [Convert]::ToInt32(0xFFFFFFFF)', Ps1ConstantFolding), '$x = -1')

    def test_a_conversion_reads_its_base_as_the_number_the_literal_names(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('7f', 0x10)", Ps1ConstantFolding), '$x = 127')

    def test_a_byte_offset_is_read_as_the_number_the_literal_names(self):
        self.assertEqual(
            self._apply(
                '$x = [BitConverter]::ToString(@(0x41, 0x42, 0x43, 0x44), 0x1, 2)',
                Ps1ConstantFolding),
            "$x = '42-43'",
        )

    def test_a_repeat_count_is_read_as_the_number_the_literal_names(self):
        self.assertEqual(self._apply("$x = 'ab' * 0x3", Ps1ConstantFolding), "$x = 'ababab'")

    def test_a_format_argument_is_formatted_as_the_negative_number_it_is(self):
        self.assertEqual(
            self._apply("$x = '{0:D3}' -f 0xFFFFFFFF", Ps1ConstantFolding), "$x = '-001'")
        self.assertEqual(
            self._apply("$x = '{0:D3}' -f 4294967295", Ps1ConstantFolding), "$x = '4294967295'")

    def test_a_loop_whose_bound_is_the_negative_number_never_runs(self):
        self.assertEqual(
            self._deobfuscate('for ($i = 0; $i -lt 0xFFFFFFFF; $i++) { Write-Output 1 }'),
            '$i = 0',
        )
        self.assertEqual(
            self._deobfuscate('for ($i = 0; $i -lt 4294967295; $i++) { Write-Output 1 }'),
            inspect.cleandoc("""
                for ($i = 0; $i -LT 4294967295; $i++) {
                  Write-Output 1
                }
            """),
        )


class TestPs1AnIntegerSiteDeclinesWhereFivePointOneThrows(TestPs1):

    def test_a_character_code_no_char_holds_is_not_folded(self):
        self._assertUnchanged('$x = [Convert]::ToChar(0xFFFFFFFF)', Ps1ConstantFolding)

    def test_a_conversion_base_no_conversion_accepts_is_not_folded(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('11', 0xFFFFFFF0)", Ps1ConstantFolding)

    def test_a_number_no_byte_holds_is_not_folded_into_a_byte_array(self):
        self._assertUnchanged('$x = [BitConverter]::ToString(@(0xFFFFFFFF))', Ps1ConstantFolding)

    def test_an_offset_outside_the_array_is_not_folded(self):
        self._assertUnchanged(
            '$x = [BitConverter]::ToString(@(0x41, 0x42, 0x43, 0x44), 0xFFFFFFFF, 2)',
            Ps1ConstantFolding,
        )


class TestPs1AValueThatIsNoIntegerIsNotReadAsOne(TestPs1):

    def test_a_real_repeat_count_is_rounded_and_not_truncated(self):
        source = "$x = 'ab' * 1.5"
        self.assertIn(self._apply(source, Ps1ConstantFolding), (source, "$x = 'abab'"))

    @opportunity
    def test_a_real_repeat_count_folds_to_the_rounded_repetition(self):
        self.assertEqual(self._apply("$x = 'ab' * 1.5", Ps1ConstantFolding), "$x = 'abab'")

    def test_a_real_index_is_rounded_and_not_truncated(self):
        source = '$x = @(10, 20, 30)[1.5]'
        self.assertIn(self._apply(source, Ps1ConstantFolding), (source, '$x = 30'))

    @opportunity
    def test_a_real_index_folds_to_the_rounded_element(self):
        self.assertEqual(self._apply('$x = @(10, 20, 30)[1.5]', Ps1ConstantFolding), '$x = 30')

    def test_a_real_byte_is_not_truncated_to_a_whole_one(self):
        self._assertUnchanged('$x = [BitConverter]::ToString(@(1.5))', Ps1ConstantFolding)

    def test_a_real_conversion_base_is_not_truncated_to_a_whole_one(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('41', 16.0)", Ps1ConstantFolding)

    def test_a_repeat_count_of_a_type_that_holds_no_width_is_the_number_it_converts_to(self):
        for source, repeated in [
            ("$x = 'ab' * $null", "$x = ''"),
            ("$x = 'ab' * $true", "$x = 'ab'"),
            ("$x = 'ab' * '3'", "$x = 'ababab'"),
        ]:
            with self.subTest(source):
                self.assertIn(self._apply(source, Ps1ConstantFolding), (source, repeated))

    @opportunity
    def test_a_repeat_count_of_a_type_that_holds_no_width_folds_to_the_repetition(self):
        self.assertEqual(self._apply("$x = 'ab' * $null", Ps1ConstantFolding), "$x = ''")
        self.assertEqual(self._apply("$x = 'ab' * $true", Ps1ConstantFolding), "$x = 'ab'")
        self.assertEqual(self._apply("$x = 'ab' * '3'", Ps1ConstantFolding), "$x = 'ababab'")


class TestPs1ReplicatingAStringANegativeNumberOfTimes(TestPs1):

    def test_a_negative_repeat_count_leaves_the_replication_where_it_stands(self):
        self._assertUnchanged("$x = 'ab' * 0xFFFFFFFF", Ps1ConstantFolding)

    def test_a_negative_repeat_count_written_in_decimal_is_no_different(self):
        self._assertUnchanged("$x = 'ab' * -1", Ps1ConstantFolding)

    def test_a_zero_repeat_count_is_the_empty_string_and_not_a_refusal(self):
        self.assertEqual(self._apply("$x = 'ab' * 0", Ps1ConstantFolding), "$x = ''")


class TestPs1ConvertFolding(TestPs1):

    def test_toint32_hex_base(self):
        result = self._deobfuscate("[Convert]::ToInt32('41', 16)")
        self.assertIn('65', result)
        self.assertNotIn('Convert', result)

    def test_toint32_binary_base(self):
        result = self._deobfuscate("[Convert]::ToInt32('01000001', 2)")
        self.assertIn('65', result)

    def test_toint32_decimal_string(self):
        result = self._deobfuscate("[Convert]::ToInt32('123')")
        self.assertIn('123', result)
        self.assertNotIn('Convert', result)

    def test_tobyte(self):
        result = self._deobfuscate("[Convert]::ToByte('FF', 16)")
        self.assertIn('255', result)

    def test_tochar(self):
        self.assertEqual(self._deobfuscate('[Convert]::ToChar(65)'), '[char]65')

    def test_toint32_octal_base(self):
        result = self._deobfuscate("[Convert]::ToInt32('77', 8)")
        self.assertIn('63', result)


class TestPs1NegativeIndexFolding(TestPs1):

    def test_string_negative_one(self):
        self.assertEqual(self._deobfuscate("'hello'[-1]"), '[char]111')

    def test_string_negative_two(self):
        self.assertEqual(self._deobfuscate("'ABCDE'[-2]"), '[char]68')

    def test_array_negative_one(self):
        result = self._deobfuscate('@(10, 20, 30)[-1]')
        self.assertIn('30', result)
        self.assertNotIn('-1', result)

    def test_string_multi_negative_index(self):
        result = self._deobfuscate("'ABCDE'[-1, -3] -Join ''")
        self.assertIn('EC', result)


class TestPs1FormatStringSpecifiers(TestPs1):

    def test_hex_uppercase(self):
        result = self._deobfuscate("'{0:X2}' -f 65")
        self.assertIn('41', result)

    def test_hex_lowercase(self):
        result = self._deobfuscate("'{0:x4}' -f 255")
        self.assertIn('00ff', result)

    def test_decimal_padding(self):
        result = self._deobfuscate("'{0:D3}' -f 7")
        self.assertIn('007', result)

    def test_alignment_right(self):
        result = self._deobfuscate("'{0,5}' -f 'hi'")
        self.assertIn('   hi', result)

    def test_alignment_left(self):
        result = self._deobfuscate("'{0,-5}' -f 'hi'")
        self.assertIn('hi   ', result)

    def test_alignment_with_format(self):
        result = self._deobfuscate("'{0,6:X2}' -f 255")
        self.assertIn('    FF', result)

    def test_hex_multi_arg(self):
        result = self._deobfuscate("'{0:X2}{1:X2}' -f 72, 105")
        self.assertIn('4869', result)


class TestPs1BitConverterFolding(TestPs1):

    def test_tostring_basic(self):
        result = self._deobfuscate('[BitConverter]::ToString(@(0x41, 0x42, 0x43))')
        self.assertIn('41-42-43', result)

    def test_tostring_single_byte(self):
        result = self._deobfuscate('[BitConverter]::ToString(@(0xFF))')
        self.assertNotIn('BitConverter', result)
        self.assertIn('FF', result)

    def test_tostring_with_offset_and_length(self):
        result = self._deobfuscate('[BitConverter]::ToString(@(0x41, 0x42, 0x43, 0x44), 1, 2)')
        self.assertIn('42-43', result)


class TestPs1EnvironmentVariableFolding(TestPs1):

    def test_comspec(self):
        result = self._deobfuscate("[Environment]::GetEnvironmentVariable('ComSpec')")
        self.assertIn('cmd.exe', result)
        self.assertNotIn('GetEnvironmentVariable', result)

    def test_os(self):
        result = self._deobfuscate("[Environment]::GetEnvironmentVariable('OS')")
        self.assertIn('Windows_NT', result)

    def test_unknown_variable_not_folded(self):
        result = self._deobfuscate("[Environment]::GetEnvironmentVariable('CUSTOM_VAR')")
        self.assertIn('GetEnvironmentVariable', result)


class TestPs1HashtableLookup(TestPs1):

    def test_basic_string_lookup(self):
        result = self._deobfuscate("@{'a'='hello'}['a']")
        self.assertIn('hello', result)
        self.assertNotIn('@{', result)

    def test_integer_value_lookup(self):
        self.assertEqual(self._deobfuscate("@{'x'=42}['x']"), '42')

    def test_a_missing_key_looks_up_null(self):
        source = "@{\n  a = 'hello'\n}['b']"
        self._assertDeobfuscatesToOneOf(source, source, '$Null')

    @opportunity
    def test_a_missing_key_folds_to_null(self):
        self.assertEqual(self._deobfuscate("@{'a'='hello'}['b']"), '$Null')


class TestPs1FoldingExtra(TestPs1):

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

    def test_b64convert(self):
        data = '[System.Convert]::FromBase64String("AQID")'
        result = self._deobfuscate(data)
        self.assertIn('0x01', result)
        self.assertIn('0x02', result)
        self.assertIn('0x03', result)

    def test_b64convert_unqualified(self):
        data = '[Convert]::FromBase64String("AQID")'
        result = self._deobfuscate(data)
        self.assertIn('0x01', result)
        self.assertIn('0x02', result)
        self.assertIn('0x03', result)

    def test_b64convert_parenthesized_type(self):
        data = '([Convert])::FromBase64String("AQID")'
        result = self._deobfuscate(data)
        self.assertIn('0x01', result)
        self.assertIn('0x02', result)
        self.assertIn('0x03', result)

    def test_encoding_utf8(self):
        data = '[System.Text.Encoding]::UTF8.GetString(@(72, 101, 108, 108, 111))'
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

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

    def test_shift_operations(self):
        result = self._deobfuscate("$x = 1 -Shl 4; $y = 256 -Shr 3")
        self.assertIn('16', result)
        self.assertIn('32', result)

    def test_format_expression_chained(self):
        result = self._deobfuscate('$x = "{0}" -f "a" -f "b"')
        self.assertIn("'a'", result)

    def test_shift_operators_use_int32_semantics(self):
        self.assertEqual('-2147483648', self._apply('1 -shl 31', Ps1ConstantFolding))
        self.assertEqual('1', self._apply('1 -shl 32', Ps1ConstantFolding))

    def test_integer_division_yields_double(self):
        self.assertEqual(self._apply('7 / 2', Ps1ConstantFolding), '3.5')

    def test_integer_modulo_keeps_dividend_sign(self):
        self.assertEqual(self._apply('-7 % 3', Ps1ConstantFolding), '-1')

    def test_replace_expands_group_reference(self):
        result = self._apply("'aXb' -replace '(a)X','$1Y'", Ps1ConstantFolding)
        self.assertEqual(result, "'aYb'")

    def test_replace_treats_backslash_literally(self):
        result = self._apply(r"'aXb' -replace '(a)X','Q\1Z'", Ps1ConstantFolding)
        self.assertEqual(result, r"'Q\1Zb'")

    def test_replace_leaves_a_pattern_mixing_a_named_and_an_unnamed_group_unfolded(self):
        self.assertEqual(
            self._apply("'ab' -replace '(?<n>a)(b)', '$1'", Ps1ConstantFolding),
            "'ab' -replace '(?<n>a)(b)', '$1'",
        )

    def test_replace_folds_a_pattern_whose_groups_are_all_named(self):
        self.assertEqual(
            self._apply("'ab' -replace '(?<n>a)(?<m>b)', '${m}'", Ps1ConstantFolding), "'b'")

    def test_format_hex_negative_twos_complement(self):
        result = self._apply("'{0:X}' -f -1", Ps1ConstantFolding)
        self.assertEqual(result, "'FFFFFFFF'")

    def test_leading_zero_integer_is_decimal(self):
        self.assertEqual(self._apply('007 + 1', Ps1ConstantFolding), '8')


class TestPs1SelectionKeepsWhatBuildingTheContainerDid(TestPs1):

    def test_an_array_element_that_runs_a_command_is_not_dropped(self):
        self._assertUnchanged('$r = @(1, (Start-Process calc))[0]', Ps1ConstantFolding)

    def test_an_array_element_that_writes_a_variable_is_not_dropped(self):
        self._assertUnchanged('$r = @(1, $x++)[0]', Ps1ConstantFolding)

    def test_an_array_element_that_can_raise_is_not_dropped(self):
        self.assertEqual(
            self._apply(
                "try { $r = @(1, [Int]'abc')[0] } catch { Start-Process calc }",
                Ps1ConstantFolding),
            "try {\n  $r = @(1, [Int]'abc')[0]\n} catch {\n  Start-Process calc\n}")

    def test_a_hashtable_value_that_runs_a_command_is_not_dropped(self):
        self.assertEqual(
            self._apply("$r = @{ a = 1; b = (Start-Process calc) }['a']", Ps1ConstantFolding),
            "$r = @{\n  a = 1\n  b = (Start-Process calc)\n}['a']")

    def test_a_hashtable_key_that_runs_a_command_is_not_dropped(self):
        self.assertEqual(
            self._apply(
                '$r = @{ "$(Start-Process calc)" = 1; a = 2 }[\'a\']', Ps1ConstantFolding),
            '$r = @{\n  "$(Start-Process calc)" = 1\n  a = 2\n}[\'a\']')

    def test_an_array_of_literals_is_still_selected_from(self):
        self.assertEqual(self._apply('$r = @(1, 2)[0]', Ps1ConstantFolding), '$r = 1')

    def test_several_indices_into_an_array_of_literals_still_select(self):
        self.assertEqual(self._apply('$r = @(1, 2, 3)[0, 2]', Ps1ConstantFolding), '$r = 1, 3')

    def test_a_hashtable_of_literals_is_still_looked_up(self):
        self.assertEqual(
            self._apply("$r = @{ a = 1; b = 2 }['a']", Ps1ConstantFolding), '$r = 1')

    def test_a_character_of_a_string_leaves_no_evaluation_behind(self):
        self.assertEqual(self._apply("$r = 'abc'[0]", Ps1ConstantFolding), '$r = [char]97')


class TestPs1ConstantInliningSelectsOnlyFromConstants(TestPs1):

    def test_an_array_holding_a_command_is_not_a_constant_to_inline_from(self):
        self._assertUnchanged(
            '$a = @(1, (Start-Process calc))\n$r = $a[0]', Ps1ConstantInlining)

    def test_an_array_holding_an_increment_is_not_a_constant_to_inline_from(self):
        self._assertUnchanged('$a = @(1, $x++)\n$r = $a[0]', Ps1ConstantInlining)

    def test_an_array_holding_a_raising_cast_is_not_a_constant_to_inline_from(self):
        self._assertUnchanged("$a = @(1, [Int]'abc')\n$r = $a[0]", Ps1ConstantInlining)

    def test_an_array_of_literals_is_still_inlined_from(self):
        self.assertEqual(
            self._apply('$a = @(1, 2)\n$r = $a[0]', Ps1ConstantInlining), '$r = 1')

    def test_a_string_is_still_indexed_when_inlined(self):
        self.assertEqual(
            self._apply("$a = 'abc'\n$r = $a[0]", Ps1ConstantInlining), '$r = [char]97'
        )


class TestPs1FoldingRedirections(TestPs1):

    def test_a_redirected_regex_pipeline_is_not_folded_into_its_value(self):
        self._assertUnchanged(
            "$m = [regex]::Matches('abc', 'b') | ForEach-Object {\n  $_.Value\n} > C:\\o.txt",
            Ps1ConstantFolding)

    def test_an_unredirected_regex_pipeline_is_still_folded(self):
        self.assertEqual(
            self._apply(
                "$m = [regex]::Matches('abc', 'b') | %{ $_.Value }", Ps1ConstantFolding),
            "$m = 'b'")


class TestPs1CountingAnArrayKeepsWhatBuildingItDid(TestPs1):

    def test_the_length_of_an_array_holding_a_command_is_not_folded(self):
        self.assertEqual(
            self._apply('$x = @(1, (Start-Process calc)).Length', Ps1ConstantFolding),
            '$x = @(1, (Start-Process calc)).Length')

    def test_the_count_of_an_array_holding_an_increment_is_not_folded(self):
        self._assertUnchanged('$x = @(1, $y++).Count', Ps1ConstantFolding)

    def test_the_length_of_an_array_holding_a_raising_cast_is_not_folded(self):
        self._assertUnchanged("$x = @(1, [Int]'abc').Length", Ps1ConstantFolding)

    def test_the_length_of_an_array_of_literals_is_still_folded(self):
        self.assertEqual(self._apply('$x = @(1, 2).Length', Ps1ConstantFolding), '$x = 2')

    def test_the_length_of_a_string_is_still_folded(self):
        self.assertEqual(self._apply("$x = 'abc'.Length", Ps1ConstantFolding), '$x = 3')

    def test_a_refused_selection_leaves_every_parent_pointer_true(self):
        source = '$r = @(1, 2, (Start-Process calc))[0, 1]'
        self._assertTreeIsIntact(source, source, Ps1ConstantFolding)

    def test_a_refused_count_leaves_every_parent_pointer_true(self):
        source = '$x = @(1, (Start-Process calc)).Length'
        self._assertTreeIsIntact(source, source, Ps1ConstantFolding)

    def test_a_repeated_index_into_an_array_of_literals_selects_that_element_twice(self):
        source = '$r = @(1, 2, 3)[0, 0]'
        result = self._apply(source, Ps1ConstantFolding)
        self.assertIn(result, (source, '$r = 1, 1'))
        self._assertTreeIsIntact(source, result, Ps1ConstantFolding)

    @opportunity
    def test_a_repeated_index_into_an_array_of_literals_folds_to_that_element_twice(self):
        self._assertTreeIsIntact('$r = @(1, 2, 3)[0, 0]', '$r = 1, 1', Ps1ConstantFolding)

    def test_a_repeated_index_reached_through_a_negative_one_selects_that_element_twice(self):
        source = '$r = @(1, 2, 3)[0, -3]'
        result = self._apply(source, Ps1ConstantFolding)
        self.assertIn(result, (source, '$r = 1, 1'))
        self._assertTreeIsIntact(source, result, Ps1ConstantFolding)

    @opportunity
    def test_a_repeated_index_reached_through_a_negative_one_folds_to_that_element_twice(self):
        self._assertTreeIsIntact('$r = @(1, 2, 3)[0, -3]', '$r = 1, 1', Ps1ConstantFolding)

    def test_distinct_indices_into_the_same_array_still_select(self):
        self.assertEqual(self._apply('$r = @(1, 2, 3)[2, 0]', Ps1ConstantFolding), '$r = 3, 1')

    def test_a_repeated_index_into_a_string_still_folds(self):
        self.assertEqual(
            self._apply("$r = 'abc'[0, 0, 1]", Ps1ConstantFolding),
            '$r = [char]97, [char]97, [char]98')


class TestPs1ACallWritingThroughAnArgumentIsAWriteOfThatVariable(TestPs1):

    def test_the_written_argument_still_names_the_variable_below_a_folded_read(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output $x[0]', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output 3')

    def test_a_read_above_the_reversal_sees_the_order_the_assignment_built(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\nWrite-Output $x[0]\n[Array]::Reverse($x)\nWrite-Output $x[0]',
                Ps1ConstantInlining),
            '$x = 1, 2, 3\nWrite-Output 1\n[Array]::Reverse($x)\nWrite-Output 3')

    def test_a_second_reversal_returns_the_array_to_the_order_it_started_in(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output $x\n'
                '[Array]::Reverse($x)\nWrite-Output $x',
                Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)\n'
            '[Array]::Reverse($x)\nWrite-Output (1, 2, 3)')

    def test_binding_the_void_result_of_the_reversal_changes_nothing(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n$r = [Array]::Reverse($x)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n$r = [Array]::Reverse($x)\nWrite-Output (3, 2, 1)')

    def test_the_deobfuscator_answers_the_read_below_the_reversal_with_the_reversed_order(self):
        self.assertIn(
            'Write-Output (3, 2, 1)',
            self._deobfuscate('$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output $x'),
        )

    def test_a_reversal_of_a_variable_nothing_assigned_is_not_answered(self):
        self._assertUnchanged('[Array]::Reverse($x)\nWrite-Output $x', Ps1ConstantInlining)

    def test_an_element_written_before_the_reversal_moves_to_the_far_end(self):
        source = '$x = 1, 2, 3\n$x[0] = 9\n[Array]::Reverse($x)\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$x = 1, 2, 3\n$x[0] = 9\n[Array]::Reverse($x)\nWrite-Output (3, 2, 9)'),
        )

    def test_a_reversal_through_an_array_element_turns_that_element_around(self):
        source = '$p = @(@(1, 2), @(3, 4))\n[Array]::Reverse($p[0])\nWrite-Output $p[0]'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$p = @(@(1, 2), @(3, 4))\n[Array]::Reverse($p[0])\nWrite-Output (2, 1)'),
        )

    def test_a_read_below_a_sort_sees_the_order_the_call_left(self):
        self.assertEqual(
            self._apply(
                '$x = 3, 1, 2\n[Array]::Sort($x)\nWrite-Output $x[0]', Ps1ConstantInlining),
            '$x = 3, 1, 2\n[Array]::Sort($x)\nWrite-Output 1')

    def test_a_reversal_under_a_condition_that_is_not_known_is_not_answered(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\nif ($env:C) {\n  [Array]::Reverse($x)\n}\nWrite-Output $x',
            Ps1ConstantInlining)

    def test_a_reversal_inside_a_called_function_turns_the_callers_array_around(self):
        source = 'function f {\n  [Array]::Reverse($x)\n}\n$x = 1, 2, 3\nf\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (
                source,
                'function f {\n  [Array]::Reverse($x)\n}\n$x = 1, 2, 3\nf\nWrite-Output (3, 2, 1)',
            ),
        )


class TestPs1AReverseIsComputedWhereItsEffectIsKnownAndTotal(TestPs1):

    def test_a_whole_array_is_reversed(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)')

    def test_a_range_inside_the_array_reverses_only_that_range(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 2)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 2)\nWrite-Output (2, 1, 3)')

    def test_a_range_spanning_the_whole_array_reverses_all_of_it(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 3)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 3)\nWrite-Output (3, 2, 1)')

    def test_a_range_of_one_element_leaves_the_order_alone(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x, 1, 1)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x, 1, 1)\nWrite-Output (1, 2, 3)')

    def test_an_empty_range_at_the_far_end_of_the_array_still_fits_inside_it(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x, 3, 0)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x, 3, 0)\nWrite-Output (1, 2, 3)')

    def test_a_range_that_does_not_fit_inside_the_array_leaves_the_order_alone(self):
        source = '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 99)\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 99)\nWrite-Output (1, 2, 3)'),
        )

    def test_a_range_whose_length_is_not_a_known_number_is_not_answered(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\n[Array]::Reverse($x, 0, $n)\nWrite-Output $x', Ps1ConstantInlining)

    def test_reversing_a_string_does_not_reverse_the_string(self):
        source = "$s = 'abc'\n[Array]::Reverse($s)\nWrite-Output $s"
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, "$s = 'abc'\n[Array]::Reverse($s)\nWrite-Output 'abc'"),
        )


class TestPs1AnArrayReachedByTwoNamesIsWrittenThroughEither(TestPs1):

    def test_a_reversal_through_one_name_is_seen_by_a_read_of_the_other(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output $y',
                Ps1ConstantInlining),
            '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)')

    def test_the_share_survives_a_read_of_it_that_cannot_be_answered(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output $y[$env:I]',
            Ps1ConstantInlining)

    def test_a_reversal_through_the_second_name_is_seen_by_a_read_of_the_first(self):
        source = '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($y)\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($y)\nWrite-Output (3, 2, 1)'),
        )

    def test_an_element_written_through_the_second_name_is_seen_by_a_read_of_the_first(self):
        source = '$x = 1, 2, 3\n$y = $x\n$y[0] = 9\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$x = 1, 2, 3\n$y = $x\n$y[0] = 9\nWrite-Output (9, 2, 3)'),
        )

    def test_rebinding_one_name_does_not_change_the_array_the_other_holds(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n$y = $x\n$x = 9, 9, 9\nWrite-Output $y', Ps1ConstantInlining),
            '$y = (1, 2, 3)\nWrite-Output $y')


class TestPs1AMethodFoldsOnlyWhereItsReceiverCarriesTheOverload(TestPs1):

    def test_upper_casing_a_char_is_not_folded(self):
        self._assertUnchanged('$x = ([char]65).ToUpper()', Ps1ConstantFolding)

    def test_lower_casing_a_char_is_not_folded(self):
        self._assertUnchanged('$x = ([char]97).ToLower()', Ps1ConstantFolding)

    def test_a_substring_of_a_char_is_not_folded(self):
        self._assertUnchanged('$x = ([char]65).Substring(0)', Ps1ConstantFolding)

    def test_a_call_with_no_overload_of_that_arity_is_not_folded(self):
        self._assertUnchanged("$x = 'abc'.Substring(0, 1, 2)", Ps1ConstantFolding)

    def test_a_char_written_by_its_own_to_string_is_the_one_character_string(self):
        self.assertEqual(self._apply('$x = ([char]65).ToString()', Ps1ConstantFolding), "$x = 'A'")

    def test_upper_casing_a_string_is_still_folded(self):
        self.assertEqual(self._apply("$x = 'abc'.ToUpper()", Ps1ConstantFolding), "$x = 'ABC'")


class TestPs1WritingAValueWithItsOwnToStringIsNotTheStringCast(TestPs1):

    def test_a_decimal_written_by_its_own_to_string_is_not_folded(self):
        source = '$x = 1.50d.ToString()'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_double_written_by_its_own_to_string_is_not_folded(self):
        source = '$x = 1.5.ToString()'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_string_cast_of_the_same_decimal_keeps_the_digits_it_was_written_with(self):
        self.assertEqual(self._deobfuscate('$x = [string]1.50d'), "$x = '1.50'")

    def test_an_integer_written_by_its_own_to_string_is_the_digits_it_spells(self):
        self.assertEqual(self._apply('$x = (5).ToString()', Ps1ConstantFolding), "$x = '5'")

    def test_a_long_written_by_its_own_to_string_is_the_digits_it_spells(self):
        self.assertEqual(self._apply('$x = (5L).ToString()', Ps1ConstantFolding), "$x = '5'")

    def test_a_byte_written_by_its_own_to_string_is_the_digits_it_spells(self):
        self.assertEqual(self._apply('$x = ([byte]5).ToString()', Ps1ConstantFolding), "$x = '5'")

    def test_a_boolean_written_by_its_own_to_string_is_the_word_it_renders_as(self):
        self.assertEqual(self._apply('$x = $true.ToString()', Ps1ConstantFolding), "$x = 'True'")

    def test_a_string_written_by_its_own_to_string_is_that_string(self):
        self.assertEqual(self._apply("$x = 'abc'.ToString()", Ps1ConstantFolding), "$x = 'abc'")


class TestPs1AMethodConvertsItsArgumentToTheParameterItBinds(TestPs1):

    def test_a_char_argument_bound_to_an_offset_arrives_as_its_code_point(self):
        self.assertEqual(
            self._apply("$x = 'abc'.Substring([char]1)", Ps1ConstantFolding), "$x = 'bc'")

    def test_a_string_argument_bound_to_a_character_array_arrives_as_its_characters(self):
        self.assertEqual(
            self._apply("$x = 'a,b;c'.Split(',;')", Ps1ConstantFolding), "$x = 'a', 'b', 'c'")

    def test_a_char_argument_bound_to_a_character_array_arrives_as_one_separator(self):
        self.assertEqual(
            self._apply("$x = 'abc'.Split([char]98)", Ps1ConstantFolding), "$x = 'a', 'c'")


class TestPs1AnOperatorConvertsEveryOperandToText(TestPs1):

    def test_a_char_replacement_contributes_its_character(self):
        self.assertEqual(
            self._apply("$x = 'x' -replace 'x', [char]65", Ps1ConstantFolding), "$x = 'A'")

    def test_a_number_between_two_strings_is_joined_as_its_digits(self):
        self.assertEqual(
            self._apply("$x = ('a', 'b') -join 5", Ps1ConstantFolding), "$x = 'a5b'")

    def test_joining_numbers_writes_the_digits_of_each_of_them(self):
        self.assertEqual(self._apply('$x = -join (72, 105)', Ps1ConstantFolding), "$x = '72105'")

    def test_a_char_separator_splits_at_the_character_it_holds(self):
        self.assertEqual(
            self._apply("$x = 'a,b' -split [char]44", Ps1ConstantFolding), "$x = 'a', 'b'")

    def test_a_char_on_the_left_of_a_replacement_is_the_text_it_writes(self):
        self.assertEqual(
            self._apply("$x = [char]65 -replace 'A', 'B'", Ps1ConstantFolding), "$x = 'B'")

    def test_a_boolean_on_the_left_of_a_replacement_is_the_word_it_renders_as(self):
        self.assertEqual(
            self._apply("$x = $true -replace 'T', 'X'", Ps1ConstantFolding), "$x = 'Xrue'")


class TestPs1ATextOnlyOperandIsWrittenAsTheTextItContributes(TestPs1):

    def test_a_char_pattern_is_written_as_the_character_it_matches(self):
        self.assertEqual(
            self._apply('$x -match [char]12499', Ps1ConstantFolding), "$x -match 'ビ'")

    def test_a_char_wildcard_is_written_as_the_character_it_matches(self):
        self.assertEqual(self._apply('$x -like [char]65', Ps1ConstantFolding), "$x -like 'A'")

    def test_a_char_replacement_pair_is_written_as_the_characters_it_replaces(self):
        self.assertEqual(
            self._apply('$x -replace [char]65, [char]66', Ps1ConstantFolding),
            "$x -replace 'A', 'B'",
        )

    def test_a_char_separator_is_written_as_the_character_it_splits_at(self):
        self.assertEqual(self._apply('$x -split [char]44', Ps1ConstantFolding), "$x -split ','")

    def test_a_char_separator_is_written_as_the_character_it_joins_with(self):
        self.assertEqual(self._apply('$x -join [char]44', Ps1ConstantFolding), "$x -join ','")

    def test_a_boolean_pattern_is_written_as_the_word_it_renders_as(self):
        self.assertEqual(self._apply('$x -match $true', Ps1ConstantFolding), "$x -match 'True'")

    def test_the_case_sensitive_and_negated_spellings_are_written_the_same_way(self):
        self.assertEqual(self._apply('$x -cmatch [char]65', Ps1ConstantFolding), "$x -cmatch 'A'")
        self.assertEqual(
            self._apply('$x -notmatch [char]65', Ps1ConstantFolding), "$x -notmatch 'A'")
        self.assertEqual(
            self._apply("$x -ireplace [char]65, 'B'", Ps1ConstantFolding), "$x -ireplace 'A', 'B'")

    def test_a_char_compared_for_equality_is_left_the_char_it_is(self):
        self._assertUnchanged('$x -eq [char]65', Ps1ConstantFolding)

    def test_a_number_handed_to_a_format_is_left_the_number_it_is(self):
        self._assertUnchanged('$fmt -f 65', Ps1ConstantFolding)


class TestPs1AHashTableKeyIsFoundByItsValueAndItsType(TestPs1):

    def test_a_string_key_is_found_by_a_string_of_another_case(self):
        self.assertEqual(self._apply("$x = @{ a = 1 }['A']", Ps1ConstantFolding), '$x = 1')

    def test_a_string_key_is_not_found_by_a_char(self):
        expected = inspect.cleandoc("""
            $x = @{
              a = 1
            }[[char]97]
        """)
        self.assertEqual(self._apply('$x = @{ a = 1 }[[char]97]', Ps1ConstantFolding), expected)

    def test_a_number_key_is_found_by_the_same_number(self):
        self.assertEqual(self._apply("$x = @{ 1 = 'x' }[1]", Ps1ConstantFolding), "$x = 'x'")

    def test_a_number_key_is_not_found_by_the_text_of_its_digits(self):
        expected = inspect.cleandoc("""
            $x = @{
              1 = 'x'
            }['1']
        """)
        self.assertEqual(self._apply("$x = @{ 1 = 'x' }['1']", Ps1ConstantFolding), expected)

    def test_a_number_key_is_not_found_by_the_same_number_of_another_width(self):
        expected = inspect.cleandoc("""
            $x = @{
              1 = 'x'
            }[1L]
        """)
        self.assertEqual(self._apply("$x = @{ 1 = 'x' }[1L]", Ps1ConstantFolding), expected)


class TestPs1ConvertReadsAStringByRulesOfItsOwn(TestPs1):

    def test_a_hexadecimal_prefix_is_no_decimal_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('0x10')", Ps1ConstantFolding)

    def test_the_cast_of_that_same_text_is_the_number_its_digits_denote(self):
        self.assertEqual(self._deobfuscate("$x = [int]'0x10'"), '$x = 16')

    def test_a_digit_separator_is_no_decimal_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('1_0')", Ps1ConstantFolding)

    def test_a_binary_prefix_is_no_decimal_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('0b1010')", Ps1ConstantFolding)

    def test_a_fraction_is_no_whole_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('7.5')", Ps1ConstantFolding)

    def test_an_exponent_is_no_whole_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('1e3')", Ps1ConstantFolding)

    def test_a_group_separator_is_no_decimal_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('1,000')", Ps1ConstantFolding)

    def test_the_empty_string_is_no_number_at_all(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('')", Ps1ConstantFolding)

    def test_whitespace_around_the_digits_is_read_over(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32(' 5 ')", Ps1ConstantFolding), '$x = 5')

    def test_a_leading_plus_is_a_sign(self):
        self.assertEqual(self._apply("$x = [Convert]::ToInt32('+7')", Ps1ConstantFolding), '$x = 7')

    def test_a_leading_minus_is_a_sign(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('-5')", Ps1ConstantFolding), '$x = -5')

    def test_leading_zeroes_are_read_over(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('007')", Ps1ConstantFolding), '$x = 7')


class TestPs1ConvertWithABaseReadsABitPatternAtTheTargetsWidth(TestPs1):

    def test_digits_filling_the_int32_width_are_the_negative_number_they_denote(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('FFFFFFFF', 16)", Ps1ConstantFolding), '$x = -1')

    def test_digits_filling_the_sign_bit_are_the_smallest_int32(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('80000000', 16)", Ps1ConstantFolding),
            '$x = -2147483648',
        )

    def test_the_target_the_method_names_is_the_type_of_the_answer(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToByte('FF', 16)", Ps1ConstantFolding), '$x = [byte]255')

    def test_an_octal_base_reads_the_digits_as_powers_of_eight(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('017', 8)", Ps1ConstantFolding), '$x = 15')

    def test_a_binary_base_reads_the_digits_as_powers_of_two(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('1010', 2)", Ps1ConstantFolding), '$x = 10')

    def test_a_sign_is_no_part_of_a_bit_pattern(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('-10', 16)", Ps1ConstantFolding)

    def test_whitespace_is_no_part_of_a_bit_pattern(self):
        self._assertUnchanged("$x = [Convert]::ToInt32(' 5 ', 16)", Ps1ConstantFolding)

    def test_a_hexadecimal_prefix_is_read_by_the_base_that_spells_it(self):
        self.assertEqual(
            self._apply("$x = [Convert]::ToInt32('0x10', 16)", Ps1ConstantFolding), '$x = 16')

    def test_a_hexadecimal_prefix_is_no_part_of_an_octal_number(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('0x10', 8)", Ps1ConstantFolding)


class TestPs1ConvertOfEverythingButAStringIsTheCast(TestPs1):

    def test_a_real_reaches_an_integer_target_by_rounding_half_to_even(self):
        self.assertEqual(self._apply('$x = [Convert]::ToInt32(1.5)', Ps1ConstantFolding), '$x = 2')
        self.assertEqual(self._apply('$x = [Convert]::ToInt32(2.5)', Ps1ConstantFolding), '$x = 2')

    def test_the_absent_value_reaches_an_integer_target_as_zero(self):
        self.assertEqual(
            self._apply('$x = [Convert]::ToInt32($null)', Ps1ConstantFolding), '$x = 0')

    def test_a_number_reaches_a_wider_target_as_a_value_of_that_width(self):
        self.assertEqual(self._apply('$x = [Convert]::ToInt64(5)', Ps1ConstantFolding), '$x = 5L')


class TestPs1AChainOfAppendsIsNotReassociated(TestPs1):

    def test_a_chain_of_appends_to_an_unknown_left_operand_is_left_alone(self):
        self._assertUnchanged("$y = $x + 'a' + 'b'", Ps1ConstantFolding)

    def test_a_chain_of_appends_to_a_literal_collection_keeps_every_element(self):
        self.assertEqual(self._apply("$y = ,1 + 'a' + 'b'", Ps1ConstantFolding), "$y = 1, 'a', 'b'")

    def test_a_chain_of_appends_to_a_literal_string_is_the_text_of_all_three(self):
        self.assertEqual(self._apply("$y = 'a' + 'b' + 'c'", Ps1ConstantFolding), "$y = 'abc'")


class TestPs1AppendingToALiteralCollectionKeepsWhatWasAppended(TestPs1):

    def test_a_char_appended_to_a_literal_collection_is_still_a_char(self):
        self.assertEqual(
            self._apply('$x = 1, 2 + [char]65', Ps1ConstantFolding), '$x = 1, 2, [char]65')

    def test_a_string_appended_to_a_literal_collection_is_still_a_string(self):
        self.assertEqual(self._apply("$x = 1, 2 + 'A'", Ps1ConstantFolding), "$x = 1, 2, 'A'")

    def test_a_char_appended_through_the_array_operator_is_still_a_char(self):
        self.assertEqual(
            self._apply('$x = @(1, 2) + [char]65', Ps1ConstantFolding), '$x = 1, 2, [char]65')


class TestPs1RepeatingACollectionByACountNoInt32Holds(TestPs1):

    def test_a_count_no_int32_holds_leaves_the_repetition_where_it_stands(self):
        self._assertUnchanged('$x = @() * [uint64]18446744073709551615', Ps1ConstantFolding)
        self._assertUnchanged('$x = @(1, 2) * [uint64]18446744073709551615', Ps1ConstantFolding)

    def test_the_largest_count_an_int32_holds_is_the_last_one_that_folds(self):
        self.assertEqual(self._apply('$x = @() * 2147483647', Ps1ConstantFolding), '$x = @()')
        self._assertUnchanged('$x = @() * 2147483648', Ps1ConstantFolding)

    def test_a_count_an_int32_holds_repeats_the_collection_it_counts(self):
        self.assertEqual(self._apply('$x = @() * 5000', Ps1ConstantFolding), '$x = @()')
        self.assertEqual(self._apply('$x = @(1, 2) * 2', Ps1ConstantFolding), '$x = 1, 2, 1, 2')


class TestPs1AJoinIsFoldedOnlyWhereTheTextItAppendsIsWritten(TestPs1):

    def test_a_string_that_spells_a_number_joined_with_a_double_is_the_text_of_both(self):
        self.assertEqual(self._apply("$x = '5' + 1.5", Ps1ConstantFolding), "$x = '51.5'")

    def test_the_empty_string_joined_with_a_double_is_the_text_of_the_double(self):
        self.assertEqual(self._apply("$x = '' + 1.5", Ps1ConstantFolding), "$x = '1.5'")

    def test_a_char_joined_with_a_double_is_the_text_of_both(self):
        self.assertEqual(self._apply('$x = [char]65 + 1.5', Ps1ConstantFolding), "$x = 'A1.5'")

    def test_a_string_joined_with_a_number_written_here_is_the_text_of_both(self):
        self.assertEqual(self._apply("$x = '5' + 5", Ps1ConstantFolding), "$x = '55'")

    def test_a_char_joined_with_a_number_written_here_is_the_text_of_both(self):
        self.assertEqual(self._apply('$x = [char]65 + 1', Ps1ConstantFolding), "$x = 'A1'")

    def test_the_pipeline_folds_a_join_with_a_double_as_it_folds_one_with_an_integer(self):
        self.assertEqual(self._deobfuscate("$x = '5' + 1.5; Write-Output $x"), "Write-Output '51.5'")
        self.assertEqual(self._deobfuscate("$x = '5' + 5; Write-Output $x"), "Write-Output '55'")


class TestPs1AnArrayACallWritesThroughIsComputedWhereverItsEffectIsDetermined(TestPs1):

    @opportunity
    def test_a_reversal_reached_through_an_array_element_is_computed_for_that_element(self):
        source = inspect.cleandoc("""
            $p = @(@(1, 2), @(3, 4))
            [Array]::Reverse($p[0])
            Write-Output $p[0]
        """)
        expected = inspect.cleandoc("""
            $p = @(@(1, 2), @(3, 4))
            [Array]::Reverse($p[0])
            Write-Output (2, 1)
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_sort_of_elements_that_share_a_type_orders_the_array_it_is_handed(self):
        source = inspect.cleandoc("""
            $x = @([char]98, [char]97)
            [Array]::Sort($x)
            Write-Output $x[0]
        """)
        expected = inspect.cleandoc("""
            $x = @([char]98, [char]97)
            [Array]::Sort($x)
            Write-Output ([char]97)
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_a_clear_over_a_range_that_fits_empties_the_elements_it_covers(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Clear($x, 0, 1)
            Write-Output $x
        """)
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Clear($x, 0, 1)
            Write-Output ($Null, 2, 3)
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)


class TestPs1ASortOrdersAnArrayOfOneComparableType(TestPs1):

    def test_numbers_order_by_magnitude_and_not_by_spelling(self):
        self.assertEqual(
            self._apply(
                '$x = 10, 2, 1\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 10, 2, 1\n[Array]::Sort($x)\nWrite-Output (1, 2, 10)')

    def test_negative_integers_order_by_magnitude(self):
        self.assertEqual(
            self._apply(
                '$x = 1, -2, -1\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, -2, -1\n[Array]::Sort($x)\nWrite-Output (-2, -1, 1)')

    def test_chars_order_by_code_point(self):
        self.assertEqual(
            self._apply(
                '$x = @([char]66, [char]65, [char]67)\n[Array]::Sort($x)\nWrite-Output $x',
                Ps1ConstantInlining),
            '$x = @([char]66, [char]65, [char]67)\n[Array]::Sort($x)\n'
            'Write-Output ([char]65, [char]66, [char]67)')

    def test_booleans_order_false_before_true(self):
        self.assertEqual(
            self._apply(
                '$x = @($true, $false)\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = @($true, $false)\n[Array]::Sort($x)\nWrite-Output ($false, $true)')

    def test_a_string_array_is_not_ordered_because_its_order_is_cultural(self):
        self._assertUnchanged(
            "$x = @('b', 'a')\n[Array]::Sort($x)\nWrite-Output $x", Ps1ConstantInlining)

    def test_a_cross_type_array_is_not_ordered(self):
        self._assertUnchanged(
            "$x = @('b', 5)\n[Array]::Sort($x)\nWrite-Output $x", Ps1ConstantInlining)

    def test_an_unreadable_element_leaves_the_order_unknown(self):
        self._assertUnchanged(
            "$x = @($a, 'b')\n[Array]::Sort($x)\nWrite-Output $x", Ps1ConstantInlining)

    def test_a_comparer_form_has_no_rule(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\n[Array]::Sort($x, $c)\nWrite-Output $x', Ps1ConstantInlining)

    def test_an_empty_array_sorts_to_the_empty_array(self):
        source = '$x = @()\n[Array]::Sort($x)\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$x = @()\n[Array]::Sort($x)\nWrite-Output @()'),
        )

    @opportunity
    def test_a_read_below_the_sort_of_an_empty_array_is_answered_with_the_empty_array(self):
        self.assertEqual(
            self._apply(inspect.cleandoc("""
                $x = @()
                [Array]::Sort($x)
                Write-Output $x
            """), Ps1ConstantInlining),
            inspect.cleandoc("""
                $x = @()
                [Array]::Sort($x)
                Write-Output @()
            """),
        )

    def test_decimals_of_one_value_and_different_scale_are_not_ordered(self):
        self._assertUnchanged(
            '$x = @(1.0d, 1.00d)\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining)

    def test_a_repeated_value_sorts_to_itself(self):
        source = '$x = @(1, 1)\n[Array]::Sort($x)\nWrite-Output $x'
        self.assertIn(
            self._apply(source, Ps1ConstantInlining),
            (source, '$x = @(1, 1)\n[Array]::Sort($x)\nWrite-Output (1, 1)'),
        )

    @opportunity
    def test_a_read_below_the_sort_of_a_repeated_value_is_answered_with_that_array(self):
        self.assertEqual(
            self._apply(inspect.cleandoc("""
                $x = @(1, 1)
                [Array]::Sort($x)
                Write-Output $x
            """), Ps1ConstantInlining),
            inspect.cleandoc("""
                $x = @(1, 1)
                [Array]::Sort($x)
                Write-Output (1, 1)
            """),
        )


class TestPs1AMutatingCallAndItsStoreGoWhereNoReadObservesThem(TestPs1):

    @opportunity
    def test_a_store_and_the_reversal_of_it_are_dropped_below_a_folded_read(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x)
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output (3, 2, 1)')


class TestPs1AConstraintOnAVariableConvertsWhatIsWrittenToIt(TestPs1):

    def test_a_declaring_write_stores_the_converted_scalar(self):
        self.assertEqual(
            self._deobfuscate('[string]$q = 5\nWrite-Output $q'), "Write-Output '5'")

    def test_a_declaring_write_parses_a_string_to_its_constrained_number(self):
        self.assertEqual(
            self._deobfuscate("[int]$n = '5'\nWrite-Output ($n + 1)"), 'Write-Output 6')

    def test_a_compound_write_to_a_constrained_variable_arrives_as_the_constrained_type(self):
        source = inspect.cleandoc("""
            [string]$q = 5
            $q += 'a'
            Write-Output (,$q)
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output (,'5a')")

    @opportunity
    def test_a_later_write_to_a_constrained_variable_arrives_as_the_constrained_type(self):
        source = inspect.cleandoc("""
            [string]$q = 5
            $q = 1, 2, 3
            Write-Output $q.Length
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output 5')


class TestPs1AScopeQualifierNamesTheBindingItsBareSpellingNames(TestPs1):

    def test_an_environment_variable_is_folded_through_its_qualifier(self):
        self.assertEqual(
            self._deobfuscate("$env:z = 'v'; Write-Output $env:z"), "Write-Output 'v'")

    def test_a_bare_read_observes_what_the_qualified_spelling_wrote(self):
        self.assertEqual(
            self._deobfuscate("$script:s = 'x'; Write-Output $s"), "Write-Output 'x'")

    def test_a_read_of_a_script_qualified_name_is_the_value_written_under_it(self):
        self.assertEqual(
            self._deobfuscate("$script:y = 'b'; Write-Output $script:y"), "Write-Output 'b'")

    def test_a_read_of_a_global_qualified_name_is_the_value_written_under_it(self):
        self.assertEqual(
            self._deobfuscate("$global:y = 'b'; Write-Output $global:y"), "Write-Output 'b'")

    def test_a_qualified_read_observes_what_the_bare_spelling_wrote(self):
        self.assertEqual(
            self._deobfuscate("$s = 'x'; Write-Output $script:s"), "Write-Output 'x'")

    def test_a_read_naming_the_other_scope_of_a_write_is_not_folded(self):
        for source, read in [
            ("$x = 'a'; Write-Output $global:x", 'Write-Output $global:x'),
            ("$global:x = 'b'; Write-Output $script:x", 'Write-Output $script:x'),
        ]:
            with self.subTest(source):
                self.assertIn(read, self._deobfuscate(source))


class TestPs1AnOperatorOverANameWrittenUnderAQualifierFoldsAsIfItWereNull(TestPs1):

    def test_a_bare_read_of_a_qualified_written_name_is_not_folded_as_null(self):
        for source, expected in [
            ('$script:q = 5; Write-Output ($q + 1)', 'Write-Output 6'),
            ('$script:k = 0x5A; Write-Output (0xFF -bxor $k)', 'Write-Output 165'),
            ('$global:n = 3; Write-Output ($n * 4)', 'Write-Output 12'),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_a_qualified_write_that_never_runs_leaves_the_bare_read_null(self):
        self.assertEqual(
            self._deobfuscate('function f { $script:q = 5 }\nWrite-Output ($q + 1)'),
            'Write-Output 1')


class TestPs1ACompoundAssignmentLeavesTheValueItsLongSpellingLeaves(TestPs1):

    def test_the_long_spelling_of_an_accumulation_is_folded(self):
        source = inspect.cleandoc("""
            $s = 'a'
            $s = $s + 'b'
            $s = $s + 'c'
            Write-Output $s
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output 'abc'")

    def test_an_added_number_is_the_sum(self):
        self.assertEqual(
            self._deobfuscate('$n = 1; $n += 2; Write-Output $n'), 'Write-Output 3')

    def test_a_subtracted_number_is_the_difference(self):
        self.assertEqual(
            self._deobfuscate('$n = 5; $n -= 2; Write-Output $n'), 'Write-Output 3')

    def test_an_incremented_number_is_the_next_one(self):
        self.assertEqual(
            self._deobfuscate('$n = 1; $n++; Write-Output $n'), 'Write-Output 2')

    def test_appended_text_is_the_text_of_every_append(self):
        source = inspect.cleandoc("""
            $s = 'a'
            $s += 'b'
            $s += 'c'
            Write-Output $s
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output 'abc'")

    def test_a_command_accumulated_by_appending_is_run_where_it_was_built(self):
        source = inspect.cleandoc("""
            $c = 'Write-Out'
            $c += 'put 5'
            Invoke-Expression $c
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output 5')


class TestPs1AnIncrementNeedsANumberAndIsNotTheBinarySum(TestPs1):

    def test_decrementing_a_number_is_the_previous_one(self):
        self.assertEqual(self._deobfuscate('$x = 5; $x--; Write-Output $x'), 'Write-Output 4')

    def test_incrementing_null_is_one(self):
        self.assertEqual(self._deobfuscate('$x = $null; $x++; Write-Output $x'), 'Write-Output 1')

    def test_incrementing_a_string_fails_and_leaves_the_string(self):
        source = '$x = "5"\n$x++\nWrite-Output $x'
        self._assertDeobfuscatesToOneOf(source, source, "Write-Output '5'")

    @opportunity
    def test_a_read_after_a_failing_increment_of_a_string_folds_to_the_string(self):
        self.assertEqual(self._deobfuscate('$x = "5"; $x++; Write-Output $x'), "Write-Output '5'")

    def test_incrementing_a_char_fails_and_leaves_the_char(self):
        source = '$x = [char]65\n$x++\nWrite-Output $x'
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output ([char]65)')

    @opportunity
    def test_a_read_after_a_failing_increment_of_a_char_folds_to_the_char(self):
        self.assertEqual(
            self._deobfuscate('$x = [char]65; $x++; Write-Output $x'), 'Write-Output ([char]65)'
        )

    def test_incrementing_a_boolean_fails_and_leaves_the_boolean(self):
        source = '$x = $True\n$x++\nWrite-Output $x'
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output $True')

    @opportunity
    def test_a_read_after_a_failing_increment_of_a_boolean_folds_to_the_boolean(self):
        self.assertEqual(
            self._deobfuscate('$x = $true; $x++; Write-Output $x'), 'Write-Output $True'
        )


class TestPs1ASharedArrayIsOneOnlyBetweenTheAliasAndTheNextRebinding(TestPs1):

    def test_a_name_taken_before_the_reversal_observes_it(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertIn('Write-Output (3, 2, 1)', self._deobfuscate(source))

    def test_a_name_rebound_between_the_alias_and_the_reversal_holds_what_rebound_it(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            $y = 9, 9, 9
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertIn('Write-Output (9, 9, 9)', self._deobfuscate(source))

    def test_a_name_aliased_only_on_a_branch_that_may_not_run_is_not_answered(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = 7, 7, 7
            if ($env:A) {
              $y = $x
            }
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_name_aliased_after_the_reversal_keeps_the_order_it_was_handed(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = 4, 5, 6
            [Array]::Reverse($y)
            $y = $x
            Write-Output $x
        """)
        self.assertIn('Write-Output (1, 2, 3)', self._deobfuscate(source))

    def test_a_name_whose_source_was_rebound_before_the_reversal_keeps_its_array(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            $x = 9, 9, 9
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertIn('Write-Output (1, 2, 3)', self._deobfuscate(source))

    def test_a_reversal_through_a_third_name_is_seen_by_a_read_of_the_first(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            $z = $y
            [Array]::Reverse($z)
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output (3, 2, 1)')


class TestPs1AConversionThatAllocatesIsNotTheArrayItWasBuiltFrom(TestPs1):

    def test_a_reversal_through_an_int_array_cast_does_not_turn_the_variable_around(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse([int[]]$x)
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output (1, 2, 3)')

    def test_a_reversal_through_a_string_array_cast_does_not_turn_the_variable_around(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse([string[]]$x)
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output (1, 2, 3)')

    def test_a_reversal_through_a_char_array_cast_does_not_turn_the_variable_around(self):
        source = inspect.cleandoc("""
            $x = 'a', 'b', 'c'
            [Array]::Reverse([char[]]$x)
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(source, source, "Write-Output ('a', 'b', 'c')")

    def test_a_reversal_through_an_as_conversion_turns_the_variable_around(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x -As [array])
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output (3, 2, 1)')

    def test_a_name_taken_through_an_as_conversion_is_not_handed_the_arrays_value(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x -as [array]
            $x[0] = 9
            Write-Output $y[0]
        """)
        answered = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x -as [array]
            $x[0] = 9
            Write-Output 9
        """)
        self.assertIn(self._apply(source, Ps1ConstantInlining), (source, answered))

    def test_a_constrained_target_takes_a_copy_the_reversal_does_not_reach(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [int[]]$y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output (1, 2, 3)')


class TestPs1AConversionBetweenTwoNamesSharesInBothDirections(TestPs1):

    _SHARING = (
        '$y = [array]$x',
        '$y = $x -As [array]',
        '[array]$y = $x',
    )

    _COPYING = (
        '[int[]]$y = $x',
        '$y = [int[]]$x',
    )

    def _assertEachConversionLeavesTheReadOrAnswersItsOwnCase(self, tail: str, stored: str) -> None:
        for definitions, answer in (
            (self._SHARING, F'Write-Output ({stored})'),
            (self._COPYING, 'Write-Output (1, 2, 3)'),
        ):
            for definition in definitions:
                with self.subTest(definition):
                    source = F'$x = 1, 2, 3\n{definition}\n{tail}'
                    self._assertDeobfuscatesToOneOf(source, source, answer)

    def test_a_store_through_the_second_name_reaches_the_first_only_where_the_two_share(self):
        self._assertEachConversionLeavesTheReadOrAnswersItsOwnCase(
            '$y[0] = 9\nWrite-Output $x', '9, 2, 3'
        )

    def test_a_reversal_through_the_second_name_reaches_the_first_only_where_the_two_share(self):
        self._assertEachConversionLeavesTheReadOrAnswersItsOwnCase(
            '[Array]::Reverse($y)\nWrite-Output $x', '3, 2, 1'
        )

    def test_a_store_through_the_first_name_reaches_the_second_only_where_the_two_share(self):
        self._assertEachConversionLeavesTheReadOrAnswersItsOwnCase(
            '$x[0] = 9\nWrite-Output $y', '9, 2, 3'
        )

    def test_a_reversal_through_the_first_name_reaches_the_second_only_where_the_two_share(self):
        self._assertEachConversionLeavesTheReadOrAnswersItsOwnCase(
            '[Array]::Reverse($x)\nWrite-Output $y', '3, 2, 1'
        )


class TestPs1ACallWhoseMemberCannotBeNamedWritesEverySlotItIsHanded(TestPs1):

    def test_a_read_below_a_call_spelled_through_a_variable_is_not_answered_from_above(self):
        source = inspect.cleandoc("""
            $m = 'Reverse'
            $x = 1, 2, 3
            [Array]::$m($x)
            Write-Output $x[0]
        """)
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::'Reverse'($x)
            Write-Output $x[0]
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_the_read_is_answered_by_the_reversal_once_the_member_is_spelled_out(self):
        source = inspect.cleandoc("""
            $m = 'Reverse'
            $x = 1, 2, 3
            [Array]::$m($x)
            Write-Output $x[0]
        """)
        self.assertIn('Write-Output 3', self._deobfuscate(source))


class TestPs1APositionThatStoresTheObjectIsNotHandedACopyOfIt(TestPs1):

    def test_an_array_stored_under_a_hashtable_key_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $h = @{}
            $h['k'] = $x
            $x[0] = 9
            Write-Output $h['k'][0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')

    def test_an_array_stored_in_a_property_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $o = [pscustomobject]@{
              P = 0
            }
            $o.P = $x
            $x[0] = 9
            Write-Output $o.P[0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')

    def test_an_array_stored_in_an_element_of_another_array_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $a = 0, 0
            $a[0] = $x
            $x[0] = 9
            Write-Output $a[0][0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')

    def test_an_array_written_into_a_hashtable_literal_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $h = @{
              k = $x
            }
            $x[0] = 9
            Write-Output $h['k'][0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')

    def test_an_array_a_collection_retains_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $list = New-Object Collections.ArrayList
            [void]$list.Add($x)
            $x[0] = 9
            Write-Output $list[0][0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')

    def test_an_array_taken_by_one_target_of_a_multi_assignment_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $a, $b = $x, 9
            $x[0] = 9
            Write-Output $a[0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')

    def test_an_array_given_to_a_name_by_a_command_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            New-Variable y $x
            $x[0] = 9
            Write-Output $y[0]
        """)
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 9')


class TestPs1ACallFillingABufferArgumentDoesNotGetTheBuffersValue(TestPs1):

    def test_the_destination_of_a_block_copy_keeps_its_name_while_the_source_folds(self):
        source = inspect.cleandoc("""
            $s = 1, 2, 3
            $d = 0, 0, 0
            [Buffer]::BlockCopy($s, 0, $d, 0, 3)
            Write-Output $d
        """)
        expected = inspect.cleandoc("""
            $d = 0, 0, 0
            [Buffer]::BlockCopy((1, 2, 3), 0, $d, 0, 3)
            Write-Output $d
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_the_output_of_a_transform_keeps_its_name_while_the_input_folds(self):
        source = inspect.cleandoc("""
            $s = 1, 2, 3
            $o = 0, 0, 0
            $transform.TransformBlock($s, 0, 3, $o, 0)
            Write-Output $o
        """)
        expected = inspect.cleandoc("""
            $o = 0, 0, 0
            $transform.TransformBlock((1, 2, 3), 0, 3, $o, 0)
            Write-Output $o
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_the_output_of_an_encoding_at_five_arguments_keeps_its_name(self):
        source = inspect.cleandoc("""
            $c = 'a', 'b'
            $o = 0, 0
            [Text.Encoding]::ASCII.GetBytes($c, 0, 2, $o, 0)
            Write-Output $o
        """)
        expected = inspect.cleandoc("""
            $o = 0, 0
            [Text.Encoding]::ASCII.GetBytes(('a', 'b'), 0, 2, $o, 0)
            Write-Output $o
        """)
        self.assertEqual(self._apply(source, Ps1ConstantInlining), expected)

    def test_an_encoding_at_one_argument_fills_nothing_and_still_folds_what_it_is_handed(self):
        source = inspect.cleandoc("""
            $s = 'ab'
            Write-Output ([Text.Encoding]::ASCII.GetBytes($s))
        """)
        self.assertEqual(
            self._deobfuscate(source), "Write-Output ([Text.Encoding]::ASCII.GetBytes('ab'))")


class TestPs1ACallBindingNoOverloadRaisesRatherThanRunning(TestPs1):

    def test_a_reversal_at_an_arity_no_overload_takes_leaves_the_array_in_the_order_it_had(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x, 0)
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            '[Array]::Reverse((1, 2, 3), 0)\nWrite-Output (1, 2, 3)',
            'Write-Output (1, 2, 3)',
        )

    @opportunity
    def test_a_reversal_at_an_arity_no_overload_takes_is_removed_and_the_read_answered(self):
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc("""
                $x = 1, 2, 3
                [Array]::Reverse($x, 0)
                Write-Output $x
            """)),
            'Write-Output (1, 2, 3)',
        )

    def test_a_sort_at_an_arity_no_overload_takes_leaves_the_array_in_the_order_it_had(self):
        source = inspect.cleandoc("""
            $x = 3, 1, 2
            [Array]::Sort($x, 0, 1, 2, 3, 4)
            Write-Output $x
        """)
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            '[Array]::Sort((3, 1, 2), 0, 1, 2, 3, 4)\nWrite-Output (3, 1, 2)',
            'Write-Output (3, 1, 2)',
        )

    @opportunity
    def test_a_sort_at_an_arity_no_overload_takes_is_removed_and_the_read_answered(self):
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc("""
                $x = 3, 1, 2
                [Array]::Sort($x, 0, 1, 2, 3, 4)
                Write-Output $x
            """)),
            'Write-Output (3, 1, 2)',
        )


class TestPs1ComputingAReversalLeavesTheTreeItReadTheArrayFrom(TestPs1):

    def test_every_child_still_names_its_parent_where_a_reversal_answers_a_read(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x)
            Write-Output $x[0]
        """)
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x)
            Write-Output 3
        """)
        self._assertTreeIsIntact(source, expected, Ps1ConstantInlining)


class TestPs1ATypeSpelledTwoWaysIsOneConstraintOnTheVariable(TestPs1):

    def test_a_constraint_spelled_by_an_accelerator_and_by_its_full_name_is_one_constraint(self):
        source = inspect.cleandoc("""
            [string]$q = 5
            [System.String]$q = 'ab'
            Write-Output $q
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output 'ab'")

    def test_the_same_script_spelling_the_constraint_one_way_folds_to_the_same_value(self):
        source = inspect.cleandoc("""
            [string]$q = 5
            [string]$q = 'ab'
            Write-Output $q
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output 'ab'")


class TestPs1AValueNoStoreCanReachFoldsBesideAnObjectAStoreDoes(TestPs1):

    def test_a_string_folds_into_an_accumulation_beside_an_array_that_is_reversed(self):
        source = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $s = 'abc'
            $t = ''
            $t += $s
            Write-Output $t
        """)
        self.assertIn("Write-Output 'abc'", self._deobfuscate(source))

    def test_a_string_folds_into_a_hashtable_key_beside_an_array_that_is_reversed(self):
        source = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $s = 'abc'
            $h = @{ k = $s }
            Write-Output $h['k']
        """)
        result = self._deobfuscate(source)
        self.assertNotIn('$s', result)
        self.assertIn("'abc'", result)

    def test_a_string_folds_into_a_multi_assignment_slot_beside_an_array_that_is_reversed(self):
        source = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $s = 'abc'
            $u, $v = $s, 9
            Write-Output $u
        """)
        result = self._deobfuscate(source)
        self.assertNotIn('$s', result)
        self.assertIn("'abc'", result)

    def test_a_string_folds_into_a_hashtable_key_beside_an_array_an_element_is_written_of(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $x[0] = 9
            $h = @{ p = $PSHome }
            Write-Output $h
        """)
        self.assertIn(
            R"p = 'C:\Windows\System32\WindowsPowerShell\v1.0'", self._deobfuscate(source)
        )


class TestPs1AConstraintOnTheNameBeingReadLeavesTheArrayItHandsOver(TestPs1):

    def test_a_constraint_on_the_name_handing_the_array_over_leaves_the_reversal_answered(self):
        source = inspect.cleandoc("""
            [Object[]]$x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertIn('Write-Output (3, 2, 1)', self._deobfuscate(source))

    def test_a_constraint_on_the_name_taking_the_array_still_refuses_the_reversal(self):
        source = inspect.cleandoc("""
            [string]$y = 0
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertEqual(self._deobfuscate(source), source)
