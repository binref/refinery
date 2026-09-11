from __future__ import annotations

import inspect
import unittest

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

    def test_real_world_02(self):
        result = self._deobfuscate(
            '''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"))''', remove_junk=False)
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
        # String ordering is culture-dependent, so it is left untouched.
        self.assertEqual(self._apply("'a' -lt 'b'", Ps1ConstantFolding), "'a' -lt 'b'")

    def test_a_text_equality_no_reading_of_code_points_decides_is_left_alone(self):
        """
        Measured on Windows PowerShell 5.1, both of these are `$True`: the comparison is
        `CompareInfo.Compare` under the invariant culture, which expands the sharp s.
        """
        source = "'ß' -eq 'SS'"
        self.assertEqual(self._apply(source, Ps1ConstantFolding), source)
        insensitive = "'ß' -ieq 'ss'"
        self.assertEqual(self._apply(insensitive, Ps1ConstantFolding), insensitive)


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


class TestPs1ControlCharStringLiteral(TestPs1):

    def test_format_newline_only_produces_backtick_escape(self):
        code = '"{0}`n{1}" -f "hello","world"'
        result = self._deobfuscate(code)
        self.assertIn('`n', result)
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


class TestPs1StringMultiplicationFolding(TestPs1):

    def test_string_times_int(self):
        result = self._deobfuscate("'x' * 5")
        self.assertIn('xxxxx', result)
        self.assertNotIn('*', result)

    def test_int_times_string(self):
        # `int * string` is governed by the integer left operand, so PowerShell coerces the right
        # side to a number (here a runtime error) rather than repeating the string; it must not be
        # folded to 'ababab'.
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
        # `0xFF00` fills neither width, so it is the Int32 65280 and its complement is -65281.
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
    """
    5.1 converts the operand of `-bnot` and complements the bits at the width the conversion
    reached, which is not the operand's own type. Measured, `-bnot [byte]5` and `-bnot [char]65` are
    Int32 -6 and -66, `-bnot 1L` is Int64 -2, and `-bnot [uint32]7` is UInt32 4294967288 — the same
    bits as -8 and not the same number. So the value that comes back carries a type as much as a
    number, and the emitted literal has to spell both.
    """

    def test_a_narrow_integer_operand_widens_to_an_int32(self):
        self.assertEqual(self._apply('$x = -bnot [byte]5', Ps1ConstantFolding), '$x = -6')

    def test_a_long_operand_stays_a_long(self):
        self.assertEqual(self._apply('$x = -bnot 1L', Ps1ConstantFolding), '$x = -2L')

    def test_an_unsigned_operand_keeps_its_unsigned_width(self):
        self.assertEqual(
            self._apply('$x = -bnot [uint32]7', Ps1ConstantFolding), '$x = [uint32]4294967288')

    def test_an_operand_5_1_converts_to_a_number_is_complemented_at_the_number(self):
        # Measured: `[int]$null` is 0, `[int]$true` is 1, `[int]'5'` is 5, `[int][char]65` is 65,
        # `[int]1.5` is 2 and `[int]10d` is 10, and each complement below is that number's.
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
        # Measured, `-bnot 'abc'` throws where `-bnot '5'` is -6.
        self._assertUnchanged("$x = -bnot 'abc'", Ps1ConstantFolding)

    def test_a_real_whose_width_no_measurement_covers_is_left_where_it_stands(self):
        """
        Measured, `-bnot 1.5` is an Int32 -3 and `-bnot 3000000000.0` is a UInt32 1294967295: the
        width follows the magnitude, so an answer keyed on the operand being a Double would be
        -3000000001 under a type 5.1 never produced here.
        """
        self._assertUnchanged('$x = -bnot 3000000000.0', Ps1ConstantFolding)


class TestPs1AHexadecimalLiteralIsNegativeWhereverItsNumberIsRead(TestPs1):
    """
    `0xFFFFFFFF` is the Int32 -1 on 5.1 and not the magnitude its eight digits spell, measured. Each
    site below reads a number out of a literal, so each is a place where the same eight digits are
    one script under the value and a different script under the digits — and where reading the
    digits would have been off by 4294967296.

    Each assertion pairs the answer 5.1 gives for -1 at that site with the site itself.
    """

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
        """
        The two spellings below name the same eight digits and print differently: .NET writes the
        Int32 -1 as `-001` under `D3` and the Int64 4294967295 as its ten digits, which is what the
        magnitude reading of `0xFFFFFFFF` would have produced.
        """
        self.assertEqual(
            self._apply("$x = '{0:D3}' -f 0xFFFFFFFF", Ps1ConstantFolding), "$x = '-001'")
        self.assertEqual(
            self._apply("$x = '{0:D3}' -f 4294967295", Ps1ConstantFolding), "$x = '4294967295'")

    def test_a_loop_whose_bound_is_the_negative_number_never_runs(self):
        """
        `0 -lt 0xFFFFFFFF` is `0 -lt -1`, which is false, so the body never runs and the whole
        script is the initializer. Written in decimal the same eight digits are a positive Int64 and
        the loop runs, which is why the two are asserted together.
        """
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
    """
    A negative number reaches these sites as an argument 5.1 refuses: a Char has no code point -1,
    a conversion has no base -16, an array offset of -1 is out of range, and a Byte cannot hold -1 —
    measured, `[byte]-1` throws. Each expression therefore terminates the script where it stands,
    and there is no value for a fold to put in its place.
    """

    def test_a_character_code_no_char_holds_is_not_folded(self):
        self._assertUnchanged('$x = [Convert]::ToChar(0xFFFFFFFF)', Ps1ConstantFolding)

    def test_a_conversion_base_no_conversion_accepts_is_not_folded(self):
        # `0xFFFFFFF0` is the Int32 -16, which is not base 16 and is no base at all.
        self._assertUnchanged("$x = [Convert]::ToInt32('11', 0xFFFFFFF0)", Ps1ConstantFolding)

    def test_a_number_no_byte_holds_is_not_folded_into_a_byte_array(self):
        self._assertUnchanged('$x = [BitConverter]::ToString(@(0xFFFFFFFF))', Ps1ConstantFolding)

    def test_an_offset_outside_the_array_is_not_folded(self):
        self._assertUnchanged(
            '$x = [BitConverter]::ToString(@(0x41, 0x42, 0x43, 0x44), 0xFFFFFFFF, 2)',
            Ps1ConstantFolding,
        )


class TestPs1AValueThatIsNoIntegerIsNotReadAsOne(TestPs1):
    """
    5.1 reaches a number from each of these by converting, and the conversion has a rule of its own:
    measured, `[int]1.5` is 2 and `[int]2.5` is 2, so it rounds half to even rather than truncating,
    and `[int]'5'` parses text. None of that is what the value *is*, so a site reading an integer
    declines and leaves the expression alone.

    What each assertion rules out is the other answer: a repeat count truncated from 1.5 to 1 would
    emit `'ab'` where 5.1 writes `abab`, and an index truncated from 1.5 to 1 would select 20 where
    5.1 selects 30.
    """

    def test_a_real_repeat_count_is_not_truncated_to_a_whole_one(self):
        self._assertUnchanged("$x = 'ab' * 1.5", Ps1ConstantFolding)

    def test_a_real_index_is_not_truncated_to_a_whole_one(self):
        self._assertUnchanged('$x = @(10, 20, 30)[1.5]', Ps1ConstantFolding)

    def test_a_real_byte_is_not_truncated_to_a_whole_one(self):
        self._assertUnchanged('$x = [BitConverter]::ToString(@(1.5))', Ps1ConstantFolding)

    def test_a_real_conversion_base_is_not_truncated_to_a_whole_one(self):
        self._assertUnchanged("$x = [Convert]::ToInt32('41', 16.0)", Ps1ConstantFolding)

    def test_a_repeat_count_of_a_type_that_holds_no_width_is_left_alone(self):
        # 5.1 writes '', `ab` and `ababab` for these three, so declining costs those three folds
        # and is the only answer that cannot invent a fourth.
        self._assertUnchanged("$x = 'ab' * $null", Ps1ConstantFolding)
        self._assertUnchanged("$x = 'ab' * $true", Ps1ConstantFolding)
        self._assertUnchanged("$x = 'ab' * '3'", Ps1ConstantFolding)


class TestPs1ReplicatingAStringANegativeNumberOfTimes(TestPs1):
    """
    Measured, `'ab' * 0xFFFFFFFF` throws `System.ArgumentOutOfRangeException` and the script writes
    nothing: 5.1 replicates a string zero or more times and refuses a negative count outright. A
    fold that answered the empty string would produce a value the input never had, so a `catch`
    around the line would run in the input and not in the output.
    """

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

    def test_existing_basic_format(self):
        result = self._deobfuscate('"{0}{2}{1}" -f "signa","ures","t"')
        self.assertIn('signatures', result)

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
        result = self._deobfuscate("@{'x'=42}['x']")
        self.assertIn('42', result)

    def test_missing_key_not_folded(self):
        result = self._deobfuscate("@{'a'='hello'}['b']")
        self.assertIn('@{', result)


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
        # `-shl`/`-shr` fold with .NET Int32 wraparound and shift-count masking.
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
        # .NET numbers unnamed groups first and named ones after; Python strictly by position. A
        # numeric reference then resolves to a different group in each, so `(?<n>a)(b)` with `$1` is
        # `b` on 5.1 and would fold to `a`. The mixed pattern is left for the engine to refuse.
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
        # `[Int]'abc'` terminates where it stands, so the input runs the handler and a folded
        # output cannot: the payload path would be dead code. Purity does not answer this — the
        # cast is side-effect free and still raises.
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
        # PowerShell rejects a bare subexpression key, so this is the spelling that reaches here.
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
        # A string is a value and not a container of expressions, so the characters this does not
        # select are not work the folded script stops doing and no gate applies to them. The array
        # of the same shape one line up is refused.
        self.assertEqual(self._apply("$r = 'abc'[0]", Ps1ConstantFolding), '$r = [char]97')


class TestPs1ConstantInliningSelectsOnlyFromConstants(TestPs1):
    """
    `Ps1ConstantInlining` selects out of a container too, and the claim that it needs no gate is
    that its containers are already proven constant. These pin the claim rather than the gate.
    """

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
            self._apply("$a = 'abc'\n$r = $a[0]", Ps1ConstantInlining), "$r = 'a'")


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

    def test_a_repeated_index_into_an_array_is_not_folded(self):
        # Folding would put the array's own node in two slots of the result, where `Node.parent`
        # holds one holder: a later replacement rewrites one occurrence of two and a walk counts it
        # twice. Copying it would run whatever it holds twice instead.
        self._assertUnchanged('$r = @(1, 2, 3)[0, 0]', Ps1ConstantFolding)

    def test_a_repeated_index_reached_through_a_negative_one_is_not_folded_either(self):
        self._assertUnchanged('$r = @(1, 2, 3)[0, -3]', Ps1ConstantFolding)

    def test_distinct_indices_into_the_same_array_still_select(self):
        self.assertEqual(self._apply('$r = @(1, 2, 3)[2, 0]', Ps1ConstantFolding), '$r = 3, 1')

    def test_a_repeated_index_into_a_string_still_folds(self):
        # A character is built fresh per index out of a value that was never a node, so nothing is
        # shared and the shape obfuscators actually write keeps working.
        self.assertEqual(
            self._apply("$r = 'abc'[0, 0, 1]", Ps1ConstantFolding),
            '$r = [char]97, [char]97, [char]98')


class TestPs1ACallWritingThroughAnArgumentIsAWriteOfThatVariable(TestPs1):
    """
    `[Array]::Reverse($x)` turns around the very array `$x` holds and returns nothing, so that
    occurrence of `$x` is a write of `$x`: it may not be replaced by the array's value, reads above
    it still see the order the assignment built, and reads below it see the order the call left.
    """

    def test_the_written_argument_still_names_the_variable_below_a_folded_read(self):
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output $x[0]', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output 3')

    def test_a_read_above_the_reversal_sees_the_order_the_assignment_built(self):
        # 5.1 prints 1 and then 3: the first read runs before the reversal does.
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

    def test_no_pass_of_the_whole_deobfuscation_replaces_the_written_argument(self):
        self.assertEqual(
            self._deobfuscate('$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output $x'),
            '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)')

    def test_a_reversal_of_a_variable_nothing_assigned_is_not_answered(self):
        self._assertUnchanged('[Array]::Reverse($x)\nWrite-Output $x', Ps1ConstantInlining)

    def test_an_element_written_before_the_reversal_is_not_answered(self):
        # 5.1 leaves `3`, `2` and `9`: the element write lands before the reversal, so it moves to
        # the far end. Declining is the conservative answer; `Write-Output (3, 2, 9)` would be the
        # complete one, and `Write-Output (3, 2, 1)` would be wrong.
        self._assertUnchanged(
            '$x = 1, 2, 3\n$x[0] = 9\n[Array]::Reverse($x)\nWrite-Output $x', Ps1ConstantInlining)

    def test_a_reversal_reached_through_an_array_element_is_not_answered(self):
        # 5.1 prints `2` and then `1`: the call reverses the inner array that `$p[0]` selects.
        self._assertUnchanged(
            '$p = @(@(1, 2), @(3, 4))\n[Array]::Reverse($p[0])\nWrite-Output $p[0]',
            Ps1ConstantInlining)

    def test_a_read_below_a_sort_sees_the_order_the_call_left(self):
        # 5.1 prints `1`: `[Array]::Sort` reorders the array the variable holds, so the read below
        # sees the sorted order and never the `3` the assignment put first. The slot stays a write:
        # the occurrence in the call is not replaced by the array's value.
        self.assertEqual(
            self._apply(
                '$x = 3, 1, 2\n[Array]::Sort($x)\nWrite-Output $x[0]', Ps1ConstantInlining),
            '$x = 3, 1, 2\n[Array]::Sort($x)\nWrite-Output 1')

    def test_a_reversal_under_a_condition_that_is_not_known_is_not_answered(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\nif ($env:C) {\n  [Array]::Reverse($x)\n}\nWrite-Output $x',
            Ps1ConstantInlining)

    def test_a_reversal_inside_a_function_the_script_calls_is_not_answered(self):
        # 5.1 prints `3`, `2` and `1`: the body writes the caller's `$x`.
        self._assertUnchanged(
            'function f {\n  [Array]::Reverse($x)\n}\n$x = 1, 2, 3\nf\nWrite-Output $x',
            Ps1ConstantInlining)


class TestPs1AReverseIsComputedWhereItsEffectIsKnownAndTotal(TestPs1):
    """
    Where the reversal covers the whole array, or a range that fits inside it, the array the call
    leaves behind is computed and answers the reads below it. A range that does not fit throws
    instead of reversing, and a bound that is not a known number is no range at all.
    """

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
        # An index one past the last element with a length of zero is the boundary that fits: what
        # has to be inside the array is `index + length`, not `index`.
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n[Array]::Reverse($x, 3, 0)\nWrite-Output $x', Ps1ConstantInlining),
            '$x = 1, 2, 3\n[Array]::Reverse($x, 3, 0)\nWrite-Output (1, 2, 3)')

    def test_a_range_that_does_not_fit_inside_the_array_is_not_answered(self):
        # 5.1 writes an error record and leaves `1`, `2` and `3`: the call throws where the range
        # runs past the end, so nothing is reversed.
        self._assertUnchanged(
            '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 99)\nWrite-Output $x', Ps1ConstantInlining)

    def test_a_range_whose_length_is_not_a_known_number_is_not_answered(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\n[Array]::Reverse($x, 0, $n)\nWrite-Output $x', Ps1ConstantInlining)

    def test_reversing_a_string_does_not_reverse_the_string(self):
        # 5.1 prints `abc`: a String bound to the `System.Array` parameter is converted to a fresh
        # one-element `object[]`, and that copy is what gets reversed and discarded.
        self._assertUnchanged(
            "$s = 'abc'\n[Array]::Reverse($s)\nWrite-Output $s", Ps1ConstantInlining)


class TestPs1AnArrayReachedByTwoNamesIsWrittenThroughEither(TestPs1):
    """
    `$y = $x` gives one array two names rather than two arrays, so a call writing through either
    name is a write the other name's reads observe. Replacing the bare `$x` in `$y = $x` with the
    array's value would turn that share into a copy, which no later write would reach.
    """

    def test_a_reversal_through_one_name_is_seen_by_a_read_of_the_other(self):
        # 5.1 prints `3`, `2` and `1`.
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output $y',
                Ps1ConstantInlining),
            '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)')

    def test_the_share_survives_a_read_of_it_that_cannot_be_answered(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output $y[$env:I]',
            Ps1ConstantInlining)

    def test_a_reversal_through_the_second_name_is_not_answered_for_the_first(self):
        # 5.1 prints `3`, `2` and `1`: `$y` and `$x` name the same array either way round.
        self._assertUnchanged(
            '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($y)\nWrite-Output $x', Ps1ConstantInlining)

    def test_an_element_written_through_the_second_name_is_not_answered_for_the_first(self):
        # 5.1 prints `9`, `2` and `3`.
        self._assertUnchanged(
            '$x = 1, 2, 3\n$y = $x\n$y[0] = 9\nWrite-Output $x', Ps1ConstantInlining)

    def test_rebinding_one_name_does_not_change_the_array_the_other_holds(self):
        # 5.1 prints `1`, `2` and `3`: the third statement rebinds `$x` rather than writing to the
        # array. Nothing writes through this array, so copying it into `$y` is faithful here.
        self.assertEqual(
            self._apply(
                '$x = 1, 2, 3\n$y = $x\n$x = 9, 9, 9\nWrite-Output $y', Ps1ConstantInlining),
            '$y = (1, 2, 3)\nWrite-Output $y')


class TestPs1AMethodFoldsOnlyWhereItsReceiverCarriesTheOverload(TestPs1):
    """
    5.1 looks an instance method up on the receiver's own .NET type. `System.Char` carries a
    `ToUpper`, but every overload of it is static, so `([char]65).ToUpper()` reports
    `MethodNotFound` and stops the script; `Substring` belongs to `System.String` and is not on a
    Char at all. `ToString` is the one no-argument instance overload a Char does carry.
    """

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
    """
    `ToString()` writes a value the way the host's culture does and `[string]` does not. Measured on
    a host whose decimal separator is a comma, `(1.50d).ToString()` is `1,50` where `[string]1.50d`
    is `1.50`, and `(1.5).ToString()` is `1,5`. What the script produces there depends on where it
    runs, so only a value of a type that carries no culture can be written out.
    """

    def test_a_decimal_written_by_its_own_to_string_is_not_folded(self):
        # A second point cannot continue a numeral, so 5.1 reads the member access here and
        # `1.50d.ToString()` runs where `5.ToString()` is a parse error.
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
    """
    An argument reaches a method as the parameter's declared type. Measured,
    `'abc'.Substring([char]1)` is `bc`: the Char binds to an `Int32` and arrives as its code point,
    where the character it writes is a control character and no offset at all. A String that binds
    to a `char[]` arrives as its characters, so `'a,b;c'.Split(',;')` is three parts and not two.
    """

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
    """
    Where a method binds a parameter, an operator converts, and `-replace`, `-split` and `-join`
    convert to String. Measured, `'x' -replace 'x', [char]65` is `A`, `('a', 'b') -join 5` is `a5b`,
    `-join (72, 105)` is `72105`, `'a,b' -split [char]44` splits at the comma,
    `[char]65 -replace 'A', 'B'` is `B` and `$true -replace 'T', 'X'` is `Xrue`.
    """

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
    """
    `-match`, `-like`, `-replace`, `-split` and `-join` read every operand as the text it converts
    to, so a constant operand of one of them says the same thing written as that text even where
    the operator itself cannot be folded: `$x -match [char]12499` and `$x -match 'ビ'` are one
    question.

    `-eq` and `-f` are not of that kind. A comparison is decided by the type of its left operand,
    `[char]65 -eq 65` being True where `'A' -eq 65` is a different question, and what an operand
    contributes to a format is decided by the specifier, `'{0:X}' -f 65` being `41` where
    `'{0:X}' -f '65'` is `65`.
    """

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
    """
    Measured, `@{ a = 1 }[[char]97]` is `$null` where `@{ a = 1 }['A']` is 1: two Strings hash
    without regard to case and a Char is no String at all. A number carries its width the same way,
    `@{ 1 = 'x' }['1']` and `@{ 1 = 'x' }[1L]` both being `$null` where `@{ 1 = 'x' }[1]` is `x`.
    """

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
    """
    `[Convert]::ToInt32` is neither the cast nor Python's own parser. Measured, it throws for
    `'0x10'` where `[int]'0x10'` is 16, and it throws for `'1_0'`, `'0b1010'`, `'7.5'`, `'1e3'`,
    `'1,000'` and for the empty string, each of which one of the other two reads. What it does read
    is a whole decimal number, with a sign and with whitespace around it if either is there.
    """

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
    """
    With a base other than ten the digits are a bit pattern that fills the target the method names.
    Measured, `[Convert]::ToInt32('FFFFFFFF', 16)` is -1, `[Convert]::ToInt32('80000000', 16)` is
    -2147483648 and `[Convert]::ToByte('FF', 16)` is the Byte 255. A sign is refused there, and so
    is whitespace, and a `0x` prefix is read by base sixteen and by no other.
    """

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
    """
    Only a String reaches `[Convert]` through a parser of its own. Every other source is converted
    the way the cast to the same target converts it, so a real is rounded half to even and the
    absent value is zero, and the answer carries the type the method's name promised.
    """

    def test_a_real_reaches_an_integer_target_by_rounding_half_to_even(self):
        self.assertEqual(self._apply('$x = [Convert]::ToInt32(1.5)', Ps1ConstantFolding), '$x = 2')
        self.assertEqual(self._apply('$x = [Convert]::ToInt32(2.5)', Ps1ConstantFolding), '$x = 2')

    def test_the_absent_value_reaches_an_integer_target_as_zero(self):
        self.assertEqual(
            self._apply('$x = [Convert]::ToInt32($null)', Ps1ConstantFolding), '$x = 0')

    def test_a_number_reaches_a_wider_target_as_a_value_of_that_width(self):
        self.assertEqual(self._apply('$x = [Convert]::ToInt64(5)', Ps1ConstantFolding), '$x = 5L')


class TestPs1AChainOfAppendsIsNotReassociated(TestPs1):
    """
    `+` is left-associative and its left operand decides what it does, so the two groupings are not
    the same program: measured with `$x = @(1)`, `($x + 'a') + 'b'` holds three elements where
    `$x + 'ab'` holds two. Joining the two constants is only sound where the left operand is known,
    which a variable the script pins nothing about is not.
    """

    def test_a_chain_of_appends_to_an_unknown_left_operand_is_left_alone(self):
        self._assertUnchanged("$y = $x + 'a' + 'b'", Ps1ConstantFolding)

    def test_a_chain_of_appends_to_a_literal_collection_keeps_every_element(self):
        self.assertEqual(self._apply("$y = ,1 + 'a' + 'b'", Ps1ConstantFolding), "$y = 1, 'a', 'b'")

    def test_a_chain_of_appends_to_a_literal_string_is_the_text_of_all_three(self):
        self.assertEqual(self._apply("$y = 'a' + 'b' + 'c'", Ps1ConstantFolding), "$y = 'abc'")


class TestPs1AppendingToALiteralCollectionKeepsWhatWasAppended(TestPs1):
    """
    Measured, `1, 2 + [char]65` is a three-element array whose last element is a `System.Char`: the
    comma binds tighter than the `+`, and an element that arrived as a Char is not one a later read
    of the array finds as a String. `@(1, 2) + [char]65` is that same array.
    """

    def test_a_char_appended_to_a_literal_collection_is_still_a_char(self):
        self.assertEqual(
            self._apply('$x = 1, 2 + [char]65', Ps1ConstantFolding), '$x = 1, 2, [char]65')

    def test_a_string_appended_to_a_literal_collection_is_still_a_string(self):
        self.assertEqual(self._apply("$x = 1, 2 + 'A'", Ps1ConstantFolding), "$x = 1, 2, 'A'")

    def test_a_char_appended_through_the_array_operator_is_still_a_char(self):
        self.assertEqual(
            self._apply('$x = @(1, 2) + [char]65', Ps1ConstantFolding), '$x = 1, 2, [char]65')


class TestPs1RepeatingACollectionByACountNoInt32Holds(TestPs1):
    """
    A repeat count is converted to an `Int32` before anything is repeated, so 5.1 refuses a count
    that does not fit one however little the repetition would come to: measured,
    `@() * [uint64]18446744073709551615` throws `InvalidCastIConvertible` where `@() * 5000` is the
    empty collection. An empty left operand therefore folds to nothing rather than to `@()`, which
    is a value the script it was folded out of never reaches.
    """

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
    """
    A String or a Char on the left of `+` makes it join, whatever stands on the right of it, and the
    join folds wherever the text each side contributes is one this module writes. Measured, `'5' + 5`
    is `55`, `'a' + 1.5` is `a1.5` and `[char]65 + 1` is `A1`: a left operand that happens to spell a
    number is still text and the join is still a join. A Double on the right contributes its invariant
    `[string]` text, which is written rather than folded as the arithmetic `'5' + 1.5` would misread —
    the Double `6.5`, neither the value nor the type a run of the script produces.
    """

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
    """
    Where a call turns around, orders or empties an array whose elements are all known, the array it
    leaves behind is determined and the reads below it can be answered. Measured on 5.1, the three
    scripts here print `2` and `1`, then `a`, then an empty line and `2` and `3`.

    The sort and the clear are answered; only the reversal reached through an element is still a
    refusal rather than a wrong answer: the emitted script is the input. Its entry is marked so that
    a rule taking that fold reports an unexpected success, and so that it cannot quietly stop being
    true meanwhile.
    """

    @unittest.expectedFailure
    def test_a_reversal_reached_through_an_array_element_is_computed_for_that_element(self):
        # The call reaches part of what `$p` holds, so what `$p` holds afterwards is the outer array
        # with its first element replaced by the reversal of that element.
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
        # `[Array]::Sort` throws where the elements do not compare, so a value for it rests on the
        # elements being of one type and not merely on all of them being known. Chars compare by
        # code point, ordinally, so the order does not depend on the host's culture.
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
    """
    `[Array]::Sort($x)` reorders in place the array `$x` holds, so a read below it sees the sorted
    order. It is answered only for the whole-array form over elements that share one type whose order
    is ordinal and so culture-independent: numbers by magnitude, a Char by its code point, a Boolean
    with `$false` before `$true`. A String array is refused, since `[Array]::Sort` compares strings by
    the current culture and the emitted script's culture is not knowable here — measured, `aa` sorts
    before `z` under en-US and after it under da-DK. A cross-type array throws, an unreadable element
    leaves the order unknown, a comparer or a range is a form with no rule here, and elements that
    compare equal are left in an order .NET does not fix.
    """

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

    def test_a_range_form_has_no_rule(self):
        self._assertUnchanged(
            '$x = 1, 2, 3\n[Array]::Sort($x, 0, 2)\nWrite-Output $x', Ps1ConstantInlining)

    def test_an_empty_array_is_left_alone(self):
        self._assertUnchanged(
            '$x = @()\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining)

    def test_decimals_of_one_value_and_different_scale_are_not_ordered(self):
        self._assertUnchanged(
            '$x = @(1.0d, 1.00d)\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining)

    def test_a_repeated_value_is_not_ordered(self):
        self._assertUnchanged(
            '$x = @(1, 1)\n[Array]::Sort($x)\nWrite-Output $x', Ps1ConstantInlining)


class TestPs1AMutatingCallAndItsStoreGoWhereNoReadObservesThem(TestPs1):
    """
    Measured on 5.1, this script prints `3`, `2` and `1`, and so does the one line it could be
    folded to. The store feeds nothing but the reversal and the reversal writes an array that no
    read below it names, so both are work the emitted script can stop doing.

    The value is folded today and the two statements that produced it are kept, so the entry is
    marked. The class above pins that the read is answered at all; this pins what is left standing.
    """

    @unittest.expectedFailure
    def test_a_store_and_the_reversal_of_it_are_dropped_below_a_folded_read(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x)
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output (3, 2, 1)')


class TestPs1AConstraintOnAVariableConvertsWhatIsWrittenToIt(TestPs1):
    """
    `[string]$q = 5` constrains the variable rather than that one assignment, so the value a write
    leaves under `$q` is converted to the constrained type. Measured on 5.1, `[string]$q = 5` leaves
    the String `5`, `$q += 'a'` accumulates the String `5a` from it, and `$q = 1, 2, 3` leaves the
    String `1 2 3` whose `Length` is 5.

    The declaring write is answered — the cast that installs the constraint is the cast that converts
    the value stored there — and the compound write follows from it. A plain later write to a
    collection stays marked: a plain write is not where the constraint settles without an ordering
    the model does not carry, and a collection to a String is a conversion the value domain refuses
    because it needs the session's `$OFS`.
    """

    def test_a_declaring_write_stores_the_converted_scalar(self):
        self.assertEqual(
            self._deobfuscate('[string]$q = 5\nWrite-Output $q'), "Write-Output '5'")

    def test_a_declaring_write_parses_a_string_to_its_constrained_number(self):
        self.assertEqual(
            self._deobfuscate("[int]$n = '5'\nWrite-Output ($n + 1)"), 'Write-Output 6')

    def test_a_compound_write_to_a_constrained_variable_arrives_as_the_constrained_type(self):
        # The comma keeps the one object it wraps, so what 5.1 writes there is the String itself
        # and not the elements a collection would have been unrolled into.
        source = inspect.cleandoc("""
            [string]$q = 5
            $q += 'a'
            Write-Output (,$q)
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output (,'5a')")

    @unittest.expectedFailure
    def test_a_later_write_to_a_constrained_variable_arrives_as_the_constrained_type(self):
        source = inspect.cleandoc("""
            [string]$q = 5
            $q = 1, 2, 3
            Write-Output $q.Length
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output 5')


class TestPs1AScopeQualifierNamesTheBindingItsBareSpellingNames(TestPs1):
    """
    At script scope `$x`, `$script:x` and `$global:x` are one variable, so a value written under any
    of the three spellings is the value a read under any other observes. What 5.1 writes for each of
    these four scripts is measured in `corpus.CLAIMS`: `b`, `b`, `x`, `x`.

    A value written under a qualifier is observed by a bare read of the name. A read spelled *with*
    a qualifier is still withheld and folds nothing (the three xfails here): a qualified read is
    filed against no occurrence of the name. `$env:` is the one qualifier whose reads are folded,
    which the environment-variable test is the control for.
    """

    def test_an_environment_variable_is_folded_through_its_qualifier(self):
        self.assertEqual(
            self._deobfuscate("$env:z = 'v'; Write-Output $env:z"), "Write-Output 'v'")

    def test_a_bare_read_observes_what_the_qualified_spelling_wrote(self):
        self.assertEqual(
            self._deobfuscate("$script:s = 'x'; Write-Output $s"), "Write-Output 'x'")

    @unittest.expectedFailure
    def test_a_read_of_a_script_qualified_name_is_the_value_written_under_it(self):
        self.assertEqual(
            self._deobfuscate("$script:y = 'b'; Write-Output $script:y"), "Write-Output 'b'")

    @unittest.expectedFailure
    def test_a_read_of_a_global_qualified_name_is_the_value_written_under_it(self):
        self.assertEqual(
            self._deobfuscate("$global:y = 'b'; Write-Output $global:y"), "Write-Output 'b'")

    @unittest.expectedFailure
    def test_a_qualified_read_observes_what_the_bare_spelling_wrote(self):
        self.assertEqual(
            self._deobfuscate("$s = 'x'; Write-Output $script:s"), "Write-Output 'x'")


class TestPs1AnOperatorOverANameWrittenUnderAQualifierFoldsAsIfItWereNull(TestPs1):
    """
    A value written under `$script:` or `$global:` is the value a bare read of the name observes, so
    an operator over that bare read folds to it and not to `$null`. Measured on 5.1, the three
    scripts here write `6`, `165` and `12`. The `-bxor` row is the soundness case: a decode key held
    in a module-scoped variable, folded as `$null`, would hand back plaintext that never ran.

    The recall half — a read spelled *with* a qualifier — is still open; the class above pins it.
    """

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
    """
    `$x op= e` stores what `$x = $x op e` stores, and the long spelling is folded today while the
    short one is not: `$s = 'a'; $s = $s + 'b'; Write-Output $s` comes back as `Write-Output 'ab'`
    and `$s = 'a'; $s += 'b'; Write-Output $s` comes back as it was written. What 5.1 writes for
    each of these scripts is measured in `corpus.CLAIMS`: `3`, `abc`, `2`, `3` and `5`.
    """

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
    """
    `$x++` and `$x--` are not the binary `$x + 1` and `$x - 1` their long spelling would be: 5.1 adds
    the delta to `$null` and to any numeric value, but throws `OperatorRequiresNumber` for a String,
    a Char, a Boolean or a collection — where the binary `+` concatenates a String and reads a
    Boolean as an integer instead. So the increment folds only where the operand is a number, and
    stands no value where 5.1 raised rather than computing a sum the operator never reaches.
    """

    def test_incrementing_a_number_is_the_next_one(self):
        self.assertEqual(self._deobfuscate('$x = 5; $x++; Write-Output $x'), 'Write-Output 6')

    def test_decrementing_a_number_is_the_previous_one(self):
        self.assertEqual(self._deobfuscate('$x = 5; $x--; Write-Output $x'), 'Write-Output 4')

    def test_incrementing_null_is_one(self):
        self.assertEqual(self._deobfuscate('$x = $null; $x++; Write-Output $x'), 'Write-Output 1')

    def test_incrementing_a_string_is_not_folded_to_a_concatenation(self):
        self.assertEqual(
            self._deobfuscate('$x = "5"; $x++; Write-Output $x'),
            '$x = "5"\n$x++\nWrite-Output $x')

    def test_incrementing_a_char_is_not_folded(self):
        self.assertEqual(
            self._deobfuscate('$x = [char]65; $x++; Write-Output $x'),
            '$x = [char]65\n$x++\nWrite-Output $x')

    def test_incrementing_a_boolean_is_not_folded_to_the_sum_of_its_integer(self):
        self.assertEqual(
            self._deobfuscate('$x = $true; $x++; Write-Output $x'),
            '$x = $True\n$x++\nWrite-Output $x')


class TestPs1ASharedArrayIsOneOnlyBetweenTheAliasAndTheNextRebinding(TestPs1):
    """
    `$y = $x` gives one array a second name rather than a copy, so `[Array]::Reverse($x)` is a write
    that a read of `$y` below it observes. The share runs from the definition that made it to the
    next rebinding of either name, and a name aliased after the reversal, or only on a branch that
    does not run, was never on the array the call turned around at all.

    Measured on 5.1, the six scripts here write `3 2 1`, `9 9 9`, `7 7 7`, `1 2 3`, `1 2 3` and
    `3 2 1`. Three of them are refused rather than answered, and what none of them may do is report
    the reversal of an array the name being read had already stopped holding.
    """

    def test_a_name_taken_before_the_reversal_observes_it(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output (3, 2, 1)
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_name_rebound_between_the_alias_and_the_reversal_holds_what_rebound_it(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            $y = 9, 9, 9
            [Array]::Reverse($x)
            Write-Output $y
        """)
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x)
            Write-Output (9, 9, 9)
        """)
        self.assertEqual(self._deobfuscate(source), expected)

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
        expected = inspect.cleandoc("""
            $y = 4, 5, 6
            [Array]::Reverse($y)
            Write-Output (1, 2, 3)
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_name_whose_source_was_rebound_before_the_reversal_is_not_answered(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            $x = 9, 9, 9
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_reversal_through_a_third_name_is_not_answered_with_the_order_from_above(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            $z = $y
            [Array]::Reverse($z)
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1AConversionThatAllocatesIsNotTheArrayItWasBuiltFrom(TestPs1):
    """
    A conversion standing between a name and a slot may hand the callee a fresh array built out of
    what the name holds rather than the array itself, and which of the two it is depends on the
    operand's runtime type. Measured on 5.1, `[Array]::Reverse([int[]]$x)` over an `Object[]` turns
    around a temporary and leaves `$x` writing `1 2 3`, as do `[string[]]` over the same array and
    `[char[]]` over `'a','b','c'`; `[int[]]$y = $x` converts on the way in, so a reversal through
    `$x` leaves `$y` writing `1 2 3` as well.

    `-as` is the same question and the opposite answer: a value already of the target type is
    converted by nothing, so `[Array]::Reverse($x -As [array])` turns `$x` itself around and writes
    `3 2 1`. The spelling settles neither case, so no value may be installed where the name stands
    and none may be computed for what the call left behind.
    """

    def test_a_reversal_through_an_int_array_cast_is_not_answered(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse([int[]]$x)
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_reversal_through_a_string_array_cast_is_not_answered(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse([string[]]$x)
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_reversal_through_a_char_array_cast_is_not_answered(self):
        source = inspect.cleandoc("""
            $x = 'a', 'b', 'c'
            [Array]::Reverse([char[]]$x)
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_reversal_through_an_as_conversion_is_not_answered(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x -As [array])
            Write-Output $x
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_name_taken_through_an_as_conversion_is_not_handed_the_arrays_value(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x -as [array]
            $x[0] = 9
            Write-Output $y[0]
        """)
        self._assertUnchanged(source, Ps1ConstantInlining)

    def test_a_constrained_target_takes_a_copy_the_reversal_does_not_reach(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [int[]]$y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1AConversionBetweenTwoNamesSharesInBothDirections(TestPs1):
    """
    `[array]$x` over an `Object[]`, `$x -as [array]` and an `[array]` constraint on the target each
    convert nothing, so the two names are left on the one array and a store through either is one a
    read of the other observes. Measured on 5.1 over `$x = 1, 2, 3`, each of `$y = [array]$x`,
    `$y = $x -As [array]` and `[array]$y = $x` makes `$y[0] = 9; Write-Output $x` write `9 2 3`,
    `[Array]::Reverse($y); Write-Output $x` write `3 2 1`, and `$x[0] = 9; Write-Output $y` write
    `9 2 3`.

    Whether a conversion allocates is a question about the operand's runtime type, and nothing that
    reads the source can answer it, so `[int[]]` is covered by the one rule from the other side:
    `[int[]]$y = $x` does build a new array, and `[Array]::Reverse($x); Write-Output $y` writes
    `1 2 3` there. Both are therefore refused, in both directions, and what neither may do is answer
    a read with the array as it stood before the store.
    """

    _DEFINITIONS = (
        '$y = [array]$x',
        '$y = $x -As [array]',
        '[array]$y = $x',
        '[int[]]$y = $x',
        '$y = [int[]]$x',
    )

    def _assertNoConversionAnswersTheRead(self, tail: str) -> None:
        for definition in self._DEFINITIONS:
            with self.subTest(definition):
                source = F'$x = 1, 2, 3\n{definition}\n{tail}'
                self.assertEqual(self._deobfuscate(source), source)

    def test_a_store_through_the_second_name_is_not_answered_for_the_first(self):
        self._assertNoConversionAnswersTheRead('$y[0] = 9\nWrite-Output $x')

    def test_a_reversal_through_the_second_name_is_not_answered_for_the_first(self):
        self._assertNoConversionAnswersTheRead('[Array]::Reverse($y)\nWrite-Output $x')

    def test_a_store_through_the_first_name_is_not_answered_for_the_second(self):
        self._assertNoConversionAnswersTheRead('$x[0] = 9\nWrite-Output $y')

    def test_a_reversal_through_the_first_name_is_not_answered_for_the_second(self):
        self._assertNoConversionAnswersTheRead('[Array]::Reverse($x)\nWrite-Output $y')

    def test_the_same_reversal_under_a_definition_that_certainly_shares_is_answered(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output (3, 2, 1)
        """)
        self.assertEqual(self._deobfuscate(source), expected)


class TestPs1ACallWhoseMemberCannotBeNamedWritesEverySlotItIsHanded(TestPs1):
    """
    `[Array]::$m($x)` names no member until `$m` is resolved, so which slots the callee writes is
    unknown and the read below the call may not be answered by the write above it. Measured on 5.1,
    `$m = 'Reverse'; $x = 1, 2, 3; [Array]::$m($x); $x[0]` is `3`, which is what the whole
    deobfuscation recovers once the member has been spelled out.
    """

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
        expected = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x)
            Write-Output 3
        """)
        self.assertEqual(self._deobfuscate(source), expected)


class TestPs1APositionThatStoresTheObjectIsNotHandedACopyOfIt(TestPs1):
    """
    Every position here keeps the array beyond the statement it stands in, so the name it is stored
    under observes what a later write through `$x` does to it. Measured on 5.1, each of these eight
    scripts writes `9`; writing `1, 2, 3` where `$x` stands would store a second array instead and
    leave the read below reporting `1`.

    Each is refused rather than answered, and the refusal is the whole claim: the read of the other
    name is not one this can resolve either way.

    Every holder is given a value it can actually hold a property or an element on. A bare `$o.P = `
    on an unbound name raises `PropertyNotFound` and `$l.Add(...)` on one raises
    `InvokeMethodOnNull`, and `New-Object PSObject` mints no note property either, so each of those
    spellings halts before it reaches the shape the test is about — a refusal asserted over a script
    that throws is a refusal asserted over nothing.
    """

    def test_an_array_stored_under_a_hashtable_key_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $h = @{}
            $h['k'] = $x
            $x[0] = 9
            Write-Output $h['k'][0]
        """)
        self.assertEqual(self._deobfuscate(source), source)

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
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_stored_in_an_element_of_another_array_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $a = 0, 0
            $a[0] = $x
            $x[0] = 9
            Write-Output $a[0][0]
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_written_into_a_hashtable_literal_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $h = @{
              k = $x
            }
            $x[0] = 9
            Write-Output $h['k'][0]
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_a_collection_retains_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $list = New-Object Collections.ArrayList
            [void]$list.Add($x)
            $x[0] = 9
            Write-Output $list[0][0]
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_handed_on_through_a_cast_that_converts_nothing_is_still_shared(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $y = [array]$x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_taken_by_one_target_of_a_multi_assignment_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $a, $b = $x, 9
            $x[0] = 9
            Write-Output $a[0]
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_given_to_a_name_by_a_command_is_the_one_the_write_reaches(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            New-Variable y $x
            $x[0] = 9
            Write-Output $y[0]
        """)
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1ACallFillingABufferArgumentDoesNotGetTheBuffersValue(TestPs1):
    """
    A callee that fills an array it is handed writes the variable that hands it over, so the buffer's
    own value may not stand in that slot while a slot the callee only reads still may.
    `[Text.Encoding]::ASCII.GetBytes($s)` fills nothing and is the control: it must keep folding.
    """

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
    """
    `[Array]::Reverse($x, 0)` binds no overload — `Reverse` takes one argument or three — so 5.1
    writes a `MethodException` and reverses nothing. Measured, the array is left in the order it was
    built in and the statement is one the script performs, so it may not be removed as work nothing
    observes.
    """

    def test_a_reversal_at_an_arity_no_overload_takes_is_not_removed_as_junk(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Reverse($x, 0)
        """)
        self.assertEqual(self._deobfuscate(source), '[Array]::Reverse((1, 2, 3), 0)')

    def test_a_sort_at_an_arity_no_overload_takes_leaves_the_array_in_the_order_it_had(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            [Array]::Sort($x, 0, 1, 2, 3, 4)
            Write-Output $x
        """)
        expected = inspect.cleandoc("""
            [Array]::Sort((1, 2, 3), 0, 1, 2, 3, 4)
            Write-Output (1, 2, 3)
        """)
        self.assertEqual(self._deobfuscate(source), expected)


class TestPs1ComputingAReversalLeavesTheTreeItReadTheArrayFrom(TestPs1):
    """
    The array a reversal leaves behind is a value built out of the elements the assignment above it
    wrote. A node adopts the children it is handed, so building that value over the elements still
    standing in the tree would leave the assignment's array holding children that name a node
    nowhere in the script, and every guard that climbs out of a statement to ask what encloses it
    would climb into the answer instead.
    """

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
    """
    `[string]$q = 5` constrains the variable rather than the assignment, and `[System.String]` names
    that same type. Measured on 5.1, `[string]$q = 5; [System.String]$q = 'ab'; Write-Output $q`
    writes `ab`, and so does the script that spells the constraint the same way twice. A name
    constrained twice over is one a value may not be read out of, so reading the two spellings as
    two constraints costs the fold that the one-spelling script already gets.
    """

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
    """
    A String, an Int32 and a Char have no identity a store reaches: nothing a script does to an
    object it holds elsewhere changes what one of them is. So the constants standing beside an array
    the script turns around, or writes an element of, still fold into the positions that store them
    — a key of a hashtable literal and a slot of a multi-assignment keep the container they fold
    into, while an accumulation folds on through to the value it leaves — and the array keeps its
    name where the call that writes through it stands.
    """

    def test_a_string_folds_into_an_accumulation_beside_an_array_that_is_reversed(self):
        source = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $s = 'abc'
            $t = ''
            $t += $s
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            Write-Output 'abc'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_string_folds_into_a_hashtable_key_beside_an_array_that_is_reversed(self):
        source = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $s = 'abc'
            $h = @{ k = $s }
            Write-Output $h['k']
        """)
        expected = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $h = @{
              k = 'abc'
            }
            Write-Output $h['k']
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_string_folds_into_a_multi_assignment_slot_beside_an_array_that_is_reversed(self):
        source = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $s = 'abc'
            $u, $v = $s, 9
            Write-Output $u
        """)
        expected = inspect.cleandoc("""
            $b = 1, 2, 3
            [Array]::Reverse($b)
            $u, $v = 'abc', 9
            Write-Output $u
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_string_folds_into_a_hashtable_key_beside_an_array_an_element_is_written_of(self):
        source = inspect.cleandoc("""
            $x = 1, 2, 3
            $x[0] = 9
            $h = @{ p = $PSHome }
            Write-Output $h
        """)
        expected = inspect.cleandoc(R"""
            $x = 1, 2, 3
            $x[0] = 9
            $h = @{
              p = 'C:\Windows\System32\WindowsPowerShell\v1.0'
            }
            Write-Output $h
        """)
        self.assertEqual(self._deobfuscate(source), expected)


class TestPs1AConstraintOnTheNameBeingReadLeavesTheArrayItHandsOver(TestPs1):
    """
    `[Object[]]$x = 1, 2, 3` converts what that write carried and leaves `$x` on the array the
    conversion produced. A read of the name converts nothing further, so `$y = $x` hands `$y` that
    same array and `[Array]::Reverse($x)` turns around what both names hold: 5.1 writes `3 2 1`.

    A constraint on the name being written is the other question and keeps the other answer.
    `[string]$y = 0` converts everything a later write to `$y` arrives with, so `$y = $x` leaves
    `$y` holding the String `1 2 3`, which is not an array at all and which the reversal below
    reaches nothing of.
    """

    def test_a_constraint_on_the_name_handing_the_array_over_leaves_the_reversal_answered(self):
        source = inspect.cleandoc("""
            [Object[]]$x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        expected = inspect.cleandoc("""
            [Object[]]$x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output (3, 2, 1)
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_constraint_on_the_name_taking_the_array_still_refuses_the_reversal(self):
        source = inspect.cleandoc("""
            [string]$y = 0
            $x = 1, 2, 3
            $y = $x
            [Array]::Reverse($x)
            Write-Output $y
        """)
        self.assertEqual(self._deobfuscate(source), source)
