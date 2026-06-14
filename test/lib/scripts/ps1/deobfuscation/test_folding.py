from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1ConstantFolding


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
        result = self._deobfuscate('-bnot 0')
        self.assertIn('-1', result)
        self.assertNotIn('bnot', result.lower())

    def test_bnot_hex(self):
        result = self._deobfuscate('-bnot 0xFF00')
        self.assertNotIn('bnot', result.lower())
        self.assertNotIn('0xFF00', result)

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
        result = self._deobfuscate('[Convert]::ToChar(65)')
        self.assertIn('A', result)

    def test_toint32_octal_base(self):
        result = self._deobfuscate("[Convert]::ToInt32('77', 8)")
        self.assertIn('63', result)


class TestPs1NegativeIndexFolding(TestPs1):

    def test_string_negative_one(self):
        result = self._deobfuscate("'hello'[-1]")
        self.assertIn('o', result)
        self.assertNotIn('-1', result)

    def test_string_negative_two(self):
        result = self._deobfuscate("'ABCDE'[-2]")
        self.assertIn('D', result)

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

    def test_format_hex_negative_twos_complement(self):
        result = self._apply("'{0:X}' -f -1", Ps1ConstantFolding)
        self.assertEqual(result, "'FFFFFFFF'")

    def test_leading_zero_integer_is_decimal(self):
        self.assertEqual(self._apply('007 + 1', Ps1ConstantFolding), '8')
