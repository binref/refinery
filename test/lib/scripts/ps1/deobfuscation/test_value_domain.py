from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.ps1.deobfuscation import TestPs1


class TestPs1AnInlinedNumberCarriesAMemberOnlyInParentheses(TestPs1):
    """
    Windows PowerShell 5.1 lexes `3.` as the beginning of a real number, so `3.ToString()` is a
    parse error; `(3).ToString()` is not. In a command argument the refusal covers every numeric
    literal, `0xFF.GetType()` and `1kb.GetType()` included, while `'abc'.ToUpper()` is always fine.
    Inlining a number into a slot that a member access reads therefore has to parenthesize it, or
    the emitted script no longer parses.

    Each assertion states the minimal faithful repair. A tool that additionally folded the member
    access away would be correct too and would rewrite these.
    """

    @unittest.expectedFailure
    def test_a_method_called_on_an_inlined_number_parenthesizes_the_receiver(self):
        self.assertEqual(self._deobfuscate('$n = 5; $n.ToString()'), '(5).ToString()')

    @unittest.expectedFailure
    def test_an_inlined_number_in_a_command_argument_parenthesizes_the_receiver(self):
        self.assertEqual(
            self._deobfuscate('$n = 5; Write-Output $n.ToString()'),
            'Write-Output (5).ToString()',
        )

    @unittest.expectedFailure
    def test_a_number_that_was_itself_folded_parenthesizes_the_receiver(self):
        self.assertEqual(self._deobfuscate('$n = 1 + 2; $n.ToString()'), '(3).ToString()')

    @unittest.expectedFailure
    def test_an_inlined_number_with_a_method_argument_parenthesizes_the_receiver(self):
        self.assertEqual(self._deobfuscate('$n = 5; $n.ToString("X")'), '(5).ToString("X")')

    @unittest.expectedFailure
    def test_an_inlined_hex_literal_in_a_command_argument_parenthesizes_the_receiver(self):
        self.assertEqual(
            self._deobfuscate('$t = 0xFF; Write-Output $t.GetType().FullName'),
            'Write-Output (0xFF).GetType().FullName',
        )

    @unittest.expectedFailure
    def test_an_inlined_suffixed_literal_in_a_command_argument_parenthesizes_the_receiver(self):
        self.assertEqual(
            self._deobfuscate('$t = 1kb; Write-Output $t.GetType().FullName'),
            'Write-Output (1kb).GetType().FullName',
        )

    def test_an_inlined_string_receiver_is_not_parenthesized(self):
        self.assertEqual(self._deobfuscate("$s = 'abc'; $s.ToUpper()"), "'ABC'")


class TestPs1ConstantsThatAreLeftUncomputed(TestPs1):
    """
    Every expression here has one answer on 5.1 that never depends on session state, and the tool
    computes none of them.
    """

    @unittest.expectedFailure
    def test_a_number_plus_a_string_is_addition_because_the_left_operand_decides(self):
        self.assertEqual(self._deobfuscate("$x = 5 + '5'"), '$x = 10')

    @unittest.expectedFailure
    def test_a_string_plus_a_number_is_concatenation_because_the_left_operand_decides(self):
        self.assertEqual(self._deobfuscate("$x = '5' + 5"), "$x = '55'")

    @unittest.expectedFailure
    def test_a_number_plus_a_hex_string_parses_the_string_as_a_hex_number(self):
        self.assertEqual(self._deobfuscate("$x = 12 + '0xabc'"), '$x = 2760')

    @unittest.expectedFailure
    def test_an_equality_against_a_collection_filters_it(self):
        self.assertEqual(self._deobfuscate('$x = 10, 20, 30 -eq 20'), '$x = @(20)')

    @unittest.expectedFailure
    def test_an_inequality_against_a_collection_filters_it(self):
        self.assertEqual(
            self._deobfuscate('$x = 10, 20, 30, 20, 10 -ne 20'),
            '$x = 10, 30, 10',
        )

    @unittest.expectedFailure
    def test_the_count_of_null_is_zero(self):
        self.assertEqual(self._deobfuscate('$x = $null.Count'), '$x = 0')

    @unittest.expectedFailure
    def test_the_count_of_an_empty_array_is_zero(self):
        self.assertEqual(self._deobfuscate('$x = @().Count'), '$x = 0')

    @unittest.expectedFailure
    def test_the_count_of_a_string_cast_to_a_char_array_is_its_character_count(self):
        self.assertEqual(self._deobfuscate("$x = ([char[]]'ABC').Count"), '$x = 3')

    @unittest.expectedFailure
    def test_the_count_of_to_char_array_is_the_character_count(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'.ToCharArray().Count"), '$x = 3')


class TestPs1ConstantsThatAreComputedWrong(TestPs1):
    """
    A numeric literal on 5.1 takes the smallest type its value or bit pattern fits, and a Char is
    not a String. Where the tool computes an answer for one of these, the answer it computes is a
    different value or a different type than the one 5.1 produces.
    """

    @unittest.expectedFailure
    def test_a_hex_literal_filling_thirty_two_bits_is_a_negative_int32(self):
        self.assertEqual(self._deobfuscate('$x = 0xFFFFFFFF + 0'), '$x = -1')

    @unittest.expectedFailure
    def test_a_negative_int32_hex_literal_stays_negative_through_bxor(self):
        self.assertEqual(self._deobfuscate('$x = 0xFFFFFFFF -bxor 0x5A'), '$x = -91')

    @unittest.expectedFailure
    def test_a_hex_literal_filling_sixty_four_bits_is_a_negative_int64(self):
        self.assertEqual(self._deobfuscate('$x = 0xFFFFFFFFFFFFFFFF + 0'), '$x = -1')

    @unittest.expectedFailure
    def test_a_kilobyte_suffix_is_an_integer(self):
        self.assertEqual(self._deobfuscate('$x = 1kb + 0'), '$x = 1024')

    @unittest.expectedFailure
    def test_a_long_suffix_survives_arithmetic_as_a_long(self):
        self.assertEqual(self._deobfuscate('$x = 1L + 0'), '$x = 1L')

    @unittest.expectedFailure
    def test_a_decimal_suffix_survives_arithmetic_as_a_decimal(self):
        self.assertEqual(self._deobfuscate('$x = 10d + 0'), '$x = 10d')

    @unittest.expectedFailure
    def test_an_int32_sum_that_overflows_widens_to_a_double(self):
        self.assertEqual(self._deobfuscate('$x = 2147483647 + 1'), '$x = 2147483648.0')

    @unittest.expectedFailure
    def test_a_char_cannot_be_replicated_because_replication_needs_a_string(self):
        source = '$x = ([char]65) * 3'
        self.assertEqual(self._deobfuscate(source), source)

    @unittest.expectedFailure
    def test_a_number_plus_a_char_is_addition(self):
        self.assertEqual(self._deobfuscate('$x = 1 + [char]65'), '$x = 66')

    @unittest.expectedFailure
    def test_a_char_plus_a_number_is_concatenation(self):
        self.assertEqual(self._deobfuscate('$x = [char]65 + 1'), "$x = 'A1'")

    @unittest.expectedFailure
    def test_indexing_a_string_yields_a_char(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'[0] -is [char]"), '$x = $True')

    @unittest.expectedFailure
    def test_a_cast_to_char_yields_a_char(self):
        self.assertEqual(self._deobfuscate('$x = [char]65 -is [char]'), '$x = $True')

    @unittest.expectedFailure
    def test_a_one_character_string_is_not_a_char(self):
        self.assertEqual(self._deobfuscate("$x = 'A' -is [char]"), '$x = $False')

    @unittest.expectedFailure
    def test_a_char_array_is_not_a_string(self):
        self.assertEqual(self._deobfuscate('$x = [char[]](72, 73) -is [string]'), '$x = $False')

    @unittest.expectedFailure
    def test_a_string_is_a_string(self):
        self.assertEqual(self._deobfuscate("$x = 'HI' -is [string]"), '$x = $True')


class TestPs1ValuesDecidedBySessionState(TestPs1):
    """
    Rendering a collection as a string separates the elements with the current value of `$OFS`,
    which lives in the session rather than in the script, so no rendering of one is a constant.
    """

    @unittest.expectedFailure
    def test_a_collection_cast_to_string_is_not_folded_because_ofs_separates_it(self):
        source = inspect.cleandoc("""
            $OFS = '-'
            $t = [string]('a', 'b')
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_collection_in_an_expandable_string_is_not_folded_because_ofs_separates_it(self):
        source = inspect.cleandoc("""
            $OFS = '-'
            $t = "$(1, 2)"
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1APipelineProducesACollection(TestPs1):
    """
    A pipeline emits one object per iteration and collects them into an `Object[]`, so a pipeline
    over two one-character strings is two strings rather than one two-character string. The
    difference is observable in the join separator, in the iteration count of a `foreach`, and in
    `.Count`.
    """

    @unittest.expectedFailure
    def test_a_pipeline_over_strings_stays_a_collection_of_strings(self):
        self.assertEqual(
            self._deobfuscate("$x = @('a', 'b') | ForEach-Object { $_ }"),
            "$x = 'a', 'b'",
        )

    @unittest.expectedFailure
    def test_joining_a_pipeline_result_puts_the_separator_between_the_elements(self):
        source = inspect.cleandoc("""
            $x = @('a', 'b') | ForEach-Object { $_ }
            Write-Output ($x -join '-')
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output 'a-b'")

    @unittest.expectedFailure
    def test_the_count_of_a_pipeline_result_is_the_number_of_emitted_objects(self):
        self.assertEqual(
            self._deobfuscate("$x = @('a', 'b') | ForEach-Object { $_ }; Write-Output $x.Count"),
            'Write-Output 2',
        )

    @unittest.expectedFailure
    def test_a_foreach_over_a_pipeline_result_runs_once_per_emitted_object(self):
        source = inspect.cleandoc("""
            $x = @('a', 'b') | ForEach-Object { $_ }
            foreach ($i in $x) {
              Write-Output $i
            }
        """)
        expected = inspect.cleandoc("""
            foreach ($i in 'a', 'b') {
              Write-Output $i
            }
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    @unittest.expectedFailure
    def test_a_pipeline_over_chars_stays_a_collection_of_chars(self):
        self.assertEqual(
            self._deobfuscate('$x = 65, 66 | ForEach-Object { [char]$_ }'),
            '$x = [char]65, [char]66',
        )

    @unittest.expectedFailure
    def test_the_count_of_a_pipeline_of_chars_is_the_number_of_emitted_objects(self):
        self.assertEqual(
            self._deobfuscate('$x = (65, 66 | ForEach-Object { [char]$_ }).Count'),
            '$x = 2',
        )

    @unittest.expectedFailure
    def test_a_pipeline_over_a_split_stays_a_collection_of_strings(self):
        self.assertEqual(
            self._deobfuscate("$x = 'a-b-c' -split '-' | ForEach-Object { $_ }"),
            "$x = 'a', 'b', 'c'",
        )


class TestPs1MembersTheObjectAdapterAddsToEveryValue(TestPs1):
    """
    5.1 adapts every object so that `Count`, `Length`, `PSObject` and `PSTypeNames` read on all of
    them, a scalar counting as one. `Rank` is the number of dimensions of an array rather than its
    element count, and a member that genuinely does not exist reads as `$null`.
    """

    @unittest.expectedFailure
    def test_the_count_of_a_string_is_one(self):
        self.assertEqual(self._deobfuscate("$x = 'AB'.Count"), '$x = 1')

    @unittest.expectedFailure
    def test_the_count_of_a_number_is_one(self):
        self.assertEqual(self._deobfuscate('$x = (5).Count'), '$x = 1')

    @unittest.expectedFailure
    def test_the_length_of_a_number_is_one(self):
        self.assertEqual(self._deobfuscate('$x = (5).Length'), '$x = 1')

    def test_the_length_of_a_string_is_its_character_count(self):
        self.assertEqual(self._deobfuscate("$x = 'AB'.Length"), '$x = 2')

    @unittest.expectedFailure
    def test_the_count_of_a_char_is_one(self):
        self.assertEqual(self._deobfuscate('$x = ([char]65).Count'), '$x = 1')

    def test_the_length_of_a_char_is_one(self):
        self.assertEqual(self._deobfuscate('$x = ([char]65).Length'), '$x = 1')

    def test_the_count_of_an_array_is_its_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @(1, 2, 3).Count'), '$x = 3')

    def test_the_length_of_an_array_is_its_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @(1, 2, 3).Length'), '$x = 3')

    @unittest.expectedFailure
    def test_the_rank_of_a_one_dimensional_array_is_one(self):
        self.assertEqual(self._deobfuscate('$x = @(1, 2, 3).Rank'), '$x = 1')

    def test_the_rank_of_a_number_is_null(self):
        self.assertEqual(self._deobfuscate('$x = (5).Rank'), '$x = $Null')

    def test_a_member_that_does_not_exist_is_null(self):
        self.assertEqual(self._deobfuscate("$x = 'AB'.Zqnope"), '$x = $Null')

    @unittest.expectedFailure
    def test_the_pstypenames_of_a_number_are_its_type_and_its_bases(self):
        self.assertEqual(
            self._deobfuscate('$x = (5).PSTypeNames'),
            "$x = 'System.Int32', 'System.ValueType', 'System.Object'",
        )

    @unittest.expectedFailure
    def test_the_pstypenames_of_a_string_are_its_type_and_its_base(self):
        self.assertEqual(
            self._deobfuscate("$x = ('AB').PSTypeNames"),
            "$x = 'System.String', 'System.Object'",
        )

    @unittest.expectedFailure
    def test_the_psobject_of_a_number_has_no_constant_spelling(self):
        source = '$x = (5).PSObject'
        self.assertEqual(self._deobfuscate(source), source)
