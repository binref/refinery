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

    def test_a_method_called_on_an_inlined_number_parenthesizes_the_receiver(self):
        self.assertEqual(self._deobfuscate('$n = 5; $n.GetType()'), '(5).GetType()')

    def test_an_inlined_number_in_a_command_argument_parenthesizes_the_receiver(self):
        self.assertEqual(
            self._deobfuscate('$n = 5; Write-Output $n.GetType()'),
            'Write-Output (5).GetType()',
        )

    def test_a_number_that_was_itself_folded_parenthesizes_the_receiver(self):
        self.assertEqual(self._deobfuscate('$n = 1 + 2; $n.GetType()'), '(3).GetType()')

    def test_an_inlined_number_with_a_method_argument_parenthesizes_the_receiver(self):
        self.assertEqual(self._deobfuscate('$n = 5; $n.ToString("X")'), '(5).ToString("X")')

    def test_an_inlined_hex_literal_in_a_command_argument_parenthesizes_the_receiver(self):
        self.assertEqual(
            self._deobfuscate('$t = 0xFF; Write-Output $t.GetType().FullName'),
            'Write-Output (0xFF).GetType().FullName',
        )

    def test_an_inlined_suffixed_literal_in_a_command_argument_parenthesizes_the_receiver(self):
        self.assertEqual(
            self._deobfuscate('$t = 1kb; Write-Output $t.GetType().FullName'),
            'Write-Output (1kb).GetType().FullName',
        )

    def test_an_inlined_string_receiver_is_not_parenthesized(self):
        self.assertEqual(self._deobfuscate("$s = 'abc'; $s.ToUpper()"), "'ABC'")


class TestPs1AFoldedNegativeNumberInACommandArgumentNeedsParentheses(TestPs1):
    """
    Windows PowerShell 5.1 never reads a leading `-` in a command argument as a sign. No binder is
    consulted and no parameter is matched: a sign joins a numeral only where the expression rule
    asked for one, which it never does for an argument, so the dash falls to the generic scan and
    the word around it is what the command receives. `Write-Output 1` writes an Int32 and
    `Write-Output (-1)` writes an Int32, but `Write-Output -1` writes the String `-1`, as do `-1.5`
    and `-1L`. A fold whose value is a negative number therefore changes the type the command
    receives unless the slot it lands in parenthesizes it.

    Each assertion states the minimal faithful repair. The unparenthesized cases are the control
    that says the parentheses belong to the sign in that slot rather than to folding as such.
    """

    def test_a_hex_literal_folded_to_a_negative_int32_is_parenthesized(self):
        self.assertEqual(
            self._deobfuscate('$t = 0xFFFFFFFF + 0; Write-Output $t'),
            'Write-Output (-1)',
        )

    def test_a_subtraction_folded_to_a_negative_number_is_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = 1 - 2; Write-Output $t'), 'Write-Output (-1)')

    def test_null_arithmetic_folded_to_a_negative_number_is_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = $null - 1; Write-Output $t'), 'Write-Output (-1)')

    def test_a_bxor_folded_to_a_negative_number_is_parenthesized(self):
        self.assertEqual(
            self._deobfuscate('$t = 0xFFFFFFFF -bxor 0x5A; Write-Output $t'),
            'Write-Output (-91)',
        )

    def test_a_fold_in_place_keeps_the_parentheses_the_negative_sign_needs(self):
        self.assertEqual(self._deobfuscate('Write-Output (1 - 2)'), 'Write-Output (-1)')

    def test_a_negative_double_is_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = 0 - 1.5; Write-Output $t'), 'Write-Output (-1.5)')

    def test_a_negative_long_is_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = 1L - 2L; Write-Output $t'), 'Write-Output (-1L)')

    def test_a_positive_number_is_not_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = 1 + 0; Write-Output $t'), 'Write-Output 1')

    def test_a_positive_hex_literal_is_not_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = 0xFF + 0; Write-Output $t'), 'Write-Output 255')

    def test_a_negative_number_assigned_to_a_variable_is_not_parenthesized(self):
        self.assertEqual(self._deobfuscate('$t = 1 - 2; $x = $t'), '$x = -1')

    def test_a_dash_argument_the_source_wrote_is_left_the_word_it_already_is(self):
        # These already pass the Strings `-1` and `+1`. Bracketing either would hand the command
        # the number the source never passed, which is the same defect in the other direction.
        self.assertEqual(self._deobfuscate('Write-Output -1'), 'Write-Output -1')
        self.assertEqual(self._deobfuscate('Write-Output +1'), 'Write-Output +1')


class TestPs1ACommandArgumentIsReadInCommandModeAllTheWayDown(TestPs1):
    """
    5.1 goes on lexing a command's arguments in command mode until something opens a new slot, so a
    numeral several levels under an argument is still in that argument's text and is read there.
    The same receiver therefore needs parentheses in one place and not in another, and a bracket
    written inside the argument puts the expression reading back.
    """

    def test_a_receiver_in_an_expression_statement_needs_no_parentheses(self):
        self.assertEqual(self._deobfuscate('$t = 0xFF; $t.GetType()'), '0xFF.GetType()')

    def test_a_receiver_on_the_right_of_an_assignment_needs_no_parentheses(self):
        self.assertEqual(self._deobfuscate('$t = 1kb; $x = $t.GetType()'), '$x = 1kb.GetType()')

    def test_a_bracket_inside_a_command_argument_restores_the_expression_reading(self):
        self.assertEqual(
            self._deobfuscate('$t = 0xFF; Write-Output ($t.GetType().FullName)'),
            'Write-Output (0xFF.GetType().FullName)',
        )

    def test_a_receiver_folded_to_a_negative_number_in_an_argument_is_parenthesized(self):
        self.assertEqual(
            self._deobfuscate('$t = 1 - 2; Write-Output $t.GetType()'),
            'Write-Output (-1).GetType()',
        )


class TestPs1ConstantsThatAreLeftUncomputed(TestPs1):
    """
    Every expression here has one answer on 5.1 that never depends on session state. The ones still
    marked as expected failures are the ones the tool does not compute; a test here that loses its
    mark has had its answer built, and is kept as the pin for it rather than deleted.
    """

    def test_a_number_plus_a_string_is_addition_because_the_left_operand_decides(self):
        self.assertEqual(self._deobfuscate("$x = 5 + '5'"), '$x = 10')

    def test_a_number_plus_a_hex_string_parses_the_string_as_a_hex_number(self):
        self.assertEqual(self._deobfuscate("$x = 12 + '0xabc'"), '$x = 2760')

    def test_a_string_plus_a_boolean_is_the_text_the_boolean_is_written_as(self):
        self.assertEqual(self._deobfuscate("$x = 'a' + $true"), "$x = 'aTrue'")

    def test_a_string_plus_a_double_is_the_text_the_double_is_written_as(self):
        self.assertEqual(self._deobfuscate("$x = 'a' + 1.5"), "$x = 'a1.5'")

    def test_a_double_cast_to_a_string_is_the_dotnet_framework_text(self):
        for source, expected in [
            ("$x = [string]0.5", "$x = '0.5'"),
            ("$x = [string]1E20", "$x = '1E+20'"),
            ("$x = [string]0.0000001", "$x = '1E-07'"),
            ("$x = [string]1.5E-7", "$x = '1.5E-07'"),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_an_equality_against_a_collection_filters_it(self):
        self.assertEqual(self._deobfuscate('$x = 10, 20, 30 -eq 20'), '$x = ,20')

    def test_an_inequality_against_a_collection_filters_it(self):
        self.assertEqual(
            self._deobfuscate('$x = 10, 20, 30, 20, 10 -ne 20'),
            '$x = 10, 30, 10',
        )

    def test_the_count_of_null_is_zero(self):
        self.assertEqual(self._deobfuscate('$x = $null.Count'), '$x = 0')

    def test_the_length_of_null_is_zero(self):
        self.assertEqual(self._deobfuscate('$x = $null.Length'), '$x = 0')

    def test_the_count_of_an_empty_array_is_zero(self):
        self.assertEqual(self._deobfuscate('$x = @().Count'), '$x = 0')

    def test_the_count_of_a_string_cast_to_a_char_array_is_its_character_count(self):
        self.assertEqual(self._deobfuscate("$x = ([char[]]'ABC').Count"), '$x = 3')

    def test_the_count_of_to_char_array_is_the_character_count(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'.ToCharArray().Count"), '$x = 3')

    def test_the_length_of_to_char_array_is_the_character_count(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'.ToCharArray().Length"), '$x = 3')

    def test_to_char_array_folds_to_the_char_array_cast_of_its_receiver(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'.ToCharArray()"), "$x = [char[]]'ABC'")

    def test_a_sub_range_to_char_array_is_not_the_whole_string_char_array(self):
        self.assertEqual(
            self._deobfuscate("$x = 'ABC'.ToCharArray(0, 2).Count"),
            "$x = 'ABC'.ToCharArray(0, 2).Count",
        )


class TestPs1ConstantsThatAreComputedWrong(TestPs1):
    """
    A numeric literal on 5.1 takes the smallest type its value or bit pattern fits, and a Char is
    not a String. Where the tool computes an answer for one of these, the answer it computes is a
    different value or a different type than the one 5.1 produces.
    """

    def test_a_hex_literal_filling_thirty_two_bits_is_a_negative_int32(self):
        self.assertEqual(self._deobfuscate('$x = 0xFFFFFFFF + 0'), '$x = -1')

    def test_a_negative_int32_hex_literal_stays_negative_through_bxor(self):
        self.assertEqual(self._deobfuscate('$x = 0xFFFFFFFF -bxor 0x5A'), '$x = -91')

    def test_a_hex_literal_filling_sixty_four_bits_is_a_negative_int64(self):
        self.assertEqual(self._deobfuscate('$x = 0xFFFFFFFFFFFFFFFF + 0'), '$x = -1L')

    def test_a_kilobyte_suffix_is_an_integer(self):
        self.assertEqual(self._deobfuscate('$x = 1kb + 0'), '$x = 1024')

    def test_a_long_suffix_survives_arithmetic_as_a_long(self):
        self.assertEqual(self._deobfuscate('$x = 1L + 0'), '$x = 1L')

    def test_a_decimal_suffix_survives_arithmetic_as_a_decimal(self):
        self.assertEqual(self._deobfuscate('$x = 10d + 0'), '$x = 10d')

    def test_an_int32_sum_that_overflows_widens_to_a_double(self):
        self.assertEqual(self._deobfuscate('$x = 2147483647 + 1'), '$x = 2147483648.0')

    def test_a_char_cannot_be_replicated_because_replication_needs_a_string(self):
        source = '$x = ([char]65) * 3'
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_number_plus_a_char_is_addition(self):
        self.assertEqual(self._deobfuscate('$x = 1 + [char]65'), '$x = 66')


class TestPs1TheIsOperatorTestsTheRuntimeType(TestPs1):
    """
    `-is` and `-isnot` test the runtime type of the left operand against the type named on the
    right, which the value domain answers from the base chain and interface set the type model
    carries. The result is always a `System.Boolean`, so unlike the value grid there is no measured
    cell to stamp; a left operand whose type is unknown, or a relation the model does not settle,
    leaves the test standing rather than guessing. Every answer here is measured on a 5.1 host.
    """

    def test_a_char_indexed_out_of_a_string_is_a_char(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'[0] -is [char]"), '$x = $True')

    def test_a_cast_to_char_is_a_char(self):
        self.assertEqual(self._deobfuscate('$x = [char]65 -is [char]'), '$x = $True')

    def test_a_one_character_string_is_not_a_char(self):
        self.assertEqual(self._deobfuscate("$x = 'A' -is [char]"), '$x = $False')

    def test_a_string_is_a_string(self):
        self.assertEqual(self._deobfuscate("$x = 'HI' -is [string]"), '$x = $True')

    def test_a_char_array_is_not_a_string(self):
        self.assertEqual(
            self._deobfuscate('$x = [char[]](72, 73) -is [string]'), '$x = $False')

    def test_isnot_is_the_negation_of_is(self):
        self.assertEqual(self._deobfuscate('$x = [char]65 -isnot [char]'), '$x = $False')
        self.assertEqual(self._deobfuscate("$x = 'A' -isnot [char]"), '$x = $True')

    def test_a_value_is_an_interface_its_type_implements(self):
        self.assertEqual(self._deobfuscate("$x = 'A' -is [System.IComparable]"), '$x = $True')

    def test_a_value_is_a_base_class_of_its_type(self):
        self.assertEqual(self._deobfuscate('$x = 5 -is [ValueType]'), '$x = $True')

    def test_a_value_is_not_a_sibling_type_in_the_hierarchy(self):
        self.assertEqual(self._deobfuscate('$x = [byte]5 -is [int]'), '$x = $False')

    def test_an_array_is_an_array_and_an_object_array(self):
        self.assertEqual(self._deobfuscate('$x = (1, 2, 3) -is [array]'), '$x = $True')
        self.assertEqual(self._deobfuscate('$x = (1, 2, 3) -is [object[]]'), '$x = $True')

    def test_null_is_not_of_any_type(self):
        self.assertEqual(self._deobfuscate('$x = $null -is [object]'), '$x = $False')
        self.assertEqual(self._deobfuscate('$x = $null -isnot [object]'), '$x = $True')

    def test_a_test_against_a_different_array_type_is_left_standing(self):
        self.assertEqual(
            self._deobfuscate('$x = (1, 2, 3) -is [string[]]'), '$x = (1, 2, 3) -Is [string[]]')

    def test_a_test_of_an_operand_whose_type_is_unknown_is_left_standing(self):
        self.assertEqual(self._deobfuscate('$x = $args -is [int]'), '$x = $args -Is [int]')


class TestPs1TheLeftOperandOfPlusDecidesWhetherItConcatenates(TestPs1):
    """
    5.1 reads `+` by its left operand: a String or a Char on that side joins the text a cast of the
    right one to String would produce, and a number on that side adds. So the same pair of values
    written in the two orders is a String one way and a number the other, and one of the two orders
    throws for operands the other accepts.
    """

    def test_a_string_plus_a_number_is_concatenation(self):
        self.assertEqual(self._deobfuscate("$x = '5' + 5"), "$x = '55'")

    def test_a_char_plus_a_number_is_concatenation(self):
        self.assertEqual(self._deobfuscate('$x = [char]65 + 1'), "$x = 'A1'")

    def test_a_decimal_is_appended_with_the_digits_it_was_written_with(self):
        self.assertEqual(self._deobfuscate("$x = 'a' + 1.50d"), "$x = 'a1.50'")

    def test_a_cast_of_a_string_that_is_folded_first_is_appended_as_the_number_it_became(self):
        self.assertEqual(self._deobfuscate("$x = 'v' + [int]'0x10'"), "$x = 'v16'")


class TestPs1ACastOfAStringIsReadByTheRulesOfFivePointOne(TestPs1):
    """
    A String operand is parsed rather than converted, and 5.1 parses it by rules of its own: `'1_0'`
    is a numeral to Python's integer parser and none to 5.1, which throws for it, and `[byte]'0x80'`
    reads the digits at the width of the target, producing a Byte where the same text under `[int]`
    is an Int32. Where the tool answers one of these it answers a value 5.1 never produces, or
    produces it under a type 5.1 did not.
    """

    def test_a_digit_separator_is_no_numeral_and_the_cast_throws(self):
        source = "$x = [int]'1_0'"
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_folded_cast_keeps_the_type_its_target_names(self):
        self.assertEqual(self._deobfuscate("$x = [byte]'0x80'"), '$x = [byte]128')

    def test_a_string_that_fills_the_target_width_is_the_negative_number_it_denotes(self):
        self.assertEqual(self._deobfuscate("$x = [int]'0xFFFFFFFF'"), '$x = -1')


class TestPs1TheSeparatorOfACollectionIsWrittenByTheScript(TestPs1):
    """
    Writing a collection as a String puts the value of `$OFS` between the elements. `$OFS` is an
    ordinary variable rather than a setting the engine keeps, and the conversion looks the name up
    wherever it happens, so what separates a collection is whatever the script wrote by that point.
    Measured on 5.1: a name nothing has written separates with one space, `$null` separates with a
    space and `''` with nothing, and every other value contributes the text it is written as. Only
    an implicit conversion consults the name; `-join` and `[string]::Join` name their own separator.

    A conversion is therefore a constant exactly where the separator standing at that point is one
    the tool can name, and every other one is an expression that has to be left where it is.
    """

    def test_an_unwritten_separator_is_the_single_space_the_conversion_falls_back_to(self):
        source = inspect.cleandoc("""
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output '1 2'")

    def test_the_separator_the_script_wrote_last_is_the_one_the_conversion_reads(self):
        source = inspect.cleandoc("""
            $OFS = ','
            $OFS = ':'
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = ','
            $OFS = ':'
            Write-Output '1:2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_null_separator_separates_with_a_space(self):
        source = inspect.cleandoc("""
            $OFS = $null
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = $Null
            Write-Output '1 2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_an_empty_separator_separates_with_nothing(self):
        source = inspect.cleandoc("""
            $OFS = ''
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = ''
            Write-Output '12'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_number_separator_separates_with_the_digits_it_is_written_as(self):
        source = inspect.cleandoc("""
            $OFS = 5
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = 5
            Write-Output '152'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_boolean_separator_separates_with_the_word_it_is_written_as(self):
        source = inspect.cleandoc("""
            $OFS = $true
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = $True
            Write-Output '1True2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_char_separator_separates_with_the_character_it_holds(self):
        source = inspect.cleandoc("""
            $OFS = [char]45
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = [char]45
            Write-Output '1-2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_each_conversion_reads_the_separator_that_stands_where_it_is_written(self):
        source = inspect.cleandoc("""
            Write-Output ([string]@(1, 2))
            $OFS = '-'
            Write-Output ([string]@(3, 4))
        """)
        expected = inspect.cleandoc("""
            Write-Output '1 2'
            $OFS = '-'
            Write-Output '3-4'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_separator_a_command_writes_by_name_is_read_by_the_conversion(self):
        source = inspect.cleandoc("""
            Set-Variable OFS '-'
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = '-'
            Write-Output '1-2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_separator_written_by_an_expression_the_tool_reads_is_read_by_the_conversion(self):
        source = inspect.cleandoc("""
            iex '$OFS = "-"'
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = "-"
            Write-Output '1-2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_write_inside_a_call_operator_block_never_reaches_the_conversion(self):
        source = inspect.cleandoc("""
            & {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            & {
              $OFS = '-'
            }
            Write-Output '1 2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_write_inside_a_function_body_never_reaches_the_conversion(self):
        source = inspect.cleandoc("""
            function f {
              $OFS = '-'
            }
            f
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            function f {
              $OFS = '-'
            }
            f
            Write-Output '1 2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_single_element_collection_has_nowhere_to_put_a_separator(self):
        source = inspect.cleandoc("""
            Invoke-Expression $env:X
            $t = [string]@(1)
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            Invoke-Expression $env:X
            Write-Output '1'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_an_empty_collection_is_the_empty_string_whatever_the_separator_holds(self):
        source = inspect.cleandoc("""
            $OFS = @('-', '+')
            $t = [string]@()
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = @('-', '+')
            Write-Output ''
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_null_element_contributes_no_text_between_the_two_separators_around_it(self):
        source = inspect.cleandoc("""
            $t = [string]@(1, $null, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output '1  2'")

    def test_a_collection_interpolated_into_a_string_reads_the_separator(self):
        source = inspect.cleandoc("""
            $OFS = ','
            $t = "$(1, 2)"
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = ','
            Write-Output '1,2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_variable_holding_a_collection_interpolated_reads_the_separator(self):
        source = inspect.cleandoc("""
            $OFS = ','
            $c = 1, 2
            $t = "$c"
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = ','
            Write-Output '1,2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_join_operator_separates_with_the_separator_it_names(self):
        source = inspect.cleandoc("""
            Invoke-Expression $env:X
            $t = @(1, 2) -join ':'
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            Invoke-Expression $env:X
            Write-Output '1:2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_the_string_join_method_separates_with_the_separator_it_names(self):
        source = inspect.cleandoc("""
            $OFS = '-'
            $t = [string]::Join(':', @(1, 2))
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = '-'
            Write-Output '1:2'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_unary_join_separates_with_nothing(self):
        source = inspect.cleandoc("""
            $OFS = '-'
            $t = -join ('a', 'b')
            Write-Output $t
        """)
        expected = inspect.cleandoc("""
            $OFS = '-'
            Write-Output 'ab'
        """)
        self.assertEqual(self._deobfuscate(source), expected)

    def test_a_separator_whose_text_the_culture_decides_is_refused(self):
        """
        `$OFS = 1.5` separates with `1,5` on a host whose culture writes a decimal comma, so the
        text of this conversion is not a property of the script at all.
        """
        source = inspect.cleandoc("""
            $OFS = 1.5
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_array_separator_is_refused(self):
        """
        Measured, an array separator contributes `System.Object[]` rather than its elements.
        """
        source = inspect.cleandoc("""
            $OFS = @('-', '+')
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_separator_whose_value_the_script_does_not_decide_is_refused(self):
        source = inspect.cleandoc("""
            $OFS = $env:X
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_write_only_a_branch_performs_is_refused(self):
        """
        The condition has to be one nothing in the script decides. A variable no statement assigns
        is `$null`, which is falsy, so `if ($c)` is a branch that provably never runs and a
        conversion after it reads the separator that stood before it.
        """
        source = inspect.cleandoc("""
            if ($args[0]) {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_write_a_branch_performs_is_refused_though_another_write_precedes_it(self):
        source = inspect.cleandoc("""
            $OFS = ','
            if ($args[0]) {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_write_a_while_body_may_perform_is_refused(self):
        source = inspect.cleandoc("""
            while ($args[0]) {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_foreach_body_over_a_literal_collection_writes_the_separator(self):
        """
        This body runs, so the conversion after it is `1-2`. Computing it is not required of the
        tool; the one answer that is wrong is the fallback space, which says nothing wrote the name.
        """
        source = inspect.cleandoc("""
            foreach ($i in 1, 2) {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        folded = inspect.cleandoc("""
            foreach ($i in 1, 2) {
              $OFS = '-'
            }
            Write-Output '1-2'
        """)
        self.assertIn(self._deobfuscate(source), (source, folded))

    def test_a_write_whose_name_nothing_can_read_is_refused(self):
        source = inspect.cleandoc("""
            Set-Variable $env:X '-'
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_the_fallback_space_is_refused_after_a_call_that_may_have_written_the_name(self):
        source = inspect.cleandoc("""
            Invoke-Expression $env:X
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_written_separator_is_refused_once_a_call_may_have_replaced_it(self):
        source = inspect.cleandoc("""
            $OFS = ','
            Invoke-Expression $env:X
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_dot_sourced_file_may_have_written_the_name(self):
        source = inspect.cleandoc("""
            . stage2.ps1
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_collection_concatenated_onto_a_string_is_left_standing(self):
        """
        `'a' + @(1, 2)` is `a1-2` here, by the same separator every other conversion reads. The tool
        computes none of this arm yet, so the one answer it may give is the expression itself.
        """
        source = inspect.cleandoc("""
            $OFS = '-'
            $t = 'a' + @(1, 2)
            Write-Output $t
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_dot_sourced_block_writes_the_separator_of_whoever_ran_it(self):
        """
        Measured, this prints `1-2`: a dotted block performs its writes on the caller. Computing it
        is not required of the tool; the one answer that is wrong is the fallback space, which says
        the name was never written.
        """
        source = inspect.cleandoc("""
            . {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        folded = inspect.cleandoc("""
            . {
              $OFS = '-'
            }
            Write-Output '1-2'
        """)
        self.assertIn(self._deobfuscate(source), (source, folded))

    def test_a_pipeline_body_writes_the_separator_of_whoever_ran_it(self):
        source = inspect.cleandoc("""
            1, 2, 3 | ForEach-Object {
              $OFS = '-'
            }
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        folded = inspect.cleandoc("""
            1, 2, 3 | ForEach-Object {
              $OFS = '-'
            }
            Write-Output '1-2'
        """)
        self.assertIn(self._deobfuscate(source), (source, folded))

    def test_a_qualified_write_in_a_function_body_writes_the_scripts_separator(self):
        source = inspect.cleandoc("""
            function f {
              $script:OFS = '-'
            }
            f
            $t = [string]@(1, 2)
            Write-Output $t
        """)
        folded = inspect.cleandoc("""
            function f {
              $script:OFS = '-'
            }
            f
            Write-Output '1-2'
        """)
        self.assertIn(self._deobfuscate(source), (source, folded))


class TestPs1APipelineProducesACollection(TestPs1):
    """
    A pipeline emits one object per iteration and collects them into an `Object[]`, so a pipeline
    over two one-character strings is two strings rather than one two-character string. The
    difference is observable in the join separator, in the iteration count of a `foreach`, and in
    `.Count`.
    """

    def test_a_pipeline_over_strings_stays_a_collection_of_strings(self):
        self.assertEqual(
            self._deobfuscate("$x = @('a', 'b') | ForEach-Object { $_ }"),
            "$x = 'a', 'b'",
        )

    def test_joining_a_pipeline_result_puts_the_separator_between_the_elements(self):
        source = inspect.cleandoc("""
            $x = @('a', 'b') | ForEach-Object { $_ }
            Write-Output ($x -join '-')
        """)
        self.assertEqual(self._deobfuscate(source), "Write-Output 'a-b'")

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

    def test_a_pipeline_over_chars_stays_a_collection_of_chars(self):
        self.assertEqual(
            self._deobfuscate('$x = 65, 66 | ForEach-Object { [char]$_ }'),
            '$x = [char]65, [char]66',
        )

    def test_the_count_of_a_pipeline_of_chars_is_the_number_of_emitted_objects(self):
        self.assertEqual(
            self._deobfuscate('$x = (65, 66 | ForEach-Object { [char]$_ }).Count'),
            '$x = 2',
        )

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

    def test_the_count_of_a_string_is_one(self):
        self.assertEqual(self._deobfuscate("$x = 'AB'.Count"), '$x = 1')

    def test_the_count_of_a_number_is_one(self):
        self.assertEqual(self._deobfuscate('$x = (5).Count'), '$x = 1')

    def test_the_length_of_a_number_is_one(self):
        self.assertEqual(self._deobfuscate('$x = (5).Length'), '$x = 1')

    def test_the_length_of_a_string_is_its_character_count(self):
        self.assertEqual(self._deobfuscate("$x = 'AB'.Length"), '$x = 2')

    def test_the_count_of_a_char_is_one(self):
        self.assertEqual(self._deobfuscate('$x = ([char]65).Count'), '$x = 1')

    def test_the_length_of_a_char_is_one(self):
        self.assertEqual(self._deobfuscate('$x = ([char]65).Length'), '$x = 1')

    def test_the_count_of_an_array_is_its_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @(1, 2, 3).Count'), '$x = 3')

    def test_the_length_of_an_array_is_its_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @(1, 2, 3).Length'), '$x = 3')

    def test_the_rank_of_a_one_dimensional_array_is_one(self):
        self.assertEqual(self._deobfuscate('$x = @(1, 2, 3).Rank'), '$x = 1')

    def test_the_rank_of_a_number_is_null(self):
        self.assertEqual(self._deobfuscate('$x = (5).Rank'), '$x = $Null')

    def test_a_member_that_does_not_exist_is_null(self):
        self.assertEqual(self._deobfuscate("$x = 'AB'.Zqnope"), '$x = $Null')

    def test_the_pstypenames_of_a_number_are_its_type_and_its_bases(self):
        self.assertEqual(
            self._deobfuscate('$x = (5).PSTypeNames'),
            "$x = 'System.Int32', 'System.ValueType', 'System.Object'",
        )

    def test_the_pstypenames_of_a_string_are_its_type_and_its_base(self):
        self.assertEqual(
            self._deobfuscate("$x = ('AB').PSTypeNames"),
            "$x = 'System.String', 'System.Object'",
        )

    def test_the_psobject_of_a_number_has_no_constant_spelling(self):
        source = '$x = (5).PSObject'
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1TheAdapterCountAndLengthThrowUnderStrictModeVersionTwo(TestPs1):
    """
    The `Count` and `Length` the object adapter fakes onto a scalar or `$null` are not real members,
    so `Set-StrictMode -Version 2` turns reading one into a statement-terminating error where the
    default semantics and `-Version 1` hand back the adapter's value. Measured on 5.1: under
    `-Version 2` every `Count` and the `Length` of a non-String — `$null.Count`, `$null.Length`,
    `'AB'.Count`, `(5).Length`, `([char]65).Length` — raises `PropertyNotFoundStrict`, while a real
    member reads on, a `String`'s own `Length` and an array's own `Count` among them. Folding the
    fake member to its value therefore hands `-Version 2` a number for a line that never produces
    one and lets it decide a branch the script never reaches.

    The fold stands down where
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.strict_mode_v2_may_be_in_force` holds —
    a version-sensitive sibling of `strict_mode_may_be_in_force`, which fires at `-Version 1` too
    where the fold is correct. It gates only the faked members, so the real-member arms the three
    passing rows pin are folded regardless.
    """

    def test_the_count_of_null_is_not_folded_under_strict_mode_v2(self):
        self._assertDeobfuscatesTo(
            'Set-StrictMode -Version 2\nWrite-Output $null.Count',
            'Set-StrictMode -Version 2\nWrite-Output $Null.Count',
        )

    def test_the_count_of_a_scalar_is_not_folded_under_strict_mode_v2(self):
        self._assertKept("Set-StrictMode -Version 2\nWrite-Output 'AB'.Count")

    def test_the_count_of_null_is_still_folded_under_strict_mode_v1(self):
        self._assertDeobfuscatesTo(
            'Set-StrictMode -Version 1\nWrite-Output $null.Count',
            'Set-StrictMode -Version 1\nWrite-Output 0',
        )

    def test_the_count_of_a_scalar_is_still_folded_under_strict_mode_v1(self):
        self._assertDeobfuscatesTo(
            "Set-StrictMode -Version 1\nWrite-Output 'AB'.Count",
            'Set-StrictMode -Version 1\nWrite-Output 1',
        )

    def test_the_real_length_of_a_string_is_still_folded_under_strict_mode_v2(self):
        self._assertDeobfuscatesTo(
            "Set-StrictMode -Version 2\nWrite-Output 'AB'.Length",
            'Set-StrictMode -Version 2\nWrite-Output 2',
        )

    def test_the_real_count_of_an_array_is_still_folded_under_strict_mode_v2(self):
        self._assertDeobfuscatesTo(
            'Set-StrictMode -Version 2\nWrite-Output (1, 2).Count',
            'Set-StrictMode -Version 2\nWrite-Output 2',
        )

    def test_a_scalar_count_still_folds_under_set_psdebug_strict(self):
        # `Set-PSDebug -Strict` is documented as `Set-StrictMode -Version 1`, under which the
        # adapter's faked member reads on, so it does not gate the fold the way version 2 does.
        self._assertDeobfuscatesTo(
            "Set-PSDebug -Strict\nWrite-Output 'AB'.Count",
            'Set-PSDebug -Strict\nWrite-Output 1',
        )

    def test_a_scalar_count_is_not_folded_when_version_two_is_armed_through_iex(self):
        # The payload string is unwrapped into a real `Set-StrictMode -Version 2`, and the fold
        # stays refused beneath it rather than being decided before the arming is seen.
        self._assertDeobfuscatesTo(
            "Invoke-Expression 'Set-StrictMode -Version 2'\nWrite-Output 'AB'.Count",
            "Set-StrictMode -Version 2\nWrite-Output 'AB'.Count",
        )


class TestPs1ACharacterOfAStringIsACharAndNotAString(TestPs1):
    """
    Measured, `'ABC'[0]` is a `System.Char`: it answers `-is [char]` with True, and reading several
    offsets at once produces a collection of Chars. A Char is a text on the left of a `+` and the
    number of its code point on the right, so `'ABC'[0] + 1` is the String `A1`.
    """

    def test_a_character_taken_out_of_a_string_is_written_as_a_char(self):
        self.assertEqual(self._deobfuscate("$x = 'ABC'[0]"), '$x = [char]65')

    def test_several_characters_taken_out_of_a_string_are_each_written_as_a_char(self):
        self.assertEqual(self._deobfuscate("$x = 'abc'[0, 1]"), '$x = [char]97, [char]98')

    def test_a_character_of_a_string_is_a_text_on_the_left_of_a_plus(self):
        self.assertEqual(self._deobfuscate_iterative("$x = 'ABC'[0] + 1"), "$x = 'A1'")

    def test_a_character_of_a_string_is_no_string_to_replicate(self):
        # A cast binds tighter than a replication, so `[char]65 * 3` is the refusal that
        # `([char]65) * 3` is, and neither is the `AAA` a one-character String would produce.
        self.assertEqual(self._deobfuscate_iterative("$x = 'ABC'[0] * 3"), '$x = [char]65 * 3')


class TestPs1ANumberOnTheLeftOfACharIsNeverJoinedToItsText(TestPs1):
    """
    5.1 reads `+` by its left operand, so `1 + [char]65` adds the code point and is the Int32 66.
    Computing it is not required of the tool; the one answer that is wrong is the String `1A` that
    reading the Char as a one-character String on the right would produce.
    """

    def test_a_number_plus_a_char_is_the_sum_or_nothing_at_all(self):
        source = '$x = 1 + [char]65'
        self.assertIn(self._deobfuscate(source), (source, '$x = 66'))


class TestPs1CountingACollectionSpelledSeveralWays(TestPs1):
    """
    `Count` and `Length` answer how many elements a value holds, and what decides is the value
    rather than the spelling it was built with. Measured, `@(@(1, 2))` and `@((1, 2))` each hold two
    elements because the array operator unrolls what it is handed, while `,(1, 2)` holds the one
    collection the comma operator wrapped around the pair.

    The tool answers every one of those spellings, the two that put a collection inside `@(...)`
    among them: it counts the elements the array operator unrolls rather than reading the receiver
    as the scalar it is not.
    """

    def test_the_count_of_an_array_operator_around_an_array_is_the_inner_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @(@(1, 2)).Count'), '$x = 2')

    def test_the_count_of_an_array_operator_around_a_comma_list_is_the_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @((1, 2)).Count'), '$x = 2')

    def test_the_length_of_an_array_operator_around_an_array_is_the_inner_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @(@(1, 2)).Length'), '$x = 2')

    def test_the_count_of_a_bracket_around_a_comma_list_is_the_element_count(self):
        self.assertEqual(self._deobfuscate('$x = ((1, 2)).Count'), '$x = 2')

    def test_the_count_of_a_collection_the_comma_operator_wrapped_is_one(self):
        self.assertEqual(self._deobfuscate('$x = (,(1, 2)).Count'), '$x = 1')

    def test_the_count_of_an_array_operator_around_a_char_array_is_its_element_count(self):
        self.assertEqual(self._deobfuscate('$x = @([char[]](72, 73, 74)).Count'), '$x = 3')

    def test_the_count_of_an_array_operator_around_a_char_array_from_a_string(self):
        self.assertEqual(self._deobfuscate("$x = @([char[]]'ABC').Count"), '$x = 3')

    def test_a_char_array_one_level_inside_the_array_operator_stays_a_single_element(self):
        self.assertEqual(self._deobfuscate('$x = @([char[]](72, 73, 74), 99).Count'), '$x = 2')


class TestPs1APreferenceVariableIsAnEnumWhoseValueIsItsOrdinal(TestPs1):
    """
    The seven preference variables hold members of the engine enums `ActionPreference` and
    `ConfirmImpact`. An enum member's text is its name and its value is its ordinal, and 5.1 reads
    the ordinal for a Boolean and for a number and the name for a String: `$VerbosePreference` holds
    `SilentlyContinue`, ordinal 0, and is false though its name is not empty, where
    `$ErrorActionPreference` holds `Continue`, ordinal 2, and `$ConfirmPreference` holds `High`,
    ordinal 3.
    """

    def test_a_silently_continue_preference_is_false(self):
        self.assertEqual(self._deobfuscate('$x = [bool]$VerbosePreference'), '$x = $False')

    def test_a_continue_preference_is_true(self):
        self.assertEqual(self._deobfuscate('$x = [bool]$ErrorActionPreference'), '$x = $True')

    def test_a_number_reads_the_ordinal(self):
        for source, expected in [
            ('$x = [int]$VerbosePreference', '$x = 0'),
            ('$x = [int]$ErrorActionPreference', '$x = 2'),
            ('$x = [int]$ConfirmPreference', '$x = 3'),
            ('$x = [byte]$ConfirmPreference', '$x = [byte]3'),
            ('$x = [double]$ErrorActionPreference', '$x = 2.0'),
            ('$x = [decimal]$ConfirmPreference', '$x = 3d'),
            ('$x = [char]$ErrorActionPreference', '$x = [char]2'),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_a_collection_of_one_preference_is_as_true_as_the_member_it_holds(self):
        for source, expected in [
            ("if (,$VerbosePreference) { Write-Host 'A' } else { Write-Host 'B' }", "Write-Host 'B'"),
            ("if (@($ErrorActionPreference)) { Write-Host 'A' } else { Write-Host 'B' }", "Write-Host 'A'"),
            ('$x = [bool]@($VerbosePreference)', '$x = $False'),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_a_string_reads_the_member_name(self):
        for source, expected in [
            ('$x = [string]$VerbosePreference', "$x = 'SilentlyContinue'"),
            ('$x = $VerbosePreference.ToString()', "$x = 'SilentlyContinue'"),
            ('$x = "$VerbosePreference"', "$x = 'SilentlyContinue'"),
            ("$x = 'a' + $VerbosePreference", "$x = 'aSilentlyContinue'"),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_the_invoke_expression_a_loader_spells_out_of_a_preference_name_is_recovered(self):
        self.assertEqual(
            self._deobfuscate("$x = $VerbosePreference.ToString()[1, 3] + 'x' -join ''"),
            "$x = 'iex'",
        )

    def test_a_member_name_is_spelled_the_way_the_enum_spells_it(self):
        self.assertEqual(
            self._deobfuscate("$x = [string][System.Management.Automation.ActionPreference]'stop'"),
            "$x = 'Stop'",
        )

    def test_an_ordinal_is_the_member_that_holds_it(self):
        self.assertEqual(
            self._deobfuscate('$x = [string][System.Management.Automation.ActionPreference]1'),
            "$x = 'Stop'",
        )

    def test_an_ordinal_no_member_holds_is_a_throw_that_decides_no_guard(self):
        for cast in [
            '[System.Management.Automation.ActionPreference]6',
            '[System.Management.Automation.ActionPreference]300',
            '[System.Management.Automation.ActionPreference]-1',
            '[System.Management.Automation.ActionPreference]-2147483648',
            '[System.Management.Automation.ConfirmImpact]9',
        ]:
            with self.subTest(cast):
                self._assertKept(F"if ({cast}) {{ Write-Host 'A' }} else {{ Write-Host 'B' }}")

    def test_an_ordinal_no_member_holds_is_a_certain_throw_that_lifts_the_catch(self):
        for cast in [
            '[System.Management.Automation.ActionPreference]6',
            '[System.Management.Automation.ActionPreference]4294967295',
            '[System.Management.Automation.ConfirmImpact]9',
        ]:
            with self.subTest(cast):
                self.assertEqual(
                    self._deobfuscate(
                        F"try {{ $null = {cast}; Write-Host 'after' }} catch {{ Write-Host 'caught' }}"),
                    "Write-Host 'caught'",
                )

    def test_a_name_no_member_holds_is_left_standing(self):
        source = "$x = [bool][System.Management.Automation.ActionPreference]'Nope'"
        self.assertEqual(self._deobfuscate(source), source)

    def test_a_preference_compared_to_a_name_is_left_standing(self):
        self.assertEqual(
            self._deobfuscate("$x = $VerbosePreference -eq 'SilentlyContinue'"),
            "$x = [System.Management.Automation.ActionPreference]'SilentlyContinue' -Eq 'SilentlyContinue'",
        )


class TestPs1AnOrdinalIsStoredAtTheEnumWidthBeforeItIsLookedUp(TestPs1):
    """
    5.1 boxes an integer into an enum at the width the enum stores its ordinals in and checks that
    boxed value against the members, so an integer too wide for an Int32 converts by its low word:
    `[ActionPreference]4294967297L` is `Stop` and `-4294967294` is `Continue`, where `4294967295`
    throws because its low word is the -1 no member holds. The certain throw the domain claims for
    an undefined ordinal must be claimed for the boxed value and never for the integer written,
    because that claim is what lifts a `catch` body over a `try` body and deletes the rest of it.
    """

    def test_an_ordinal_wider_than_the_enum_stores_is_read_at_the_stored_width(self):
        for source, expected in [
            ('$x = [string][System.Management.Automation.ActionPreference]4294967297L', "$x = 'Stop'"),
            ('$x = [string][System.Management.Automation.ActionPreference]0x100000002', "$x = 'Continue'"),
            ('$x = [string][System.Management.Automation.ActionPreference](-4294967294)', "$x = 'Continue'"),
            ('$x = [string][System.Management.Automation.ActionPreference][uint64]4294967299', "$x = 'Inquire'"),
            ('$x = [string][System.Management.Automation.ConfirmImpact]4294967299', "$x = 'High'"),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_a_wide_ordinal_that_names_a_member_keeps_the_statements_after_it(self):
        self._assertDeobfuscatesTo(
            """
            try { $null = [System.Management.Automation.ActionPreference]4294967297L; Write-Host 'after' } catch { Write-Host 'caught' }
            """,
            """
            try { Write-Host 'after' } catch { Write-Host 'caught' }
            """,
        )

    def test_an_as_over_an_ordinal_no_member_holds_is_not_a_certain_throw(self):
        self.assertEqual(
            self._deobfuscate(
                "try { $x = 6 -as [System.Management.Automation.ActionPreference]; Write-Host 'after' }"
                " catch { Write-Host 'caught' }"
            ),
            inspect.cleandoc("""
                try {
                  $x = 6 -As [System.Management.Automation.ActionPreference]
                  Write-Host 'after'
                } catch {
                  Write-Host 'caught'
                }
            """),
        )


class TestPs1AFoldOverAPreferenceThatTheEnumModelDoesNotComputeYet(TestPs1):
    """
    Each answer below is what 5.1 computes, and each was folded before the preference variables
    became enum members, when their String spelling happened to give the same answer. The binary
    grid has no row for an enum, `_to_enum` computes only an exact member name and `integer_of`
    hands no slot the ordinal a member is stored as, so these are left standing now; they are the
    folds to recover.
    """

    @unittest.expectedFailure
    def test_a_preference_indexes_a_collection_by_its_ordinal(self):
        self.assertEqual(
            self._deobfuscate('$x = @(10, 20, 30)[$ErrorActionPreference]'), '$x = 30')

    @unittest.expectedFailure
    def test_a_preference_repeats_a_string_by_its_ordinal(self):
        self.assertEqual(self._deobfuscate("$x = 'ab' * $ErrorActionPreference"), "$x = 'abab'")

    @unittest.expectedFailure
    def test_a_preference_compared_to_its_member_name_is_true(self):
        self.assertEqual(
            self._deobfuscate("$x = $VerbosePreference -eq 'SilentlyContinue'"), '$x = $True')

    @unittest.expectedFailure
    def test_two_preferences_holding_the_same_member_compare_equal(self):
        self.assertEqual(
            self._deobfuscate('$x = $ErrorActionPreference -eq $WarningPreference'), '$x = $True')

    @unittest.expectedFailure
    def test_a_preference_formatted_writes_its_member_name(self):
        self.assertEqual(
            self._deobfuscate('$x = $VerbosePreference -f 1'), "$x = 'SilentlyContinue'")

    @unittest.expectedFailure
    def test_a_digit_string_and_a_unique_prefix_name_the_member_5_1_reads(self):
        for source in [
            "$x = [string][System.Management.Automation.ActionPreference]'1'",
            "$x = [string][System.Management.Automation.ActionPreference]'St'",
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), "$x = 'Stop'")


class TestPs1AnEnumOutsideTheEngineIsNotComputed(TestPs1):
    """
    `ConsoleColor` is a captured enum whose `Black` is the ordinal 0, so 5.1 takes the `else`
    branch below. The domain computes the two engine enums only, because 5.1's rule for which
    ordinals an enum accepts differs for a `[Flags]` enum and for one with a negative member and
    the capture does not say which an enum is. The guard is left standing, which is the cost of
    that gate and not a decision.
    """

    def test_a_guard_on_a_captured_enum_is_left_standing(self):
        self._assertKept("if ([ConsoleColor]'Black') { Write-Host 'A' } else { Write-Host 'B' }")

    def test_a_cast_to_a_captured_enum_is_left_standing(self):
        source = '$x = [int][DayOfWeek]9'
        self.assertEqual(self._deobfuscate(source), source)
