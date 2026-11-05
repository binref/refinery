from __future__ import annotations

from test import opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1ConstantFolding,
    Ps1TypeCasts,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1CharIntFolding(TestPs1):

    def test_char_int_literal(self):
        self.assertEqual(self._deobfuscate('[Char][int]83'), '[char]83')

    def test_char_literal_regression(self):
        self.assertEqual(self._deobfuscate('[Char]65'), '[char]65')

    def test_char_int_concat(self):
        result = self._deobfuscate_iterative('([Char][int]72 + [Char][int]105)')
        self.assertEqual(result.strip(), "'Hi'")

    def test_a_char_cast_of_a_negative_number_keeps_the_cast_that_throws(self):
        self.assertEqual(self._deobfuscate('$x = [Char][int](-65)'), '$x = [Char]-65')

    def test_int_identity_cast_stripped(self):
        result = self._deobfuscate('[int]42')
        self.assertEqual(result.strip(), '42')

    def test_a_string_of_digits_cast_to_int_is_the_number_it_spells(self):
        self.assertEqual(self._deobfuscate("$x = [int]'27'"), '$x = 27')

    def test_a_cast_of_an_indexed_string_element_is_the_number_that_element_spells(self):
        self.assertEqual(
            self._deobfuscate("$x = [int](('10', '20', '30')[2])"),
            '$x = 30',
        )

    def test_array_literal_index_scalar(self):
        result = self._deobfuscate("$x = ('hello', 'world', 'foo')[2]")
        self.assertIn('foo', result)
        self.assertNotIn('hello', result)

    def test_array_literal_index_nested(self):
        result = self._deobfuscate(
            "$x = ('a', 'b', 'c', 'd')[[int](('3', '1', '0')[2])]")
        self.assertNotIn("'b'", result)
        self.assertNotIn("'c'", result)
        self.assertNotIn("'d'", result)

    def test_char_int_multi_concat(self):
        result = self._deobfuscate_iterative(
            '([Char][int]83 + [Char][int]116 + [Char][int]111 + [Char][int]112)')
        self.assertEqual(result.strip(), "'Stop'")

    def test_char_int_partial_with_variable(self):
        result = self._deobfuscate_iterative(
            '([Char][int]83 + [Char][int]$x + [Char][int]112)')
        # `$x` is never assigned, so `[Char][int]$x` is `[char]0`, the NUL character.
        self.assertIn("S`0p", result)


class TestPs1TypeCastExtra(TestPs1):

    def test_typecast_char_hex(self):
        self.assertEqual(self._deobfuscate('[char]0x41'), '[char]65')

    def test_a_string_cast_of_a_string_literal_is_that_literal(self):
        self.assertEqual(self._apply('$x = [string]"foo"', Ps1TypeCasts), "$x = 'foo'")

    def test_a_char_array_cast_stands_rather_than_folding_to_a_string(self):
        self.assertEqual(
            self._deobfuscate('[char[]](72,101,108,108,111)'),
            '[char[]](72, 101, 108, 108, 111)')

    @opportunity
    def test_a_parenthesized_as_char_conversion_is_written_as_the_bare_char_cast(self):
        self.assertEqual(self._deobfuscate('(45 -As [Char])'), '[char]45')

    def test_a_type_cast_of_a_type_name_is_the_type_literal_naming_it(self):
        self.assertEqual(self._apply("$x = [Type]'Convert'", Ps1TypeCasts), '$x = [Convert]')

    def test_a_string_cast_inside_a_method_argument_is_the_string_it_produces(self):
        self.assertEqual(
            self._apply('''$snug.replAce(("M0I"),[strIng]"'")''', Ps1TypeCasts),
            '''$snug.replAce(("M0I"), "'")''',
        )

    def test_char_zero_is_nul_character(self):
        result = self._apply("'a' + [char]0 + 'b'", Ps1TypeCasts, Ps1ConstantFolding)
        self.assertEqual(result, '"a`0b"')


class TestPs1ACastToATypeWithNoLiteralIsWrittenAsACast(TestPs1):

    def test_a_hex_string_cast_to_uint16_keeps_the_uint16_cast(self):
        self.assertEqual(self._apply("$x = [uint16]'0xFFFF'", Ps1TypeCasts), '$x = [uint16]65535')

    def test_a_boolean_cast_to_int16_keeps_the_int16_cast(self):
        self.assertEqual(self._apply('$x = [int16]$true', Ps1TypeCasts), '$x = [int16]1')

    def test_a_byte_cast_of_a_numeral_is_left_standing(self):
        self._assertUnchanged('$x = [byte]5', Ps1TypeCasts)

    def test_an_sbyte_cast_of_a_negative_numeral_is_left_standing(self):
        self._assertUnchanged('$x = [sbyte]-5', Ps1TypeCasts)

    def test_an_int16_cast_of_a_numeral_is_left_standing(self):
        self._assertUnchanged('$x = [int16]7', Ps1TypeCasts)

    def test_a_uint32_cast_of_a_numeral_is_left_standing(self):
        self._assertUnchanged('$x = [uint32]7', Ps1TypeCasts)

    def test_a_uint64_cast_of_a_numeral_too_wide_for_int64_is_left_standing(self):
        self._assertUnchanged('$x = [uint64]18446744073709551615', Ps1TypeCasts)


class TestPs1ACastToATypeWithALiteralIsWrittenAsOne(TestPs1):

    def test_an_int_cast_of_an_int32_numeral_is_that_numeral(self):
        self.assertEqual(self._apply('$x = [int]5', Ps1TypeCasts), '$x = 5')

    def test_a_long_cast_is_written_with_the_long_suffix(self):
        self.assertEqual(self._apply('$x = [long]5', Ps1TypeCasts), '$x = 5L')

    def test_a_decimal_cast_is_written_with_the_decimal_suffix(self):
        self.assertEqual(self._apply('$x = [decimal]5', Ps1TypeCasts), '$x = 5d')

    def test_a_double_cast_of_an_integer_numeral_is_written_as_a_real(self):
        self.assertEqual(self._apply('$x = [double]5', Ps1TypeCasts), '$x = 5.0')

    def test_a_double_cast_of_a_decimal_numeral_is_written_as_a_real(self):
        self.assertEqual(self._apply('$x = [double]1.5d', Ps1TypeCasts), '$x = 1.5')

    def test_a_string_cast_of_a_numeral_is_written_as_a_string_literal(self):
        self.assertEqual(self._apply('$x = [string]5', Ps1TypeCasts), "$x = '5'")

    def test_a_string_cast_of_a_decimal_numeral_keeps_the_digits_it_was_written_with(self):
        self.assertEqual(self._apply('$x = [string]10d', Ps1TypeCasts), "$x = '10'")

    def test_a_string_cast_of_a_boolean_is_the_word_it_renders_as(self):
        self.assertEqual(self._apply('$x = [string]$true', Ps1TypeCasts), "$x = 'True'")

    def test_a_string_cast_of_the_absent_value_is_the_empty_string(self):
        self.assertEqual(self._apply('$x = [string]$null', Ps1TypeCasts), "$x = ''")

    def test_a_bool_cast_of_zero_is_the_false_literal(self):
        self.assertEqual(self._apply('$x = [bool]0', Ps1TypeCasts), '$x = $False')

    def test_a_bool_cast_of_one_is_the_true_literal(self):
        self.assertEqual(self._apply('$x = [bool]1', Ps1TypeCasts), '$x = $True')

    def test_an_int_cast_of_a_boolean_is_one(self):
        self.assertEqual(self._apply('$x = [int]$true', Ps1TypeCasts), '$x = 1')

    def test_an_int_cast_of_the_absent_value_is_zero(self):
        self.assertEqual(self._apply('$x = [int]$null', Ps1TypeCasts), '$x = 0')


class TestPs1ACastToAnIntegerRoundsHalfToEven(TestPs1):

    def test_a_half_below_an_odd_number_rounds_up_to_the_even_one(self):
        self.assertEqual(self._apply('$x = [int]1.5', Ps1TypeCasts), '$x = 2')

    def test_a_half_above_an_even_number_rounds_down_to_it(self):
        self.assertEqual(self._apply('$x = [int]2.5', Ps1TypeCasts), '$x = 2')

    def test_less_than_a_half_rounds_down(self):
        self.assertEqual(self._apply('$x = [int]1.4', Ps1TypeCasts), '$x = 1')

    def test_a_negative_half_rounds_to_the_even_neighbour(self):
        self.assertEqual(self._apply('$x = [int]-1.5', Ps1TypeCasts), '$x = -2')

    def test_the_rounded_value_carries_the_type_the_target_names(self):
        self.assertEqual(self._apply('$x = [long]1.5', Ps1TypeCasts), '$x = 2L')

    def test_a_decimal_numeral_reaches_an_integer_target_whole(self):
        self.assertEqual(self._apply('$x = [int]10d', Ps1TypeCasts), '$x = 10')


class TestPs1ACastWhoseConversionFailsIsLeftStanding(TestPs1):

    def test_a_byte_cast_above_the_byte_range_is_left_standing(self):
        self._assertUnchanged('$x = [byte]300', Ps1TypeCasts)

    def test_a_byte_cast_of_a_negative_numeral_is_left_standing(self):
        self._assertUnchanged('$x = [byte]-1', Ps1TypeCasts)

    def test_an_int_cast_above_the_int32_range_is_left_standing(self):
        self._assertUnchanged('$x = [int]2147483648', Ps1TypeCasts)

    def test_a_char_cast_above_the_utf16_code_unit_range_is_left_standing(self):
        self._assertUnchanged('$x = [char]65536', Ps1TypeCasts)

    def test_a_char_cast_of_a_negative_numeral_is_left_standing(self):
        self._assertUnchanged('$x = [char]-1', Ps1TypeCasts)

    def test_a_byte_cast_of_a_hex_string_one_digit_wider_than_the_target_is_left_standing(self):
        self._assertUnchanged("$x = [byte]'0x100'", Ps1TypeCasts)

    def test_a_byte_cast_of_a_negative_decimal_string_is_left_standing(self):
        self._assertUnchanged("$x = [byte]'-1'", Ps1TypeCasts)


class TestPs1ACastOfAnOperandTheSourcePinsNothingForIsLeftStanding(TestPs1):

    def test_a_cast_of_a_variable_is_left_standing(self):
        self._assertUnchanged('$x = [int]$y', Ps1TypeCasts)

    def test_a_cast_of_a_variable_to_a_width_is_left_standing(self):
        self._assertUnchanged('$x = [byte]$y', Ps1TypeCasts)


class TestPs1AnAsConversionIsNotACast(TestPs1):

    def test_an_as_conversion_whose_value_does_not_fit_is_left_standing(self):
        self._assertUnchanged('$x = 300 -as [byte]', Ps1TypeCasts)

    def test_an_as_conversion_of_a_string_that_names_no_number_is_left_standing(self):
        self._assertUnchanged("$x = 'abc' -as [int]", Ps1TypeCasts)

    def test_the_cast_of_a_string_that_names_no_number_is_left_standing(self):
        self._assertUnchanged("$x = [int]'abc'", Ps1TypeCasts)

    def test_an_as_conversion_above_the_int32_range_is_left_standing(self):
        self._assertUnchanged('$x = 2147483648 -as [int]', Ps1TypeCasts)

    def test_a_settled_as_conversion_is_written_as_the_value_it_produces(self):
        self.assertEqual(self._apply('$x = 5 -as [long]', Ps1TypeCasts), '$x = 5L')

    def test_a_settled_as_conversion_to_a_width_is_written_as_the_cast_that_spells_it(self):
        self.assertEqual(self._apply('$x = 5 -as [byte]', Ps1TypeCasts), '$x = [byte]5')

    def test_a_settled_as_conversion_to_a_char_is_written_as_the_char_cast(self):
        self.assertEqual(self._apply('$x = 45 -as [char]', Ps1TypeCasts), '$x = [char]45')

    def test_a_settled_as_conversion_of_a_string_is_written_as_the_number_it_names(self):
        self.assertEqual(self._apply("$x = '5' -as [int]", Ps1TypeCasts), '$x = 5')


class TestPs1ACastOfAStringIsReadByTheHostsParserAndNotPythons(TestPs1):

    def test_a_string_of_digits_with_leading_zeroes_is_a_decimal_number(self):
        self.assertEqual(self._apply("$x = [int]'007'", Ps1TypeCasts), '$x = 7')

    def test_the_empty_string_is_zero(self):
        self.assertEqual(self._apply("$x = [int]''", Ps1TypeCasts), '$x = 0')

    def test_a_string_of_nothing_but_whitespace_is_left_standing(self):
        # On 5.1, `[int]'   '` throws although `[int]''` is 0 and `[int]' 5 '` is 5.
        self._assertUnchanged("$x = [int]'   '", Ps1TypeCasts)

    def test_whitespace_around_a_number_is_stripped(self):
        self.assertEqual(self._apply("$x = [int]' 5 '", Ps1TypeCasts), '$x = 5')

    def test_a_leading_plus_is_a_sign(self):
        self.assertEqual(self._apply("$x = [int]'+7'", Ps1TypeCasts), '$x = 7')

    def test_a_trailing_point_is_a_whole_number(self):
        self.assertEqual(self._apply("$x = [int]'5.'", Ps1TypeCasts), '$x = 5')

    def test_a_leading_point_is_a_fraction_that_rounds_to_zero(self):
        self.assertEqual(self._apply("$x = [int]'.5'", Ps1TypeCasts), '$x = 0')

    def test_a_fractional_string_rounds_half_to_even(self):
        self.assertEqual(self._apply("$x = [int]'7.5'", Ps1TypeCasts), '$x = 8')
        self.assertEqual(self._apply("$x = [int]'2.5'", Ps1TypeCasts), '$x = 2')

    def test_a_hexadecimal_string_is_read_at_the_width_of_the_target(self):
        self.assertEqual(self._apply("$x = [byte]'0x80'", Ps1TypeCasts), '$x = [byte]128')
        self.assertEqual(self._apply("$x = [sbyte]'0x80'", Ps1TypeCasts), '$x = [sbyte]-128')

    def test_a_hexadecimal_string_filling_the_int32_width_is_the_negative_number_it_denotes(self):
        self.assertEqual(self._apply("$x = [int]'0xFFFFFFFF'", Ps1TypeCasts), '$x = -1')

    def test_a_digit_separator_is_no_numeral_and_the_cast_is_left_standing(self):
        self._assertUnchanged("$x = [int]'1_0'", Ps1TypeCasts)

    def test_a_binary_prefix_is_no_numeral_and_the_cast_is_left_standing(self):
        self._assertUnchanged("$x = [int]'0b1010'", Ps1TypeCasts)

    def test_an_octal_prefix_is_no_numeral_and_the_cast_is_left_standing(self):
        self._assertUnchanged("$x = [int]'0o17'", Ps1TypeCasts)

    def test_a_multiplier_suffix_is_no_numeral_and_the_cast_is_left_standing(self):
        self._assertUnchanged("$x = [int]'1kb'", Ps1TypeCasts)

    def test_a_string_is_true_by_its_length_and_never_by_its_text(self):
        self.assertEqual(self._apply("$x = [bool]'0'", Ps1TypeCasts), '$x = $True')
        self.assertEqual(self._apply("$x = [bool]''", Ps1TypeCasts), '$x = $False')


class TestPs1ACastAlreadySpellingItsOwnValueIsNotRewritten(TestPs1):

    def _reports_a_change(self, source: str) -> bool:
        transform = Ps1TypeCasts()
        transform.visit(Ps1Parser(source).parse())
        return transform.changed

    def test_a_byte_cast_of_the_value_it_already_spells_reports_no_change(self):
        self.assertFalse(self._reports_a_change('$x = [byte]128'))

    def test_a_uint16_cast_of_the_value_it_already_spells_reports_no_change(self):
        self.assertFalse(self._reports_a_change('$x = [uint16]65535'))

    def test_an_sbyte_cast_of_the_negative_value_it_already_spells_reports_no_change(self):
        self.assertFalse(self._reports_a_change('$x = [sbyte]-128'))

    def test_what_the_pass_writes_for_a_hex_string_is_a_fixed_point_of_the_pass(self):
        written = self._apply("$x = [sbyte]'0x80'", Ps1TypeCasts)
        self.assertEqual(written, '$x = [sbyte]-128')
        self.assertFalse(self._reports_a_change(written))

    def test_a_char_cast_of_the_value_it_already_spells_reports_no_change(self):
        self.assertFalse(self._reports_a_change('$x = [char]65'))

    def test_what_the_pass_writes_for_a_char_of_a_string_is_a_fixed_point_of_the_pass(self):
        written = self._apply("$x = [char]'A'", Ps1TypeCasts)
        self.assertEqual(written, '$x = [char]65')
        self.assertFalse(self._reports_a_change(written))


class TestPs1ACharIsCarriedAsACharAndWrittenAsACast(TestPs1):

    def test_a_char_cast_of_a_one_character_string_is_written_as_the_code_point(self):
        self.assertEqual(self._apply("$x = [char]'A'", Ps1TypeCasts), '$x = [char]65')

    def test_a_char_cast_of_a_numeral_is_the_cast_it_already_is(self):
        self.assertEqual(self._apply('$x = [char]65', Ps1TypeCasts), '$x = [char]65')

    def test_a_char_cast_of_a_string_of_two_characters_is_left_standing(self):
        self._assertUnchanged("$x = [char]'AB'", Ps1TypeCasts)

    def test_a_char_cast_of_the_empty_string_is_left_standing(self):
        self._assertUnchanged("$x = [char]''", Ps1TypeCasts)

    def test_a_string_cast_of_a_char_is_the_one_character_string(self):
        self.assertEqual(self._apply('$x = [string][char]65', Ps1TypeCasts), "$x = 'A'")

    def test_an_int_cast_of_a_char_is_the_code_point_of_its_character(self):
        self.assertEqual(self._deobfuscate("$x = [int][char]'A'"), '$x = 65')
