from __future__ import annotations

import math
import unicodedata

from collections.abc import Callable

from test import TestBase

from refinery.lib.scripts.js.numbers import (
    TRIMMABLE_WHITESPACE,
    is_negative_zero,
    js_number_to_string,
    js_parse_float,
    js_parse_int,
    js_string_to_number,
)

NAMED_WHITESPACE = [0x0009, 0x000B, 0x000C, 0xFEFF]
"""
The code points the ECMA-262 WhiteSpace production names one at a time: the tab, the vertical tab,
the form feed and the zero width no-break space. Its one remaining alternative is `<USP>`, which is
every code point of the Unicode general category `Zs`.
"""

LINE_TERMINATORS = [0x000A, 0x000D, 0x2028, 0x2029]
"""
The code points of the ECMA-262 LineTerminator production: the line feed, the carriage return, the
line separator and the paragraph separator.
"""


def _str_whitespace() -> str:
    space_separators = (cp for cp in range(0x110000) if unicodedata.category(chr(cp)) == 'Zs')
    return ''.join(map(chr, sorted({*NAMED_WHITESPACE, *LINE_TERMINATORS, *space_separators})))


LANGUAGE_WHITESPACE = _str_whitespace()
"""
Every character the ECMA-262 StrWhiteSpaceChar production admits, assembled from the two productions
above and the Unicode database rather than copied out of the code under test. Node removes exactly
these twenty-five characters with `String.prototype.trim` and accepts exactly them as padding around
a number.
"""


def _spelled(characters: str) -> list[str]:
    return [F'U+{ord(character):04X}' for character in characters]


def _every_character_that(is_padding: Callable[[str], bool]) -> list[str]:
    return [F'U+{cp:04X}' for cp in range(0x110000) if is_padding(chr(cp))]


class TestJsParseInt(TestBase):

    def _parses(self, text: str, radix: int = 0) -> float:
        parsed = js_parse_int(text, radix)
        if parsed is None:
            self.fail(F'{text!r} was refused')
        return parsed

    def _sign(self, text: str, radix: int = 0) -> float:
        return math.copysign(1.0, self._parses(text, radix))

    def test_a_string_that_names_negative_zero_keeps_the_sign_of_its_zero(self):
        self.assertEqual(0.0, self._parses('-0'))
        self.assertEqual(-1.0, self._sign('-0'))
        self.assertEqual(-1.0, self._sign('  -0  '))
        self.assertEqual(-1.0, self._sign('-0x0', 16))
        self.assertEqual(1.0, self._sign('0'))

    def test_non_ascii_decimal_digits_name_no_number(self):
        self.assertIsNone(js_parse_int('\u0661\u0662\u0663'))
        self.assertIsNone(js_parse_int('\uFF11\uFF12\uFF13'))
        self.assertIsNone(js_parse_int('\u0967\u0968\u0969'))

    def test_padding_python_strips_and_javascript_does_not_ends_the_parse(self):
        self.assertIsNone(js_parse_int('\u001C5'))
        self.assertIsNone(js_parse_int('\u001D5'))
        self.assertIsNone(js_parse_int('\u001E5'))
        self.assertIsNone(js_parse_int('\u001F5'))
        self.assertEqual(5.0, self._parses('5\u001C'))

    def test_the_byte_order_mark_pads_a_number_the_way_a_space_does(self):
        self.assertEqual(5.0, self._parses('\uFEFF5'))
        self.assertEqual(5.0, self._parses('5\uFEFF'))
        self.assertEqual(18.0, self._parses('\uFEFF\uFEFF12\uFEFF', 16))

    def test_a_digit_string_past_two_to_the_fifty_three_parses_to_the_nearest_double(self):
        self.assertEqual(9007199254740992.0, self._parses('9007199254740993'))
        self.assertEqual(9007199254740992.0, self._parses('9007199254740993', 10))
        self.assertEqual(9007199254740992.0, self._parses('0x20000000000001'))

    def test_a_digit_string_outside_the_double_range_parses_to_an_infinity(self):
        self.assertEqual(1e308, self._parses('1' + '0' * 308))
        self.assertEqual(math.inf, self._parses('9' * 309))
        self.assertEqual(math.inf, self._parses('1' + '0' * 309))
        self.assertEqual(-math.inf, self._parses('-' + '1' * 400))
        self.assertEqual(math.inf, self._parses('1' * 5000))
        self.assertEqual(math.inf, self._parses('0x' + 'f' * 300))

    def test_leading_zeros_are_not_digits_of_the_number_they_precede(self):
        self.assertEqual(5.0, self._parses('0' * 500 + '5'))
        self.assertEqual(5.0, self._parses('0' * 5000 + '5'))

    def test_a_binary_prefix_is_not_read_when_the_radix_is_not_supplied(self):
        self.assertEqual(0.0, self._parses('0b' + '1' * 1100))


class TestStringNumericGrammar(TestBase):

    def _number(self, text: str) -> float | str:
        value = js_string_to_number(text)
        return 'NaN' if math.isnan(value) else value

    def _float(self, text: str) -> float | str:
        value = js_parse_float(text)
        return 'NaN' if math.isnan(value) else value

    def test_a_string_that_only_begins_as_a_literal_is_a_number_to_parse_float_alone(self):
        self.assertEqual('NaN', self._number('2.5abc'))
        self.assertEqual(2.5, self._float('2.5abc'))
        self.assertEqual('NaN', self._number('12px'))
        self.assertEqual(12.0, self._float('12px'))
        self.assertEqual('NaN', self._number('1.2.3'))
        self.assertEqual(1.2, self._float('1.2.3'))
        self.assertEqual('NaN', self._number('5 5'))
        self.assertEqual(5.0, self._float('5 5'))
        self.assertEqual('NaN', self._number('1,000'))
        self.assertEqual(1.0, self._float('1,000'))
        self.assertEqual('NaN', self._number('1..2'))
        self.assertEqual(1.0, self._float('1..2'))

    def test_a_point_opens_or_closes_a_literal_but_never_stands_alone(self):
        self.assertEqual(3.0, self._number('3.'))
        self.assertEqual(3.0, self._float('3.'))
        self.assertEqual(0.5, self._number('.5'))
        self.assertEqual(0.5, self._float('.5'))
        self.assertEqual('NaN', self._number('.'))
        self.assertEqual('NaN', self._float('.'))
        self.assertEqual('NaN', self._number('..5'))
        self.assertEqual('NaN', self._float('..5'))
        self.assertEqual('NaN', self._number('0.5.'))
        self.assertEqual(0.5, self._float('0.5.'))

    def test_an_exponent_belongs_to_the_literal_both_functions_read(self):
        self.assertEqual(1000.0, self._number('1e3'))
        self.assertEqual(1000.0, self._float('1e3'))
        self.assertEqual(1000.0, self._number('1E3'))
        self.assertEqual(1000.0, self._float('1E3'))
        self.assertEqual(1000.0, self._number('1e+3'))
        self.assertEqual(1000.0, self._float('1e+3'))
        self.assertEqual(0.001, self._number('1e-3'))
        self.assertEqual(0.001, self._float('1e-3'))
        self.assertEqual(50.0, self._number('.5e2'))
        self.assertEqual(50.0, self._float('.5e2'))
        self.assertEqual(100.0, self._number('1.e2'))
        self.assertEqual(100.0, self._float('1.e2'))
        self.assertEqual(-150.0, self._number('-1.5e2'))
        self.assertEqual(-150.0, self._float('-1.5e2'))

    def test_an_exponent_that_is_begun_and_never_finished_shortens_the_literal(self):
        self.assertEqual('NaN', self._number('1e'))
        self.assertEqual(1.0, self._float('1e'))
        self.assertEqual('NaN', self._number('1E'))
        self.assertEqual(1.0, self._float('1E'))
        self.assertEqual('NaN', self._number('1e+'))
        self.assertEqual(1.0, self._float('1e+'))
        self.assertEqual('NaN', self._number('1e-'))
        self.assertEqual(1.0, self._float('1e-'))
        self.assertEqual('NaN', self._number('1.2e'))
        self.assertEqual(1.2, self._float('1.2e'))
        self.assertEqual('NaN', self._number('1.5e-'))
        self.assertEqual(1.5, self._float('1.5e-'))
        self.assertEqual('NaN', self._number('1ee3'))
        self.assertEqual(1.0, self._float('1ee3'))
        self.assertEqual('NaN', self._number('1e 3'))
        self.assertEqual(1.0, self._float('1e 3'))
        self.assertEqual('NaN', self._number('1e2.5'))
        self.assertEqual(100.0, self._float('1e2.5'))
        self.assertEqual('NaN', self._number('1e+3e4'))
        self.assertEqual(1000.0, self._float('1e+3e4'))

    def test_an_exponent_with_no_digits_ahead_of_it_names_no_number(self):
        self.assertEqual('NaN', self._number('e3'))
        self.assertEqual('NaN', self._float('e3'))
        self.assertEqual('NaN', self._number('.e3'))
        self.assertEqual('NaN', self._float('.e3'))

    def test_a_sign_is_read_where_a_literal_begins_and_nowhere_else(self):
        self.assertEqual(1.0, self._number('+1'))
        self.assertEqual(1.0, self._float('+1'))
        self.assertEqual(-1.0, self._number('-1'))
        self.assertEqual(-1.0, self._float('-1'))
        self.assertEqual(0.5, self._number('+.5'))
        self.assertEqual(0.5, self._float('+.5'))
        self.assertEqual(-0.5, self._number('-.5'))
        self.assertEqual(-0.5, self._float('-.5'))
        self.assertEqual('NaN', self._number('+-1'))
        self.assertEqual('NaN', self._float('+-1'))
        self.assertEqual('NaN', self._number('--1'))
        self.assertEqual('NaN', self._float('--1'))
        self.assertEqual('NaN', self._number('+'))
        self.assertEqual('NaN', self._float('+'))
        self.assertEqual('NaN', self._number('-'))
        self.assertEqual('NaN', self._float('-'))
        self.assertEqual('NaN', self._number('- 1'))
        self.assertEqual('NaN', self._float('- 1'))
        self.assertEqual('NaN', self._number('+ 1'))
        self.assertEqual('NaN', self._float('+ 1'))
        self.assertEqual('NaN', self._number('1-'))
        self.assertEqual(1.0, self._float('1-'))
        self.assertEqual('NaN', self._number('1+'))
        self.assertEqual(1.0, self._float('1+'))

    def test_the_word_infinity_names_an_infinity_behind_an_optional_sign(self):
        self.assertEqual(math.inf, self._number('Infinity'))
        self.assertEqual(math.inf, self._float('Infinity'))
        self.assertEqual(math.inf, self._number('+Infinity'))
        self.assertEqual(math.inf, self._float('+Infinity'))
        self.assertEqual(-math.inf, self._number('-Infinity'))
        self.assertEqual(-math.inf, self._float('-Infinity'))
        self.assertEqual(math.inf, self._number(' Infinity '))
        self.assertEqual(math.inf, self._float(' Infinity '))
        self.assertEqual('NaN', self._number('Infinityabc'))
        self.assertEqual(math.inf, self._float('Infinityabc'))
        self.assertEqual('NaN', self._number('Infinit'))
        self.assertEqual('NaN', self._float('Infinit'))
        self.assertEqual('NaN', self._number('infinity'))
        self.assertEqual('NaN', self._float('infinity'))
        self.assertEqual('NaN', self._number('INFINITY'))
        self.assertEqual('NaN', self._float('INFINITY'))
        self.assertEqual('NaN', self._number('- Infinity'))
        self.assertEqual('NaN', self._float('- Infinity'))

    def test_the_infinity_and_nan_spellings_python_reads_name_no_number(self):
        self.assertEqual('NaN', self._number('inf'))
        self.assertEqual('NaN', self._float('inf'))
        self.assertEqual('NaN', self._number('-inf'))
        self.assertEqual('NaN', self._float('-inf'))
        self.assertEqual('NaN', self._number('Inf'))
        self.assertEqual('NaN', self._float('Inf'))
        self.assertEqual('NaN', self._number('nan'))
        self.assertEqual('NaN', self._float('nan'))
        self.assertEqual('NaN', self._number('NaN'))
        self.assertEqual('NaN', self._float('NaN'))

    def test_a_magnitude_above_the_largest_double_names_an_infinity(self):
        self.assertEqual(1.7976931348623157e308, self._number('1.7976931348623157e308'))
        self.assertEqual(1.7976931348623157e308, self._float('1.7976931348623157e308'))
        self.assertEqual(math.inf, self._number('1.7976931348623159e308'))
        self.assertEqual(math.inf, self._float('1.7976931348623159e308'))
        self.assertEqual(math.inf, self._number('1e309'))
        self.assertEqual(-math.inf, self._number('-1e309'))
        self.assertEqual(math.inf, self._number('1e999'))
        self.assertEqual(-math.inf, self._number('-1e999'))
        self.assertEqual(math.inf, self._float('1e999'))
        self.assertEqual(-math.inf, self._float('-1e999'))

    def test_a_magnitude_below_the_smallest_double_names_a_zero_that_keeps_its_sign(self):
        self.assertEqual(5e-324, self._number('5e-324'))
        self.assertEqual(5e-324, self._float('5e-324'))
        self.assertEqual(5e-324, self._number('2.5e-324'))
        self.assertEqual(5e-324, self._float('2.5e-324'))
        self.assertEqual(-5e-324, self._number('-5e-324'))
        self.assertEqual(0.0, self._number('2e-324'))
        self.assertFalse(is_negative_zero(js_string_to_number('2e-324')))
        self.assertEqual(0.0, self._number('1e-999'))
        self.assertFalse(is_negative_zero(js_string_to_number('1e-999')))
        self.assertEqual(0.0, self._number('-1e-999'))
        self.assertTrue(is_negative_zero(js_string_to_number('-1e-999')))
        self.assertTrue(is_negative_zero(js_parse_float('-1e-999')))
        self.assertTrue(is_negative_zero(js_string_to_number('-1e-400')))

    def test_every_spelling_of_a_signed_zero_names_negative_zero(self):
        for text in ['-0', '-0.0', '-0e5']:
            with self.subTest(text=text):
                self.assertEqual(0.0, self._number(text))
                self.assertEqual(0.0, self._float(text))
                self.assertTrue(is_negative_zero(js_string_to_number(text)))
                self.assertTrue(is_negative_zero(js_parse_float(text)))
        self.assertEqual('NaN', self._number('-0x0'))
        self.assertEqual(0.0, self._float('-0x0'))
        self.assertTrue(is_negative_zero(js_parse_float('-0x0')))
        self.assertTrue(is_negative_zero(js_parse_float('-0x10')))
        self.assertTrue(is_negative_zero(js_parse_float('-0b101')))
        self.assertEqual(0.0, self._number('+0'))
        self.assertFalse(is_negative_zero(js_string_to_number('+0')))
        self.assertFalse(is_negative_zero(js_parse_float('+0x10')))

    def _pads_a_number(self, pad: str) -> bool:
        return self._number(F'{pad}42{pad}') == 42.0

    def _pads_a_float(self, pad: str) -> bool:
        return self._float(F'{pad}-1.5e2{pad}') == -150.0

    def test_the_characters_that_pad_a_number_are_the_ones_the_language_calls_whitespace(self):
        for pad in LANGUAGE_WHITESPACE:
            with self.subTest(pad=F'U+{ord(pad):04X}'):
                self.assertEqual(42.0, self._number(F'{pad}42{pad}'))
                self.assertEqual(42.0, self._float(F'{pad}42{pad}'))
                self.assertEqual(-150.0, self._number(F'{pad}-1.5e2{pad}'))
                self.assertEqual(-150.0, self._float(F'{pad}-1.5e2{pad}'))
                self.assertEqual(0.0, self._number(pad * 3))
                self.assertEqual('NaN', self._float(pad * 3))
        self.assertEqual(
            _spelled(LANGUAGE_WHITESPACE), _every_character_that(self._pads_a_number)
        )
        self.assertEqual(
            _spelled(LANGUAGE_WHITESPACE), _every_character_that(self._pads_a_float)
        )

    def test_padding_python_strips_and_the_language_does_not_ends_the_number(self):
        for pad in '\u001C\u001D\u001E\u001F\u0085':
            with self.subTest(pad=F'U+{ord(pad):04X}'):
                self.assertEqual('NaN', self._number(F'{pad}5'))
                self.assertEqual('NaN', self._float(F'{pad}5'))
                self.assertEqual('NaN', self._number(F'5{pad}'))
                self.assertEqual(5.0, self._float(F'5{pad}'))
                self.assertEqual('NaN', self._number(pad))
                self.assertEqual('NaN', self._float(pad))

    def test_the_byte_order_mark_python_leaves_in_place_is_padding(self):
        self.assertEqual(42.0, self._number('\uFEFF42\uFEFF'))
        self.assertEqual(42.0, self._float('\uFEFF42\uFEFF'))
        self.assertEqual(-150.0, self._float('\uFEFF-1.5e2'))
        self.assertEqual(0.0, self._number('\uFEFF'))
        self.assertEqual('NaN', self._float('\uFEFF'))

    def test_a_character_that_merely_looks_like_a_space_is_not_padding(self):
        for pad in '\u200B\u2060\u180E\u0000':
            with self.subTest(pad=F'U+{ord(pad):04X}'):
                self.assertEqual('NaN', self._number(F'{pad}42'))
                self.assertEqual('NaN', self._float(F'{pad}42'))

    def test_decimal_digits_from_another_script_name_no_number(self):
        for text in ['\u0661\u0662\u0663', '\uFF11\uFF12\uFF13', '\u0967\u0968\u0969', '\u0660']:
            with self.subTest(text=text):
                self.assertEqual('NaN', self._number(text))
                self.assertEqual('NaN', self._float(text))
        self.assertEqual('NaN', self._number('1\u0661'))
        self.assertEqual(1.0, self._float('1\u0661'))

    def test_characters_that_merely_look_like_digits_name_no_number(self):
        for text in ['\u00B2', '\u00BD', '\u216B', '\u2160', '\u2460']:
            with self.subTest(text=text):
                self.assertEqual('NaN', self._number(text))
                self.assertEqual('NaN', self._float(text))
        self.assertEqual('NaN', self._number('2\u00B2'))
        self.assertEqual(2.0, self._float('2\u00B2'))

    def test_a_base_other_than_ten_is_a_number_only_to_the_whole_string_reader(self):
        self.assertEqual(16.0, self._number('0x10'))
        self.assertEqual(0.0, self._float('0x10'))
        self.assertEqual(16.0, self._number('0X10'))
        self.assertEqual(0.0, self._float('0X10'))
        self.assertEqual(255.0, self._number('0xff'))
        self.assertEqual(0.0, self._float('0xff'))
        self.assertEqual(5.0, self._number('0b101'))
        self.assertEqual(0.0, self._float('0b101'))
        self.assertEqual(5.0, self._number('0B101'))
        self.assertEqual(15.0, self._number('0o17'))
        self.assertEqual(0.0, self._float('0o17'))
        self.assertEqual(15.0, self._number('0O17'))
        self.assertEqual(16.0, self._number(' 0x10 '))
        self.assertEqual(0.0, self._float(' 0x10 '))

    def test_a_leading_zero_names_no_octal(self):
        self.assertEqual(777.0, self._number('0777'))
        self.assertEqual(777.0, self._float('0777'))
        self.assertEqual(0.0, self._number('00'))
        self.assertEqual(0.0, self._float('00'))

    def test_a_sign_before_a_base_other_than_ten_names_no_number(self):
        self.assertEqual('NaN', self._number('-0x10'))
        self.assertEqual(0.0, self._float('-0x10'))
        self.assertEqual('NaN', self._number('+0x10'))
        self.assertEqual(0.0, self._float('+0x10'))
        self.assertEqual('NaN', self._number('-0b101'))
        self.assertEqual(0.0, self._float('-0b101'))

    def test_a_numeric_separator_names_no_number(self):
        self.assertEqual('NaN', self._number('1_0'))
        self.assertEqual(1.0, self._float('1_0'))
        self.assertEqual('NaN', self._number('1_000.5'))
        self.assertEqual(1.0, self._float('1_000.5'))
        self.assertEqual('NaN', self._number('0x1_0'))
        self.assertEqual(0.0, self._float('0x1_0'))

    def test_a_base_prefix_that_no_digit_of_that_base_follows_names_no_number(self):
        for text in ['0x', '0b', '0o', '0xg', '0o8', '0b2']:
            with self.subTest(text=text):
                self.assertEqual('NaN', self._number(text))
                self.assertEqual(0.0, self._float(text))

    def test_a_bigint_suffix_names_no_number(self):
        self.assertEqual('NaN', self._number('10n'))
        self.assertEqual(10.0, self._float('10n'))
        self.assertEqual('NaN', self._number('0x10n'))
        self.assertEqual(0.0, self._float('0x10n'))

    def test_a_base_other_than_ten_names_the_double_nearest_its_value(self):
        self.assertEqual(9007199254740991.0, self._number('0x1fffffffffffff'))
        self.assertEqual(9007199254740992.0, self._number('0x20000000000001'))
        self.assertEqual(math.inf, self._number('0x' + 'f' * 300))
        self.assertEqual(math.inf, self._number('0b' + '1' * 1100))

    def test_an_empty_string_names_zero_to_one_reader_and_no_number_to_the_other(self):
        for text in ['', ' ', '\t\n', '\xa0\u3000', '   \r\n\t  ']:
            with self.subTest(text=text):
                self.assertEqual(0.0, self._number(text))
                self.assertEqual('NaN', self._float(text))
                self.assertFalse(is_negative_zero(js_string_to_number(text)))

    def test_a_very_long_run_of_digits_names_the_double_it_denotes(self):
        self.assertEqual(math.inf, self._number('1' * 400))
        self.assertEqual(math.inf, self._float('1' * 400))
        self.assertEqual(-math.inf, self._number('-' + '1' * 400))
        self.assertEqual(-math.inf, self._float('-' + '1' * 400))
        self.assertEqual(math.inf, self._number('1' * 5000))
        self.assertEqual(0.0, self._number('0.' + '0' * 400 + '1'))
        self.assertEqual(0.0, self._number('0.' + '0' * 5000 + '1'))
        self.assertEqual(11111111111111110000.0, self._number('1' * 20 + '.' + '5' * 20))
        self.assertEqual(11111111111111110000.0, self._float('1' * 20 + '.' + '5' * 20))
        self.assertEqual('NaN', self._number('1' * 400 + 'x'))
        self.assertEqual(math.inf, self._float('1' * 400 + 'x'))

    def test_a_very_long_exponent_names_the_double_it_denotes(self):
        self.assertEqual(math.inf, self._number('1e' + '9' * 400))
        self.assertEqual(math.inf, self._float('1e' + '9' * 400))
        self.assertEqual(0.0, self._number('1e-' + '9' * 400))
        self.assertEqual(0.0, self._float('1e-' + '9' * 400))
        self.assertEqual(100000.0, self._number('1e' + '0' * 400 + '5'))
        self.assertEqual(1e-05, self._number('1e-' + '0' * 400 + '5'))
        self.assertEqual('NaN', self._number('1e' + '9' * 400 + 'x'))
        self.assertEqual(math.inf, self._float('1e' + '9' * 400 + 'x'))


class TestJsNumberToStringSpellsAnIntegerAsTheDoubleItDenotes(TestBase):

    def _spelled(self, value: int) -> str:
        return js_number_to_string(value)

    def test_an_integer_a_double_holds_exactly_keeps_every_digit_it_was_written_with(self):
        self.assertEqual('0', self._spelled(0))
        self.assertEqual('1', self._spelled(1))
        self.assertEqual('-1', self._spelled(-1))
        self.assertEqual('255', self._spelled(255))
        self.assertEqual('4294967296', self._spelled(2 ** 32))
        self.assertEqual('9007199254740991', self._spelled(2 ** 53 - 1))
        self.assertEqual('9007199254740992', self._spelled(2 ** 53))
        self.assertEqual('9007199254740994', self._spelled(2 ** 53 + 2))

    def test_an_integer_past_the_precision_of_a_double_is_spelled_as_its_nearest_one(self):
        """
        `String` writes the fewest digits that name the double and fills the rest with zeros, so
        `2 ** 63`, which a double holds exactly, prints as `9223372036854776000`.
        """
        self.assertEqual('9007199254740992', self._spelled(2 ** 53 + 1))
        self.assertEqual('-9007199254740992', self._spelled(-(2 ** 53 + 1)))
        self.assertEqual('9223372036854776000', self._spelled(2 ** 63))
        self.assertEqual('18446744073709552000', self._spelled(2 ** 64))
        self.assertEqual(
            '1.2345678901234568e+29', self._spelled(123456789012345678901234567890))
        self.assertEqual('1.2676506002282294e+30', self._spelled(2 ** 100))

    def test_an_integer_wide_enough_is_spelled_with_an_exponent_rather_than_its_digits(self):
        self.assertEqual('100000000000000000000', self._spelled(10 ** 20))
        self.assertEqual('1e+21', self._spelled(10 ** 21))
        self.assertEqual('1e+21', self._spelled(10 ** 21 + 1))
        self.assertEqual('1e+308', self._spelled(10 ** 308))
        self.assertEqual('8.98846567431158e+307', self._spelled(2 ** 1023))

    def test_an_integer_too_large_for_a_double_is_spelled_as_the_infinity_it_denotes(self):
        self.assertEqual('Infinity', self._spelled(10 ** 309))
        self.assertEqual('Infinity', self._spelled(2 ** 1024))
        self.assertEqual('-Infinity', self._spelled(-(2 ** 1024)))
        self.assertEqual('Infinity', self._spelled(10 ** 400))
        self.assertEqual('-Infinity', self._spelled(-(10 ** 400)))
        self.assertEqual('Infinity', self._spelled(int('1' * 400)))
        self.assertEqual('Infinity', self._spelled(2 ** 5000))


class TestThePaddingOfANumberIsTwoSetsReadAsOne(TestBase):

    def test_the_padding_of_a_number_is_the_whitespace_and_the_line_terminators_together(self):
        self.assertEqual(
            sorted(_spelled(LANGUAGE_WHITESPACE)), sorted(_spelled(TRIMMABLE_WHITESPACE)))
        self.assertEqual(len(set(TRIMMABLE_WHITESPACE)), len(TRIMMABLE_WHITESPACE))
