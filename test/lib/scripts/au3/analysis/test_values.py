"""
The value domain against the AutoIt3 interpreter. Every expected answer below is a literal an
AutoIt3 probe printed (`temp/au3_semantics_probe/`, version 3.3.18.0), so a change in the value
layer either breaks a probe fact or is a behavior change the interpreter never pinned. Where the
probe could not distinguish two readings, the expected answer is `None` — the refusal — and the
case says which readings fit.

The functions under test are the ones the constant folder reads, so a value reaches them exactly
the way the folder delivers one: parsed out of AutoIt3 source by `literal_value`, then combined
by `compare` or `apply_binary`, or fed to a builtin by `evaluate_builtin`. What is asserted is
the value's printed text, which is what the probes observed and what a folded literal spells.
Where a probe read a number's type off `VarGetType`, the assertion is a witness — the printed
text, `IsInt`, `IsFloat`, and `Hex` of the same value — because `Hex` is the one reading that
separates an Int from a Double holding a whole number.
"""
from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Expression
from refinery.lib.scripts.au3.analysis.builtins import evaluate_builtin
from refinery.lib.scripts.au3.analysis.values import (
    apply_binary,
    apply_unary,
    compare,
    literal_value,
    of_bool,
    of_string,
    render_literal,
    to_string,
    truthy,
)
from refinery.lib.scripts.au3.parser import Au3Parser


def _value(source: str):
    return literal_value(Au3Parser(source).parse_expression(), frozenset())


class TestAu3Values(TestBase):

    @staticmethod
    def _printed(result):
        return None if result is None else to_string(result)

    def _compared(self, operator: str, one: str, two: str):
        return self._printed(compare(operator, _value(one), _value(two)))

    def _applied(self, operator: str, one: str, two: str):
        return self._printed(apply_binary(operator, _value(one), _value(two)))

    def _called(self, name: str, *sources: str):
        return self._printed(evaluate_builtin(name, tuple(_value(s) for s in sources)))

    def _witnessed(self, result):
        """
        The four readings a probe took of a number: its printed text, `IsInt`, `IsFloat`, and
        `Hex`. `Hex` is the only one that separates an Int from a Double holding a whole number,
        because `IsInt` answers 1 over both (probe6 53, 54).
        """
        if result is None:
            return None
        readings = [to_string(result)]
        for name in ('isint', 'isfloat', 'hex'):
            witness = evaluate_builtin(name, (result,))
            readings.append(None if witness is None else to_string(witness))
        return tuple(readings)

    def _typed(self, operator: str, one: str, two: str):
        return self._witnessed(apply_binary(operator, _value(one), _value(two)))

    def _typed_call(self, name: str, *sources: str):
        return self._witnessed(evaluate_builtin(name, tuple(_value(s) for s in sources)))

    def test_two_strings_compare_case_insensitively(self):
        for operator, one, two, expected in (
            ('=', '"abc"', '"ABC"', 'True'),
            ('=', '"10"', '"10.0"', 'False'),
            ('=', '""', '"0"', 'False'),
            ('==', '"abc"', '"ABC"', 'False'),
            ('==', '"10"', '"10.0"', 'False'),
            ('==', '""', '"0"', 'False'),
        ):
            with self.subTest(operator=operator, one=one, two=two):
                self.assertEqual(self._compared(operator, one, two), expected)

    def test_a_boolean_operand_makes_equality_boolean(self):
        """
        With `=`, both sides go to their truth (`False = "False"` is false because a non-empty
        string is true); with `==`, both sides go to their text and compare case-sensitively.
        """
        for operator, one, two, expected in (
            ('=', 'False', '""', 'True'),
            ('=', 'True', '"true"', 'True'),
            ('=', 'False', '"False"', 'False'),
            ('=', 'True', '"True "', 'True'),
            ('=', 'True', '1', 'True'),
            ('=', 'True', '-1', 'True'),
            ('=', '0', '""', 'True'),
            ('=', '0', '"abc"', 'True'),
            ('=', '1', '"1"', 'True'),
            ('=', '1', '"1.0"', 'True'),
            ('==', 'True', '"true"', 'False'),
            ('==', 'True', '"True"', 'True'),
            ('==', 'True', '1', 'False'),
            ('==', '1', '1.0', 'True'),
            ('==', '"1"', '1', 'True'),
            ('=', '"1"', '1', 'True'),
        ):
            with self.subTest(operator=operator, one=one, two=two):
                self.assertEqual(self._compared(operator, one, two), expected)

    def test_the_relationals_read_two_strings_as_text(self):
        for operator, one, two, expected in (
            ('>', '"10"', '"9"', 'False'),
            ('>', '10', '"9"', 'True'),
            ('>', '"abc"', '1', 'False'),
            ('<', '"2"', '"10"', 'False'),
            ('>', '"True"', '"false"', 'True'),
            ('>', '"a"', '"B"', 'False'),
        ):
            with self.subTest(operator=operator, one=one, two=two):
                self.assertEqual(self._compared(operator, one, two), expected)

    def test_the_relationals_refuse_a_boolean_operand(self):
        """
        Numeric and case-insensitive-text both fit every probe answer (`True > "abc"` is true
        either way), so which one AutoIt applies is not a fact any probe pinned.
        """
        for operator, one, two in (
            ('>', 'True', '"abc"'),
            ('>', 'True', '0'),
            ('<=', 'False', 'True'),
        ):
            with self.subTest(operator=operator, one=one, two=two):
                self.assertIsNone(self._compared(operator, one, two))

    def test_arithmetic_coerces_strings_by_prefix(self):
        for operator, one, two, expected in (
            ('+', '"5"', '"6"', '11'),
            ('+', '"abc"', '1', '1'),
            ('+', '"True"', '1', '1'),
            ('*', '"3.14"', '2', '6.28'),
            ('+', '"1e1"', '0', '10'),
            ('+', 'True', 'True', '2'),
            ('/', '10', '4', '2.5'),
            ('/', '10', '2', '5'),
            ('^', '2', '10', '1024'),
            ('^', '2', '0.5', '1.4142135623731'),
            ('^', '-2', '2', '4'),
            ('^', '2', '-1', '0.5'),
            ('^', '2', '62', '4.61168601842739e+18'),
            ('+', '99999999999999999999', '0', '9223372036854775807'),
        ):
            with self.subTest(operator=operator, one=one, two=two):
                self.assertEqual(self._applied(operator, one, two), expected)

    def test_arithmetic_types_by_operand_position(self):
        """
        The left operand keeps its type — a string stays the number its text spells, a boolean
        becomes a double — and a string or a boolean on the right makes the whole result a double
        (probe6 10-17, 30-33, 40-46; probe7 10-18).
        """
        for operator, one, two, expected in (
            ('+', '5', '"2"', ('7', '1', '0', '401C000000000000')),
            ('+', '"5"', '"6"', ('11', '1', '0', '4026000000000000')),
            ('*', '"5"', '2', ('10', '1', '0', '0000000A')),
            ('-', '"5"', '0', ('5', '1', '0', '00000005')),
            ('+', '5', '"2.5"', ('7.5', '0', '1', '401E000000000000')),
            ('+', '"abc"', '1', ('1', '1', '0', '00000001')),
            ('+', '"0x10"', '0', ('16', '1', '0', '00000010')),
            ('+', '"1e3"', '0', ('1000', '1', '0', '408F400000000000')),
            ('+', 'True', '1', ('2', '1', '0', '4000000000000000')),
            ('+', 'True', 'True', ('2', '1', '0', '4000000000000000')),
            ('*', 'True', '2.5', ('2.5', '0', '1', '4004000000000000')),
            ('+', '5', '2', ('7', '1', '0', '00000007')),
            ('+', '1', '2147483647', ('2147483648', '1', '0', '0000000080000000')),
            ('-', '5', '5.0', ('0', '1', '0', '00000000')),
            ('*', '5', '"2"', ('10', '1', '0', '4024000000000000')),
            ('-', '5', '"2"', ('3', '1', '0', '4008000000000000')),
            ('*', '"5"', '"2"', ('10', '1', '0', '4024000000000000')),
            ('-', '"5"', '"2"', ('3', '1', '0', '4008000000000000')),
            ('+', '1', 'True', ('2', '1', '0', '4000000000000000')),
            ('*', '2', 'True', ('2', '1', '0', '4000000000000000')),
            ('-', '2', 'False', ('2', '1', '0', '4000000000000000')),
            ('+', '"2"', 'True', ('3', '1', '0', '4008000000000000')),
            ('+', 'True', '"2"', ('3', '1', '0', '4008000000000000')),
        ):
            with self.subTest(operator=operator, one=one, two=two):
                self.assertEqual(self._typed(operator, one, two), expected)

    def test_a_left_string_past_the_int64_range_is_refused(self):
        """
        The number literal saturates at int64 max (probe3 60), but whether the interpreter
        saturates or promotes a string spelling past it is not a fact any probe pinned, so the
        left-operand reading refuses.
        """
        self.assertIsNone(apply_binary('+', _value('"99999999999999999999"'), _value('0')))

    def test_a_sign_types_like_a_left_operand(self):
        """
        `-"2"` is an Int32 while `-"2.5"` and `-True` are doubles (probe6 18, 32; probe7 19).
        """
        self.assertEqual(
            self._witnessed(apply_unary('-', _value('"2"'))), ('-2', '1', '0', 'FFFFFFFE'))
        self.assertEqual(
            self._witnessed(apply_unary('-', _value('"2.5"'))),
            ('-2.5', '0', '1', 'C004000000000000'))
        self.assertEqual(
            self._witnessed(apply_unary('-', _value('True'))), ('-1', '1', '0', 'BFF0000000000000'))

    def test_mod_types_by_argument_kind(self):
        """
        `Mod` types by the value kinds of its arguments, not by the arithmetic operand
        positions: an integer only when both arguments are Int values, and a double once any
        argument is a double, a string, or a boolean (probe6 19; probe7 20-25).
        """
        for sources, expected in (
            (('7', '2'), ('1', '1', '0', '00000001')),
            (('7.0', '2'), ('1', '1', '0', '3FF0000000000000')),
            (('"7"', '"2"'), ('1', '1', '0', '3FF0000000000000')),
            (('7', '"2"'), ('1', '1', '0', '3FF0000000000000')),
            (('True', '2'), ('1', '1', '0', '3FF0000000000000')),
            (('7', '2.0'), ('1', '1', '0', '3FF0000000000000')),
            (('"7"', '2'), ('1', '1', '0', '3FF0000000000000')),
        ):
            with self.subTest(sources=sources):
                self.assertEqual(self._typed_call('mod', *sources), expected)

    def test_builtin_result_types(self):
        """
        `Int`, `Floor`, `Ceiling`, one-argument `Round`, `Asc`, `Dec`, the bitwise family, and
        `Number` over an integer text answer integers — over numbers, strings and booleans
        alike — while `Abs`, `Sqrt` and the two-argument `Round` answer doubles (probe6 42, 43,
        45; probe7 40-55; probe8 10-31).
        """
        for name, sources, expected in (
            ('int', ('7.5',), ('7', '1', '0', '00000007')),
            ('floor', ('2.5',), ('2', '1', '0', '00000002')),
            ('ceiling', ('2.5',), ('3', '1', '0', '00000003')),
            ('round', ('2.5',), ('3', '1', '0', '00000003')),
            ('round', ('2.25', '1'), ('2.3', '0', '1', '4002666666666666')),
            ('abs', ('-2',), ('2', '1', '0', '4000000000000000')),
            ('abs', ('-2.5',), ('2.5', '0', '1', '4004000000000000')),
            ('sqrt', ('4',), ('2', '1', '0', '4000000000000000')),
            ('asc', ('"A"',), ('65', '1', '0', '00000041')),
            ('dec', ('"FF"',), ('255', '1', '0', '000000FF')),
            ('bitxor', ('5', '1'), ('4', '1', '0', '00000004')),
            ('bitand', ('7.0', '3'), ('3', '1', '0', '00000003')),
            ('bitnot', ('0',), ('-1', '1', '0', 'FFFFFFFF')),
            ('int', ('"7"',), ('7', '1', '0', '00000007')),
            ('number', ('"2"',), ('2', '1', '0', '00000002')),
            ('number', ('"2.0"',), ('2', '1', '0', '4000000000000000')),
            ('number', ('" 7"',), ('7', '1', '0', '00000007')),
            ('stringlen', ('"ab"',), ('2', '1', '0', '00000002')),
            ('floor', ('"2.5"',), ('2', '1', '0', '00000002')),
            ('abs', ('"-2"',), ('2', '1', '0', '4000000000000000')),
            ('floor', ('"7"',), ('7', '1', '0', '00000007')),
            ('floor', ('"2"',), ('2', '1', '0', '00000002')),
            ('floor', ('"abc"',), ('0', '1', '0', '00000000')),
            ('floor', ('7.0',), ('7', '1', '0', '00000007')),
            ('floor', ('7',), ('7', '1', '0', '00000007')),
            ('floor', ('True',), ('1', '1', '0', '00000001')),
            ('ceiling', ('"2.5"',), ('3', '1', '0', '00000003')),
            ('ceiling', ('"7"',), ('7', '1', '0', '00000007')),
            ('ceiling', ('7.0',), ('7', '1', '0', '00000007')),
            ('ceiling', ('True',), ('1', '1', '0', '00000001')),
            ('round', ('"2.5"',), ('3', '1', '0', '00000003')),
            ('round', ('"2.25"', '1'), ('2.3', '0', '1', '4002666666666666')),
            ('round', ('2.5', '0'), ('3', '1', '0', '4008000000000000')),
            ('round', ('7.0',), ('7', '1', '0', '00000007')),
            ('round', ('True',), ('1', '1', '0', '00000001')),
            ('int', ('"7.5"',), ('7', '1', '0', '00000007')),
            ('int', ('"abc"',), ('0', '1', '0', '00000000')),
            ('int', ('7.0',), ('7', '1', '0', '00000007')),
            ('int', ('True',), ('1', '1', '0', '00000001')),
            ('sqrt', ('"4"',), ('2', '1', '0', '4000000000000000')),
            ('sqrt', ('True',), ('1', '1', '0', '3FF0000000000000')),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._typed_call(name, *sources), expected)

    def test_two_argument_round_over_an_integer_is_refused(self):
        """
        The two-argument `Round` is pinned only over a fractional first argument (probe7 44;
        probe8 22, 23), so an integer one — where AutoIt might answer the integer back — is not
        a reading any probe pinned and refuses.
        """
        self.assertIsNone(evaluate_builtin('round', (_value('7'), _value('0'))))

    def test_the_is_family_answers_integers(self):
        """
        The `Is…` functions answer the integers 1 and 0, never a boolean (probe6 53, 54; probe7
        30-38; probe8 40-45).
        """
        for name, source, expected in (
            ('isint', '5', '1'),
            ('isstring', '"a"', '1'),
            ('isbool', 'True', '1'),
            ('isarray', '0', '0'),
            ('isfloat', '2.5', '1'),
            ('isint', '"5"', '0'),
            ('isnumber', '"5"', '0'),
            ('isint', '2.5', '0'),
            ('isfloat', '5', '0'),
            ('isfloat', '"5"', '0'),
            ('isfloat', '"2.5"', '0'),
            ('isfloat', '"abc"', '0'),
            ('isnumber', '"2.5"', '0'),
            ('isint', '"2.5"', '0'),
            ('isbool', '"1"', '0'),
            ('isint', '7.0', '1'),
            ('isfloat', '7.0', '0'),
        ):
            with self.subTest(name=name, source=source):
                self.assertEqual(self._called(name, source), expected)

    def test_the_is_family_refuses_a_boolean_operand(self):
        """
        `IsInt`, `IsFloat`, and `IsNumber` over a boolean are not readings any probe pinned —
        the probes covered numbers and strings only — so they refuse rather than guess.
        """
        self.assertIsNone(evaluate_builtin('isint', (_value('True'),)))
        self.assertIsNone(evaluate_builtin('isfloat', (_value('True'),)))
        self.assertIsNone(evaluate_builtin('isnumber', (_value('True'),)))

    def test_hex_reads_a_double_as_its_bits(self):
        """
        `Hex` over a double is the hex of its 64-bit IEEE bits read as a signed int64, and an
        explicit length keeps the rightmost digits exactly as for integers (probe7 60-64).
        """
        for sources, expected in (
            (('7.0',), '401C000000000000'),
            (('-1.0',), 'BFF0000000000000'),
            (('2.5',), '4004000000000000'),
            (('7.0', '4'), '0000'),
            (('7.0', '8'), '00000000'),
        ):
            with self.subTest(sources=sources):
                self.assertEqual(self._called('hex', *sources), expected)

    def test_and_or_answer_a_boolean(self):
        """
        In expression position `And` and `Or` answer a boolean whatever the operands' kinds
        (probe4 62-65).
        """
        self.assertEqual(self._applied('and', '1', '2'), 'True')
        self.assertEqual(self._applied('or', '0', '""'), 'False')
        self.assertEqual(self._applied('and', '"abc"', '1'), 'True')
        self.assertEqual(self._applied('or', '1', '0'), 'True')

    def test_division_by_zero_is_refused(self):
        """
        The probe terminated at `1 / 0`: a division by zero is fatal in AutoIt, so folding it
        would remove a crash the original script had.
        """
        self.assertIsNone(apply_binary('/', _value('1'), _value('0')))

    def test_a_double_prints_like_the_interpreter(self):
        for one, two, operator, expected in (
            ('1', '3', '/', '0.333333333333333'),
            ('0.1', '0.2', '+', '0.3'),
        ):
            with self.subTest(one=one, two=two):
                self.assertEqual(self._applied(operator, one, two), expected)

    def test_concatenation_joins_the_printed_text(self):
        for one, two, expected in (
            ('"a"', '"b"', 'ab'),
            ('1.0', '""', '1'),
            ('True', '""', 'True'),
            ('False', '""', 'False'),
            ('100000000000000000', '""', '100000000000000000'),
            ('1e15', '""', '1e+15'),
            ('1e21', '""', '1e+21'),
            ('0x7FFFFFFFFFFFFFFF', '""', '9223372036854775807'),
            ('99999999999999999999', '""', '9223372036854775807'),
        ):
            with self.subTest(one=one, two=two):
                self.assertEqual(self._applied('&', one, two), expected)

    def test_concatenation_with_a_binary_operand(self):
        """
        A binary value reaches an operator the same way the folder delivers one: through the
        builtin table, which is what `Binary("0x43")` folds through before anything reads it.
        """
        def binary(digits):
            return evaluate_builtin('binary', (_value(F'"{digits}"'),))
        appended = apply_binary('&', _value('"AB"'), binary('0x43'))
        self.assertEqual(self._printed(appended), 'AB0x43')
        joined = apply_binary('&', binary('0x41'), binary('0x42'))
        self.assertEqual(self._printed(joined), '0x4142')

    def test_concatenation_onto_a_binary_is_refused(self):
        """
        `Binary("0x4142") & "CD"` printed `0x4142CD` — the string appended as hex text — and
        `Binary("0x41") & 66` printed `0x4166`, but a binary and a plain string carrying the
        result both fit every probe answer, so the result type is not a fact any probe pinned.
        """
        def binary(digits):
            return evaluate_builtin('binary', (_value(F'"{digits}"'),))
        for source in ('"CD"', '66'):
            with self.subTest(source=source):
                self.assertIsNone(apply_binary('&', binary('0x4142'), _value(source)))

    def test_not_inverts_the_truth(self):
        self.assertEqual(self._printed(apply_unary('not', _value('True'))), 'False')
        self.assertEqual(self._printed(apply_unary('not', _value('0'))), 'True')

    def test_a_boolean_prints_its_keyword(self):
        self.assertEqual(to_string(of_bool(True)), 'True')
        self.assertEqual(to_string(of_bool(False)), 'False')
        self.assertEqual(self._called('string', 'True'), 'True')
        self.assertEqual(self._called('string', 'False'), 'False')

    def test_the_truth_of_every_literal_kind(self):
        for source, expected in (
            ('"abc"', True),
            ('""', False),
            ('"0"', True),
            ('"0.0"', True),
            ('"00"', True),
            ('0', False),
            ('1', True),
            ('0.0', False),
            ('True', True),
            ('False', False),
        ):
            with self.subTest(source=source):
                self.assertIs(truthy(_value(source)), expected)
        empty_binary = evaluate_builtin('binary', (_value('"0x00"'),))
        self.assertIs(truthy(empty_binary), True)

    def test_conversion_functions(self):
        for name, sources, expected in (
            ('int', ('-1.5',), '-1'),
            ('int', ('1.9',), '1'),
            ('int', ('"10.9"',), '10'),
            ('floor', ('-1.5',), '-2'),
            ('ceiling', ('-1.5',), '-1'),
            ('number', ('"3.14e2"',), '314'),
            ('number', ('"abc"',), '0'),
            ('number', ('"0x10"',), '16'),
            ('number', ('"True"',), '0'),
            ('number', ('"False"',), '0'),
            ('number', ('"10abc"',), '10'),
            ('number', ('" 10 "',), '10'),
            ('number', ('"-.5"',), '-0.5'),
            ('number', ('"+.5"',), '0.5'),
            ('number', ('"0x"',), '0'),
            ('number', ('"1e"',), '1'),
            ('number', ('"0b101"',), '0'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_number_with_a_flag_is_refused(self):
        """
        `Number("0x10", 1)` printed `16` — the same answer as without the flag — and what the
        flag changes on any other input is not a fact any probe pinned, so the two-argument call
        is refused rather than guessed.
        """
        self.assertIsNone(
            evaluate_builtin('number', (_value('"0x10"'), _value('1'))))

    def test_bitwise_functions_work_on_32_bits(self):
        for name, sources, expected in (
            ('bitnot', ('0',), '-1'),
            ('bitnot', ('1',), '-2'),
            ('bitxor', ('0xFFFFFFFF', '0'), '-1'),
            ('bitshift', ('1', '60'), '0'),
            ('bitshift', ('-1', '1'), '-1'),
            ('bitrotate', ('1', '4'), '16'),
            ('bitand', ('0xFFFFFFFFFFFFFFFF', '255'), '255'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_chr_answers_by_code_point_limit(self):
        for name, sources, expected in (
            ('chr', ('321',), ''),
            ('chr', ('65',), 'A'),
            ('chr', ('-1',), '￿'),
            ('chr', ('255',), 'ÿ'),
            ('chr', ('0',), '\x00'),
            ('chrw', ('65601',), ''),
            ('chrw', ('-1',), '￿'),
            ('asc', ('"AB"',), '65'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_ascw_answers_the_first_utf16_code_unit(self):
        """
        `AscW` is codepage-independent: the code unit of the first character — the high surrogate
        of one beyond the BMP — and zero over the empty string (probe10).
        """
        for sources, expected in (
            (('"A"',), '65'),
            (('"é"',), '233'),
            (('"\U00010437"',), '55297'),
            (('""',), '0'),
        ):
            with self.subTest(sources=sources):
                self.assertEqual(self._called('ascw', *sources), expected)

    def test_dec_and_hex_answer_in_the_probed_widths(self):
        for name, sources, expected in (
            ('dec', ('"FF"',), '255'),
            ('dec', ('"FFFFFFFF"', '1'), '-1'),
            ('dec', ('"FFFFFFFF"', '2'), '4294967295'),
            ('hex', ('255', '2'), 'FF'),
            ('hex', ('-1',), 'FFFFFFFF'),
            ('hex', ('0x123456789',), '0000000123456789'),
            ('hex', ('-1', '16'), 'FFFFFFFFFFFFFFFF'),
            ('hex', ('0x123456789', '4'), '6789'),
            ('hex', ('0x123456789ABCDEF',), '0123456789ABCDEF'),
            ('hex', ('255',), '000000FF'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_mod_answers_with_the_sign_of_the_dividend(self):
        for sources, expected in (
            (('-5', '3'), '-2'),
            (('5', '-3'), '2'),
            (('-5.5', '2'), '-1.5'),
        ):
            with self.subTest(sources=sources):
                self.assertEqual(self._called('mod', *sources), expected)

    def test_mod_refuses_an_operand_beyond_the_exact_integers(self):
        """
        An integer past the double mantissa loses its low bits on the way through the remainder,
        and the interpreter's own reading of such operands is not a fact any probe pinned.
        """
        self.assertIsNone(evaluate_builtin('mod', (_value('9007199254740993'), _value('2'))))

    def test_hex_refuses_a_length_beyond_sixteen(self):
        """
        Sixteen digits is the widest int64 hex the probes pinned; a wider request would have to
        spell a number the parser saturates, so it is refused rather than padded.
        """
        self.assertIsNone(self._called('hex', '255', '17'))

    def test_a_non_ascii_digit_is_not_a_number_prefix(self):
        """
        Python's `str.isdigit` admits characters beyond the ASCII digits; AutoIt's prefix reader
        stops at the first one, so a superscript two is the number zero and never a crash.
        """
        self.assertEqual(self._applied('+', '"²"', '1'), '1')

    def test_an_infinite_float_literal_is_not_a_value(self):
        """
        A decimal literal past the double range parses as infinity in Python; no AutoIt literal
        spells it, so the walk refuses it before any builtin sees it.
        """
        self.assertIsNone(_value('1e999'))

    def test_case_insensitive_text_refuses_non_ascii_operands(self):
        """
        Python's `lower` widens U+0130 to two characters where AutoIt folds only the ASCII range,
        so which position a search or comparison answers over non-ASCII text is not a fact any
        probe pinned.
        """
        self.assertIsNone(self._called('stringinstr', '"aİb"', '"b"'))
        self.assertIsNone(self._compared('=', '"aİ"', '"ai"'))

    def test_a_trim_past_the_end_empties_the_string(self):
        """
        AutoIt removes the count or the whole string, whichever is smaller; a Python slice over
        the negative remainder would wrap and keep a tail instead.
        """
        for name, sources, expected in (
            ('stringtrimright', ('"abcde"', '7'), ''),
            ('stringtrimleft', ('"abcde"', '7'), ''),
            ('stringright', ('"abcde"', '7'), 'abcde'),
            ('stringleft', ('"abcde"', '7'), 'abcde'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_string_functions(self):
        for name, sources, expected in (
            ('stringmid', ('"Hello"', '2', '3'), 'ell'),
            ('stringinstr', ('"aAbB"', '"b"'), '3'),
            ('stringinstr', ('"aB"', '"b"'), '2'),
            ('stringinstr', ('"aAbB"', '"b"', '1'), '3'),
            ('stringinstr', ('"aB"', '"b"', '1'), '0'),
            ('stringreplace', ('"AaA"', '"a"', '"b"'), 'bbb'),
            ('stringleft', ('"Hello"', '0'), ''),
            ('stringlen', ('"Hello"',), '5'),
            ('stringupper', ('"aB"',), 'AB'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_binary_functions(self):
        for name, sources, expected in (
            ('binarytostring', ('"0x414243"', '1'), 'ABC'),
            ('binarytostring', ('"0x41004200"', '2'), 'AB'),
            ('binarytostring', ('"AB"',), 'AB'),
            ('stringtobinary', ('"AB"', '1'), '0x4142'),
            ('binary', ('"0x41"',), '0x41'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_a_binary_call_reads_back_as_its_value(self):
        """
        `Binary("0x41")` is the spelling `render_literal` writes for a binary, so it reads back
        as one — unless a script function named `Binary` shadows the builtin, in which case the
        call would run foreign code and is not a literal.
        """
        value = literal_value(Au3Parser('Binary("0x41")').parse_expression(), frozenset())
        self.assertEqual(self._printed(value), '0x41')
        shadowed = literal_value(
            Au3Parser('Binary("0x41")').parse_expression(), frozenset({'binary'}))
        self.assertIsNone(shadowed)

    def test_a_string_no_literal_spells_reads_back_as_its_chain(self):
        """
        The `&` chain `render_literal` writes for a string holding a character no literal
        expresses reads back as that string, so the pair stays symmetric and a fold re-rendering
        such a chain spells the text it already holds.
        """
        for source, text in (
            ('"a" & @CRLF & "b"', 'a\r\nb'),
            ('"a" & @CR & "b" & Chr(0)', 'a\rb\x00'),
            ('ChrW(55296) & "x"', '\ud800x'),
            ('"x" & ChrW(8232)', 'x '),
        ):
            with self.subTest(source=source):
                value = literal_value(Au3Parser(source).parse_expression(), frozenset())
                self.assertEqual(self._printed(value), text)

    def test_a_chain_piece_is_refused_when_its_builtin_is_shadowed(self):
        self.assertIsNone(
            literal_value(Au3Parser('"a" & Chr(0)').parse_expression(), frozenset({'chr'})))

    def test_a_shared_memo_answers_what_an_unmemoized_read_answers(self):
        """
        The constant evaluator shares one memo across every read of a tree, so a read through it
        answers exactly the value the same node answers without one — refusals included — both
        when the memo fills around the node's own descent and when it answers from a full memo.
        """
        tree = Au3Parser(
            '$x = "a" & "b" & @CR & Chr(0) & Binary("0x41") & $y & -1 & True & [1, "s"] & f(1)\n'
        ).parse()
        expressions = [node for node in tree.walk() if isinstance(node, Expression)]
        memo: dict = {}
        for expression in expressions:
            self.assertEqual(
                literal_value(expression, frozenset(), memo),
                literal_value(expression, frozenset()))
        for expression in expressions:
            self.assertEqual(
                literal_value(expression, frozenset(), memo),
                literal_value(expression, frozenset()))
        self.assertIsNone(
            literal_value(
                Au3Parser('"a" & ChrW(55296)').parse_expression(), frozenset({'chrw'})))

    def test_rendering_a_string_no_literal_spells_round_trips(self):
        for text in ('a\r\nb\x00', '\ud800x', 'x ', '\r', '\n'):
            with self.subTest(text=repr(text)):
                rendered = render_literal(of_string(text), frozenset())
                self.assertEqual(self._printed(literal_value(rendered, frozenset())), text)

    def test_rendering_a_string_no_literal_spells_is_refused_under_a_shadow(self):
        self.assertIsNone(render_literal(of_string('\x00'), frozenset({'chr'})))
        self.assertIsNone(render_literal(of_string('\ud800'), frozenset({'chrw'})))

    def test_a_number_argument_to_a_binary_function_is_refused(self):
        """
        `BinaryToString(0x4142)` printed `AB`, which the number's hex text and its big-endian
        bytes both explain and nothing in the probes distinguishes, so the coercion is refused
        rather than guessed.
        """
        self.assertIsNone(evaluate_builtin('binarytostring', (_value('0x4142'),)))

    def test_string_split_answers_the_probed_shapes(self):
        split = evaluate_builtin('stringsplit', (_value('"a,b,c"'), _value('","')))
        self.assertEqual(
            [to_string(element) for element in split.payload], ['3', 'a', 'b', 'c'])
        self.assertEqual(self._printed(evaluate_builtin('ubound', (split,))), '4')
        no_count = evaluate_builtin(
            'stringsplit', (_value('"a,b,c"'), _value('","'), _value('2')))
        self.assertEqual([to_string(element) for element in no_count.payload], ['a', 'b', 'c'])
        empty = evaluate_builtin('stringsplit', (_value('""'), _value('","')))
        self.assertEqual([to_string(element) for element in empty.payload], ['1', ''])
        empty_no_count = evaluate_builtin(
            'stringsplit', (_value('""'), _value('","'), _value('2')))
        self.assertEqual(len(empty_no_count.payload), 1)
        per_char = evaluate_builtin('stringsplit', (_value('"abc"'), _value('""')))
        self.assertEqual(
            [to_string(element) for element in per_char.payload], ['3', 'a', 'b', 'c'])

    def test_execute_has_no_evaluator(self):
        """
        The probes pinned what `Execute` answers over unparseable and unknown-callee input, and
        those answers are structural: this layer never emulates the call, so a fold can only
        leave it standing.
        """
        self.assertIsNone(evaluate_builtin('execute', (_value('"1 + 1"'),)))
