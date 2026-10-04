from __future__ import annotations

from refinery.lib.excel.formula.model import XlBinaryOperator
from refinery.lib.scripts.xlm import (
    XlmReference,
    XlmValue,
    apply_binary,
    concat,
    condition,
    unwrap_literal,
    wrap_literal,
)
from refinery.lib.scripts.xlm.values import error_value
from test import TestBase


class TestLiteralQuoting(TestBase):

    def test_texts_are_wrapped_with_their_quotes_doubled(self):
        self.assertEqual(wrap_literal('cache'), '"cache"')
        self.assertEqual(wrap_literal('say "hi"'), '"say ""hi"""')

    def test_numbers_keep_their_own_text(self):
        self.assertEqual(wrap_literal(5), '5')
        self.assertEqual(wrap_literal(1.0), '1.0')
        self.assertEqual(wrap_literal('12'), '12')

    def test_a_text_that_carries_quotes_keeps_them(self):
        self.assertEqual(wrap_literal('"spelled"'), '"spelled"')

    def test_forced_wrapping_redoubles_the_quotes_a_text_carries(self):
        self.assertEqual(wrap_literal('"spelled"', must_wrap=True), '"""spelled"""')
        self.assertEqual(wrap_literal('4', must_wrap=True), '4')

    def test_unwrapping_strips_quotes_and_undoubles_the_doubled_quote(self):
        self.assertEqual(unwrap_literal('"a""b"'), 'a"b')
        self.assertEqual(unwrap_literal('"spelled"'), 'spelled')
        self.assertEqual(unwrap_literal('plain'), 'plain')

    def test_the_reference_spelling_of_a_cell(self):
        self.assertEqual(XlmReference(None, 1, 1).a1(), 'A1')
        self.assertEqual(XlmReference('Sheet2', 2, 3).a1(), 'Sheet2!C2')


class TestValueText(TestBase):

    def test_a_value_without_text_prints_its_own_spelling(self):
        self.assertEqual(XlmValue(value=None).text, '')
        self.assertEqual(XlmValue(value=12).text, '12')
        self.assertEqual(XlmValue(value=12.0).text, '12')
        self.assertEqual(XlmValue(value=0.5).text, '0.5')
        self.assertEqual(XlmValue(value='x').text, '"x"')
        self.assertEqual(XlmValue(value=True).text, 'TRUE')

    def test_a_given_numeric_text_is_normalized(self):
        self.assertEqual(XlmValue(text='1e3').text, '1000')
        self.assertEqual(XlmValue(text='2.50').text, '2.5')
        self.assertEqual(XlmValue(text='25').text, '25')
        self.assertEqual(XlmValue(text='cache').text, 'cache')

    def test_unwrap_answers_the_text_without_literal_quotes(self):
        self.assertEqual(XlmValue(value='x').unwrap(), 'x')
        self.assertEqual(XlmValue().unwrap(), '')


class TestCondition(TestBase):

    def test_the_spellings_of_the_truth_values_answer_their_truth(self):
        self.assertEqual(condition(XlmValue(value=True)), True)
        self.assertEqual(condition(XlmValue(value=False)), False)
        self.assertEqual(condition(XlmValue(value='TRUE')), True)
        self.assertEqual(condition(XlmValue(value='false')), False)
        self.assertEqual(condition(XlmValue(value='False')), False)

    def test_a_number_holds_when_it_is_not_zero(self):
        self.assertEqual(condition(XlmValue(value=1)), True)
        self.assertEqual(condition(XlmValue(value=0)), False)
        self.assertEqual(condition(XlmValue(value=0.0)), False)
        self.assertEqual(condition(XlmValue(value=-2.5)), True)

    def test_a_text_that_spells_a_number_is_no_truth_value(self):
        self.assertEqual(condition(XlmValue(value='1')).text, '#VALUE!')
        self.assertEqual(condition(XlmValue(value='yes')).text, '#VALUE!')
        self.assertEqual(condition(XlmValue(value='A1:B2')).text, '#VALUE!')

    def test_a_value_that_holds_nothing_answers_false(self):
        self.assertEqual(condition(XlmValue()), False)
        self.assertEqual(condition(XlmValue(value='')), False)

    def test_an_error_value_answers_itself(self):
        self.assertEqual(condition(error_value('#DIV/0!')).text, '#DIV/0!')
        self.assertEqual(condition(error_value('#VALUE!')).error, True)


class TestConcat(TestBase):

    def test_full_values_join_their_texts(self):
        joined = concat(XlmValue(value='ab'), XlmValue(value='cd'))
        self.assertEqual(joined.text, '"abcd"')
        self.assertEqual(joined.partial, False)

    def test_a_partial_side_joins_the_texts_with_the_operator(self):
        left = XlmValue(value='x', partial=True)
        joined = concat(left, XlmValue(value='cd'))
        self.assertEqual(joined.text, 'x&cd')
        self.assertEqual(joined.partial, True)
        self.assertEqual(joined.value, 'x&cd')


class TestBinaryOperators(TestBase):

    def test_subtraction_of_integers(self):
        result = apply_binary(XlBinaryOperator.SUB, XlmValue(value=113), XlmValue(value=2))
        self.assertEqual(result.value, 111)
        self.assertEqual(result.text, '111')

    def test_division_and_the_rounding_of_the_quotient(self):
        whole = apply_binary(XlBinaryOperator.DIV, XlmValue(value=8), XlmValue(value=2))
        self.assertEqual(whole.text, '4')
        third = apply_binary(XlBinaryOperator.DIV, XlmValue(value=10), XlmValue(value=3))
        self.assertEqual(third.text, '3.3333333333')

    def test_a_division_by_zero_is_the_excel_error(self):
        result = apply_binary(XlBinaryOperator.DIV, XlmValue(value=1), XlmValue(value=0))
        self.assertEqual(result.text, '#DIV/0!')
        self.assertEqual(result.partial, False)

    def test_the_text_of_a_number_computes_as_one(self):
        result = apply_binary(XlBinaryOperator.ADD, XlmValue(value='5'), XlmValue(value=1))
        self.assertEqual(result.text, '6')

    def test_true_and_false_coerce_to_one_and_zero(self):
        true = apply_binary(XlBinaryOperator.ADD, XlmValue(value=True), XlmValue(value=1))
        self.assertEqual(true.text, '2')
        spelled = apply_binary(XlBinaryOperator.ADD, XlmValue(value='true'), XlmValue(value=1))
        self.assertEqual(spelled.text, '2')
        false = apply_binary(XlBinaryOperator.MUL, XlmValue(value='false'), XlmValue(value=5))
        self.assertEqual(false.text, '0')

    def test_an_empty_text_is_zero(self):
        result = apply_binary(XlBinaryOperator.ADD, XlmValue(), XlmValue(value=5))
        self.assertEqual(result.text, '5')

    def test_exponentiation(self):
        result = apply_binary(XlBinaryOperator.POW, XlmValue(value=2), XlmValue(value=10))
        self.assertEqual(result.text, '1024')

    def test_comparisons_answer_true_and_false(self):
        self.assertEqual(
            apply_binary(XlBinaryOperator.EQ, XlmValue(value='a'), XlmValue(value='a')).text,
            'TRUE',
        )
        self.assertEqual(
            apply_binary(XlBinaryOperator.GT, XlmValue(value=3), XlmValue(value=2)).text,
            'TRUE',
        )
        self.assertEqual(
            apply_binary(XlBinaryOperator.LT, XlmValue(value='a'), XlmValue(value='b')).text,
            'TRUE',
        )

    def test_a_failed_coercion_is_the_excel_error(self):
        result = apply_binary(XlBinaryOperator.SUB, XlmValue(value='a'), XlmValue(value='b'))
        self.assertEqual(result.text, '#VALUE!')

    def test_the_texts_of_dates_compare_as_moments(self):
        first = XlmValue(value='2017-12-27 00:00:00.000000')
        second = XlmValue(value='2017-12-28 00:00:00.000000')
        self.assertEqual(apply_binary(XlBinaryOperator.GT, second, first).text, 'TRUE')
        self.assertEqual(apply_binary(XlBinaryOperator.EQ, first, second).text, 'FALSE')

    def test_a_range_presents_its_corners(self):
        left = XlmValue(value=XlmReference(None, 1, 1))
        right = XlmValue(value=XlmReference(None, 2, 2))
        result = apply_binary(XlBinaryOperator.RANGE, left, right)
        self.assertEqual(result.value, 'A1:B2')
        self.assertEqual(result.cells, (left, right))
        self.assertEqual(result.partial, False)

    def test_partial_operands_spell_the_operation_unevaluated(self):
        left = XlmValue(value='x', partial=True)
        result = apply_binary(XlBinaryOperator.ADD, left, XlmValue(value=1))
        self.assertEqual(result.text, 'x+1')
        self.assertEqual(result.partial, True)

    def test_intersection_and_union_stay_partial(self):
        left = XlmValue(value='A1')
        right = XlmValue(value='B2')
        isect = apply_binary(XlBinaryOperator.ISECT, left, right)
        self.assertEqual(isect.value, 'A1 B2')
        self.assertEqual(isect.partial, True)
        union = apply_binary(XlBinaryOperator.UNION, left, right)
        self.assertEqual(union.value, 'A1,B2')
        self.assertEqual(union.partial, True)
