from __future__ import annotations

from refinery.lib.excel import parse_formula
from refinery.lib.scripts.xlm import XlmCursor, XlmEngine, XlmView
from refinery.lib.scripts.xlm.trace import XlmStatus
from test import TestBase
from test.lib.excel.samples import XLM_MACRO_TEXT_XLSM
from test.lib.scripts.xlm.test_engine import _steps, _with_cell_formula

_CURSOR = XlmCursor('Doc1', 109, 52)


def _answer(formula: str):
    engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
    return engine.call(parse_formula(formula), _CURSOR)


class TestNumericCommands(TestBase):

    def test_arithmetic_commands_answer_their_numbers(self):
        for formula, expected in [
            ('ABS(-3)', '3'),
            ('INT(4.7)', '4'),
            ('SQRT(10)', '3'),
            ('TRUNC(-4.7)', '-4'),
            ('ROUND(3.14159,2)', '3.14'),
            ('ROUNDUP(3.1)', '4'),
            ('MOD(7,2)', '1'),
            ('SUM(1,2,3)', '6'),
            ('PRODUCT(2,3)', '6'),
            ('MAX(0,5)', '5'),
            ('VALUE("42")', '42'),
            ('_xlfn.ARABIC("XIV")', '14'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_quotient_divides_both_of_its_operands(self):
        outcome = _answer('QUOTIENT(7,2)')
        self.assertEqual(outcome.value.text, '3')
        self.assertEqual(outcome.status, None)

    def test_max_keeps_a_zero_result(self):
        outcome = _answer('MAX(-1,0)')
        self.assertEqual(outcome.value.text, '0')
        self.assertEqual(outcome.status, None)

    def test_a_partial_operand_leaves_mod_unevaluated(self):
        steps = _steps(('AZ110', 'MOD(FOO(1),2)'))
        self.assertEqual(steps[1].status, XlmStatus.PartialEvaluation)
        self.assertEqual(steps[1].text, 'MOD(FOO(1),2)')

    def test_now_advances_two_seconds_per_call(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        first = engine.call(parse_formula('NOW()'), _CURSOR).value.value
        second = engine.call(parse_formula('NOW()'), _CURSOR).value.value
        self.assertAlmostEqual((second - first) * 86400, 2, delta=1)

    def test_iserror_flips_after_ten_repeats_at_one_cell(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        call = parse_formula('ISERROR(1)')
        answers = [engine.call(call, _CURSOR).value.value for _ in range(12)]
        self.assertEqual(answers, [False] * 10 + [True, False])

    def test_value_rejects_a_text_that_spells_no_number(self):
        outcome = _answer('VALUE("x")')
        self.assertEqual(outcome.status, XlmStatus.Error)
        self.assertEqual(outcome.value.value, 0)

    def test_arabic_degrades_a_text_that_is_no_roman_numeral(self):
        outcome = _answer('_xlfn.ARABIC("junk")')
        self.assertEqual(outcome.value.partial, True)
        self.assertEqual(outcome.value.text, '_xlfn.ARABIC("junk")')

    def test_logic_commands_answer_the_truth_of_their_arguments(self):
        for formula, expected in [
            ('AND(TRUE,TRUE)', 'True'),
            ('AND(TRUE,FALSE)', 'False'),
            ('OR(FALSE,TRUE)', 'True'),
            ('OR(FALSE,FALSE)', 'False'),
            ('NOT(TRUE)', 'False'),
            ('COUNT(1,2,3)', '3'),
            ('ISNUMBER(1)', '1'),
            ('ISNUMBER("a")', '0'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)


class TestStringCommands(TestBase):

    def test_string_commands_answer_their_texts(self):
        for formula, expected in [
            ('CHAR(65)', 'A'),
            ('CODE("A")', '65'),
            ('CONCATENATE("a","b")', '"ab"'),
            ('LEN("abcd")', '4'),
            ('MID("abcdef",2,3)', 'bcd'),
            ('SEARCH("c","abcd")', '2'),
            ('T(5)', '5'),
            ('TEXT(5,0)', '5'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_char_answers_an_error_for_a_code_outside_the_bytes(self):
        outcome = _answer('CHAR(300)')
        self.assertEqual(outcome.status, XlmStatus.Error)


class TestLookupCommands(TestBase):

    def test_address_spells_the_cell_it_names(self):
        self.assertEqual(_answer('ADDRESS(2,3)').value.text, 'Doc1!$C$2')
        self.assertEqual(_answer('ADDRESS(2,3,4,FALSE)').value.text, 'Doc1!R[2]C[3]')

    def test_absref_adds_an_offset_to_a_cell(self):
        self.assertEqual(_answer('ABSREF("R[1]C[2]",AZ109)').value.text, 'BB110')

    def test_rows_counts_the_rows_of_a_range(self):
        outcome = _answer('ROWS(AZ112:AZ116)')
        self.assertEqual(outcome.value.value, 5)
        self.assertEqual(outcome.status, None)

    def test_index_reads_the_cell_of_a_range_at_a_position(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(parse_formula('INDEX(AZ112:AZ116,2)'), _CURSOR)
        self.assertEqual(outcome.value.value, 123)

    def test_indirect_reads_the_cell_its_text_names(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(parse_formula('INDIRECT("AZ113")'), _CURSOR)
        self.assertEqual(outcome.value.value, 123)

    def test_hlookup_finds_the_first_match_below_its_index_row(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ114', '"needle"')
        engine = XlmEngine(XlmView(data))
        call = parse_formula('HLOOKUP("needle",AZ112:AZ116,1,FALSE)')
        outcome = engine.call(call, _CURSOR)
        self.assertEqual(outcome.value.value, 'needle')
        self.assertEqual(outcome.status, None)

    def test_counta_counts_the_cells_of_a_range_that_hold_a_value(self):
        self.assertEqual(_answer('COUNTA(AZ109:AZ109)').value.value, 1)
        self.assertEqual(_answer('COUNTA(AZ200:AZ210)').value.value, 0)
