"""
The operator oracle: every binary operator of the formula language applied to every pair of a
matrix of operand spellings, computed by the emulator and checked against the answer Microsoft
Excel itself cached in the workbook.
"""
from __future__ import annotations

from refinery.lib.excel import (
    CellKind,
    open_workbook,
    synthesize_formula,
)
from refinery.lib.scripts.xlm import XlmCursor, XlmEngine, XlmValue, XlmView
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from test import TestBase
from test.lib.excel.samples import (
    OPERATOR_ORACLE_BIFF8,
    OPERATOR_ORACLE_XLSB,
    OPERATOR_ORACLE_XLSX,
)


def _cached(cell) -> tuple:
    if cell.kind is CellKind.ERROR:
        return ('error', cell.value)
    if cell.kind is CellKind.BOOLEAN:
        return ('boolean', cell.value)
    if cell.kind is CellKind.NUMBER:
        return ('number', float(cell.value))
    return ('text', cell.value)


def _computed(value: XlmValue) -> tuple:
    if value.partial:
        return ('partial', value.text)
    if value.error:
        return ('error', value.text)
    if isinstance(value.value, bool):
        return ('boolean', value.value)
    if isinstance(value.value, (int, float)):
        return ('number', float(value.value))
    return ('text', value.unwrap())


class TestOperatorOracle(TestBase):

    def _checked_formulas(self, key: str) -> int:
        data = self.download_sample(key)
        workbook = open_workbook(data)
        sheet = {sheet.name: sheet for sheet in workbook.sheets()}['Oracle']
        engine = XlmEngine(XlmView(data))
        checked = 0
        for cell in sheet.cells():
            formula = workbook.formula(cell.formula)
            if formula is None:
                continue
            computed = evaluate_expression(
                engine,
                formula,
                XlmCursor(sheet.name, cell.row, cell.col),
            )
            answer = _computed(computed)
            expected = _cached(cell)
            with self.subTest(cell=(cell.row, cell.col)):
                if answer != expected:
                    self.assertEqual(answer, expected, synthesize_formula(formula))
            checked += 1
        return checked

    def test_the_ooxml_workbook_answers_as_excel_does(self):
        self.assertGreater(self._checked_formulas(OPERATOR_ORACLE_XLSX), 5000)

    def test_the_xlsb_workbook_answers_as_excel_does(self):
        self.assertGreater(self._checked_formulas(OPERATOR_ORACLE_XLSB), 5000)

    def test_the_biff8_workbook_answers_as_excel_does(self):
        self.assertGreater(self._checked_formulas(OPERATOR_ORACLE_BIFF8), 5000)
