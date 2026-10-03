from __future__ import annotations

import random

from refinery.lib.scripts.xlm import XlmEngine, XlmView
from refinery.lib.scripts.xlm.deobfuscation import deobfuscate
from refinery.lib.scripts.xlm.model import XlmCell
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)
from test.lib.scripts.xlm.modify import drop_defined_names

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _cells(view: XlmView) -> set[tuple[str, int, int]]:
    return {
        (macrosheet.name, cell.row, cell.col)
        for macrosheet in view.macrosheets()
        for cell in macrosheet.body
        if isinstance(cell, XlmCell)
    }


def _trace(view: XlmView) -> list[tuple[str, int, int, str, str]]:
    return [
        (step.sheet, step.row, step.col, step.status.name, step.text)
        for step in XlmEngine(view).run()
    ]


class TestDeadCellSweep(TestBase):

    _TRACE_SAMPLES = [
        XLM_MACRO_NAMES_BIFF8,
        XLM_MACRO_ASSIGN_BIFF8,
        XLM_MACRO_RPN_BIFF8,
        XLM_MACRO_TEXT_XLSM,
        XLM_MACRO_FORMULA_XLSM,
    ]

    def test_the_trace_of_every_sample_is_the_same_before_and_after_the_sweep(self):
        for data in self._TRACE_SAMPLES:
            with self.subTest(sample=data[:8].hex()):
                self.assertEqual(_trace(XlmView(data)), _trace(self._sweeped(data)))

    def _sweeped(self, data: bytes, start_point: str = '') -> XlmView:
        view = XlmView(data)
        deobfuscate(view, start_point)
        return view

    def test_the_names_sample_keeps_only_the_entry_column_below_its_reference(self):
        self.assertEqual(
            _cells(self._sweeped(XLM_MACRO_NAMES_BIFF8)),
            {('Acf444', 9590, 1), ('Acf444', 9591, 1), ('Acf444', 29999, 1), ('Acf444', 30009, 1)},
        )

    def test_the_assign_sample_loses_only_its_two_dead_cells(self):
        default = _cells(XlmView(XLM_MACRO_ASSIGN_BIFF8))
        swept = _cells(self._sweeped(XLM_MACRO_ASSIGN_BIFF8))
        self.assertEqual(default - swept, {('sod', 65, 65), ('sod', 66, 65)})
        self.assertEqual(len(swept), len(default) - 2)

    def test_the_rpn_padding_stays_because_the_program_reads_it(self):
        default = _cells(XlmView(XLM_MACRO_RPN_BIFF8))
        swept = _cells(self._sweeped(XLM_MACRO_RPN_BIFF8))
        self.assertEqual(swept, default)

    def test_the_start_point_anchors_the_sweep_where_no_name_points_anywhere(self):
        nameless = drop_defined_names(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(
            _cells(self._sweeped(nameless, 'Doc1!AZ102')),
            _cells(XlmView(XLM_MACRO_TEXT_XLSM)),
        )

    def test_without_a_start_point_or_a_name_the_unreferenced_cells_go(self):
        nameless = drop_defined_names(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(len(_cells(self._sweeped(nameless))), 27)

    def test_the_maldoc_listing_shrinks_without_touching_its_trace(self):
        data = self.download_sample(_MALDOC)
        plain = XlmView(data)
        before = len(_cells(plain))
        random.seed(0xBAADF00D)
        plain_trace = _trace(plain)
        random.seed(0xBAADF00D)
        self.assertEqual(plain_trace, _trace(self._sweeped(data)))
        self.assertEqual(len(_cells(self._sweeped(data))), before - 63)
