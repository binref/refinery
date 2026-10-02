from __future__ import annotations

import io
import zipfile

from refinery.lib.excel import SheetKind, synthesize_formula
from refinery.lib.excel.formula import International
from refinery.lib.scripts import TREE_RECURSION_DEPTH, RecursionDepth
from refinery.lib.scripts.xlm import XlmCell, XlmMacrosheet, XlmView
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _view(data: bytes) -> XlmView:
    with RecursionDepth(TREE_RECURSION_DEPTH):
        return XlmView(data)


def _macrosheet(view: XlmView, name: str) -> XlmMacrosheet:
    sheet = view.macrosheet(name)
    assert sheet is not None
    return sheet


def _with_broken_shared_string(data: bytes) -> bytes:
    """
    Point the shared-string reference of cell AP74 of the worksheet Doc2 at an index outside
    the string table, so the walk of that worksheet fails at that cell and everything after
    it is not read.
    """
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == 'xl/worksheets/sheet2.xml':
                old = b'<c r="AP74" s="7" t="s"><v>0</v></c>'
                assert old in content
                content = content.replace(old, b'<c r="AP74" s="7" t="s"><v>99999</v></c>', 1)
            target.writestr(info, content)
    return buffer.getvalue()


class TestXlmViewCells(TestBase):

    def test_worksheet_cells_read_as_the_reader_spelled_them(self):
        view = _view(XLM_MACRO_FORMULA_XLSM)
        self.assertEqual(view.cell('Tgbfgs', 4, 9).value, 'r"&"eg"&"s"&"vr3"&"2.e"&"x"&"e')
        self.assertEqual(view.cell('Cdfea', 2, 16).value, '-')
        self.assertEqual(view.cell('Tgbs', 14, 6).value, '"http://buchhave.net/cache/t82rF5S/",')
        self.assertEqual(view.cell('Tgbfgs', 1000, 1), None)

    def test_a_worksheet_is_materialized_as_a_coordinate_dictionary(self):
        view = _view(XLM_MACRO_FORMULA_XLSM)
        worksheet = view.worksheet('Tgbfgs')
        assert worksheet is not None
        self.assertEqual(
            sorted(worksheet),
            [(4, 9), (5, 17), (8, 14), (10, 7), (12, 13), (15, 19), (16, 6), (17, 10)],
        )

    def test_a_worksheet_whose_walk_fails_keeps_the_cells_before_the_defect(self):
        view = _view(_with_broken_shared_string(XLM_MACRO_TEXT_XLSM))
        worksheet = view.worksheet('Doc2')
        assert worksheet is not None
        self.assertEqual(
            sorted(worksheet),
            [
                (11, 42), (11, 43), (11, 44), (11, 45), (11, 46), (11, 47),
                (12, 47), (13, 47), (14, 47), (15, 47), (16, 47), (17, 47),
                (18, 47), (19, 47), (20, 47), (21, 47), (22, 47), (23, 47),
                (24, 47), (25, 47), (26, 47), (27, 47), (28, 47), (29, 47),
                (72, 41), (72, 42), (72, 43), (72, 44), (72, 45), (72, 46),
                (73, 41), (73, 42), (73, 43), (73, 44), (73, 45), (73, 46),
                (74, 41),
            ],
        )

    def test_macrosheet_cells_read_as_cells_of_the_model(self):
        view = _view(XLM_MACRO_TEXT_XLSM)
        cell = view.cell('Doc1', 97, 59)
        self.assertIsInstance(cell, XlmCell)
        self.assertEqual(cell.value, '..\\iekdhfe.dsk')

    def test_sheets_the_workbook_does_not_have_answer_none(self):
        view = _view(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(view.cell('Nope', 1, 1), None)
        self.assertEqual(view.macrosheet('Nope'), None)
        self.assertEqual(view.worksheet('Doc1'), None)


class TestXlmViewExecution(TestBase):

    _ANCHORS = [
        (XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 41, 19, (41, 19)),
        (XLM_MACRO_NAMES_BIFF8, 'Acf444', 9591, 1, (9591, 1)),
        (XLM_MACRO_ASSIGN_BIFF8, 'sod', 25268, 148, (25268, 148)),
        (XLM_MACRO_TEXT_XLSM, 'Doc1', 102, 52, (109, 52)),
        (XLM_MACRO_FORMULA_XLSM, 'PCWV', 1, 7, (8, 7)),
    ]

    def test_the_auto_open_anchor_falls_through_to_the_next_formula_cell(self):
        for data, name, row, col, target in self._ANCHORS:
            with self.subTest(name=name, row=row):
                cell = _macrosheet(_view(data), name).next_formula_cell(row, col)
                assert cell is not None
                self.assertEqual((cell.row, cell.col), target)

    def test_the_anchor_of_the_maldoc_falls_through_to_its_program(self):
        cell = _macrosheet(_view(self.download_sample(_MALDOC)), 'Tiposa').next_formula_cell(1, 7)
        assert cell is not None
        self.assertEqual((cell.row, cell.col), (25, 7))


class TestXlmViewWorkbook(TestBase):

    def test_workbook_name_follows_the_container_family(self):
        for data, expected in [
            (XLM_MACRO_RPN_BIFF8, 'workbook.xls'),
            (XLM_MACRO_NAMES_BIFF8, 'workbook.xls'),
            (XLM_MACRO_ASSIGN_BIFF8, 'workbook.xls'),
            (XLM_MACRO_TEXT_XLSM, 'workbook.xlsm'),
            (XLM_MACRO_FORMULA_XLSM, 'workbook.xlsm'),
        ]:
            with self.subTest(expected=expected):
                self.assertEqual(_view(data).workbook_name, expected)
        self.assertEqual(_view(self.download_sample(_MALDOC)).workbook_name, 'workbook.xlsb')

    def test_international_characters_are_the_defaults(self):
        view = _view(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(view.international, International())
        self.assertEqual(
            (
                view.international.list_separator,
                view.international.left_bracket,
                view.international.right_bracket,
            ),
            (',', '[', ']'),
        )

    def test_the_name_table_of_the_view_resolves_entry_points(self):
        view = _view(XLM_MACRO_FORMULA_XLSM)
        entry = view.names.resolve('NEVR3')
        assert entry is not None
        with RecursionDepth(TREE_RECURSION_DEPTH):
            self.assertEqual(synthesize_formula(entry.formula), 'PCWV!$G$17')

    def test_macrosheets_of_the_maldoc_in_document_order(self):
        view = _view(self.download_sample(_MALDOC))
        self.assertEqual(
            [sheet.name for sheet in view.macrosheets()],
            [
                'Sheet', 'Vtreytr', 'Tiposa', 'Tiposa1', 'Tiposa1111', 'Tiposa11111',
                'Tiposa2', 'Tiposa3', 'Detr', 'Xwtrd', 'Xwtrdferyy', 'Xwtrd2', 'Tiposa6',
            ],
        )
        self.assertEqual(view.macrosheets()[0].kind, SheetKind.MACROSHEET)
