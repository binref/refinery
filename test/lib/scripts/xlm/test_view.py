from __future__ import annotations

import io
import unittest
import zipfile

from refinery.lib.excel import SheetKind, synthesize_formula
from refinery.lib.excel.formula import International
from refinery.lib.scripts.xlm import XlmCell, XlmMacrosheet, XlmView
from test import TestBase
from test.lib.excel.samples import (
    DATES_XLSB,
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _macrosheet(view: XlmView, name: str) -> XlmMacrosheet:
    sheet = view.macrosheet(name)
    assert sheet is not None
    return sheet


def _cell(view: XlmView, sheet_name: str, row: int, col: int) -> XlmCell:
    cell = view.cell(sheet_name, row, col)
    assert cell is not None
    return cell


def _with_part_replacement(data: bytes, part: str, old: bytes, new: bytes) -> bytes:
    """
    Replace the first occurrence of `old` in one part of the XLSM sample.
    """
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == part:
                assert old in content
                content = content.replace(old, new, 1)
            target.writestr(info, content)
    return buffer.getvalue()


class TestXlmViewCells(TestBase):

    def test_worksheet_cells_read_as_the_reader_spelled_them(self):
        view = XlmView(XLM_MACRO_FORMULA_XLSM)
        self.assertEqual(_cell(view, 'Tgbfgs', 4, 9).value, 'r"&"eg"&"s"&"vr3"&"2.e"&"x"&"e')
        self.assertEqual(_cell(view, 'Cdfea', 2, 16).value, '-')
        self.assertEqual(_cell(view, 'Tgbs', 14, 6).value, '"http://buchhave.net/cache/t82rF5S/",')
        self.assertEqual(view.cell('Tgbfgs', 1000, 1), None)

    def test_worksheet_formulas_decode_into_the_formula_model(self):
        cell = _cell(XlmView(XLM_MACRO_FORMULA_XLSM), 'Cdfea', 2, 5)
        assert cell.formula is not None
        self.assertEqual(synthesize_formula(cell.formula), 'CHAR(113-2)')

    def test_worksheet_formulas_of_the_xlsb_maldoc_decode_from_their_token_stream(self):
        cell = _cell(XlmView(self.download_sample(_MALDOC)), 'Sheet2', 12, 11)
        assert cell.formula is not None
        self.assertEqual(synthesize_formula(cell.formula), '".dat"')

    @unittest.expectedFailure
    def test_a_date_cell_keeps_the_serial_number_excel_stores(self):
        worksheet = XlmView(DATES_XLSB).worksheet('Sheet1')
        assert worksheet is not None
        self.assertEqual(
            [worksheet[row, 1].value for row in (1, 2, 3)],
            [43893, 0.9201388888888888, 43893.92013888889],
        )

    def test_a_worksheet_is_materialized_as_a_coordinate_dictionary(self):
        view = XlmView(XLM_MACRO_FORMULA_XLSM)
        worksheet = view.worksheet('Tgbfgs')
        assert worksheet is not None
        self.assertEqual(
            sorted(worksheet),
            [(4, 9), (5, 17), (8, 14), (10, 7), (12, 13), (15, 19), (16, 6), (17, 10)],
        )

    def test_a_worksheet_holds_no_cells_without_formula_or_value(self):
        worksheet = XlmView(XLM_MACRO_TEXT_XLSM).worksheet('Doc2')
        assert worksheet is not None
        self.assertEqual(len(worksheet), 50)
        self.assertEqual(
            [cell for cell in worksheet.values() if cell.formula is None and cell.value is None],
            [],
        )

    def test_a_worksheet_whose_walk_fails_keeps_the_cells_before_the_defect(self):
        view = XlmView(_with_part_replacement(
            XLM_MACRO_TEXT_XLSM,
            'xl/worksheets/sheet2.xml',
            b'<c r="AP76" s="7" t="s"><v>7</v></c>',
            b'<c r="AP76" s="7" t="s"><v>99999</v></c>',
        ))
        worksheet = view.worksheet('Doc2')
        assert worksheet is not None
        self.assertEqual(
            list(worksheet),
            [
                (74, 42),
                (74, 43),
                (74, 44),
                (74, 45),
                (74, 46),
                (75, 42),
                (75, 43),
                (75, 44),
                (75, 45),
                (75, 46),
            ],
        )

    def test_a_macrosheet_whose_walk_fails_keeps_the_rest_of_the_workbook(self):
        view = XlmView(_with_part_replacement(
            XLM_MACRO_TEXT_XLSM,
            'xl/macrosheets/intlsheet1.xml',
            b'<c r="BI116" s="9" t="s"><v>26</v></c>',
            b'<c r="BI116" s="9" t="s"><v>99999</v></c>',
        ))
        self.assertEqual(len(_macrosheet(view, 'Doc1').body), 24)
        worksheet = view.worksheet('Doc2')
        assert worksheet is not None
        self.assertEqual(len(worksheet), 50)
        self.assertEqual([entry.name for entry in view.names.entries()], ['auto_open'])

    def test_macrosheet_cells_read_as_cells_of_the_model(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        cell = view.cell('Doc1', 97, 59)
        self.assertIsInstance(cell, XlmCell)
        self.assertEqual(_macrosheet(view, 'Doc1').cell(97, 59), cell)
        self.assertEqual(_cell(view, 'Doc1', 97, 59).value, '..\\iekdhfe.dsk')

    def test_sheet_names_match_case_insensitively(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(view.macrosheet('DOC1'), view.macrosheet('Doc1'))
        self.assertEqual(view.cell('doc1', 97, 59), view.cell('Doc1', 97, 59))
        self.assertEqual(view.worksheet('dOC2'), view.worksheet('Doc2'))
        self.assertEqual(_cell(view, 'doc2', 84, 44).value, 0)

    def test_sheets_the_workbook_does_not_have_answer_none(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(view.cell('Nope', 1, 1), None)
        self.assertEqual(view.macrosheet('Nope'), None)
        self.assertEqual(view.worksheet('Nope'), None)

    def test_a_macrosheet_is_not_a_worksheet(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(view.worksheet('Doc1'), None)
        self.assertEqual(view.macrosheet('Doc2'), None)


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
                cell = _macrosheet(XlmView(data), name).next_formula_cell(row, col)
                assert cell is not None
                self.assertEqual((cell.row, cell.col), target)

    def test_the_anchor_of_the_maldoc_falls_through_to_its_program(self):
        view = XlmView(self.download_sample(_MALDOC))
        cell = _macrosheet(view, 'Tiposa').next_formula_cell(1, 7)
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
                self.assertEqual(XlmView(data).workbook_name, expected)
        self.assertEqual(XlmView(self.download_sample(_MALDOC)).workbook_name, 'workbook.xlsb')

    def test_international_characters_are_the_defaults(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
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
        view = XlmView(XLM_MACRO_FORMULA_XLSM)
        entry = view.names.resolve('NEVR3')
        assert entry is not None
        assert entry.formula is not None
        self.assertEqual(synthesize_formula(entry.formula), 'PCWV!$G$17')

    def test_macrosheets_of_the_maldoc_in_document_order(self):
        view = XlmView(self.download_sample(_MALDOC))
        self.assertEqual(
            [sheet.name for sheet in view.macrosheets()],
            [
                'Sheet',
                'Vtreytr',
                'Tiposa',
                'Tiposa1',
                'Tiposa1111',
                'Tiposa11111',
                'Tiposa2',
                'Tiposa3',
                'Detr',
                'Xwtrd',
                'Xwtrdferyy',
                'Xwtrd2',
                'Tiposa6',
            ],
        )
        self.assertEqual(view.macrosheets()[0].kind, SheetKind.MACROSHEET)
