from __future__ import annotations

import io
import zipfile

from refinery.lib.excel import CellKind, SheetKind, open_workbook, synthesize_formula
from refinery.lib.excel.formula.model import (
    XlBinaryExpression,
    XlBinaryOperator,
    XlFunctionCall,
    XlUnparsedFormula,
)
from refinery.lib.scripts.xlm import XlmCell, XlmMacrosheet, build_xlm_model
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _model(data: bytes | bytearray) -> list[XlmMacrosheet]:
    return build_xlm_model(open_workbook(data))


def _sheet(macrosheets: list[XlmMacrosheet], name: str) -> XlmMacrosheet:
    sheet = next(sheet for sheet in macrosheets if sheet.name == name)
    return sheet


def _body(sheet: XlmMacrosheet) -> list[XlmCell]:
    cells: list[XlmCell] = []
    for cell in sheet.body:
        assert isinstance(cell, XlmCell)
        cells.append(cell)
    return cells


def _cell(macrosheets: list[XlmMacrosheet], name: str, row: int, col: int) -> XlmCell:
    cell = _sheet(macrosheets, name).cell(row, col)
    assert cell is not None
    return cell


def _formula_text(macrosheets: list[XlmMacrosheet], name: str, row: int, col: int) -> str:
    cell = _cell(macrosheets, name, row, col)
    assert cell.formula is not None
    return synthesize_formula(cell.formula)


def _carrier_count(macrosheets: list[XlmMacrosheet]) -> int:
    return sum(
        1
        for sheet in macrosheets
        for cell in _body(sheet)
        if isinstance(cell.formula, XlUnparsedFormula)
    )


def _with_macrosheet_replacement(data: bytes, old: bytes, new: bytes) -> bytes:
    """
    Replace the first occurrence of `old` in the macrosheet part of the XLSM sample.
    """
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == 'xl/macrosheets/intlsheet1.xml':
                assert old in content
                content = content.replace(old, new, 1)
            target.writestr(info, content)
    return buffer.getvalue()


class TestXlmModelInventory(TestBase):

    def test_sheet_inventory_of_every_embedded_sample(self):
        for data, expected in [
            (XLM_MACRO_RPN_BIFF8, [('mP9mScF1m5', 1179, 128)]),
            (XLM_MACRO_NAMES_BIFF8, [('Acf444', 11, 0)]),
            (XLM_MACRO_ASSIGN_BIFF8, [('sod', 426, 0)]),
            (XLM_MACRO_TEXT_XLSM, [('Doc1', 37, 0)]),
            (XLM_MACRO_FORMULA_XLSM, [('PCWV', 1, 0)]),
        ]:
            with self.subTest(sample=expected[0][0]):
                macrosheets = _model(data)
                self.assertEqual(
                    [
                        (sheet.name, sheet.kind, len(sheet.body))
                        for sheet in macrosheets
                    ],
                    [
                        (name, SheetKind.MACROSHEET, count)
                        for name, count, _ in expected
                    ],
                )
                self.assertEqual(
                    _carrier_count(macrosheets),
                    sum(carriers for _, _, carriers in expected),
                )

    def test_sheet_inventory_of_the_xlsb_maldoc(self):
        macrosheets = _model(self.download_sample(_MALDOC))
        self.assertEqual(
            [(sheet.name, len(sheet.body)) for sheet in macrosheets],
            [
                ('Sheet', 0),
                ('Vtreytr', 2),
                ('Tiposa', 75),
                ('Tiposa1', 10),
                ('Tiposa1111', 2),
                ('Tiposa11111', 2),
                ('Tiposa2', 3),
                ('Tiposa3', 1),
                ('Detr', 1),
                ('Xwtrd', 3),
                ('Xwtrdferyy', 2),
                ('Xwtrd2', 2),
                ('Tiposa6', 1),
            ],
        )

    def test_cells_that_hold_neither_a_formula_nor_a_value_are_skipped(self):
        workbook = open_workbook(XLM_MACRO_TEXT_XLSM)
        sheet = next(sheet for sheet in workbook.sheets() if sheet.name == 'Doc1')
        self.assertEqual(sum(1 for _ in sheet.cells()), 10529)
        macrosheets = _model(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(
            [
                cell
                for cell in _body(macrosheets[0])
                if cell.formula is None and cell.value is None
            ],
            [],
        )


class TestXlmModelCells(TestBase):

    def test_pinned_formula_texts(self):
        for data, name, row, col, text in [
            (
                XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 1, 2,
                'CHAR(A1-1)',
            ),
            (
                XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 41, 19,
                'FORMULA(B1&B3&B4&B5&B6&B7&B8&B9&B10&B11&B12&B13&B14&B15&B16&B17&B18&B19&B20'
                '&B21&B22&B23&B24&B25&B26&B27&B28&B29&B30&B31&B32&B33&B34&B35&B36&B37&B38&B39'
                '&B40&B41&B42,T1)',
            ),
            (
                XLM_MACRO_NAMES_BIFF8, 'Acf444', 2, 1,
                'RETURN()',
            ),
            (
                XLM_MACRO_NAMES_BIFF8, 'Acf444', 9584, 1,
                'SET.NAME("sozIcSWorX",VPYBVp)',
            ),
            (
                XLM_MACRO_NAMES_BIFF8, 'Acf444', 9591, 1,
                'EXEC("po"&"wershel"&"l -Command "&Acf444!A9590:Acf444!A9590&"")',
            ),
            (
                XLM_MACRO_NAMES_BIFF8, 'Acf444', 29999, 1,
                'Application.Quit',
            ),
            (
                XLM_MACRO_NAMES_BIFF8, 'Acf444', 30009, 1,
                'HALT()',
            ),
            (
                XLM_MACRO_ASSIGN_BIFF8, 'sod', 7064, 99,
                'SET.NAME("xofsDmlZLmJV",'
                '$GM$58975&$FU$44596&$HF$14661&$C$21018&$FX$28366&$FQ$7632)',
            ),
            (
                XLM_MACRO_ASSIGN_BIFF8, 'sod', 25268, 148,
                '$DQ$42603()',
            ),
            (
                XLM_MACRO_TEXT_XLSM, 'Doc1', 93, 56,
                'CALL(BD108&"n",BD109&"A",BD119,Doc2!AR84,Doc1!BD113,Doc1!BG98&"1",0,0)',
            ),
            (
                XLM_MACRO_TEXT_XLSM, 'Doc1', 97, 59,
                '"..\\iekdhfe.dsk"',
            ),
            (
                XLM_MACRO_TEXT_XLSM, 'Doc1', 109, 52,
                'SET.VALUE(BD108,Doc2!AP74&Doc2!AP75&Doc2!AP76&Doc2!AP77&Doc2!AP78)',
            ),
        ]:
            with self.subTest(name=name, row=row, col=col):
                self.assertEqual(_formula_text(_model(data), name, row, col), text)

    def test_value_only_cells_keep_the_cached_value(self):
        self.assertEqual(
            _cell(_model(XLM_MACRO_RPN_BIFF8), 'mP9mScF1m5', 1, 1).value,
            62,
        )
        self.assertEqual(
            _cell(_model(XLM_MACRO_NAMES_BIFF8), 'Acf444', 9581, 1).value,
            '132',
        )
        self.assertEqual(
            _cell(_model(XLM_MACRO_FORMULA_XLSM), 'PCWV', 8, 7).value,
            True,
        )

    def test_cells_keep_the_kind_of_their_cached_value(self):
        macrosheets = _model(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(_cell(macrosheets, 'Doc1', 91, 56).kind, CellKind.BOOLEAN)
        self.assertEqual(_cell(macrosheets, 'Doc1', 97, 59).kind, CellKind.TEXT)

    def test_the_program_of_the_pcwv_macrosheet_spans_ten_formula_calls(self):
        cell = _cell(_model(XLM_MACRO_FORMULA_XLSM), 'PCWV', 8, 7)
        formula = cell.formula
        assert isinstance(formula, XlBinaryExpression)
        self.assertEqual(formula.operator, XlBinaryOperator.EQ)
        self.assertEqual(
            len([
                node
                for node in formula.walk()
                if isinstance(node, XlFunctionCall) and node.callee == 'FORMULA'
            ]),
            10,
        )


class TestXlmModelDefects(TestBase):
    """
    Defects of a macrosheet, added to authentic cells of the XLSM sample by byte modification.
    """

    def test_a_macrosheet_whose_walk_fails_keeps_the_cells_before_the_defect(self):
        broken = _with_macrosheet_replacement(
            XLM_MACRO_TEXT_XLSM,
            b'<c r="BI116" s="9" t="s"><v>26</v></c>',
            b'<c r="BI116" s="9" t="s"><v>99999</v></c>',
        )
        intact = _sheet(_model(XLM_MACRO_TEXT_XLSM), 'Doc1')
        kept = [(cell.row, cell.col) for cell in _body(_sheet(_model(broken), 'Doc1'))]
        self.assertEqual(
            kept,
            [(cell.row, cell.col) for cell in _body(intact) if (cell.row, cell.col) < (116, 61)],
        )
        self.assertEqual(len(kept), 24)

    def test_a_coordinate_stored_twice_holds_its_last_record(self):
        data = _with_macrosheet_replacement(
            XLM_MACRO_TEXT_XLSM,
            b'<c r="BG97" ',
            b'<c r="BG97" s="9" t="s"><v>26</v></c><c r="BG97" ',
        )
        sheet = _sheet(_model(data), 'Doc1')
        cell = sheet.cell(97, 59)
        assert cell is not None
        self.assertEqual(len(sheet.body), 37)
        self.assertEqual(sheet.next_formula_cell(97, 59), cell)
        self.assertEqual(_formula_text([sheet], 'Doc1', 97, 59), '"..\\iekdhfe.dsk"')


class TestXlmAssignmentNormalization(TestBase):
    """
    The `bx` attribute of an OOXML macrosheet formula marks a formula that assigns to a name.
    No sample of the corpus carries one, so every vector here adds the attribute to authentic
    cells of the XLSM sample by byte modification, the only kind of vector that can exist.
    """

    _STRING_CELL_FORMULA = b'<f>"..\\iekdhfe.dsk"</f>'

    def _assigned(self, formula: bytes) -> XlmCell:
        data = _with_macrosheet_replacement(
            XLM_MACRO_TEXT_XLSM,
            self._STRING_CELL_FORMULA,
            b'<f bx="1">' + formula + b'</f>',
        )
        return _cell(_model(data), 'Doc1', 97, 59)

    def test_bx_on_a_comparison_of_a_bare_name_becomes_the_set_name_call(self):
        cell = self._assigned(b'PldtZqwb="..\\iekdhfe.dsk"')
        self.assertEqual(cell.assignment, True)
        assert cell.formula is not None
        self.assertEqual(
            synthesize_formula(cell.formula),
            'SET.NAME("PldtZqwb","..\\iekdhfe.dsk")',
        )

    def test_bx_assigns_a_value_that_is_itself_a_comparison(self):
        # the assigned value is everything after the first equals sign of the formula text
        for formula, expected in [
            (b'PldtZqwb=BG98="x"', 'SET.NAME("PldtZqwb",BG98="x")'),
            (b'PldtZqwb=BG98&lt;&gt;BG99', 'SET.NAME("PldtZqwb",BG98<>BG99)'),
            (b'PldtZqwb=GET.WORKSPACE(13)&lt;770', 'SET.NAME("PldtZqwb",GET.WORKSPACE(13)<770)'),
            (b'PldtZqwb=BG98=BG99=BG100', 'SET.NAME("PldtZqwb",BG98=BG99=BG100)'),
        ]:
            with self.subTest(formula=formula):
                cell = self._assigned(formula)
                assert cell.formula is not None
                self.assertEqual(synthesize_formula(cell.formula), expected)

    def test_bx_on_a_formula_that_is_no_comparison_keeps_the_tree(self):
        cell = self._assigned(b'"..\\iekdhfe.dsk"')
        self.assertEqual(cell.assignment, True)
        assert cell.formula is not None
        self.assertEqual(synthesize_formula(cell.formula), '"..\\iekdhfe.dsk"')

    def test_bx_on_a_parenthesized_comparison_keeps_the_tree(self):
        cell = self._assigned(b'(PldtZqwb=BG98)=1')
        assert cell.formula is not None
        self.assertEqual(synthesize_formula(cell.formula), '(PldtZqwb=BG98)=1')

    def test_bx_on_a_comparison_that_names_nothing_keeps_the_tree(self):
        data = _with_macrosheet_replacement(
            XLM_MACRO_TEXT_XLSM,
            b'<c r="BD91" s="9" t="b"><f>',
            b'<c r="BD91" s="9" t="b"><f bx="1">',
        )
        cell = _cell(_model(data), 'Doc1', 91, 56)
        self.assertEqual(cell.assignment, True)
        formula = cell.formula
        assert isinstance(formula, XlBinaryExpression)
        self.assertEqual(formula.operator, XlBinaryOperator.EQ)
        self.assertIsInstance(formula.left, XlBinaryExpression)
        self.assertEqual(
            _formula_text(_model(data), 'Doc1', 91, 56),
            _formula_text(_model(XLM_MACRO_TEXT_XLSM), 'Doc1', 91, 56),
        )


class TestXlmRowFallThrough(TestBase):

    _ANCHORS = [
        (XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 41, 19, (41, 19)),
        (XLM_MACRO_NAMES_BIFF8, 'Acf444', 9591, 1, (9591, 1)),
        (XLM_MACRO_ASSIGN_BIFF8, 'sod', 25268, 148, (25268, 148)),
        (XLM_MACRO_TEXT_XLSM, 'Doc1', 102, 52, (109, 52)),
        (XLM_MACRO_FORMULA_XLSM, 'PCWV', 1, 7, (8, 7)),
    ]

    def test_the_anchor_falls_through_to_the_next_formula_cell(self):
        for data, name, row, col, target in self._ANCHORS:
            with self.subTest(name=name, row=row):
                cell = _sheet(_model(data), name).next_formula_cell(row, col)
                assert cell is not None
                self.assertEqual((cell.row, cell.col), target)

    def test_the_anchor_of_the_maldoc_falls_through_to_its_program(self):
        macrosheets = _model(self.download_sample(_MALDOC))
        cell = _sheet(macrosheets, 'Tiposa').next_formula_cell(1, 7)
        assert cell is not None
        self.assertEqual((cell.row, cell.col), (25, 7))

    def test_the_fall_through_is_bounded_to_ten_thousand_rows_below_the_anchor(self):
        sheet = _sheet(_model(XLM_MACRO_NAMES_BIFF8), 'Acf444')
        cell = sheet.next_formula_cell(19999, 1)
        assert cell is not None
        self.assertEqual((cell.row, cell.col), (29999, 1))
        self.assertEqual(sheet.next_formula_cell(9592, 1), None)


class TestXlmSortedCells(TestBase):

    def test_value_cells_follow_the_formula_cells_in_document_order(self):
        self.assertEqual(
            [(cell.row, cell.col) for cell in _model(XLM_MACRO_NAMES_BIFF8)[0].sorted_cells()],
            [
                (2, 1),
                (9584, 1),
                (9585, 1),
                (9586, 1),
                (9587, 1),
                (9588, 1),
                (9591, 1),
                (29999, 1),
                (30009, 1),
                (9581, 1),
                (9590, 1),
            ],
        )

    def test_formula_cells_sort_by_column_letters_then_by_row_before_the_value_cells(self):
        self.assertEqual(
            [(cell.row, cell.col) for cell in _model(XLM_MACRO_TEXT_XLSM)[0].sorted_cells()],
            [
                (109, 52),
                (110, 52),
                (112, 52),
                (113, 52),
                (114, 52),
                (115, 52),
                (116, 52),
                (118, 52),
                (120, 52),
                (121, 52),
                (91, 56),
                (93, 56),
                (95, 56),
                (97, 56),
                (99, 56),
                (104, 56),
                (109, 58),
                (110, 58),
                (111, 58),
                (112, 58),
                (113, 58),
                (97, 59),
                (98, 59),
                (99, 59),
                (100, 59),
                (101, 59),
                (114, 62),
                (116, 61),
                (116, 62),
                (117, 61),
                (117, 62),
                (118, 61),
                (118, 62),
                (119, 61),
                (119, 62),
                (120, 61),
                (120, 62),
            ],
        )
