from __future__ import annotations

import struct

from refinery.lib.excel import open_workbook
from refinery.lib.excel.formula import parse_formula, synthesize_formula
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlR1C1Reference,
    XlUnparsedFormula,
)
from refinery.lib.ole.file import OleFile
from refinery.lib.scripts import TREE_RECURSION_DEPTH, RecursionDepth, canonical

from ... import TestBase
from .samples import (
    FORMULA_TEST_NAMES,
    FORMULA_TEST_SJMACHIN,
    PROFILES_BIFF8,
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
)


def _formula_texts(data: bytes) -> dict[tuple[str, int, int], str]:
    """
    The synthesized formula text of every cell whose formula the reader decodes, keyed by sheet
    name and one-based cell coordinates.
    """
    workbook = open_workbook(data)
    return {
        (sheet.name, cell.row, cell.col): synthesize_formula(formula)
        for sheet in workbook.sheets()
        for cell in sheet.cells()
        if cell.formula is not None
        and not isinstance(formula := workbook.formula(cell.formula), XlUnparsedFormula)
    }


def _contains_relative_3d_area(expression) -> bool:
    for node in expression.walk():
        if not isinstance(node, XlBinaryExpression) or node.operator is not XlBinaryOperator.RANGE:
            continue
        for corner in (node.left, node.right):
            if isinstance(corner, (XlA1Reference, XlR1C1Reference)):
                if corner.sheets and (corner.relative_row or corner.relative_col):
                    return True
    return False


class TestBiffFormulaDecoding(TestBase):

    def test_literals_operators_and_references(self):
        self.assertEqual(
            _formula_texts(FORMULA_TEST_SJMACHIN),
            {
                ('Sheet1', 3, 2): '1/7',
                ('Sheet1', 4, 2): '"ABC"&"DEF"',
                ('Sheet1', 5, 2): 'REPT("foo",0)',
                ('Sheet1', 6, 2): '2>1',
                ('Sheet1', 7, 2): '1/0',
                ('Sheet1', 8, 2): 'B2',
            },
        )

    def test_macro_command_ids_live_above_the_worksheet_function_ids(self):
        # the identifier 0x8060 names FORMULA in the macro-command half of the id space, while
        # the worksheet function of the base id 0x60 is RESULT
        self.assertEqual(
            _formula_texts(XLM_MACRO_ASSIGN_BIFF8)[('sod', 14678, 148)],
            'RETURN(FORMULA.FILL(xofsDmlZLmJV,jRiUYymkewtQ))',
        )

    def test_macro_command_call_with_two_arguments(self):
        self.assertEqual(
            _formula_texts(XLM_MACRO_RPN_BIFF8)[('mP9mScF1m5', 41, 19)],
            'FORMULA(B1&B3&B4&B5&B6&B7&B8&B9&B10&B11&B12&B13&B14&B15&B16&B17&B18&B19&B20&B21'
            '&B22&B23&B24&B25&B26&B27&B28&B29&B30&B31&B32&B33&B34&B35&B36&B37&B38&B39&B40&B41'
            '&B42,T1)',
        )

    def test_assignment_attribute_and_defined_name_operand(self):
        self.assertEqual(
            _formula_texts(XLM_MACRO_ASSIGN_BIFF8)[('sod', 7064, 99)],
            'SET.NAME("xofsDmlZLmJV",$GM$58975&$FU$44596&$HF$14661&$C$21018&$FX$28366&$FQ$7632)',
        )

    def test_user_defined_call_names_its_callee_from_the_stack(self):
        self.assertEqual(
            _formula_texts(XLM_MACRO_ASSIGN_BIFF8)[('sod', 25270, 148)],
            'pjZFOONS($GN$30239,0)',
        )

    def test_relative_flags_of_a_cross_sheet_area_survive_decoding(self):
        # the column words of this token carry both relative flags set; the retiring oracle
        # renders the area absolute because its own decompiler drops the flags whenever the
        # referenced sheet differs from the sheet holding the formula
        self.assertEqual(
            _formula_texts(PROFILES_BIFF8)[('PROFILELEVELS', 2, 3)],
            'AXISDATUMLEVELS!B2:AXISDATUMLEVELS!B15',
        )

    def test_relative_area_names_the_stored_row(self):
        # the stored row of this relative area is the row above the formula, which Excel
        # resolves against the cell the reference is anchored at; the retiring oracle adds the
        # anchoring row a second time and names a row past the end of the sheet
        self.assertEqual(
            _formula_texts(XLM_MACRO_NAMES_BIFF8)[('Acf444', 9591, 1)],
            'EXEC("po"&"wershel"&"l -Command "&Acf444!A9590:Acf444!A9590&"")',
        )

    def test_shared_formula_members_degrade_to_carriers(self):
        workbook = open_workbook(XLM_MACRO_RPN_BIFF8)
        decoded = carriers = 0
        for sheet in workbook.sheets():
            for cell in sheet.cells():
                if cell.formula is None:
                    continue
                if isinstance(workbook.formula(cell.formula), XlUnparsedFormula):
                    carriers += 1
                else:
                    decoded += 1
        self.assertEqual(decoded, 467)
        self.assertEqual(carriers, 128)


class TestBiffFormulaAgainstXlrd(TestBase):
    """
    The token stream of every formula cell decodes to the same program the retiring xlrd2
    reader reports for it, compared canonically so that number spellings, redundant
    parentheses and quoted sheet names cannot mask a match. xlrd2 decodes relative 3-D areas
    wrongly — it drops the relative flags whenever the referenced sheet differs from the
    formula's own sheet, and it adds the anchoring row twice when it does not — so those cells
    carry their own pinned expectations above and are excluded here.
    """

    def test_formula_programs_match_the_oracle(self):
        try:
            import xlrd2
        except ImportError:
            self.skipTest('the xlrd2 oracle is not installed')
        for name, data in [
            ('formula_test_names', FORMULA_TEST_NAMES),
            ('formula_test_sjmachin', FORMULA_TEST_SJMACHIN),
            ('profiles', PROFILES_BIFF8),
            ('xlm_macro_rpn', XLM_MACRO_RPN_BIFF8),
            ('xlm_macro_assign', XLM_MACRO_ASSIGN_BIFF8),
            ('xlm_macro_names', XLM_MACRO_NAMES_BIFF8),
        ]:
            with self.subTest(sample=name):
                book = xlrd2.open_workbook(file_contents=data)
                expected = {
                    (sheet.name, row + 1, col + 1): sheet.cell(row, col).formula
                    for sheet in book.sheets()
                    for row in range(sheet.nrows)
                    for col in range(sheet.ncols)
                    if sheet.cell(row, col).formula
                }
                workbook = open_workbook(data)
                actual = {}
                for sheet in workbook.sheets():
                    for cell in sheet.cells():
                        if cell.formula is None:
                            continue
                        formula = workbook.formula(cell.formula)
                        if isinstance(formula, XlUnparsedFormula):
                            continue
                        if _contains_relative_3d_area(formula):
                            continue
                        actual[sheet.name, cell.row, cell.col] = formula
                self.assertEqual(set(actual) & set(expected), set(actual))
                with RecursionDepth(TREE_RECURSION_DEPTH):
                    for key in actual:
                        oracle = parse_formula(expected[key])
                        self.assertNotIsInstance(oracle, XlUnparsedFormula)
                        self.assertEqual(
                            canonical(actual[key]),
                            canonical(oracle),
                            F'{name} {key}: {expected[key]}',
                        )


class TestBiffFormulaDefects(TestBase):

    @staticmethod
    def _truncate_inside_formula_record(data: bytes) -> bytes:
        """
        Cut the first FORMULA record of the workbook stream down to its fixed header and two
        bytes of its token stream, rewriting the record length the header carries. The rgce
        size the header records now reaches past the record's end.
        """
        stream = bytes(OleFile(data).openstream('Workbook'))
        position = 0
        while struct.unpack_from('<HH', stream, position)[0] != 0x0006:
            position += 4 + struct.unpack_from('<HH', stream, position)[1]
        end = position + 4 + struct.unpack_from('<HH', stream, position)[1]
        cut = position + 4 + 22
        modified = bytearray(stream[:cut] + stream[end:])
        struct.pack_into('<H', modified, position + 2, 22)
        delta = len(modified) - len(stream)
        offset_position = 0
        while len(modified) - offset_position >= 4:
            opcode, = struct.unpack_from('<H', modified, offset_position)
            if opcode == 0x0085:
                offset, = struct.unpack_from('<i', modified, offset_position + 4)
                if offset >= end:
                    struct.pack_into('<i', modified, offset_position + 4, offset + delta)
            offset_position += 4 + struct.unpack_from('<HH', modified, offset_position)[1]
        return bytes(modified)

    def test_token_stream_cut_inside_a_token_is_a_carrier(self):
        truncated = self._truncate_inside_formula_record(FORMULA_TEST_SJMACHIN)
        self.assertEqual(
            _formula_texts(truncated),
            {
                ('Sheet1', 4, 2): '"ABC"&"DEF"',
                ('Sheet1', 5, 2): 'REPT("foo",0)',
                ('Sheet1', 6, 2): '2>1',
                ('Sheet1', 7, 2): '1/0',
                ('Sheet1', 8, 2): 'B2',
            },
        )
        workbook = open_workbook(truncated)
        cut = [
            cell
            for sheet in workbook.sheets()
            for cell in sheet.cells()
            if (sheet.name, cell.row, cell.col) == ('Sheet1', 3, 2)
        ]
        self.assertEqual(len(cut), 1)
        self.assertIsInstance(workbook.formula(cut[0].formula), XlUnparsedFormula)

    def test_cells_still_yield_when_the_token_stream_is_cut(self):
        original = open_workbook(FORMULA_TEST_SJMACHIN)
        truncated = open_workbook(self._truncate_inside_formula_record(FORMULA_TEST_SJMACHIN))
        self.assertEqual(
            [sheet.name for sheet in truncated.sheets()],
            [sheet.name for sheet in original.sheets()],
        )
        self.assertEqual(
            [
                (cell.row, cell.col, cell.kind, cell.value)
                for sheet in truncated.sheets()
                for cell in sheet.cells()
            ],
            [
                (cell.row, cell.col, cell.kind, cell.value)
                for sheet in original.sheets()
                for cell in sheet.cells()
            ],
        )
