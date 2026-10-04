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
from refinery.lib.excel.formula.ptg import RpnError
from refinery.lib.ole.file import OleFile
from refinery.lib.scripts import TREE_RECURSION_DEPTH, RecursionDepth, Transformer, canonical

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


class _R1C1AgainstCell(Transformer):
    """
    Resolve the relative references of a shared-formula template against the member cell that
    holds it. The reader keeps the template position-independent, while the oracle renders it
    resolved into absolute coordinates, so the comparison needs both sides in one notation.
    """

    def __init__(self, row: int, col: int):
        super().__init__()
        self._row = row
        self._col = col

    def visit_XlR1C1Reference(self, node: XlR1C1Reference):
        return XlA1Reference(
            sheets=node.sheets,
            row=self._row + node.row if node.relative_row else node.row,
            col=self._col + node.col if node.relative_col else node.col,
            relative_row=node.relative_row,
            relative_col=node.relative_col,
        )


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
        # the column words of this token carry both relative flags set
        self.assertEqual(
            _formula_texts(PROFILES_BIFF8)[('PROFILELEVELS', 2, 3)],
            'AXISDATUMLEVELS!B2:AXISDATUMLEVELS!B15',
        )

    def test_relative_area_names_the_stored_row(self):
        # the stored row of this relative area is the row above the formula, which Excel
        # resolves against the cell the reference is anchored at
        self.assertEqual(
            _formula_texts(XLM_MACRO_NAMES_BIFF8)[('Acf444', 9591, 1)],
            'EXEC("po"&"wershel"&"l -Command "&Acf444!A9590:Acf444!A9590&"")',
        )

    def test_shared_formula_members_carry_the_template(self):
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
        self.assertEqual(decoded, 595)
        self.assertEqual(carriers, 0)
        self.assertEqual(
            _formula_texts(XLM_MACRO_RPN_BIFF8)[('mP9mScF1m5', 66, 12)],
            'CHAR(RC[-1])',
        )

    def test_a_relative_column_reads_its_low_byte_whatever_the_unused_bits_hold(self):
        stream = bytes(OleFile(XLM_MACRO_RPN_BIFF8).openstream('Workbook'))
        # a ptgRefN to RC[-1] in the shared formula templates, its column word written as the
        # fourteen-bit offset rather than the byte that Excel writes
        stored = bytes.fromhex('4c0000ffc0416f00')
        widened = bytes.fromhex('4c0000ffff416f00')
        self.assertEqual(stream.count(stored), 3)
        self.assertEqual(
            _formula_texts(stream.replace(stored, widened))[('mP9mScF1m5', 66, 12)],
            'CHAR(RC[-1])',
        )


class TestBiffFormulaAgainstXlrd(TestBase):
    """
    The token stream of every formula cell decodes to the same program the xlrd2 reader
    reports for it, compared canonically so that number spellings, redundant parentheses
    and quoted sheet names cannot mask a match. xlrd2 decodes relative 3-D areas wrongly — it
    drops the relative flags whenever the referenced sheet differs from the formula's own
    sheet, and it adds the anchoring row twice when it does not — so those cells carry their
    own pinned expectations above and are excluded here. The member cells of a shared
    formula are excluded too: xlrd2 renders their `ptgExp` token as the placeholder
    text `SHARED FMLA at rowx=…` instead of the template, which this reader resolves.
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
                    (sheet.name, row + 1, col + 1): text
                    for sheet in book.sheets()
                    for row in range(sheet.nrows)
                    for col in range(sheet.ncols)
                    if (text := sheet.cell(row, col).formula)
                    and not text.startswith('SHARED FMLA at rowx=')
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
                with RecursionDepth(TREE_RECURSION_DEPTH):
                    for key in actual.keys() & expected.keys():
                        oracle = parse_formula(expected[key])
                        self.assertNotIsInstance(oracle, XlUnparsedFormula)
                        resolved = _R1C1AgainstCell(key[1], key[2]).visit(actual[key])
                        self.assertEqual(
                            canonical(resolved or actual[key]),
                            canonical(oracle),
                            F'{name} {key}: {expected[key]}',
                        )


class TestBiffFormulaDefects(TestBase):

    @staticmethod
    def _with_foreign_supbook(data: bytes) -> bytes:
        """
        Replace the second supporting book of the workbook stream — the add-in library — with an
        external document that carries one sheet name, and point the second extern-sheet entry
        at it. A 3-D reference through that entry names a sheet of another document, which the
        reader has to refuse rather than present as a sheet of this workbook.
        """
        stream = bytearray(bytes(OleFile(data).openstream('Workbook')))
        position = 0
        while struct.unpack_from('<H', stream, position)[0] != 0x01AE:
            position += 4 + struct.unpack_from('<HH', stream, position)[1]
        position += 4 + struct.unpack_from('<HH', stream, position)[1]
        end = position + 4 + struct.unpack_from('<HH', stream, position)[1]
        # one sheet, an empty source path, and the sheet name X, each length-counted
        supbook = struct.pack('<HH', 0x01AE, 9) + b'\x01\x00\x00\x00\x00\x01\x00\x00X'
        stream[position:end] = supbook
        delta = len(supbook) - (end - position)
        position = 0
        while position + 4 <= len(stream):
            opcode, length = struct.unpack_from('<HH', stream, position)
            if opcode == 0x0017:
                # the second entry of the extern-sheet table: the supporting book the
                # replacement occupies, and its first and only sheet
                struct.pack_into('<HHH', stream, position + 4 + 2 + 6, 1, 0, 0)
            elif opcode == 0x0085:
                offset, = struct.unpack_from('<i', stream, position + 4)
                if offset >= end:
                    struct.pack_into('<i', stream, position + 4, offset + delta)
            position += 4 + length
        return bytes(stream)

    def test_extern_sheets_refuse_a_sheet_of_another_document(self):
        workbook = open_workbook(self._with_foreign_supbook(XLM_MACRO_RPN_BIFF8))
        with self.assertRaises(RpnError):
            workbook.extern_sheets(1)

    def test_extern_sheets_still_resolve_the_workbook_itself(self):
        original = open_workbook(XLM_MACRO_RPN_BIFF8)
        modified = open_workbook(self._with_foreign_supbook(XLM_MACRO_RPN_BIFF8))
        self.assertEqual(
            modified.extern_sheets(0),
            original.extern_sheets(0),
        )

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

    @staticmethod
    def _with_first_formula_token(data: bytes, token: int) -> bytes:
        """
        Overwrite the first token byte of the first FORMULA record of the workbook stream. The
        record keeps its length, so every other record of the stream reads as before.
        """
        stream = bytearray(bytes(OleFile(data).openstream('Workbook')))
        position = 0
        while struct.unpack_from('<HH', stream, position)[0] != 0x0006:
            position += 4 + struct.unpack_from('<HH', stream, position)[1]
        # the token stream follows the record header and the 22 bytes of the fixed record body
        stream[position + 4 + 22] = token
        return bytes(stream)

    def test_a_token_byte_that_names_no_token_is_a_carrier(self):
        expected = _formula_texts(FORMULA_TEST_SJMACHIN)
        del expected[('Sheet1', 3, 2)]
        # no ptg is numbered 0x00, and none in the range from 0x30 to 0x37
        for token in (0x00, 0x36):
            with self.subTest(token=token):
                data = self._with_first_formula_token(FORMULA_TEST_SJMACHIN, token)
                self.assertEqual(_formula_texts(data), expected)
                workbook = open_workbook(data)
                cell = next(
                    cell
                    for sheet in workbook.sheets()
                    for cell in sheet.cells()
                    if (sheet.name, cell.row, cell.col) == ('Sheet1', 3, 2)
                )
                self.assertIsInstance(workbook.formula(cell.formula), XlUnparsedFormula)

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
