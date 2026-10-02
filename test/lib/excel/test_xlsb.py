from __future__ import annotations

import datetime
import io
import tempfile
import zipfile

from refinery.lib.excel import (
    CellKind,
    ExcelFormat,
    ExcelFormatError,
    SheetKind,
    detect_format,
    open_workbook,
)

from ... import TestBase
from .samples import DATES_XLSB, TEST_1904_XLSB, TEST_XLSB


def _cells(data: bytes) -> dict[tuple[int, int], tuple[CellKind, object]]:
    sheet = open_workbook(data).sheets()[0]
    return {(cell.row, cell.col): (cell.kind, cell.value) for cell in sheet.cells()}


def _formulas(data: bytes) -> set[tuple[int, int]]:
    sheet = open_workbook(data).sheets()[0]
    return {(cell.row, cell.col) for cell in sheet.cells() if cell.formula is not None}


def _truncate_inside_cell_record(data: bytes, part: str, cell_count: int) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(data))
    body = source.read(part)
    position = 0
    cut = None
    seen = 0
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
        if 1 <= rtype <= 11:
            seen += 1
            if seen == cell_count:
                cut = position + length // 2
                break
        position += length
    assert cut is not None
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == part:
                content = content[:cut]
            target.writestr(info, content)
    return buffer.getvalue()


def _with_lone_surrogate(data: bytes, part: str) -> bytes:
    """
    Overwrite the first two characters of the first shared string item of the part with an
    unpaired UTF-16 surrogate, which no decoder can resolve.
    """
    source = zipfile.ZipFile(io.BytesIO(data))
    body = bytearray(source.read(part))
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
        if rtype == 19:
            start = position + 1 + 4
            body[start:start + 2] = b'\x00\xd8'
            break
        position += length
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = bytes(body) if info.filename == part else source.read(info)
            target.writestr(info, content)
    return buffer.getvalue()


_TEST_VALUES = {
    (1, 1): (CellKind.TEXT, 'A'),
    (1, 2): (CellKind.TEXT, 'B'),
    (1, 3): (CellKind.TEXT, 'A'),
    (1, 4): (CellKind.TEXT, 'B'),
    (2, 1): (CellKind.NUMBER, 1),
    (2, 2): (CellKind.NUMBER, 42.1337),
    (2, 3): (CellKind.NUMBER, -1),
    (2, 4): (CellKind.NUMBER, -42.1337),
    (2, 5): (CellKind.NUMBER, 1),
    (2, 6): (CellKind.NUMBER, 42.1337),
    (2, 7): (CellKind.NUMBER, -1),
    (2, 8): (CellKind.NUMBER, -42.1337),
    (3, 1): (CellKind.BOOLEAN, True),
    (3, 2): (CellKind.BOOLEAN, False),
    (3, 3): (CellKind.BOOLEAN, True),
    (3, 4): (CellKind.BOOLEAN, False),
    (4, 1): (CellKind.ERROR, '#DIV/0!'),
    (4, 2): (CellKind.ERROR, '#REF!'),
    (4, 3): (CellKind.ERROR, '#DIV/0!'),
    (4, 4): (CellKind.ERROR, '#REF!'),
    (5, 1): (CellKind.DATE, datetime.datetime(2017, 12, 27, 0, 0)),
    (5, 2): (CellKind.DATE, datetime.time(18, 6)),
    (5, 3): (CellKind.DATE, datetime.datetime(2017, 12, 27, 18, 8)),
    (5, 4): (CellKind.DATE, datetime.datetime(2017, 12, 27, 0, 0)),
    (5, 5): (CellKind.DATE, datetime.time(18, 6)),
    (5, 6): (CellKind.DATE, datetime.datetime(2017, 12, 27, 18, 8)),
}

_TEST_1904_VALUES = _TEST_VALUES | {
    (5, 3): (CellKind.DATE, datetime.datetime(2017, 12, 27, 18, 6)),
    (5, 6): (CellKind.DATE, datetime.datetime(2017, 12, 27, 18, 6)),
}

_TEST_FORMULAS = {
    (1, 3), (1, 4),
    (2, 5), (2, 6), (2, 7), (2, 8),
    (3, 3), (3, 4),
    (4, 3), (4, 4),
    (5, 4), (5, 5), (5, 6),
}


class TestXlsbWorkbook(TestBase):

    def test_detect_xlsb(self):
        for data in (TEST_XLSB, DATES_XLSB, TEST_1904_XLSB):
            self.assertEqual(detect_format(data), ExcelFormat.XLSB)

    def test_parts_outside_the_conventional_folder_are_not_detected(self):
        # A workbook whose parts do not sit inside the `xl` folder is one the reader cannot
        # resolve, and it is not detected as a workbook at all.
        source = zipfile.ZipFile(io.BytesIO(TEST_XLSB))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as target:
            for info in source.infolist():
                name = info.filename[3:] if info.filename.startswith('xl/') else info.filename
                target.writestr(name, source.read(info))
        self.assertIsNone(detect_format(buffer.getvalue()))

    def test_sheets(self):
        for data, name in ((TEST_XLSB, 'Test'), (DATES_XLSB, 'Sheet1'), (TEST_1904_XLSB, 'Test')):
            sheets = open_workbook(data).sheets()
            self.assertEqual(len(sheets), 1)
            self.assertEqual(sheets[0].name, name)
            self.assertEqual(sheets[0].kind, SheetKind.WORKSHEET)

    def test_values(self):
        self.assertEqual(_cells(TEST_XLSB), _TEST_VALUES)
        self.assertEqual(_cells(TEST_1904_XLSB), _TEST_1904_VALUES)

    def test_formula_cells_carry_token_streams(self):
        self.assertEqual(_formulas(TEST_XLSB), _TEST_FORMULAS)

    def test_dates_of_second_sample(self):
        self.assertEqual(_cells(DATES_XLSB), {
            (1, 1): (CellKind.DATE, datetime.datetime(2020, 3, 3, 0, 0)),
            (2, 1): (CellKind.DATE, datetime.time(22, 5)),
            (3, 1): (CellKind.DATE, datetime.datetime(2020, 3, 3, 22, 5)),
        })

    def test_truncated_sheet_part_yields_partial_cells(self):
        part = 'xl/worksheets/sheet1.bin'
        data = _truncate_inside_cell_record(TEST_XLSB, part, 4)
        sheet = open_workbook(data).sheets()[0]
        cells = []
        with self.assertRaises(ExcelFormatError):
            for cell in sheet.cells():
                cells.append(cell)
        self.assertEqual(len(cells), 3)
        self.assertEqual((cells[0].row, cells[0].col, cells[0].value), (1, 1, 'A'))

    def test_lone_surrogate_in_shared_strings_is_a_defect(self):
        data = _with_lone_surrogate(TEST_XLSB, 'xl/sharedStrings.bin')
        with self.assertRaises(ExcelFormatError):
            open_workbook(data)

    def test_relationships_that_declare_an_entity_read_like_missing_relationships(self):
        part = 'xl/_rels/workbook.bin.rels'
        source = zipfile.ZipFile(io.BytesIO(TEST_XLSB))

        def package(relationships: bytes | None) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as target:
                for info in source.infolist():
                    if info.filename != part:
                        target.writestr(info.filename, source.read(info))
                    elif relationships is not None:
                        target.writestr(info.filename, relationships)
            return buffer.getvalue()

        declared = package(
            source.read(part).replace(b'?>', b'?><!DOCTYPE root [<!ENTITY e "x">]>'))
        missing = package(None)
        self.assertEqual(
            [(sheet.name, sheet.kind) for sheet in open_workbook(declared).sheets()],
            [(sheet.name, sheet.kind) for sheet in open_workbook(missing).sheets()],
        )


class TestAgainstPyxlsb2(TestBase):

    def test_positions_and_plain_values_match(self):
        try:
            from pyxlsb2 import Workbook as Pyxlsb2Workbook
            from pyxlsb2.xlsbpackage import XlsbPackage
        except ImportError:
            self.skipTest('the pyxlsb2 oracle is not installed')
        for data in (TEST_XLSB, DATES_XLSB, TEST_1904_XLSB):
            mine = _cells(data)
            oracle = {}
            with tempfile.TemporaryDirectory() as folder:
                sample = F'{folder}/sample.xlsb'
                with open(sample, 'wb') as stream:
                    stream.write(data)
                with Pyxlsb2Workbook(XlsbPackage(sample)) as book:
                    for row in book.get_sheet_by_index(0).rows():
                        for cell in row:
                            oracle[(cell.r + 1, cell.c + 1)] = cell
            self.assertEqual(set(mine), set(oracle))
            for key in sorted(mine):
                kind, value = mine[key]
                reference = oracle[key].v
                # Error cells are excluded because the oracle renders them as `#ERR!<code>`
                # without a text table, and date cells because the oracle converts them with an
                # off-by-one in the 1904 epoch; the reader's handling of both is asserted by
                # the behavior tests above.
                if kind in (CellKind.TEXT, CellKind.NUMBER, CellKind.BOOLEAN):
                    self.assertEqual(value, reference, key)
                else:
                    self.assertIn(kind, (CellKind.ERROR, CellKind.DATE))
