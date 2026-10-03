from __future__ import annotations

import datetime
import struct

from refinery.lib.excel import (
    Cell,
    CellKind,
    ExcelFormat,
    ExcelFormatError,
    SheetKind,
    detect_format,
    open_workbook,
    serial_to_datetime,
)
from refinery.lib.excel.biff import BiffWorkbook
from refinery.lib.ole.file import OleFile

from ... import TestBase
from .samples import (
    BIFF4_RAW,
    CORRUPTED_ERROR,
    FORMATE_BIFF8,
    FORMULA_TEST_NAMES,
    FORMULA_TEST_SJMACHIN,
    ISSUE20,
    PICTURE_IN_CELL,
    PROFILES_BIFF8,
    RAGGED,
)

_ENCRYPTED_XLS_RC4 = '4908a2b6b37f0c16ff3d7ce7b397623d7fcfaca4c4411905755ff512c39d9da5'

_ALL_SAMPLES = [
    FORMATE_BIFF8,
    PROFILES_BIFF8,
    FORMULA_TEST_NAMES,
    FORMULA_TEST_SJMACHIN,
    ISSUE20,
    RAGGED,
    PICTURE_IN_CELL,
    BIFF4_RAW,
    CORRUPTED_ERROR,
]


def _cells(data: bytes) -> dict[tuple[str, int, int], Cell]:
    return {
        (sheet.name, cell.row, cell.col): cell
        for sheet in open_workbook(data).sheets()
        for cell in sheet.cells()
    }


def _records(stream: bytes):
    position = 0
    while len(stream) - position >= 4:
        opcode, length = struct.unpack_from('<HH', stream, position)
        yield position, opcode, length, stream[position + 4:position + 4 + length]
        position += 4 + length


def _shift_sheet_offsets(stream: bytes, modified: bytearray, boundary: int) -> None:
    """
    Shift the BOUNDSHEET offsets of a stream whose insertion moved everything after the
    given boundary by the number of bytes the modification added.
    """
    delta = len(modified) - len(stream)
    for position, opcode, _, _ in _records(bytes(modified)):
        if opcode != 0x0085:
            continue
        offset, = struct.unpack_from('<i', modified, position + 4)
        if offset >= boundary:
            struct.pack_into('<i', modified, position + 4, offset + delta)


def _split_shared_string_table(stream: bytes) -> bytes:
    """
    Split the SST record of the stream in two at a character boundary inside its only
    uncompressed string, inserting a CONTINUE record with the options byte that a writer
    of the file would have placed there. The sheet offsets recorded in BOUNDSHEET records
    are shifted by the bytes the insertion adds.
    """
    start, _, length, body = next(r for r in _records(stream) if r[1] == 0x00FC)
    count, = struct.unpack_from('<i', body, 4)
    position = 8
    split = None
    for _ in range(count):
        nchars, = struct.unpack_from('<H', body, position)
        options = body[position + 2]
        position += 3
        if options & 0x08:
            position += 2
        if options & 0x04:
            position += 4
        size = 2 * nchars if options & 0x01 else nchars
        if options & 0x01:
            split = position + size - 2
        position += size
    assert split is not None
    flag = 0x01
    first = stream[:start] + struct.pack('<HH', 0x00FC, split) + body[:split]
    second = struct.pack('<HH', 0x003C, length - split + 1) + bytes([flag]) + body[split:]
    modified = bytearray(first + second + stream[start + 4 + length:])
    _shift_sheet_offsets(stream, modified, start + 4 + length)
    return bytes(modified)


def _split_shared_string_table_between_strings(stream: bytes) -> bytes:
    """
    Split the SST record of the stream in two right after its first string, so that the
    second string begins at the first byte of a CONTINUE record.
    """
    start, _, length, body = next(r for r in _records(stream) if r[1] == 0x00FC)
    nchars, = struct.unpack_from('<H', body, 8)
    options = body[10]
    position = 11
    if options & 0x08:
        position += 2
    if options & 0x04:
        position += 4
    position += 2 * nchars if options & 0x01 else nchars
    first = stream[:start] + struct.pack('<HH', 0x00FC, position) + body[:position]
    second = struct.pack('<HH', 0x003C, length - position) + body[position:]
    modified = bytearray(first + second + stream[start + 4 + length:])
    _shift_sheet_offsets(stream, modified, start + 4 + length)
    return bytes(modified)


class TestBiffWorkbook(TestBase):

    def test_detect_biff(self):
        for data in _ALL_SAMPLES:
            with self.subTest(data=data[:8]):
                self.assertIs(detect_format(data), ExcelFormat.BIFF)

    def test_sheets_of_formate(self):
        self.assertEqual(
            [(sheet.name, sheet.kind) for sheet in open_workbook(FORMATE_BIFF8).sheets()],
            [
                ('Blätt1', SheetKind.WORKSHEET),
                ('ÖÄÜ', SheetKind.WORKSHEET),
                ('Blätt3', SheetKind.WORKSHEET),
                ('Formate', SheetKind.WORKSHEET),
            ],
        )

    def test_dates_carry_the_serial_by_cell_format(self):
        cells = _cells(FORMATE_BIFF8)
        self.assertEqual(cells[('Blätt1', 1, 2)], Cell(1, 2, CellKind.DATE, 2741, None))
        self.assertEqual(cells[('Blätt1', 2, 2)], Cell(2, 2, CellKind.DATE, 38406, None))
        self.assertEqual(cells[('Blätt1', 4, 2)], Cell(4, 2, CellKind.DATE, 0.2736111111111111, None))
        # the cells of this sheet carry no date format and stay numbers
        self.assertEqual(cells[('Blätt3', 1, 1)], Cell(1, 1, CellKind.NUMBER, 100, None))

    def test_date_serials_resolve_their_values(self):
        for key, expected in [
            (('Blätt1', 1, 2), datetime.datetime(1907, 7, 3)),
            (('Blätt1', 2, 2), datetime.datetime(2005, 2, 23)),
            (('Blätt1', 4, 2), datetime.time(6, 34)),
        ]:
            with self.subTest(key=key):
                cell = _cells(FORMATE_BIFF8)[key]
                self.assertEqual(serial_to_datetime(cell.value, False), expected)

    def test_formula_cells_carry_cached_results(self):
        cells = _cells(FORMULA_TEST_SJMACHIN)
        sheet = 'Sheet1'
        number = cells[(sheet, 3, 2)]
        self.assertEqual((number.row, number.col, number.kind, number.value), (3, 2, CellKind.NUMBER, 1 / 7))
        text = cells[(sheet, 4, 2)]
        self.assertEqual((text.row, text.col, text.kind, text.value), (4, 2, CellKind.TEXT, 'ABCDEF'))
        self.assertIsInstance(text.formula, bytes)
        self.assertNotEqual(text.formula, b'')
        literal = cells[(sheet, 2, 2)]
        self.assertEqual(
            (literal.row, literal.col, literal.kind, literal.value),
            (2, 2, CellKind.TEXT, 'МОСКВА Москва'),
        )
        self.assertIsNone(literal.formula)

    def test_error_and_boolean_cells(self):
        cells = _cells(FORMULA_TEST_SJMACHIN)
        boolean = cells[('Sheet1', 6, 2)]
        self.assertEqual((boolean.row, boolean.col, boolean.kind, boolean.value), (6, 2, CellKind.BOOLEAN, True))
        self.assertIsInstance(boolean.formula, bytes)
        error = cells[('Sheet1', 7, 2)]
        self.assertEqual((error.row, error.col, error.kind, error.value), (7, 2, CellKind.ERROR, '#DIV/0!'))
        boolean = _cells(FORMULA_TEST_NAMES)[('Sheet1', 8, 2)]
        self.assertEqual((boolean.row, boolean.col, boolean.kind, boolean.value), (8, 2, CellKind.BOOLEAN, True))

    def test_blank_cells(self):
        cells = _cells(ISSUE20)
        blanks = [key for key, cell in cells.items() if cell.kind is CellKind.BLANK]
        self.assertEqual(blanks, [
            ('Sheet1', 12, 4),
            ('Sheet1', 13, 4),
            ('Sheet1', 14, 4),
            ('Sheet1', 17, 4),
            ('Sheet1', 18, 4),
        ])
        # a sheet whose only cell carries formatting but no value reads as one blank cell
        self.assertEqual(
            [(cell.row, cell.col, cell.kind) for cell in open_workbook(PICTURE_IN_CELL).sheets()[0].cells()],
            [(1, 1, CellKind.BLANK)],
        )

    def test_raw_biff4_worksheet_stream(self):
        workbook = open_workbook(BIFF4_RAW)
        self.assertEqual(
            [(sheet.name, sheet.kind) for sheet in workbook.sheets()],
            [('Sheet 1', SheetKind.WORKSHEET)],
        )
        cells = _cells(BIFF4_RAW)
        self.assertEqual(cells[('Sheet 1', 1, 1)], Cell(1, 1, CellKind.TEXT, 'ID', None))
        self.assertEqual(len(cells), 108)
        self.assertTrue(all(cell.kind is CellKind.TEXT for cell in cells.values()))

    def test_defective_ole_container(self):
        # the OLE container of this workbook is defective; the cells of all nine sheets are
        # still readable
        workbook = open_workbook(CORRUPTED_ERROR)
        self.assertEqual(len(workbook.sheets()), 9)
        self.assertEqual(workbook.sheets()[0].name, 'Трубы ВГП')
        cells = _cells(CORRUPTED_ERROR)
        self.assertEqual(cells[('Трубы ВГП', 1, 1)], Cell(1, 1, CellKind.TEXT, 'ПРАЙС-ЛИСТ', None))
        self.assertGreater(len(cells), 20000)

    def test_encrypted_workbook_raises(self):
        data = self.download_sample(_ENCRYPTED_XLS_RC4)
        with self.assertRaises(ExcelFormatError):
            open_workbook(data)

    def test_sheet_without_eof_record(self):
        # truncating the last two bytes of the stream removes the EOF record of the last
        # sheet, which ends its extraction after the cells before the defect have been read
        stream = bytes(OleFile(FORMULA_TEST_SJMACHIN).openstream('Workbook'))[:-2]
        sheets = open_workbook(stream).sheets()
        self.assertEqual(len(list(sheets[0].cells())), 16)
        self.assertEqual(len(list(sheets[1].cells())), 0)
        with self.assertRaises(ExcelFormatError):
            list(sheets[2].cells())

    def test_sheet_header_with_negative_substream_length(self):
        # The BOF of the raw stream is turned into the globals substream of a BIFF4W
        # workbook, followed by a sheet header that announces a negative substream length;
        # rewinding the record stream to that extent is a defect.
        stream = bytearray(BIFF4_RAW[:10])
        struct.pack_into('<H', stream, 6, 0x0100)
        stream += struct.pack('<HH', 0x008F, 6) + struct.pack('<i', -1) + b'\x01X'
        stream += BIFF4_RAW[10:]
        with self.assertRaises(ExcelFormatError):
            open_workbook(bytes(stream))

    def test_inflated_label_length_is_a_defect(self):
        # A LABEL record that announces more characters than its body holds must not
        # silently decode to the characters that are present; the length field of its
        # string sits at offset six of the record body.
        position = next(p for p, opcode, _, _ in _records(BIFF4_RAW) if opcode == 0x0204)
        stream = bytearray(BIFF4_RAW)
        struct.pack_into('<H', stream, position + 4 + 6, 100)
        sheet = open_workbook(bytes(stream)).sheets()[0]
        with self.assertRaises(ExcelFormatError):
            list(sheet.cells())

    def test_inflated_boundsheet_name_is_a_defect(self):
        # The name of a BIFF8 BOUNDSHEET record is announced by a one-byte length that
        # must not exceed the record body.
        stream = bytes(OleFile(FORMATE_BIFF8).openstream('Workbook'))
        position = next(p for p, opcode, _, _ in _records(stream) if opcode == 0x0085)
        modified = bytearray(stream)
        modified[position + 4 + 6] = 200
        with self.assertRaises(ExcelFormatError):
            open_workbook(bytes(modified))


class TestSharedStringContinueRecords(TestBase):
    """
    The shared string table of the workbook is split into a CONTINUE chain inside its only
    uncompressed string; a reader must read the split stream exactly like the original one.
    """

    def _stream(self) -> bytes:
        return bytes(OleFile(FORMULA_TEST_SJMACHIN).openstream('Workbook'))

    def test_split_stream_reads_like_the_original(self):
        original = self._stream()
        split = _split_shared_string_table(original)
        self.assertNotEqual(original, split)
        expected = _cells(FORMULA_TEST_SJMACHIN)
        actual = _cells(split)
        self.assertEqual(actual, expected)
        self.assertNotEqual(len(original), len(split))

    def test_split_between_strings_reads_like_the_original(self):
        original = self._stream()
        split = _split_shared_string_table_between_strings(original)
        self.assertNotEqual(original, split)
        self.assertEqual(_cells(split), _cells(FORMULA_TEST_SJMACHIN))

    def test_negative_section_size_is_a_defect(self):
        # The phonetic section size of a string in the table is signed and must not be
        # negative; walking backwards through the chunks would read unrelated bytes.
        chunks = [memoryview(b'abcdefgh')]
        with self.assertRaises(ExcelFormatError):
            BiffWorkbook._advance_chunks(chunks, 0, 2, -1)

    def test_split_stream_reads_like_the_original_in_xlrd(self):
        try:
            import xlrd2
        except ImportError:
            self.skipTest('the xlrd2 oracle is not installed')

        def values(data):
            book = xlrd2.open_workbook(file_contents=data)
            return [
                (sheet.name, row, col, sheet.cell(row, col).value)
                for sheet in book.sheets()
                for row in range(sheet.nrows)
                for col in range(sheet.ncols)
                if sheet.cell(row, col).ctype
            ]

        original = self._stream()
        split = _split_shared_string_table(original)
        self.assertEqual(values(split), values(original))


class TestAgainstXlrd(TestBase):

    def test_cells_and_sheets_match(self):
        try:
            import xlrd2
        except ImportError:
            self.skipTest('the xlrd2 oracle is not installed')
        for name, data in [
            ('formate', FORMATE_BIFF8),
            ('profiles', PROFILES_BIFF8),
            ('formula_test_names', FORMULA_TEST_NAMES),
            ('formula_test_sjmachin', FORMULA_TEST_SJMACHIN),
            ('issue20', ISSUE20),
            ('ragged', RAGGED),
            ('picture_in_cell', PICTURE_IN_CELL),
            ('biff4_raw', BIFF4_RAW),
            ('corrupted_error', CORRUPTED_ERROR),
        ]:
            with self.subTest(sample=name):
                kwargs = {'ignore_workbook_corruption': True} if name == 'corrupted_error' else {}
                book = xlrd2.open_workbook(file_contents=data, **kwargs)
                expected = {}
                for sheet in book.sheets():
                    for row in range(sheet.nrows):
                        for col in range(sheet.ncols):
                            cell = sheet.cell(row, col)
                            if cell.ctype in (xlrd2.XL_CELL_BLANK, xlrd2.XL_CELL_EMPTY):
                                continue
                            value = cell.value
                            # date cells keep the serial number in both readers; the serials
                            # of this corpus resolve to their moments in the tests above
                            if cell.ctype == xlrd2.XL_CELL_BOOLEAN:
                                value = bool(value)
                            elif cell.ctype == xlrd2.XL_CELL_ERROR:
                                value = xlrd2.error_text_from_code.get(value, F'#{value:02X}')
                            if isinstance(value, float) and value.is_integer():
                                value = int(value)
                            kind = {
                                xlrd2.XL_CELL_TEXT: CellKind.TEXT,
                                xlrd2.XL_CELL_NUMBER: CellKind.NUMBER,
                                xlrd2.XL_CELL_DATE: CellKind.DATE,
                                xlrd2.XL_CELL_BOOLEAN: CellKind.BOOLEAN,
                                xlrd2.XL_CELL_ERROR: CellKind.ERROR,
                            }[cell.ctype]
                            # a number cell whose format string xlrd classifies as text holds
                            # a float either way and is a number in the unified model
                            if kind is CellKind.TEXT and isinstance(value, float):
                                kind = CellKind.NUMBER
                            expected[sheet.name, row + 1, col + 1] = (kind, value)
                actual = {
                    key: (cell.kind, cell.value)
                    for key, cell in _cells(data).items()
                    if cell.kind is not CellKind.BLANK
                }
                self.assertEqual(actual, expected)
                self.assertEqual(
                    [sheet.name for sheet in open_workbook(data).sheets()],
                    book.sheet_names(),
                )
