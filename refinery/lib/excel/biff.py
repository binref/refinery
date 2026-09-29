"""
A reader for the cell values of workbooks in the BIFF record format, which covers the
XLS file extension. Every version from BIFF2 to BIFF8 is read, including the raw streams
of BIFF4 workbook files that are not wrapped in an OLE container. The reader implements
the value model of `refinery.lib.excel.common`: date cells are converted according to the
number format of the cell, and formula cells expose the cached result that Excel stored
with the file together with the uninterpreted formula token stream.
"""
from __future__ import annotations

import struct

from collections.abc import Iterator, Sequence
from enum import IntEnum
from typing import NamedTuple

from refinery.lib.excel.common import (
    ERROR_TEXT,
    Cell,
    CellKind,
    ExcelFormatError,
    SheetKind,
    date_cell,
    decode_rk,
    is_builtin_date_format,
    is_date_format_string,
)
from refinery.lib.excel.workbook import ExcelSheet, ExcelWorkbook
from refinery.lib.ole.file import OleFile, is_ole_file


class BiffVersion(IntEnum):
    """
    The BIFF version of a stream. BIFF7 workbooks parse exactly like BIFF5, so there is no
    member for it; BIFF2 workbooks without XF records fall back to the BIFF2.0 rule that
    reads the format key from the cell attributes.
    """

    BIFF2_1 = 21
    BIFF3 = 30
    BIFF4 = 40
    BIFF4W = 45
    BIFF5 = 50
    BIFF8 = 80


class _Record(IntEnum):
    """
    The BIFF record identifiers the reader consumes; every other record is skipped.
    """

    BLANK_B2 = 0x0001
    INTEGER_B2 = 0x0002
    NUMBER_B2 = 0x0003
    LABEL_B2 = 0x0004
    BOOLERR_B2 = 0x0005
    FORMULA = 0x0006
    STRING_B2 = 0x0007
    ARRAY_B2 = 0x0021
    TABLEOP_B2 = 0x0036
    TABLEOP2 = 0x0037
    CONTINUE = 0x003C
    XF2 = 0x0043
    IXFE = 0x0044
    CODEPAGE = 0x0042
    DATEMODE = 0x0022
    FILEPASS = 0x002F
    FORMULA4 = 0x0406
    MULRK = 0x00BD
    MULBLANK = 0x00BE
    ARRAY = 0x0221
    RSTRING = 0x00D6
    SST = 0x00FC
    LABELSST = 0x00FD
    BLANK = 0x0201
    NUMBER = 0x0203
    LABEL = 0x0204
    BOOLERR = 0x0205
    FORMULA3 = 0x0206
    STRING = 0x0207
    TABLEOP = 0x0236
    XF = 0x00E0
    FORMAT = 0x041E
    FORMAT2 = 0x001E
    RK = 0x027E
    SHRFMLA = 0x04BC
    BOUNDSHEET = 0x0085
    SHEETSOFFSET = 0x008E
    SHEETHDR = 0x008F
    XF3 = 0x0243
    XF4 = 0x0443
    EOF = 0x000A


_FORMULA_RECORDS = frozenset((
    _Record.FORMULA,
    _Record.FORMULA3,
    _Record.FORMULA4,
))

_STRING_RECORDS = frozenset((
    _Record.STRING,
    _Record.STRING_B2,
))

_FORMULA_INTERMEDIATE_RECORDS = frozenset((
    _Record.SHRFMLA,
    _Record.ARRAY,
    _Record.ARRAY_B2,
    _Record.TABLEOP,
    _Record.TABLEOP2,
    _Record.TABLEOP_B2,
))

_BIFF2_CELL_RECORDS = frozenset((
    _Record.BLANK_B2,
    _Record.INTEGER_B2,
    _Record.NUMBER_B2,
    _Record.LABEL_B2,
    _Record.BOOLERR_B2,
))

_BOF_OPCODES = frozenset((0x0009, 0x0209, 0x0409, 0x0809))

_THIRD_PARTY_VERSION_WORDS = {
    0x0000: BiffVersion.BIFF2_1,
    0x0007: BiffVersion.BIFF2_1,
    0x0200: BiffVersion.BIFF2_1,
    0x0300: BiffVersion.BIFF3,
    0x0400: BiffVersion.BIFF4,
}

_OPCODE_VERSIONS = {
    0x00: BiffVersion.BIFF2_1,
    0x02: BiffVersion.BIFF3,
    0x04: BiffVersion.BIFF4,
}

_STREAM_GLOBALS = 0x0005
_STREAM_GLOBALS_4W = 0x0100
_STREAM_WORKSHEET = 0x0010
_STREAM_MACROSHEET = 0x0040

_SHEET_KINDS = {
    0x00: SheetKind.WORKSHEET,
    0x01: SheetKind.MACROSHEET,
    0x02: SheetKind.CHART,
    0x06: SheetKind.MODULE,
}

_CODEPAGE_ENCODINGS = {
    1200: 'utf_16_le',
    10000: 'mac_roman',
    10006: 'mac_greek',
    10007: 'mac_cyrillic',
    10029: 'mac_latin2',
    10079: 'mac_iceland',
    10081: 'mac_turkish',
    32768: 'mac_roman',
    32769: 'cp1252',
}

_DEFECTS = (struct.error, UnicodeDecodeError, IndexError)


def _u16(data: memoryview | bytes, offset: int = 0) -> int:
    return int.from_bytes(data[offset:offset + 2], 'little')


class _RecordStream:
    """
    An iterator over the record framing of a BIFF stream: a two-byte record identifier
    followed by a two-byte body length, both little-endian. The absolute position of the
    next record is tracked so that sheet substreams can be located by their offset.
    """

    def __init__(self, view: memoryview, position: int = 0):
        self.view = view
        self.position = position
        self._pending: tuple[int, memoryview] | None = None

    def peek(self) -> tuple[int, memoryview] | None:
        if self._pending is None:
            try:
                self._pending = next(self)
            except StopIteration:
                return None
        return self._pending

    def __iter__(self) -> Iterator[tuple[int, memoryview]]:
        return self

    def __next__(self) -> tuple[int, memoryview]:
        if self._pending is not None:
            pending, self._pending = self._pending, None
            return pending
        view = self.view
        if len(view) - self.position < 4:
            raise StopIteration
        opcode = int.from_bytes(view[self.position:self.position + 2], 'little')
        length = int.from_bytes(view[self.position + 2:self.position + 4], 'little')
        body = view[self.position + 4:self.position + 4 + length]
        if len(body) < length:
            raise ExcelFormatError('the BIFF stream ends inside a record body')
        self.position += 4 + length
        return opcode, body

    def next_record(self) -> tuple[int, memoryview]:
        """
        Read the next record; a truncated stream is a defect rather than the end of the
        stream, which only ever follows a complete record.
        """
        try:
            return next(self)
        except StopIteration:
            raise ExcelFormatError('the BIFF stream ends where a record was required') from None


class _Bof(NamedTuple):
    version: BiffVersion
    stream_type: int


def _read_bof(stream: _RecordStream) -> _Bof:
    """
    Read the BOF record at the current position of the stream and derive the BIFF version
    and substream type from it: the high byte of the record opcode selects the version
    family, and for BIFF5+ workbooks the version word inside the record can override it,
    including the words written by third-party tools. A BIFF4 workbook globals stream is
    a BIFF4W substream.
    """
    opcode, body = stream.next_record()
    if opcode not in _BOF_OPCODES:
        raise ExcelFormatError('the BIFF stream does not start with a BOF record')
    if len(body) < 4:
        raise ExcelFormatError('the BOF record is truncated')
    version_word = _u16(body)
    stream_type = _u16(body, 2)
    family = opcode >> 8
    if family == 0x08:
        if version_word == 0x0600:
            version = BiffVersion.BIFF8
        elif version_word == 0x0500:
            version = BiffVersion.BIFF5
        else:
            version = _THIRD_PARTY_VERSION_WORDS.get(version_word)
    else:
        version = _OPCODE_VERSIONS.get(family)
    if version is None:
        raise ExcelFormatError(F'the BOF record has the unknown version word {version_word:#06x}')
    if version is BiffVersion.BIFF4 and stream_type == _STREAM_GLOBALS_4W:
        version = BiffVersion.BIFF4W
    return _Bof(version, stream_type)


class BiffSheet(ExcelSheet):
    """
    A worksheet or macrosheet of a `BiffWorkbook`. Calling `cells` walks the sheet
    substream; when it is malformed, the cells read up to the defect are yielded first
    and an `ExcelFormatError` is raised afterwards.
    """

    def __init__(self, name: str, kind: SheetKind, offset: int, workbook: BiffWorkbook):
        self.name = name
        self.kind = kind
        self._offset = offset
        self._workbook = workbook
        self._cells: list[Cell] | None = None
        self._error: ExcelFormatError | None = None

    def cells(self) -> Iterator[Cell]:
        """
        Iterate over every cell of the sheet, in document order.
        """
        if self._cells is None:
            cells: list[Cell] = []
            try:
                cells.extend(self._read())
            except ExcelFormatError as error:
                self._error = error
            except _DEFECTS as error:
                self._error = ExcelFormatError(F'sheet {self.name!r} is malformed: {error}')
            self._cells = cells
        yield from self._cells
        if self._error is not None:
            raise self._error

    def _read(self) -> Iterator[Cell]:
        workbook = self._workbook
        view = workbook._view
        if not 0 <= self._offset < len(view):
            raise ExcelFormatError(F'sheet {self.name!r} starts outside the stream')
        stream = _RecordStream(view, self._offset)
        if self is workbook._whole_stream_sheet:
            stream.next_record()
        else:
            bof = _read_bof(stream)
            if not (
                bof.stream_type == _STREAM_WORKSHEET
                or bof.stream_type == _STREAM_MACROSHEET and bof.version is BiffVersion.BIFF8
            ):
                raise ExcelFormatError(F'sheet {self.name!r} is not a worksheet substream')
        if workbook.version is BiffVersion.BIFF4W:
            workbook._reset_formats()
        eof_found = False
        while not eof_found:
            try:
                opcode, body = next(stream)
            except StopIteration:
                break
            if opcode == _Record.EOF:
                eof_found = True
            elif opcode in _BOF_OPCODES:
                for opcode, body in stream:
                    if opcode == _Record.EOF:
                        break
            elif opcode in _BIFF2_CELL_RECORDS and workbook.version < BiffVersion.BIFF3:
                yield from self._biff2_record(opcode, body)
            else:
                workbook._state_record(opcode, body, stream)
                yield from self._cell_record(opcode, body, stream)
        if not eof_found:
            raise ExcelFormatError(F'sheet {self.name!r} has no EOF record')

    def _cell_record(self, opcode: int, body: memoryview, stream: _RecordStream) -> Iterator[Cell]:
        workbook = self._workbook
        if opcode in _FORMULA_RECORDS:
            yield self._formula(body, stream)
        elif opcode == _Record.NUMBER:
            row, col, xf, number = struct.unpack_from('<HHHd', body)
            yield self._number(row, col, number, xf)
        elif opcode == _Record.RK:
            row, col, xf = struct.unpack_from('<HHH', body)
            yield self._number(row, col, decode_rk(body[6:10]), xf)
        elif opcode == _Record.MULRK:
            row, first = struct.unpack_from('<HH', body)
            last = _u16(body, len(body) - 2)
            pos = 4
            for col in range(first, last + 1):
                yield self._number(row, col, decode_rk(body[pos + 2:pos + 6]), _u16(body, pos))
                pos += 6
        elif opcode == _Record.LABELSST:
            row, col, _xf, index = struct.unpack_from('<HHHi', body)
            strings = workbook._shared_strings
            if not 0 <= index < len(strings):
                raise ExcelFormatError(
                    F'sheet {self.name!r} references shared string {index}'
                    F' outside the table of {len(strings)} entries')
            yield Cell(row + 1, col + 1, CellKind.TEXT, strings[index], None)
        elif opcode == _Record.LABEL or opcode == _Record.RSTRING:
            row, col = struct.unpack_from('<HH', body)
            yield Cell(row + 1, col + 1, CellKind.TEXT, workbook._decode_cell_string(body, 6), None)
        elif opcode == _Record.BOOLERR:
            row, col, _xf, value, is_error = struct.unpack_from('<HHHBB', body)
            yield self._boolean_or_error(row, col, value, is_error)
        elif opcode == _Record.BLANK:
            row, col = struct.unpack_from('<HH', body)
            yield Cell(row + 1, col + 1, CellKind.BLANK, None, None)
        elif opcode == _Record.MULBLANK:
            row, first = struct.unpack_from('<HH', body)
            last = _u16(body, len(body) - 2)
            for col in range(first, last + 1):
                yield Cell(row + 1, col + 1, CellKind.BLANK, None, None)

    def _biff2_record(self, opcode: int, body: memoryview) -> Iterator[Cell]:
        workbook = self._workbook
        if opcode == _Record.NUMBER_B2 or opcode == _Record.INTEGER_B2:
            row, col = struct.unpack_from('<HH', body)
            format_key = workbook._biff2_format_key(body[4:7])
            if opcode == _Record.INTEGER_B2:
                number, = struct.unpack_from('<H', body, 7)
            else:
                number, = struct.unpack_from('<d', body, 7)
            yield self._number(row, col, number, None, format_key)
        elif opcode == _Record.LABEL_B2:
            row, col = struct.unpack_from('<HH', body)
            yield Cell(row + 1, col + 1, CellKind.TEXT, workbook._decode_short_string(body, 7), None)
        elif opcode == _Record.BOOLERR_B2:
            row, col = struct.unpack_from('<HH', body)
            yield self._boolean_or_error(row, col, body[7], body[8])
        elif opcode == _Record.BLANK_B2:
            row, col = struct.unpack_from('<HH', body)
            yield Cell(row + 1, col + 1, CellKind.BLANK, None, None)

    def _formula(self, body: memoryview, stream: _RecordStream) -> Cell:
        workbook = self._workbook
        if workbook.version < BiffVersion.BIFF3:
            row, col = struct.unpack_from('<HH', body)
            result = body[7:15]
            formula = bytes(body[20:20 + body[19]])
            xf = None
            format_key = workbook._biff2_format_key(body[4:7])
        else:
            row, col, xf = struct.unpack_from('<HHH', body)
            result = body[6:14]
            formula = bytes(body[22:22 + _u16(body, 20)])
            format_key = None
        position = row + 1, col + 1
        if result[6:8] == b'\xff\xff':
            code = result[0]
            if code == 0:
                text = self._string_after_formula(stream)
                return Cell(*position, CellKind.TEXT, text, formula)
            if code == 1:
                return Cell(*position, CellKind.BOOLEAN, bool(result[2]), formula)
            if code == 2:
                return Cell(*position, CellKind.ERROR, _error_text(result[2]), formula)
            if code == 3:
                return Cell(*position, CellKind.TEXT, '', formula)
            raise ExcelFormatError(F'a formula cell has the unknown result code {code}')
        number, = struct.unpack('<d', result)
        return self._number(row, col, number, xf, format_key, formula)

    def _string_after_formula(self, stream: _RecordStream) -> str:
        opcode, body = stream.next_record()
        if opcode not in _STRING_RECORDS:
            if opcode not in _FORMULA_INTERMEDIATE_RECORDS:
                raise ExcelFormatError(F'a string formula result is followed by record {opcode:#06x}')
            opcode, body = stream.next_record()
            if opcode not in _STRING_RECORDS:
                raise ExcelFormatError(F'a string formula result is followed by record {opcode:#06x}')
        return self._workbook._decode_string_record(body, stream)

    def _number(
        self,
        row: int,
        col: int,
        value: int | float,
        xf: int | None,
        format_key: int | None = None,
        formula: bytes | None = None,
    ) -> Cell:
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        workbook = self._workbook
        if format_key is None:
            format_key = workbook._format_key_of_xf(xf)
        if format_key is not None and workbook._format_is_date(format_key):
            return date_cell(row + 1, col + 1, value, workbook._date_mode_1904, formula)
        return Cell(row + 1, col + 1, CellKind.NUMBER, value, formula)

    def _boolean_or_error(self, row: int, col: int, value: int, is_error: int) -> Cell:
        if is_error:
            kind = CellKind.ERROR
            rendered = _error_text(value)
        else:
            kind = CellKind.BOOLEAN
            rendered = bool(value)
        return Cell(row + 1, col + 1, kind, rendered, None)


def _error_text(code: int) -> str:
    return ERROR_TEXT.get(code, F'#{code:02X}')


class BiffWorkbook(ExcelWorkbook):
    """
    A reader for workbooks in the BIFF record format. The stream is located inside the OLE
    container of an XLS file, or the whole input is taken as the stream of a raw BIFF4
    workbook. Workbooks protected by a password raise an `ExcelFormatError`.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self._view = self._locate_stream(memoryview(data))
        stream = _RecordStream(self._view)
        bof = _read_bof(stream)
        if not (
            bof.stream_type == _STREAM_GLOBALS
            or bof.stream_type == _STREAM_GLOBALS_4W and bof.version is BiffVersion.BIFF4W
            or bof.version < BiffVersion.BIFF5 and bof.stream_type == _STREAM_WORKSHEET
            or bof.stream_type == _STREAM_MACROSHEET and bof.version is BiffVersion.BIFF8
        ):
            raise ExcelFormatError('the BIFF stream is not a workbook substream')
        self.version = bof.version
        self._encoding: str | None = None
        self._date_mode_1904 = False
        self._shared_strings: list[str] = []
        self._formats: dict[int, str] = {}
        self._format_count = 0
        self._xf_format_keys: list[int] = []
        self._ixfe: int | None = None
        self._sheethdr_count = 0
        self._sheets: list[BiffSheet] = []
        self._whole_stream_sheet: BiffSheet | None = None
        if self.version < BiffVersion.BIFF4W:
            self._whole_stream_sheet = BiffSheet('Sheet 1', SheetKind.WORKSHEET, 0, self)
            self._sheets.append(self._whole_stream_sheet)
        else:
            try:
                self._parse_globals(stream)
            except ExcelFormatError:
                raise
            except _DEFECTS as error:
                raise ExcelFormatError('the workbook stream is malformed') from error

    def sheets(self) -> Sequence[BiffSheet]:
        """
        All sheets of the workbook in document order; only worksheets and macrosheets
        appear in this list.
        """
        return self._sheets

    @staticmethod
    def _locate_stream(view: memoryview) -> memoryview:
        if not is_ole_file(view):
            return view
        try:
            ole = OleFile(view)
            for name in ('Workbook', 'Book'):
                if ole.exists(name):
                    return memoryview(bytes(ole.openstream(name)))
        except (OSError, EOFError) as error:
            raise ExcelFormatError('the OLE container of the workbook is defective') from error
        raise ExcelFormatError('the OLE container has no workbook stream')

    def _parse_globals(self, stream: _RecordStream) -> None:
        for opcode, body in stream:
            if opcode == _Record.EOF:
                return
            self._state_record(opcode, body, stream)

    def _state_record(
        self,
        opcode: int,
        body: memoryview,
        stream: _RecordStream,
    ) -> None:
        """
        Handle a record that carries workbook-level state. For BIFF4W and earlier, such
        records also appear inside sheet substreams.
        """
        if opcode == _Record.BOUNDSHEET:
            self._boundsheet(body)
        elif opcode == _Record.SST:
            self._shared_strings = self._shared_string_table(body, stream)
        elif opcode == _Record.CODEPAGE:
            codepage = _u16(body)
            if codepage in _CODEPAGE_ENCODINGS:
                self._encoding = _CODEPAGE_ENCODINGS[codepage]
            elif 300 <= codepage <= 1999:
                self._encoding = F'cp{codepage}'
            else:
                self._encoding = 'iso-8859-1'
        elif opcode == _Record.DATEMODE:
            self._date_mode_1904 = body[0] == 1
        elif opcode == _Record.FILEPASS:
            raise ExcelFormatError('the workbook is encrypted')
        elif opcode == _Record.FORMAT or opcode == _Record.FORMAT2:
            self._format(body, opcode == _Record.FORMAT2)
        elif opcode == _Record.XF:
            self._xf_format_keys.append(_u16(body, 2))
        elif opcode == _Record.XF2:
            self._xf_format_keys.append(body[2] & 0x3F)
        elif opcode == _Record.XF3 or opcode == _Record.XF4:
            self._xf_format_keys.append(body[1])
        elif opcode == _Record.IXFE:
            self._ixfe = _u16(body)
        elif opcode == _Record.SHEETHDR:
            self._sheethdr(body, stream)

    def _boundsheet(self, body: memoryview) -> None:
        if self.version is BiffVersion.BIFF4W:
            name = self._decode_short_string(body, 0)
            self._sheets.append(BiffSheet(name, SheetKind.WORKSHEET, -1, self))
        else:
            offset, = struct.unpack_from('<i', body)
            kind = _SHEET_KINDS.get(body[5], SheetKind.OTHER)
            if self.version >= BiffVersion.BIFF8:
                name = self._decode_unicode_string(body, 6, 1)
            else:
                name = self._decode_short_string(body, 6)
            if kind in (SheetKind.WORKSHEET, SheetKind.MACROSHEET):
                self._sheets.append(BiffSheet(name, kind, offset, self))

    def _sheethdr(self, body: memoryview, stream: _RecordStream) -> None:
        """
        Handle a BIFF4W sheet header, which announces the sheet substream that directly
        follows it by its length in bytes. The workbook continues after that substream.
        """
        length, = struct.unpack_from('<i', body)
        if length < 0:
            raise ExcelFormatError('a sheet header announces a negative substream length')
        name = self._decode_short_string(body, 4)
        position = stream.position
        index = self._sheethdr_count
        if index < len(self._sheets) and self._sheets[index].name == name:
            self._sheets[index]._offset = position
        else:
            self._sheets.append(BiffSheet(name, SheetKind.WORKSHEET, position, self))
        self._sheethdr_count += 1
        stream.position = position + length

    def _shared_string_table(self, body: memoryview, stream: _RecordStream) -> list[str]:
        if len(body) < 8:
            raise ExcelFormatError('the shared string table is truncated')
        chunks = [body]
        while (pending := stream.peek()) is not None and pending[0] == _Record.CONTINUE:
            chunks.append(next(stream)[1])
        count, = struct.unpack_from('<i', body, 4)
        strings: list[str] = []
        index = 0
        pos = 8
        for _ in range(count):
            while pos >= len(chunks[index]):
                index += 1
                if index >= len(chunks):
                    raise ExcelFormatError('the shared string table is truncated')
                pos = 0
            nchars = _u16(chunks[index], pos)
            pos += 2
            options = chunks[index][pos]
            pos += 1
            runs = _u16(chunks[index], pos) if options & 0x08 else 0
            if options & 0x08:
                pos += 2
            phonetic = struct.unpack_from('<i', chunks[index], pos)[0] if options & 0x04 else 0
            if options & 0x04:
                pos += 4
            parts: list[str] = []
            collected = 0
            while collected < nchars:
                need = nchars - collected
                available = len(chunks[index]) - pos
                take = min(available >> 1, need) if options & 0x01 else min(available, need)
                raw = bytes(chunks[index][pos:pos + (2 * take if options & 0x01 else take)])
                parts.append(raw.decode('utf_16_le' if options & 0x01 else 'latin_1'))
                pos += 2 * take if options & 0x01 else take
                collected += take
                if collected < nchars:
                    index += 1
                    if index >= len(chunks):
                        raise ExcelFormatError('the shared string table is truncated')
                    options = chunks[index][0]
                    pos = 1
            for _ in range(runs):
                pos, index = self._advance_chunks(chunks, index, pos, 4)
            pos, index = self._advance_chunks(chunks, index, pos, phonetic)
            strings.append(''.join(parts))
        return strings

    @staticmethod
    def _advance_chunks(chunks: list[memoryview], index: int, pos: int, count: int) -> tuple[int, int]:
        if count < 0:
            raise ExcelFormatError('the shared string table announces a negative section size')
        while count:
            available = len(chunks[index]) - pos
            if not available:
                index += 1
                if index >= len(chunks):
                    raise ExcelFormatError('the shared string table is truncated')
                pos = 0
                continue
            take = min(available, count)
            pos += take
            count -= take
        return pos, index

    def _format(self, body: memoryview, format2: bool) -> None:
        version = BiffVersion.BIFF3 if format2 else self.version
        if version >= BiffVersion.BIFF8:
            key = _u16(body)
            text = self._decode_unicode_string(body, 2, 2)
        elif version >= BiffVersion.BIFF5:
            key = _u16(body)
            text = self._decode_short_string(body, 2)
        else:
            key = self._format_count
            text = self._decode_short_string(body, 0 if format2 else 2)
        self._format_count += 1
        self._formats[key] = text

    def _reset_formats(self) -> None:
        self._formats = {}
        self._format_count = 0
        self._xf_format_keys = []

    def _format_key_of_xf(self, xf: int | None) -> int | None:
        if xf is None or not 0 <= xf < len(self._xf_format_keys):
            return None
        return self._xf_format_keys[xf]

    def _format_is_date(self, format_key: int) -> bool:
        text = self._formats.get(format_key)
        if text is not None:
            return is_date_format_string(text)
        return self.version >= BiffVersion.BIFF5 and is_builtin_date_format(format_key)

    def _biff2_format_key(self, attributes: memoryview) -> int:
        if self.version is BiffVersion.BIFF2_1 and self._xf_format_keys:
            index = attributes[0] & 0x3F
            if index == 0x3F:
                if self._ixfe is None:
                    raise ExcelFormatError('a BIFF2 cell references XF index 63 with no IXFE record')
                index = self._ixfe
            return self._format_key_of_xf(index) or 0
        return attributes[1] & 0x3F

    @property
    def _codepage(self) -> str:
        if self._encoding is None:
            self._encoding = 'utf_16_le' if self.version >= BiffVersion.BIFF8 else 'iso-8859-1'
        return self._encoding

    def _decode_short_string(self, body: memoryview, offset: int) -> str:
        length = body[offset]
        if offset + 1 + length > len(body):
            raise ExcelFormatError('the BIFF stream ends inside a string record')
        return bytes(body[offset + 1:offset + 1 + length]).decode(self._codepage)

    def _decode_cell_string(self, body: memoryview, offset: int) -> str:
        nchars = _u16(body, offset)
        pos = offset + 2
        if self.version >= BiffVersion.BIFF8:
            options = body[pos]
            pos += 1
            if options & 0x08:
                pos += 2
            if options & 0x04:
                pos += 4
            if options & 0x01:
                encoding, width = 'utf_16_le', 2
            else:
                encoding, width = 'latin_1', 1
        else:
            encoding, width = self._codepage, 1
        if pos + width * nchars > len(body):
            raise ExcelFormatError('the BIFF stream ends inside a string record')
        return bytes(body[pos:pos + width * nchars]).decode(encoding)

    def _decode_unicode_string(self, body: memoryview, offset: int, count_size: int) -> str:
        nchars = int.from_bytes(body[offset:offset + count_size], 'little')
        options = body[offset + count_size]
        pos = offset + count_size + 1
        if options & 0x08:
            pos += 2
        if options & 0x04:
            pos += 4
        if options & 0x01:
            encoding, width = 'utf_16_le', 2
        else:
            encoding, width = 'latin_1', 1
        if pos + width * nchars > len(body):
            raise ExcelFormatError('the BIFF stream ends inside a string record')
        return bytes(body[pos:pos + width * nchars]).decode(encoding)

    def _decode_string_record(self, body: memoryview, stream: _RecordStream) -> str:
        count_size = 2 if self.version >= BiffVersion.BIFF3 else 1
        nchars = int.from_bytes(body[:count_size], 'little')
        pos = count_size
        parts: list[str] = []
        collected = 0
        while True:
            if self.version >= BiffVersion.BIFF8:
                encoding = 'utf_16_le' if body[pos] & 1 else 'latin_1'
                pos += 1
            else:
                encoding = self._codepage
            chunk = bytes(body[pos:]).decode(encoding)
            parts.append(chunk)
            collected += len(chunk)
            if collected >= nchars:
                if collected > nchars:
                    raise ExcelFormatError('a string formula result is longer than its length field')
                return ''.join(parts)
            opcode, body = stream.next_record()
            if opcode != _Record.CONTINUE:
                raise ExcelFormatError(F'a string formula result is followed by record {opcode:#06x}')
            pos = 0
