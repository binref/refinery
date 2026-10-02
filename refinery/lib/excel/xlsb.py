"""
A reader for the cell values of workbooks in the MS-XLSB format, which covers the XLSB file
extension: a zip package of binary record streams. The framing of the streams differs from
the BIFF format — a record starts with a one- or two-byte identifier and a variable-length
integer for the size of its body. The reader implements the value model of
`refinery.lib.excel.common`: a number whose format marks it as a date carries the date kind
together with the serial number Excel stores, and formula cells expose the cached result
that Excel stored with the file together with the uninterpreted formula token stream.
"""
from __future__ import annotations

import posixpath
import struct

from collections.abc import Iterator, Sequence
from enum import IntEnum

from defusedxml.ElementTree import fromstring

from refinery.lib.excel.common import (
    ERROR_TEXT,
    XML_DEFECTS,
    Cell,
    CellKind,
    DefinedName,
    ExcelFormatError,
    FormulaSource,
    SheetKind,
    date_cell,
    decode_rk,
    is_builtin_date_format,
    is_date_format_string,
)
from refinery.lib.excel.formula.model import Expression, XlDefinedName, XlUnparsedFormula
from refinery.lib.excel.formula.ptg import RpnError
from refinery.lib.excel.formula.xlsb import XlsbRpnDecoder
from refinery.lib.excel.workbook import ExcelFormat, ExcelSheet, ExcelWorkbook, _Package

_REL_WORKSHEET = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet'
_REL_CHARTSHEET = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/chartsheet'
_REL_MACROSHEET = 'http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet'
_REL_INTL_MACROSHEET = 'http://schemas.microsoft.com/office/2006/relationships/xlIntlMacrosheet'

_SHEET_KINDS = {
    _REL_WORKSHEET: SheetKind.WORKSHEET,
    _REL_CHARTSHEET: SheetKind.CHART,
    _REL_MACROSHEET: SheetKind.MACROSHEET,
    _REL_INTL_MACROSHEET: SheetKind.MACROSHEET,
}


class _Record(IntEnum):
    """
    The MS-XLSB record identifiers the reader consumes; every other record is skipped.
    """

    ROW_HDR = 0
    CELL_BLANK = 1
    CELL_RK = 2
    CELL_ERROR = 3
    CELL_BOOL = 4
    CELL_REAL = 5
    CELL_ST = 6
    CELL_ISST = 7
    FMLA_STRING = 8
    FMLA_NUM = 9
    FMLA_BOOL = 10
    FMLA_ERROR = 11
    SST_ITEM = 19
    FMT = 44
    XF = 47
    END_SHEET = 130
    BEGIN_BOOK = 131
    END_BOOK = 132
    BEGIN_BUNDLE_SHS = 143
    END_BUNDLE_SHS = 144
    BEGIN_SHEET_DATA = 145
    END_SHEET_DATA = 146
    WB_PROP = 153
    BUNDLE_SH = 156
    BEGIN_SST = 159
    END_SST = 160
    END_STYLE_SHEET = 279
    NAME = 39
    BEGIN_EXTERNALS = 353
    END_EXTERNALS = 354
    SUP_BOOK_SRC = 355
    SUP_SELF = 357
    SUP_SAME = 358
    EXTERN_SHEET = 362
    BEGIN_FMTS = 615
    END_FMTS = 616
    BEGIN_CELL_XFS = 617
    END_CELL_XFS = 618
    BEGIN_CELL_STYLE_XFS = 626
    END_CELL_STYLE_XFS = 627
    SUP_ADDIN = 667


_CELL_RECORDS = frozenset((
    _Record.CELL_BLANK,
    _Record.CELL_RK,
    _Record.CELL_ERROR,
    _Record.CELL_BOOL,
    _Record.CELL_REAL,
    _Record.CELL_ST,
    _Record.CELL_ISST,
    _Record.FMLA_STRING,
    _Record.FMLA_NUM,
    _Record.FMLA_BOOL,
    _Record.FMLA_ERROR,
))

_FORMULA_RECORDS = frozenset((
    _Record.FMLA_STRING,
    _Record.FMLA_NUM,
    _Record.FMLA_BOOL,
    _Record.FMLA_ERROR,
))

# the records that each open one supporting link of the externals section; the order they
# appear in is the index the entries of the extern-sheet table name. A BrtSupTabs record
# names the sheets of an external workbook inside the external link part, so it opens no
# link here.
_SUPPORTING_LINKS = frozenset((
    _Record.SUP_BOOK_SRC,
    _Record.SUP_SELF,
    _Record.SUP_SAME,
    _Record.SUP_ADDIN,
))

_GLOBAL_NAME = 0xFFFFFFFF

_DEFECTS = (struct.error, UnicodeDecodeError, IndexError)


def _records(view: memoryview) -> Iterator[tuple[int, memoryview]]:
    """
    Iterate over the record framing of an MS-XLSB stream: a record identifier of one or two
    bytes, where the high bit of the first byte announces a second byte holding seven more
    bits, followed by the size of the record body as a variable-length integer of up to four
    bytes with seven bits per byte.
    """
    position = 0
    size = len(view)
    while position < size:
        rtype = view[position]
        position += 1
        if rtype & 0x80:
            if position >= size:
                raise ExcelFormatError('the record stream ends inside a record header')
            rtype = (rtype & 0x7F) | ((view[position] & 0x7F) << 7)
            position += 1
        length = 0
        for index in range(4):
            if position >= size:
                raise ExcelFormatError('the record stream ends inside a record header')
            byte = view[position]
            position += 1
            length |= (byte & 0x7F) << (7 * index)
            if not byte & 0x80:
                break
        body = view[position:position + length]
        if len(body) < length:
            raise ExcelFormatError('the record stream ends inside a record body')
        position += length
        yield rtype, body


class _Body:
    """
    A cursor over the body of an MS-XLSB record.
    """

    def __init__(self, view: memoryview):
        self.view = view
        self.position = 0

    def _take(self, count: int) -> memoryview:
        part = self.view[self.position:self.position + count]
        if len(part) < count:
            raise ExcelFormatError('the record body ends inside a value')
        self.position += count
        return part

    def u8(self) -> int:
        return self._take(1)[0]

    def read(self, count: int) -> memoryview:
        return self._take(count)

    def u16(self) -> int:
        return int.from_bytes(self._take(2), 'little')

    def u32(self) -> int:
        return int.from_bytes(self._take(4), 'little')

    def i32(self) -> int:
        return int.from_bytes(self._take(4), 'little', signed=True)

    def double(self) -> float:
        return struct.unpack('<d', self._take(8))[0]

    def rk(self) -> float:
        return decode_rk(self._take(4))

    def string(self) -> str:
        count = self.u32()
        if count:
            return bytes(self._take(2 * count)).decode('utf_16_le')
        return ''


class XlsbSheet(ExcelSheet):
    """
    A worksheet or macrosheet of an `XlsbWorkbook`. Calling `cells` walks the record stream
    of the sheet part; when it is malformed, the cells read up to the defect are yielded first
    and an `ExcelFormatError` is raised afterwards.
    """

    def __init__(self, name: str, kind: SheetKind, part: str | None, workbook: XlsbWorkbook):
        self.name = name
        self.kind = kind
        self._part = part
        self._workbook = workbook

    def cells(self) -> Iterator[Cell]:
        """
        Iterate over every cell of the sheet, in document order.
        """
        if self._part is None:
            raise ExcelFormatError(F'sheet {self.name!r} is not attached to a sheet part')
        body = self._workbook._part(self._part)
        if body is None:
            raise ExcelFormatError(F'part {self._part!r} of sheet {self.name!r} is missing')
        row = -1
        in_data = False
        try:
            for rtype, record in _records(memoryview(body)):
                if rtype == _Record.ROW_HDR:
                    row = _Body(record).u32()
                elif rtype == _Record.BEGIN_SHEET_DATA:
                    in_data = True
                elif rtype == _Record.END_SHEET_DATA:
                    return
                elif in_data and rtype in _CELL_RECORDS:
                    if row < 0:
                        raise ExcelFormatError(
                            F'sheet {self.name!r} has a cell record before any row header')
                    yield self._cell(rtype, record, row)
        except _DEFECTS as error:
            raise ExcelFormatError(F'sheet {self.name!r} is malformed: {error}') from error

    def _cell(self, rtype: int, record: memoryview, row: int) -> Cell:
        workbook = self._workbook
        body = _Body(record)
        col = body.u32()
        style = body.u32()
        formula: bytes | None = None
        if rtype == _Record.CELL_BLANK:
            return Cell(row + 1, col + 1, CellKind.BLANK, None, None)
        if rtype == _Record.CELL_ISST:
            index = body.u32()
            strings = workbook._shared_strings
            if not 0 <= index < len(strings):
                raise ExcelFormatError(
                    F'sheet {self.name!r} references shared string {index}'
                    F' outside the table of {len(strings)} entries')
            return Cell(row + 1, col + 1, CellKind.TEXT, strings[index], None)
        if rtype == _Record.CELL_ST or rtype == _Record.FMLA_STRING:
            kind = CellKind.TEXT
            value: str | bool | float = body.string()
        elif rtype == _Record.CELL_RK:
            kind = CellKind.NUMBER
            value = body.rk()
        elif rtype == _Record.CELL_REAL or rtype == _Record.FMLA_NUM:
            kind = CellKind.NUMBER
            value = body.double()
        elif rtype == _Record.CELL_BOOL or rtype == _Record.FMLA_BOOL:
            kind = CellKind.BOOLEAN
            value = body.u8() != 0
        elif rtype == _Record.CELL_ERROR or rtype == _Record.FMLA_ERROR:
            kind = CellKind.ERROR
            code = body.u8()
            value = ERROR_TEXT.get(code, F'#{code:02X}')
        else:
            return Cell(row + 1, col + 1, CellKind.BLANK, None, None)
        if rtype in _FORMULA_RECORDS:
            body.u16()
            size = body.u32()
            formula = bytes(body.read(size)) if size else None
        if kind is CellKind.NUMBER:
            assert isinstance(value, float)
            if value.is_integer():
                value = int(value)
            if workbook._style_is_date(style):
                return date_cell(row + 1, col + 1, value, workbook.date_mode_1904, formula)
        return Cell(row + 1, col + 1, kind, value, formula)


class XlsbWorkbook(ExcelWorkbook):
    """
    A reader for workbooks in the MS-XLSB format. The sheets of the zip package are located
    through the relationships of the workbook part so that oddly named sheet parts do not
    break extraction.
    """

    format = ExcelFormat.XLSB

    def __init__(self, data: bytes | bytearray | memoryview):
        self._package = _Package(data)
        self.date_mode_1904 = False
        self._shared_strings: list[str] = []
        self._formats: dict[int, str] = {}
        self._style_formats: list[int] | None = None
        self._sheets: list[XlsbSheet] = []
        self._names: list[DefinedName] = []
        self._supporting_links: list[int] = []
        self._externsheet: list[tuple[int, int, int]] = []
        part = self._part('xl/workbook.bin')
        if part is None:
            raise ExcelFormatError('the package has no workbook part')
        rels = self._relationships()
        try:
            for rtype, record in _records(memoryview(part)):
                if rtype == _Record.END_BOOK:
                    break
                if rtype == _Record.WB_PROP:
                    body = _Body(record)
                    flags = body.u32()
                    self.date_mode_1904 = bool(flags & 1)
                elif rtype == _Record.BUNDLE_SH:
                    body = _Body(record)
                    body.u32()
                    body.u32()
                    rid = body.string()
                    name = body.string()
                    target, rel_type = rels.get(rid, (None, None))
                    kind = _SHEET_KINDS.get(rel_type or '', SheetKind.OTHER)
                    part_name = None if target is None else self._resolve(target)
                    self._sheets.append(XlsbSheet(name, kind, part_name, self))
                elif rtype == _Record.NAME:
                    self._names.append(self._name_record(record))
                elif rtype == _Record.EXTERN_SHEET:
                    self._extern_sheet_record(record)
                elif rtype in _SUPPORTING_LINKS:
                    self._supporting_links.append(rtype)
        except _DEFECTS as error:
            raise ExcelFormatError('the workbook part is malformed') from error
        self._load_shared_strings()

    def sheets(self) -> Sequence[XlsbSheet]:
        """
        All sheets of the workbook in document order.
        """
        return self._sheets

    def defined_names(self) -> Sequence[DefinedName]:
        """
        All defined names of the workbook, in the order their BrtName records appear; the
        one-based position of a name in this list is the index its `ptgName` tokens carry.
        """
        return self._names

    def formula(self, source: FormulaSource) -> Expression | None:
        """
        Decode the formula token stream of a cell or a defined name of this workbook. A stream
        that does not decode in full — hostile bytes, a name that does not resolve — yields
        the carrier that prints the raw bytes in hexadecimal; `None` yields `None`. Text is
        not an XLSB source.
        """
        if source is None:
            return None
        if isinstance(source, str):
            return XlUnparsedFormula(text=source)
        try:
            decoder = XlsbRpnDecoder(memoryview(source), self)
            return decoder.decode()
        except RpnError:
            return XlUnparsedFormula(text=bytes(source).hex())

    def _name_record(self, record: memoryview) -> DefinedName:
        """
        Parse one BrtName record: option flags, a keyboard shortcut, the scope sheet index,
        the name, and the formula stream, closed by a comment this reader does not consume.
        """
        body = _Body(record)
        body.u32()
        body.u8()
        scope = body.u32()
        name = body.string()
        size = body.u32()
        return DefinedName(
            name=name,
            formula=bytes(body.read(size)),
            sheet=None if scope == _GLOBAL_NAME else scope,
        )

    def _extern_sheet_record(self, record: memoryview) -> None:
        """
        Parse one BrtExternSheet record: the number of entries, then each entry as a
        supporting-link index and the first and last sheet of the span it names.
        """
        body = _Body(record)
        for _ in range(body.u32()):
            self._externsheet.append((body.u32(), body.i32(), body.i32()))

    def extern_sheets(self, ixti: int) -> tuple[str, ...]:
        """
        The sheet names one extern-sheet index spans: one entry for a plain qualification and
        two for the 3-D span of a `ptgArea3d`. Raises `RpnError` when the index does not
        resolve to sheets of this workbook.
        """
        if not 0 <= ixti < len(self._externsheet):
            raise RpnError(F'the extern-sheet index {ixti} does not exist')
        link, first, last = self._externsheet[ixti]
        if not 0 <= link < len(self._supporting_links):
            raise RpnError(F'the extern-sheet index {ixti} names a missing supporting link')
        if self._supporting_links[link] != _Record.SUP_SELF:
            raise RpnError(F'the extern-sheet index {ixti} names a sheet of another document')
        if first == last == -1 or first == last == -2:
            raise RpnError('a 3-D reference names a deleted or unspecified sheet')
        sheets = [sheet.name for sheet in self._sheets]
        if first > last or not 0 <= first < len(sheets) or not 0 <= last < len(sheets):
            raise RpnError(F'the extern-sheet index {ixti} does not span sheets of this workbook')
        if first == last:
            return (sheets[first],)
        return (sheets[first], sheets[last])

    def defined_name(self, index: int) -> XlDefinedName:
        """
        The model node for the defined name a one-based `ptgName` index refers to. Raises
        `RpnError` when the index does not resolve inside this workbook.
        """
        if not 1 <= index <= len(self._names):
            raise RpnError(F'the name index {index} does not exist')
        record = self._names[index - 1]
        sheet = None
        if record.sheet is not None:
            if not 0 <= record.sheet < len(self._sheets):
                raise RpnError(F'the name {record.name} is scoped to a missing sheet')
            sheet = self._sheets[record.sheet].name
        return XlDefinedName(name=record.name, sheet=sheet)

    def _part(self, part: str) -> bytes | None:
        stream = self._package.open(part)
        if stream is None:
            return None
        return stream.read()

    @staticmethod
    def _resolve(target: str) -> str:
        target = target.replace('\\', '/')
        if target.startswith('/'):
            return target.lstrip('/')
        return posixpath.normpath(posixpath.join('xl', target))

    def _relationships(self) -> dict[str, tuple[str, str]]:
        part = self._part('xl/_rels/workbook.bin.rels')
        if part is None:
            return {}
        try:
            root = fromstring(part)
        except XML_DEFECTS:
            return {}
        result: dict[str, tuple[str, str]] = {}
        for element in root.iter():
            if element.tag.rsplit('}', 1)[-1] != 'Relationship':
                continue
            rid = element.get('Id')
            if rid:
                result[rid] = (element.get('Target') or '', element.get('Type') or '')
        return result

    def _load_shared_strings(self) -> None:
        part = self._part('xl/sharedStrings.bin')
        if part is None:
            return
        try:
            for rtype, record in _records(memoryview(part)):
                if rtype == _Record.SST_ITEM:
                    body = _Body(record)
                    body.u8()
                    self._shared_strings.append(body.string())
                elif rtype == _Record.END_SST:
                    return
        except _DEFECTS as error:
            raise ExcelFormatError('the shared string part is malformed') from error

    def _load_styles(self) -> None:
        part = self._part('xl/styles.bin')
        self._style_formats = []
        if part is None:
            return
        reading_xfs = False
        for rtype, record in _records(memoryview(part)):
            if rtype == _Record.FMT:
                body = _Body(record)
                key = body.u16()
                self._formats[key] = body.string()
            elif rtype == _Record.BEGIN_CELL_XFS:
                reading_xfs = True
            elif rtype == _Record.END_CELL_XFS:
                reading_xfs = False
            elif rtype == _Record.XF and reading_xfs:
                body = _Body(record)
                body.u16()
                self._style_formats.append(body.u16())
            elif rtype == _Record.END_STYLE_SHEET:
                return

    def _style_is_date(self, style: int) -> bool:
        if self._style_formats is None:
            self._load_styles()
        assert self._style_formats is not None
        if not 0 <= style < len(self._style_formats):
            return False
        fmt_id = self._style_formats[style]
        code = self._formats.get(fmt_id)
        if code is not None:
            return is_date_format_string(code)
        return is_builtin_date_format(fmt_id)
