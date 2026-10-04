from __future__ import annotations

import datetime
import enum
import functools
import re
import struct

from typing import NamedTuple
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException


class ExcelFormatError(Exception):
    """
    The structure of a workbook is defective; the cells that were read before the defect are
    still available to the caller while anything after it is not.
    """


#: What parsing the markup of a package part raises when the part is defective: markup that is
#: not well-formed, and the entity declarations the hardened parser refuses to expand.
XML_DEFECTS = (ParseError, DefusedXmlException)


class CellKind(enum.Enum):
    """
    The kind of value a spreadsheet cell holds. A formula cell with a cached result carries the
    kind of that result together with the formula source; a formula cell without a cached
    result carries `FORMULA` and no value.
    """
    TEXT = enum.auto()
    NUMBER = enum.auto()
    DATE = enum.auto()
    BOOLEAN = enum.auto()
    ERROR = enum.auto()
    BLANK = enum.auto()
    FORMULA = enum.auto()


class SheetKind(enum.Enum):
    """
    The purpose of a sheet inside a workbook; only worksheets and macrosheets contain cells.
    """
    WORKSHEET = enum.auto()
    MACROSHEET = enum.auto()
    CHART = enum.auto()
    MODULE = enum.auto()
    OTHER = enum.auto()


#: The value a spreadsheet cell carries; a date cell carries the serial number Excel stores,
#: which only the date mode of its workbook turns into a calendar date.
CellValue = str | int | float | bool | None
FormulaSource = str | bytes | None


class Cell(NamedTuple):
    """
    A single spreadsheet cell at a one-based `row` and `col`. The `value` is typed by `kind`;
    `formula` is the formula source as stored by the format, without interpretation, and is
    `None` for cells that are not formulas. `assignment` marks a formula the container says
    assigns a value to a name — the `bx` attribute of an OOXML macrosheet formula, whose text
    spells the assignment as a comparison; the formats that store the assignment as the
    `SET.NAME` call it already spells leave the flag unset.
    """
    row: int
    col: int
    kind: CellKind
    value: CellValue
    formula: FormulaSource
    assignment: bool = False


class BiffVersion(enum.IntEnum):
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


class DefinedName(NamedTuple):
    """
    A defined name of a workbook. The `formula` is the name's formula source as stored by the
    format, without interpretation; `sheet` is the zero-based index of the sheet the name is
    scoped to, counted in the document order of the format's own sheet table, or `None` when
    the name is global.
    """
    name: str
    formula: FormulaSource
    sheet: int | None


def local_name(tag: str) -> str:
    """
    Return the part of an XML tag that follows its namespace.
    """
    return tag.rsplit('}', 1)[-1]


def ref2rc(ref: str) -> tuple[int, int]:
    """
    Convert a cell reference like `B12` into its one-based row and column.
    """
    match = re.match(R'^([A-Za-z]+)(\d+)$', ref)
    if not match:
        raise ValueError
    col = functools.reduce(
        lambda acc, c: (acc * 26) + c,
        (ord(c.upper()) - 0x40 for c in match[1]),
        0,
    )
    row = int(match[2], 10)
    if row <= 0:
        raise ValueError
    return row, col


def column_letters(col: int) -> str:
    """
    The A1 letters of a one-based column number, so that `column_letters(1)` is `A`.
    """
    letters = ''
    while col:
        col, letter = divmod(col - 1, 26)
        letters = chr(0x41 + letter) + letters
    return letters


def rc2ref(row: int, col: int) -> str:
    """
    Convert one-based row and column numbers into a cell reference like `B12`.
    """
    if row <= 0:
        raise ValueError
    if col <= 0:
        raise ValueError
    return F'{column_letters(col)}{row}'


ERROR_TEXT = {
    0x00: '#NULL!',
    0x07: '#DIV/0!',
    0x0F: '#VALUE!',
    0x17: '#REF!',
    0x1D: '#NAME?',
    0x24: '#NUM!',
    0x2A: '#N/A',
    0x2B: '#GETTING_DATA',
}

_EPOCH_1904 = datetime.datetime(1904, 1, 1)
_EPOCH_1900 = datetime.datetime(1899, 12, 31)
_EPOCH_1900_LEAP = datetime.datetime(1899, 12, 30)
_MARCH_FIRST_1900 = datetime.datetime(1900, 3, 1)
_MILLISECONDS_PER_DAY = 86400000.0


def serial_to_datetime(
    serial: int | float,
    date_mode_1904: bool,
) -> datetime.datetime | datetime.time:
    """
    Convert an Excel serial date number into a datetime, or into a time when the serial number
    carries only a fraction of a day. The 1900 epoch accounts for the spurious leap day that
    Excel inherited from Lotus 1-2-3: serial 60 is the non-existent date of February 29, 1900,
    and serials up to 59 are shifted back by one day.
    """
    days, fraction = divmod(float(serial), 1.0)
    milliseconds = round(fraction * _MILLISECONDS_PER_DAY)
    if 0 <= serial < 1 and milliseconds < _MILLISECONDS_PER_DAY:
        return (datetime.datetime.min + datetime.timedelta(milliseconds=milliseconds)).time()
    if date_mode_1904:
        epoch = _EPOCH_1904
    elif 0 < serial < 60:
        epoch = _EPOCH_1900
    else:
        epoch = _EPOCH_1900_LEAP
    return epoch + datetime.timedelta(days=days, milliseconds=milliseconds)


def datetime_to_serial(
    value: datetime.datetime | datetime.time,
    date_mode_1904: bool,
) -> int | float:
    """
    Convert a datetime or a time into the Excel serial date number that `serial_to_datetime`
    turns back into it. A time names the fraction of a day it covers; a datetime of the 1900
    epoch before March 1, 1900 counts from December 31, 1899, so the spurious leap day that
    Excel inherited from Lotus 1-2-3 keeps serial 60 out of the round trip: February 29,
    1900 does not exist, and the February 28 that serials 59 and 60 both resolve to converts
    back to 59 only. A serial number carries no time zone, so a datetime that names one counts
    by the wall-clock time it spells.
    """
    if isinstance(value, datetime.time):
        milliseconds = (value.hour * 60 + value.minute) * 60000 + value.second * 1000
        milliseconds += value.microsecond // 1000
        serial = milliseconds / _MILLISECONDS_PER_DAY
    else:
        value = value.replace(tzinfo=None)
        if date_mode_1904:
            epoch = _EPOCH_1904
        elif value < _MARCH_FIRST_1900:
            epoch = _EPOCH_1900
        else:
            epoch = _EPOCH_1900_LEAP
        delta = value - epoch
        milliseconds = delta.seconds * 1000 + delta.microseconds // 1000
        serial = delta.days + milliseconds / _MILLISECONDS_PER_DAY
    if isinstance(serial, float) and serial.is_integer():
        return int(serial)
    return serial


def date_cell(
    row: int,
    col: int,
    serial: int | float,
    date_mode_1904: bool,
    formula: FormulaSource = None,
    assignment: bool = False,
) -> Cell:
    """
    Compose the cell of a number whose format marks it as a date. The cell keeps the serial
    number Excel stores — the interpretation of the serial is a question of the reader, not of
    the workbook — and a serial number that no datetime can represent degrades to the
    `#VALUE!` error that Excel displays for it.
    """
    try:
        serial_to_datetime(serial, date_mode_1904)
    except (OverflowError, ValueError):
        return Cell(row, col, CellKind.ERROR, ERROR_TEXT[0x0F], formula, assignment)
    return Cell(row, col, CellKind.DATE, serial, formula, assignment)


def decode_rk(rk: bytes | bytearray | memoryview) -> float:
    """
    Decode the four-byte RK number encoding in which BIFF and XLSB store small numbers: either
    a signed 30-bit integer or the top 30 bits of an IEEE 754 double, with the two low bits of
    the first byte holding flags that select the type and a division by one hundred.
    """
    flags = rk[0] & 0x03
    if flags & 0x02:
        number = int.from_bytes(rk, 'little', signed=True) >> 2
    else:
        high = bytes((rk[0] & 0xFC, rk[1], rk[2], rk[3]))
        number = struct.unpack('<d', b'\0\0\0\0' + high)[0]
    if flags & 0x01:
        return number / 100.0
    return float(number)


_BUILTIN_DATE_FORMATS = frozenset(
    code
    for lo, hi in [
        (14, 22),
        (27, 36),
        (45, 47),
        (50, 58),
        (71, 81),
    ]
    for code in range(lo, hi + 1)
)

_NON_DATE_FORMATS = frozenset([
    '0.00E+00',
    '##0.0E+0',
    'General',
    'GENERAL',
    'general',
    '@',
])
_SKIP_FORMAT_CHARS = frozenset('$-+/(): ')
_DATE_FORMAT_CHARS = frozenset('ymdhsYMDHS')
_NUM_FORMAT_CHARS = frozenset('0#?')
_BRACKETED_FORMAT = re.compile(r'\[[^\]]*\]')


def is_date_format_string(fmt: str) -> bool:
    """
    Decide whether a number format string describes a date or time rather than a number.
    Quoted and escaped literals are ignored, as are bracketed sections; among what remains,
    the count of date letters like `y`, `m`, `d`, `h`, and `s` is weighed against the count
    of digit placeholders.
    """
    literal = ''
    escaped = False
    quoted = False
    for char in fmt:
        if escaped:
            escaped = False
        elif quoted:
            if char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in r'\_*':
            escaped = True
        elif char not in _SKIP_FORMAT_CHARS:
            literal += char
    reduced = _BRACKETED_FORMAT.sub('', literal)
    if reduced in _NON_DATE_FORMATS:
        return False
    date_count = 0
    num_count = 0
    for char in reduced:
        if char in _DATE_FORMAT_CHARS:
            date_count += 1
        elif char in _NUM_FORMAT_CHARS:
            num_count += 1
    if date_count and not num_count:
        return True
    if num_count and not date_count:
        return False
    return date_count > num_count


def is_builtin_date_format(fmt_id: int) -> bool:
    """
    Decide whether a built-in number format identifier describes a date or time.
    """
    return fmt_id in _BUILTIN_DATE_FORMATS


_XSTRING_ESCAPE = re.compile('_x([0-9A-Fa-f]{4})_')


def decode_xstring(value: str) -> str:
    """
    Decode the ST_Xstring escaping in which an OOXML workbook stores control characters that
    XML cannot represent, writing them as `_xHHHH_`. The escape of an underscore itself is
    `_x005F_`, so a literal `_x000F_` is stored as `_x005F_x000F_` and survives decoding.
    """
    return _XSTRING_ESCAPE.sub(lambda m: chr(int(m[1], 16)), value)
