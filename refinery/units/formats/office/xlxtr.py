from __future__ import annotations

import codecs
import datetime
import re

from fnmatch import fnmatch

from refinery.lib.excel import (
    Cell,
    CellKind,
    ExcelFormatError,
    ExcelWorkbook,
    SheetKind,
    detect_format,
    open_workbook,
    rc2ref,
    ref2rc,
    serial_to_datetime,
)
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit

_CELL_REFERENCE = re.compile(R'^[A-Z]+\d+$')


def _render_cell(cell: Cell, workbook: ExcelWorkbook) -> str | None:
    if cell.kind is CellKind.BLANK:
        return None
    if cell.kind is CellKind.FORMULA:
        return None
    value = cell.value
    if cell.kind is CellKind.DATE:
        # a date cell carries the serial number Excel stores, which only the epoch of this
        # particular workbook turns into a calendar date
        assert isinstance(value, (int, float))
        value = serial_to_datetime(value, workbook.date_mode_1904)
        if isinstance(value, datetime.datetime):
            return value.isoformat(' ', 'seconds')
        return value.isoformat('seconds')
    return str(value)


class SheetReference:

    Separator = '!'

    def _parse_sheet(self, token: str):
        try:
            sheet, token = token.rsplit(self.Separator, 1)
        except ValueError:
            sheet = None
        else:
            try:
                sheet = int(sheet, 0) - 1
            except (TypeError, ValueError):
                if sheet[0] in ('"', "'") and sheet[~0] == sheet[0] and len(sheet) > 2:
                    sheet = sheet[1:-1]
        return sheet, token

    def _parse_range(self, token: str):
        try:
            start, end = token.split(':')
            return start, end
        except ValueError:
            return token, token

    @staticmethod
    def _parse_token(token: str):
        if _CELL_REFERENCE.match(token) is not None:
            row, col = ref2rc(token)
        else:
            row, col = (int(x, 0) for x in token.split('.'))
        if row <= 0:
            raise ValueError(F'row must be positive, {row} is an invalid value')
        if col <= 0:
            raise ValueError(F'col must be positive, {col} is an invalid value')
        return row, col

    def __init__(self, sheet_reference=None):
        self.lbound = 1, 1
        self.ubound = None
        if sheet_reference is None:
            self.sheet = None
            return
        self.sheet, token = self._parse_sheet(sheet_reference)
        if not token:
            return
        try:
            start, stop = (self._parse_token(x) for x in self._parse_range(token))
        except Exception:
            self.sheet = sheet_reference
        else:
            row_min = min(start[0], stop[0])
            col_min = min(start[1], stop[1])
            row_max = max(start[0], stop[0])
            col_max = max(start[1], stop[1])
            self.lbound = (row_min, col_min)
            self.ubound = (row_max, col_max)

    def match(self, index: int, name: str):
        if self.sheet is None:
            return True
        if isinstance(self.sheet, int):
            return self.sheet == index
        return self.sheet == name or fnmatch(name, self.sheet)

    def __contains__(self, ref):
        if self.ubound is None:
            return True
        if not isinstance(ref, tuple):
            ref = self._parse_token(ref)
        row, col = ref
        if row not in range(self.lbound[0], self.ubound[0] + 1):
            return False
        if col not in range(self.lbound[1], self.ubound[1] + 1):
            return False
        return True


class xlxtr(Unit):
    """
    Extract data from Microsoft Excel documents, both legacy and XML type.

    A sheet reference is of the form `B1` or `1.2`, both specifying the first cell of the
    second column. A cell range can be specified as `B1:C12`, or `1.2:C12`, or `1.2:12.3`.
    Finally, the unit will always refer to the first sheet in the document and to change
    this, specify the sheet name or index separated by a hashtag, i.e. `sheet{s}B1:C12` or
    `1{s}B1:C12`. Note that indices are 1-based. To get all elements of one sheet, use
    `sheet{s}`. If parsing a sheet reference fails, the script will assume that the given
    reference specifies a sheet.
    """
    def __init__(
        self,
        *references: Param[buf, Arg(metavar='reference', help=(
            'A sheet reference to be extracted. '
            'If no sheet references are given, the unit lists all sheet names.'))]
    ):
        if not references:
            references = b'*',
        super().__init__(references=references)

    @classmethod
    def handles(cls, data) -> bool | None:
        return detect_format(data) is not None

    def process(self, data):
        try:
            workbook = open_workbook(data)
        except ExcelFormatError as error:
            raise ValueError('Input not recognized as Excel document.') from error
        references = [SheetReference(codecs.decode(r, self.codec)) for r in self.args.references]
        for ref in references:
            for index, sheet in enumerate(workbook.sheets()):
                if not ref.match(index, sheet.name):
                    continue
                if sheet.kind not in (SheetKind.WORKSHEET, SheetKind.MACROSHEET):
                    continue
                try:
                    for cell in sheet.cells():
                        if (cell.row, cell.col) not in ref:
                            continue
                        value = _render_cell(cell, workbook)
                        if value is None:
                            continue
                        yield self.labelled(
                            value.encode(self.codec),
                            row=cell.row,
                            col=cell.col,
                            ref=rc2ref(cell.row, cell.col),
                            sheet=sheet.name
                        )
                except ExcelFormatError as error:
                    self.log_info(F'error reading sheet {sheet.name}:', error)


if __doc := xlxtr.__doc__:
    xlxtr.__doc__ = __doc.format(s=SheetReference.Separator)
