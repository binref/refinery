#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from fnmatch import fnmatch
import openpyxl
import xlrd2 as xlrd
import re
import io
import defusedxml
import functools

from ... import arg, Unit
from ....lib.structures import MemoryFile


defusedxml.defuse_stdlib()


def _ref2rc(ref: str):
    match = re.match(R'^([A-Z]+)(\d+)$', ref)
    if not match:
        raise ValueError
    col = functools.reduce(lambda acc, c: (acc * 26) + c, (ord(c) - 0x40 for c in match[1]), 0)
    row = int(match[2], 10)
    return row, col


def _rc2ref(row: int, col: int):
    if row <= 0:
        raise ValueError
    if col <= 0:
        raise ValueError
    alphabetic = ''
    while col:
        col, letter = divmod(col - 1, 26)
        alphabetic = chr(0x41 + letter) + alphabetic
    return F'{alphabetic}{row}'


class SheetReference:

    def _parse_sheet(self, token: str):
        try:
            sheet, token = token.rsplit('#', 1)
        except ValueError:
            sheet = 0
        else:
            try:
                sheet = int(sheet, 0) - 1
            except (TypeError, ValueError):
                if sheet[0] in ('"', "'") and sheet[~0] == sheet[0] and len(sheet) > 2:
                    sheet = sheet[1:~1]
        return sheet, token

    def _parse_range(self, token):
        try:
            start, end = token.split(':')
            return start, end
        except ValueError:
            return token, token

    @staticmethod
    def _parse_token(token):
        try:
            return _ref2rc(token)
        except ValueError:
            pass
        row, col = (int(x, 0) for x in token.split('.'))
        return row, col

    def __init__(self, sheet_reference):
        self.lbound = self.ubound = None
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
        if isinstance(self.sheet, int):
            return self.sheet == index
        return self.sheet == name or fnmatch(name, self.sheet)

    def __contains__(self, ref):
        if self.lbound is None and self.ubound is None:
            return True
        if not isinstance(ref, tuple):
            ref = self._parse_token(ref)
        row, col = ref
        if row not in range(self.lbound[0], self.ubound[0] + 1):
            return False
        if col not in range(self.lbound[1], self.ubound[1] + 1):
            return False
        return True

    def __iter__(self):
        x, y = self.lbound[0], self.lbound[1]
        while True:
            yield x, y
            if y < self.ubound[1]:
                y += 1
            elif x < self.ubound[0]:
                x, y = x + 1, self.lbound[1]
            else:
                break


class xlxtr(Unit):
    """
    Extract data from Microsoft Excel documents, both Legacy and new XML type documents. A sheet reference is of the form `B1` or `1.2`,
    both specifying the first cell of the second column. A cell range can be specified as `B1:C12`, or `1.2:C12`, or `1.2:12.3`. Finally,
    the unit will always refer to the first sheet in the document and to change this, specify the sheet name or index separated by a
    hashtag, i.e. `sheet#B1:C12` or `1#B1:C12`. Note that indices are 1-based. To get all elements of one sheet, use `sheet#`. The unit
    If parsing a sheet reference fails, the script will assume that the given reference specifies a sheet.
    """
    def __init__(self, *refs: arg(metavar='reference', type=SheetReference, help=(
        'A sheet reference to be extracted. '
        'If no sheet references are given, the unit lists all sheet names.'
    ))):
        super().__init__(refs=refs)

    def _rcmatch(self, sheet_index, sheet_name, row, col):
        assert row > 0
        assert col > 0
        if not self.args.refs:
            return True
        for ref in self.args.refs:
            ref: SheetReference
            if not ref.match(sheet_index, sheet_name):
                continue
            if (row, col) in ref:
                return True
        else:
            return False

    def _get_value(self, sheet_index, sheet, callable, col, row):
        if not self._rcmatch(sheet_index, sheet, row + 1, col + 1):
            return
        try:
            value = callable(row, col)
        except IndexError:
            return
        row += 1
        col += 1
        if not value:
            return
        if isinstance(value, float):
            if float(int(value)) == value:
                value = int(value)
        yield self.labelled(
            str(value).encode(self.codec),
            row=row,
            col=col,
            ref=_rc2ref(row, col),
            sheet=sheet
        )

    def _process_old(self, data):
        with io.StringIO() as logfile:
            wb = xlrd.open_workbook(file_contents=data, logfile=logfile, verbosity=self.args.verbose - 1, on_demand=True)
            logfile.seek(0)
            for entry in logfile:
                entry = entry.strip()
                if re.search(R'^[A-Z]+:', entry) or '***' in entry:
                    self.log_info(entry)
        for k, name in enumerate(wb.sheet_names()):
            sheet = wb.sheet_by_name(name)
            self.log_info(F'iterating {sheet.ncols} columns and {sheet.nrows} rows')
            for row in range(sheet.nrows):
                for col in range(sheet.ncols):
                    yield from self._get_value(k, name, sheet.cell_value, col, row)

    def _process_new(self, data):
        workbook = openpyxl.load_workbook(MemoryFile(data), read_only=True)
        for k, name in enumerate(workbook.sheetnames):
            sheet = workbook.get_sheet_by_name(name)
            cells = [row for row in sheet.iter_rows(values_only=True)]
            nrows = len(cells)
            ncols = max(len(row) for row in cells)
            for row in range(nrows):
                for col in range(ncols):
                    yield from self._get_value(k, name, lambda r, c: cells[r][c], col, row)

    def process(self, data):
        try:
            yield from self._process_new(data)
        except Exception as e:
            self.log_info(F'reverting to xlrd module due to exception: {e!s}')
            yield from self._process_old(data)
