#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import openpyxl
import xlrd2 as xlrd
import re
import io
import defusedxml
import itertools
import functools

from ... import arg, Unit
from ....lib.structures import MemoryFile
from .. import UnpackResult, PathExtractorUnit

defusedxml.defuse_stdlib()


class SheetReference:

    def _parse_sheet(self, token):
        try:
            sheet, token = token.split('#')
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

    def _parse_token(self, token):
        match = re.match(R'^([A-Z]+)(\d+)$', token)
        if not match:
            row, col = (int(x, 0) for x in token.split('.'))
        else:
            col = functools.reduce(
                lambda acc, c: (acc * 26) + c,
                (ord(c) - 0x40 for c in match[1]),
                0
            )
            row = int(match[2], 10)
        return row, col

    def __init__(self, token):
        self.sheet, token = self._parse_sheet(token)
        start, stop = (self._parse_token(x) for x in self._parse_range(token))
        if start > stop:
            self.stop = start
            self.start = stop
        else:
            self.stop = stop
            self.start = start

    def get_sheet_index(self, names):
        return self.sheet if isinstance(self.sheet, int) else names.index(self.sheet)

    def __iter__(self):
        xmin = min(self.start[0], self.stop[0])
        ymin = min(self.start[1], self.stop[1])
        xmax = max(self.start[0], self.stop[0])
        ymax = max(self.start[1], self.stop[1])
        x, y = xmin, ymin
        while True:
            yield x, y
            if y < ymax:
                y += 1
            elif x < xmax:
                x, y = x + 1, ymin
            else:
                break


class xlxtr(PathExtractorUnit):
    """
    Extract data from Microsoft Excel documents, both Legacy and new XML type
    documents. A sheet reference is of the form `B1` or `1.2`, both specifying
    the first cell of the second column. A cell range can be specified as
    `B1:C12`, or `1.2:C12`, or `1.2:12.3`. Finally, the unit will always refer
    to the first sheet in the document and to change this, specify the sheet
    name or index separated by a hashtag, i.e. `sheet#B1:C12` or `1#B1:C12`.
    Note that indices are 1-based.
    """

    def __init__(
        self, *paths, list=False, join=False, regex=False, fuzzy=False,
        rows: arg.switch(help='Group results by row instead of column.') = False,
    ):
        super().__init__(*paths, list=list, join=join, regex=regex, fuzzy=fuzzy, rows=rows)

    # def __init__(self, *refs: arg(metavar='reference', type=SheetReference, help=(
    #     'A sheet reference to be extracted. '
    #     'If no sheet references are given, the unit lists all sheet names.'
    # ))):
    #     super().__init__(refs=refs)

    def _row_col_iter(self, nrows, ncols):
        outer, inner = range(ncols), range(nrows)
        if self.args.rows:
            outer, inner = inner, outer
        for col, row in itertools.product(outer, inner):
            if self.args.rows:
                row, col = col, row
                yield str(row), self._col_translate(col), col, row
            else:
                yield self._col_translate(col), str(row), col, row

    @staticmethod
    def _col_translate(index):
        alphabetic = ''
        index += 1
        while index:
            index, letter = divmod(index - 1, 26)
            alphabetic = chr(0x41 + letter) + alphabetic
        return alphabetic

    def _get_value(self, callable, col, row):
        try:
            value = callable(row, col)
        except IndexError:
            return None
        if not value:
            return None
        if isinstance(value, str):
            value = value.encode(self.codec)
        else:
            typename = type(value).__name__
            self.log_warn(F'unable to handle value of type {typename} in ({col},{row}):', value)
            raise ValueError
        return value

    def _process_legacy(self, data):
        with io.StringIO() as logfile:
            wb = xlrd.open_workbook(
                file_contents=data,
                logfile=logfile,
                verbosity=self.args.verbose - 1,
                on_demand=True
            )
            logfile.seek(0)
            for entry in logfile:
                entry = entry.strip()
                if re.search(R'^[A-Z]+:', entry) or '***' in entry:
                    self.log_info(entry)
        for name in wb.sheet_names():
            sheet = wb.sheet_by_name(name)
            self.log_info(F'iterating {sheet.ncols} columns and {sheet.nrows} rows')
            for outer, inner, col, row in self._row_col_iter(sheet.nrows, sheet.ncols):
                value = self._get_value(sheet.cell_value, col, row)
                if value is not None:
                    yield UnpackResult(F'{name}/{outer}/{inner}', value)

    def _process_xlsx(self, data):
        workbook = openpyxl.load_workbook(MemoryFile(data), read_only=True)
        for name in workbook.sheetnames:
            sheet = workbook.worksheets[name]
            cells = [row for row in sheet.iter_rows(values_only=True)]
            nrows = len(cells)
            ncols = max(len(row) for row in cells)
            for outer, inner, col, row in self._row_col_iter(nrows, ncols):
                value = self._get_value(lambda c, r: cells[r][c], col, row)
                if value is not None:
                    yield UnpackResult(F'{name}/{outer}/{inner}', value)

    def unpack(self, data):
        try:
            yield from self._process_xlsx(data)
        except Exception:
            self.log_info('reverting to xlrd module')
            yield from self._process_legacy(data)
