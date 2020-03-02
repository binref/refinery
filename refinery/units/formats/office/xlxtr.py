#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import openpyxl
import xlrd
import re
import defusedxml
import math
import functools

from ... import Unit


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
                (ord(c) - 0x40 for c in match.group(1)),
                0
            )
            row = int(match.group(2), 10)
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


class xlxtr(Unit):
    """
    Extract data from Microsoft Excel documents, both Legacy and new XML type
    documents. A sheet reference is of the form `B1` or `1.2`, both specifying
    the first cell of the second column. A cell range can be specified as
    `B1:C12`, or `1.2:C12`, or `1.2:3.12`. Finally, the unit will always refer
    to the first sheet in the document and to change this, specify the sheet
    name or index separated by a hashtag, i.e. `sheet#B1:C12` or `1#B1:C12`.
    Note that indices are 1-based.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument('refs', metavar='reference', type=SheetReference, nargs='*',
            help='A sheet reference to be extracted.')
        argp.epilog = 'If no sheet references are given, the unit lists all sheet names.'
        return super().interface(argp)

    def _process_legacy(self, data):
        import io

        logfile = io.StringIO()
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

        if not self.args.refs:
            self._display_sheet_names(wb.sheet_names())
        for ref in self.args.refs:
            sh = wb.sheet_by_index(ref.get_sheet_index(wb.sheet_names()))
            for cell in ref:
                self.log_debug('emitting cell: ({},{})'.format(*cell))
                col, row = cell
                try:
                    value = sh.cell_value(col - 1, row - 1)
                except IndexError:
                    continue
                if isinstance(value, str):
                    yield value.encode(self.codec)
                else:
                    self.log_warn(F'value not a string in ({col},{row}):', value)

    def _process_xlsx(self, wb):
        if not self.args.refs:
            self._display_sheet_names(wb.sheetnames)
        for ref in self.args.refs:
            sh = wb.worksheets[ref.get_sheet_index(wb.sheetnames)]
            for cell in ref:
                self.log_debug('emitting cell: ({},{})'.format(*cell))
                value = sh.cell(*cell).value
                if value:
                    yield value.encode(self.codec)

    def _display_sheet_names(self, sheets):
        sheets = list(sheets)
        if not sheets:
            return
        width = int(math.log(len(sheets), 10)) + 1
        for k, name in enumerate(sheets):
            self.output(F'sheet {k:{width}d}:', name)

    def process(self, data):
        try:
            workbook = openpyxl.load_workbook(
                io.BytesIO(data),
                read_only=True
            )
        except Exception:
            self.log_info('reverting to xlrd module')
            yield from self._process_legacy(data)
        else:
            yield from self._process_xlsx(workbook)
