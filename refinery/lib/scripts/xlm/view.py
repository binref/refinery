"""
The workbook view of an XLM macro language program: the one object the interpreter is handed,
combining the macrosheet model with the worksheet data the macro formulas read and the name
table the entry points resolve through.
"""
from __future__ import annotations

from refinery.lib.excel import (
    ExcelFormat,
    International,
    SheetKind,
    open_workbook,
    parse_formula,
)
from refinery.lib.excel.formula.model import XlA1Reference, XlR1C1Reference
from refinery.lib.excel.workbook import ExcelSheet
from refinery.lib.scripts.xlm.model import XlmCell, XlmMacrosheet, build_xlm_model, sheet_cells
from refinery.lib.scripts.xlm.names import XlmNameTable
from refinery.lib.scripts.xlm.references import XlmCursor, XlmReference, resolve_reference

#: The workbook name of each container family, a generic spelling — no reader exposes the name
#: the file was saved under.
_WORKBOOK_NAMES = {
    ExcelFormat.BIFF: 'workbook.xls',
    ExcelFormat.OOXML: 'workbook.xlsm',
    ExcelFormat.XLSB: 'workbook.xlsb',
}


class XlmView:
    """
    A workbook opened for interpretation. The macrosheets are the model the trace and the
    deobfuscation passes work on; the worksheets are data, each read into a coordinate dictionary
    of model cells when it is first asked for, because no reader offers random access to them.
    Sheet names are matched case-insensitively, as Excel matches them.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        workbook = open_workbook(data)
        self._workbook = workbook
        self._macrosheets: dict[str, XlmMacrosheet] = {}
        for macrosheet in build_xlm_model(workbook):
            self._macrosheets.setdefault(macrosheet.name.lower(), macrosheet)
        self._worksheet_sources: dict[str, ExcelSheet] = {}
        for sheet in workbook.sheets():
            if sheet.kind is SheetKind.WORKSHEET:
                self._worksheet_sources.setdefault(sheet.name.lower(), sheet)
        self._worksheets: dict[str, dict[tuple[int, int], XlmCell]] = {}
        self.names = XlmNameTable(workbook)
        self.workbook_name = _WORKBOOK_NAMES[workbook.format]
        self.international = International()

    def macrosheets(self) -> list[XlmMacrosheet]:
        """
        Every macrosheet of the workbook in document order.
        """
        return list(self._macrosheets.values())

    def entry_points(self, start_point: str = '') -> list[XlmReference]:
        """
        The cells a run of the program starts at: every defined name that fuzzy-spells
        `auto_open` or `auto_close` points at one, and without such a name a start point a
        caller named is the only entry.
        """
        result: list[XlmReference] = []
        for pattern in ('auto_open', 'auto_close'):
            for entry in self.names.fuzzy(pattern):
                formula = entry.formula
                if not isinstance(formula, (XlA1Reference, XlR1C1Reference)):
                    continue
                reference = resolve_reference(formula, XlmCursor('', 0, 0))
                if reference.sheet is not None:
                    result.append(reference)
        if not result and start_point:
            parsed = parse_formula(start_point)
            if isinstance(parsed, (XlA1Reference, XlR1C1Reference)):
                reference = resolve_reference(parsed, XlmCursor('', 0, 0))
                if reference.sheet is not None:
                    result.append(reference)
        return result

    def macrosheet(self, name: str) -> XlmMacrosheet | None:
        """
        The macrosheet a name spells, or `None` when the workbook has none.
        """
        return self._macrosheets.get(name.lower())

    def worksheet(self, name: str) -> dict[tuple[int, int], XlmCell] | None:
        """
        The cells of the worksheet a name spells, keyed by one-based row and column as
        `refinery.lib.scripts.xlm.model.sheet_cells` reads them, or `None` when the workbook has
        no such worksheet.
        """
        key = name.lower()
        cells = self._worksheets.get(key)
        if cells is None:
            sheet = self._worksheet_sources.get(key)
            if sheet is None:
                return None
            cells = self._worksheets[key] = sheet_cells(self._workbook, sheet)
        return cells

    def sheet_index(self, name: str) -> int | None:
        """
        The position of the sheet a name spells in the full sheet table of the workbook — the
        sequence the scopes of its defined names count, chartsheets included — or `None` when
        the workbook has no such sheet.
        """
        return self._workbook.sheet_index(name)

    def cell(self, sheet_name: str, row: int, col: int) -> XlmCell | None:
        """
        The cell of the sheet a name spells at the one-based `row` and `col`, or `None` when the
        sheet or the cell does not exist.
        """
        macrosheet = self.macrosheet(sheet_name)
        if macrosheet is not None:
            return macrosheet.cell(row, col)
        worksheet = self.worksheet(sheet_name)
        if worksheet is not None:
            return worksheet.get((row, col))
        return None
