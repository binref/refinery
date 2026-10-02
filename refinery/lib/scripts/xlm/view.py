"""
The workbook view of an XLM macro language program: the one object the interpreter is handed,
combining the macrosheet model with the worksheet data the macro formulas read and the name
table the entry points resolve through. It replaces the three wrappers of the retiring port.
"""
from __future__ import annotations

from refinery.lib.excel import (
    Cell,
    ExcelFormat,
    ExcelFormatError,
    International,
    SheetKind,
    open_workbook,
)
from refinery.lib.excel.workbook import ExcelWorkbook
from refinery.lib.scripts.xlm.model import XlmCell, XlmMacrosheet, build_xlm_model
from refinery.lib.scripts.xlm.names import XlmNameTable

#: The workbook name of each container family, as the wrappers of the retiring port spelled
#: them; no reader exposes the name the file was saved under.
_WORKBOOK_NAMES = {
    ExcelFormat.BIFF: 'workbook.xls',
    ExcelFormat.OOXML: 'workbook.xlsm',
    ExcelFormat.XLSB: 'workbook.xlsb',
}


class XlmView:
    """
    A workbook opened for interpretation. The macrosheets are the model the trace and the
    deobfuscation passes work on; the worksheets are data, their cells materialized once into
    a coordinate dictionary because no reader offers random access to them. A worksheet whose
    walk fails partway through keeps the cells it read before the defect.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self._workbook: ExcelWorkbook = open_workbook(data)
        self._macrosheets: dict[str, XlmMacrosheet] = {}
        for macrosheet in build_xlm_model(self._workbook):
            self._macrosheets.setdefault(macrosheet.name, macrosheet)
        self._worksheets: dict[str, dict[tuple[int, int], Cell]] = {}
        for sheet in self._workbook.sheets():
            if sheet.kind is not SheetKind.WORKSHEET:
                continue
            cells: dict[tuple[int, int], Cell] = {}
            try:
                for cell in sheet.cells():
                    cells[(cell.row, cell.col)] = cell
            except ExcelFormatError:
                pass
            self._worksheets.setdefault(sheet.name, cells)
        self.names = XlmNameTable(self._workbook)
        self.workbook_name = _WORKBOOK_NAMES[self._workbook.format]
        self.international = International()

    def macrosheets(self) -> list[XlmMacrosheet]:
        """
        Every macrosheet of the workbook in document order.
        """
        return list(self._macrosheets.values())

    def macrosheet(self, name: str) -> XlmMacrosheet | None:
        """
        The macrosheet a name spells, or `None` when the workbook has none.
        """
        return self._macrosheets.get(name)

    def worksheet(self, name: str) -> dict[tuple[int, int], Cell] | None:
        """
        The cells of the worksheet a name spells, keyed by one-based row and column, or `None`
        when the workbook has no such worksheet.
        """
        return self._worksheets.get(name)

    def cell(self, sheet_name: str, row: int, col: int) -> XlmCell | Cell | None:
        """
        The cell of the sheet a name spells at the one-based `row` and `col`: a cell of the
        macrosheet model when the sheet is one, the reader cell when it is a worksheet, and
        `None` when the sheet or the cell does not exist.
        """
        macrosheet = self._macrosheets.get(sheet_name)
        if macrosheet is not None:
            return macrosheet.cell(row, col)
        worksheet = self._worksheets.get(sheet_name)
        if worksheet is not None:
            return worksheet.get((row, col))
        return None
