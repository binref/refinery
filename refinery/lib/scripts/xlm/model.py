"""
The macrosheet model of the XLM macro language: one `XlmMacrosheet` script per macrosheet of a
workbook and one `XlmCell` statement per cell, built from the sheets of an
`refinery.lib.excel.workbook.ExcelWorkbook`. Worksheets are data rather than program, so the
model holds macrosheets only; the view layer reads worksheet cells straight from the workbook.
"""
from __future__ import annotations

import datetime

from dataclasses import dataclass

from refinery.lib.excel.common import SheetKind, column_letters
from refinery.lib.excel.formula.model import (
    Expression,
    XlBinaryExpression,
    XlBinaryOperator,
    XlDefinedName,
    XlFunctionCall,
    XlString,
)
from refinery.lib.excel.workbook import ExcelWorkbook
from refinery.lib.scripts import Script, Statement

#: How far the row fall-through scans below its starting row before it gives up, as the old
#: port's `get_formula_cell` does.
_ROW_FALL_THROUGH_LIMIT = 10000


@dataclass(repr=False, eq=False)
class XlmCell(Statement):
    """
    A single cell of a macrosheet at a one-based `row` and `col`. The `formula` is the decoded
    expression tree, the unparsed carrier for a formula the reader could not decode, or `None`
    for a cell that holds only a value; `value` is the cached value as the reader spelled it,
    with a date or a time stored as its ISO text so that every field of the node is a primitive;
    `assignment` marks a formula the container says assigns to a name.
    """

    row: int = 0
    col: int = 0
    assignment: bool = False
    formula: Expression | None = None
    value: str | int | float | bool | None = None


@dataclass(repr=False, eq=False)
class XlmMacrosheet(Script):
    """
    A macrosheet as a script of cells in document order. The `body` field is inherited from
    `refinery.lib.scripts.Script` and holds `XlmCell` statements; a body typed as a list of
    cells would fail the variance check the framework's field classification runs.
    """

    name: str = ''
    kind: SheetKind = SheetKind.MACROSHEET

    def cell(self, row: int, col: int) -> XlmCell | None:
        """
        The cell at the one-based `row` and `col`, or `None` where the sheet holds none.
        """
        for item in self.body:
            if isinstance(item, XlmCell) and item.row == row and item.col == col:
                return item
        return None

    def sorted_cells(self) -> list[XlmCell]:
        """
        The cells in the order the extract listing shows them: by column letters, then by row.
        """
        return sorted(
            (cell for cell in self.body if isinstance(cell, XlmCell)),
            key=lambda cell: (column_letters(cell.col), cell.row),
        )

    def next_formula_cell(self, row: int, col: int) -> XlmCell | None:
        """
        The row fall-through of the macro language: the first cell at or below `row` in the
        same column that holds a formula, bounded by `_ROW_FALL_THROUGH_LIMIT` rows below the
        starting row.
        """
        result: XlmCell | None = None
        for item in self.body:
            if not isinstance(item, XlmCell) or item.col != col or item.formula is None:
                continue
            if not row <= item.row <= row + _ROW_FALL_THROUGH_LIMIT:
                continue
            if result is None or item.row < result.row:
                result = item
        return result


def build_xlm_model(workbook: ExcelWorkbook) -> list[XlmMacrosheet]:
    """
    One `XlmMacrosheet` for every macrosheet of the workbook, its cells in document order. A
    cell that holds neither a formula nor a value is skipped, as the readers of the retiring
    port did, so that the body holds only the program the sheet spells.
    """
    result: list[XlmMacrosheet] = []
    for sheet in workbook.sheets():
        if sheet.kind is not SheetKind.MACROSHEET:
            continue
        cells: list[Statement] = []
        for cell in sheet.cells():
            if cell.value is None and cell.formula is None:
                continue
            value = cell.value
            if isinstance(value, (datetime.datetime, datetime.time)):
                value = value.isoformat()
            cells.append(XlmCell(
                row=cell.row,
                col=cell.col,
                assignment=cell.assignment,
                formula=_decode_formula(workbook, cell),
                value=value,
            ))
        result.append(XlmMacrosheet(name=sheet.name, kind=sheet.kind, body=cells))
    return result


def _decode_formula(workbook: ExcelWorkbook, cell) -> Expression | None:
    """
    The decoded formula of a cell, normalized where the container says the formula assigns to a
    name: a formula the `bx` attribute marks whose tree is a comparison of a bare name is the
    `SET.NAME` call the assignment spells, because the attribute is the only sound
    disambiguator between that assignment and a comparison. Any other shape keeps its tree and
    its flag, and a formula no reader decodes stays the carrier rather than raising.
    """
    formula = workbook.formula(cell.formula)
    if not cell.assignment or not isinstance(formula, XlBinaryExpression):
        return formula
    if formula.operator is not XlBinaryOperator.EQ:
        return formula
    left = formula.left
    if not isinstance(left, XlDefinedName) or left.sheet is not None:
        return formula
    right = formula.right
    if right is None:
        return formula
    return XlFunctionCall(
        callee='SET.NAME',
        arguments=[XlString(value=left.name), right],
    )
