"""
The cell model of the XLM macro language: one `XlmMacrosheet` script per macrosheet of a workbook
and one `XlmCell` statement per cell, built from the sheets of an
`refinery.lib.excel.workbook.ExcelWorkbook`. Worksheets are data rather than program, so no script
holds their cells; `sheet_cells` reads the cells of either kind of sheet.
"""
from __future__ import annotations

import datetime

from dataclasses import dataclass

from refinery.lib.excel.common import Cell, CellKind, ExcelFormatError, SheetKind, column_letters
from refinery.lib.excel.formula.model import (
    Expression,
    XlBinaryExpression,
    XlBinaryOperator,
    XlDefinedName,
    XlFunctionCall,
    XlString,
)
from refinery.lib.excel.workbook import ExcelSheet, ExcelWorkbook
from refinery.lib.scripts import Script, Statement, set_child

#: How many rows below its starting row the row fall-through scans before it gives up.
_ROW_FALL_THROUGH_LIMIT = 10000

_COMPARISONS = frozenset((
    XlBinaryOperator.EQ,
    XlBinaryOperator.NE,
    XlBinaryOperator.LT,
    XlBinaryOperator.LE,
    XlBinaryOperator.GT,
    XlBinaryOperator.GE,
))


@dataclass(repr=False, eq=False)
class XlmCell(Statement):
    """
    A single cell at a one-based `row` and `col`. The `formula` is the decoded expression tree,
    the unparsed carrier for a formula the reader could not decode, or `None` for a cell that holds
    only a value; `value` is the cached value as the reader spelled it, of the `kind` the reader
    gave it, with a date or a time stored as its ISO text so that every field of the node is a
    primitive; `assignment` marks a formula the container says assigns to a name.
    """

    row: int = 0
    col: int = 0
    kind: CellKind = CellKind.BLANK
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
        The cells in the order the sorted extract listing shows them: the cells that hold a
        formula by column letters and then by row, followed by the cells that hold only a value,
        in document order.
        """
        cells = [cell for cell in self.body if isinstance(cell, XlmCell)]
        formulas = sorted(
            (cell for cell in cells if cell.formula is not None),
            key=lambda cell: (column_letters(cell.col), cell.row),
        )
        return formulas + [cell for cell in cells if cell.formula is None]

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


def sheet_cells(workbook: ExcelWorkbook, sheet: ExcelSheet) -> dict[tuple[int, int], XlmCell]:
    """
    The cells of a sheet of the workbook, keyed by one-based row and column in document order.
    A coordinate the sheet stores more than once holds the last record stored there, a cell that
    holds neither a formula nor a value is skipped, and a sheet whose walk fails partway through
    keeps the cells read before the defect.
    """
    records: dict[tuple[int, int], Cell] = {}
    try:
        for record in sheet.cells():
            coordinates = record.row, record.col
            if record.value is None and record.formula is None:
                records.pop(coordinates, None)
            else:
                records[coordinates] = record
    except ExcelFormatError:
        pass
    return {
        coordinates: _model_cell(workbook, record)
        for coordinates, record in records.items()
    }


def build_xlm_model(workbook: ExcelWorkbook) -> list[XlmMacrosheet]:
    """
    One `XlmMacrosheet` for every macrosheet of the workbook, holding the cells `sheet_cells`
    reads from it.
    """
    result: list[XlmMacrosheet] = []
    for sheet in workbook.sheets():
        if sheet.kind is not SheetKind.MACROSHEET:
            continue
        body: list[Statement] = list(sheet_cells(workbook, sheet).values())
        result.append(XlmMacrosheet(name=sheet.name, kind=sheet.kind, body=body))
    return result


def _model_cell(workbook: ExcelWorkbook, record: Cell) -> XlmCell:
    value = record.value
    if isinstance(value, (datetime.datetime, datetime.time)):
        value = value.isoformat()
    return XlmCell(
        row=record.row,
        col=record.col,
        kind=record.kind,
        assignment=record.assignment,
        formula=_decode_formula(workbook, record),
        value=value,
    )


def _decode_formula(workbook: ExcelWorkbook, record: Cell) -> Expression | None:
    """
    The decoded formula of a cell, normalized where the container says the formula assigns to a
    name. The text of such a formula spells the name, an equals sign, and the value; because all
    comparisons share one left-associative level, a value that is itself a comparison parses
    with the assignment as the innermost comparison on the left: `x=A1<>B1` reads as `(x=A1)<>B1`.
    Where that innermost comparison is an equality whose left side is a bare name, the formula
    is the `SET.NAME` call the assignment spells, and its value is the chain of comparisons with
    the assignment replaced by its right side. The attribute is the only sound disambiguator
    between that assignment and a comparison. Any other shape keeps its tree and its flag, and a
    formula no reader decodes stays the carrier rather than raising.
    """
    formula = workbook.formula(record.formula)
    if not record.assignment:
        return formula
    chain: list[XlBinaryExpression] = []
    node = formula
    while isinstance(node, XlBinaryExpression) and node.operator in _COMPARISONS:
        chain.append(node)
        node = node.left
    if not chain:
        return formula
    assignment = chain.pop()
    name = assignment.left
    value = assignment.right
    if (
        assignment.operator is not XlBinaryOperator.EQ
        or not isinstance(name, XlDefinedName)
        or name.sheet is not None
        or value is None
    ):
        return formula
    if chain:
        set_child(chain[-1], 'left', value)
        value = chain[0]
    return XlFunctionCall(
        callee='SET.NAME',
        arguments=[XlString(value=name.name), value],
    )
