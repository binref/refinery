"""
The removal of the cells no run of the program can reach: the padding obfuscation scatters over
its macrosheets. Execution enters a column only at a cell a formula references — a jump target,
a write destination, an operand — or at an entry point, and moves down from there, so a cell is
dead exactly when no formula anywhere references it and its column holds no such cell at or
above its row.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel.formula.model import XlA1Reference, XlR1C1Reference
from refinery.lib.scripts import set_body
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.references import XlmCursor, XlmReference, resolve_reference

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.view import XlmView


def _references(formula, cursor: XlmCursor) -> list[XlmReference]:
    """
    The addresses a formula names, resolved against the cell it belongs to.
    """
    if formula is None:
        return []
    result = []
    for node in formula.walk():
        if isinstance(node, (XlA1Reference, XlR1C1Reference)):
            result.append(resolve_reference(node, cursor))
    return result


def sweep(view: XlmView, start_point: str = '') -> None:
    """
    Remove the dead cells of every macrosheet of the view. A cell is live when any formula of
    the workbook names its address — a reference in a cell of any macrosheet or in a defined
    name — or when it is an entry point of a run, and every cell of a column at or below the
    highest live cell of that column is live too, because the row fall-through reaches it. The
    sweep keeps worksheets untouched: they are data, not program.
    """
    live: set[tuple[str, int, int]] = set()
    sheets = view.macrosheets()
    for macrosheet in sheets:
        sheet = macrosheet.name.lower()
        for cell in macrosheet.body:
            if not isinstance(cell, XlmCell):
                continue
            cursor = XlmCursor(sheet, cell.row, cell.col)
            for reference in _references(cell.formula, cursor):
                target = reference.sheet or sheet
                live.add((target.lower(), reference.row, reference.col))
    for entry in view.names.entries():
        for reference in _references(entry.formula, XlmCursor('', 0, 0)):
            if reference.sheet is not None:
                live.add((reference.sheet.lower(), reference.row, reference.col))
    for reference in view.entry_points(start_point):
        if reference.sheet is not None:
            live.add((reference.sheet.lower(), reference.row, reference.col))
    for macrosheet in sheets:
        sheet = macrosheet.name.lower()
        lowest: dict[int, int] = {}
        for name, row, col in live:
            if name == sheet and (col not in lowest or row < lowest[col]):
                lowest[col] = row
        kept = [
            cell
            for cell in macrosheet.body
            if not isinstance(cell, XlmCell)
            or (sheet, cell.row, cell.col) in live
            or cell.col in lowest
            and cell.row >= lowest[cell.col]
        ]
        set_body(macrosheet, kept)
