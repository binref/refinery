"""
The resolution of the reference nodes of the formula model against the cell a formula sits in:
the cursor of the running engine turns the offsets of an R1C1-relative reference into absolute
positions and the corners of a range into the cells it spans, and the pending positions of a
run — the branches a partial `IF` holds, the loops `WHILE` and `FOR.CELL` open, and the calls
the run returns to — carry the cursors they continue from.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.excel.formula.model import XlA1Reference, XlR1C1Reference
from refinery.lib.scripts.xlm.values import XlmReference, XlmValue


class XlmCursor(NamedTuple):
    """
    The cell the engine is currently evaluating: the sheet it sits on with its one-based row
    and column. The relative references of the formula in this cell resolve against it.
    """

    sheet: str
    row: int
    col: int

    def reference(self) -> XlmReference:
        """
        The address of the cursor's own cell.
        """
        return XlmReference(None, self.row, self.col)


class XlmFrame(NamedTuple):
    """
    One branch of a partial `IF` that has not run yet: the cell the branch runs at — its cursor
    is the base the relative references of the branch resolve against — the expression the
    branch runs instead of the cell's own formula, the snapshot a false branch rolls back to,
    the indentation the branch reports, and the label the first step of the branch carries.
    """

    cursor: XlmCursor
    branch: object | None
    snapshot: XlmSnapshot | None
    indent: int
    desc: str


class XlmLoop:
    """
    One `WHILE` or `FOR.CELL` loop on the loop stack: the cursor of the cell that heads it,
    whether it still holds — a `WHILE` loop holds when its condition is true, a `FOR.CELL` loop
    until its range runs out, and a loop the engine opened while it skipped the body of another
    never holds — and for a `FOR.CELL`, the addresses of its range with the position of the
    next one. The engine skips the body of every loop that does not hold.
    """

    def __init__(
        self,
        cursor: XlmCursor,
        holds: bool = False,
        cells: tuple[XlmReference, ...] | None = None,
    ):
        self.cursor = cursor
        self.holds = holds
        self.cells = cells
        self.position = 0

    def advance(self) -> XlmReference | None:
        """
        The next address of a `FOR.CELL` range, or `None` once the range ran out.
        """
        if self.cells is None or self.position >= len(self.cells):
            return None
        reference = self.cells[self.position]
        self.position += 1
        return reference

    def copy(self) -> XlmLoop:
        """
        A copy of the loop that later iterations of the original leave as it is.
        """
        loop = XlmLoop(self.cursor, self.holds, self.cells)
        loop.position = self.position
        return loop


class XlmReturnSlot:
    """
    The entry a macro call inside an expression leaves on the call stack: the value the
    subroutine returns lands here rather than in a cell, and the run of the subroutine ends
    with it.
    """

    def __init__(self):
        self.value: XlmValue | None = None


class XlmSnapshot(NamedTuple):
    """
    The state a false branch of a partial `IF` starts from: the journal position the writes of
    the true branch roll back to, and the state of the run the journal does not hold — the
    call stack, the open loops with their positions, and the cell the program selected.
    """

    journal: int
    call_stack: tuple[XlmCursor | XlmReturnSlot, ...]
    loops: tuple[XlmLoop, ...]
    active_cell: XlmReference | None


def resolve_reference(
    node: XlA1Reference | XlR1C1Reference,
    cursor: XlmCursor,
) -> XlmReference:
    """
    The address a reference node names, resolved against the cursor. The numbers of an A1
    reference are absolute positions already; the number of a relative axis of an R1C1
    reference is an offset from the cursor on that axis. A reference qualified by a 3-D span
    of two sheets names the first sheet of the span.
    """
    if isinstance(node, XlR1C1Reference):
        row = cursor.row + node.row if node.relative_row else node.row
        col = cursor.col + node.col if node.relative_col else node.col
    else:
        row = node.row
        col = node.col
    sheet = node.sheets[0] if node.sheets else None
    return XlmReference(sheet, row, col)


def expand_range(top_left: XlmReference, bottom_right: XlmReference) -> list[XlmReference]:
    """
    Every cell address of the rectangle two corners span, in row-major order. The sheet of
    each address is the sheet of the top left corner.
    """
    row_min = min(top_left.row, bottom_right.row)
    row_max = max(top_left.row, bottom_right.row)
    col_min = min(top_left.col, bottom_right.col)
    col_max = max(top_left.col, bottom_right.col)
    return [
        XlmReference(top_left.sheet, row, col)
        for row in range(row_min, row_max + 1)
        for col in range(col_min, col_max + 1)
    ]
