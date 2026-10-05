"""
The resolution of the reference nodes of the formula model against the cell a formula sits in:
the cursor of the running engine turns the offsets of an R1C1-relative reference into absolute
positions and the corners of a range into the cells it spans, and the pending positions of a
run — the branches a partial `IF` holds, the loops `WHILE` and `FOR.CELL` open, and the calls
the run returns to — carry the cursors they continue from.
"""
from __future__ import annotations

import enum

from typing import Callable, Iterator, NamedTuple

from refinery.lib.excel.formula.model import XlA1Reference, XlR1C1Reference
from refinery.lib.scripts.xlm.values import XlmReference, XlmValue


class XlmArrival(enum.Enum):
    """
    How the engine reached the cell of the step it runs: by the jump a command asked for, by
    the row fall-through or the continuation below the cell a return hands its value to, by
    resuming a branch of a partial `IF` or the anchor a run or a call starts at, or by the
    replay of a false branch onto the marker of its block. A marker that carries an arm — an
    `ELSE`, or an `ELSE.IF` that names a condition — runs it for a jump and for a replay, and
    skips to the `END.IF` of the block for a fall — an arm that ran to its end, or the cell
    below one a macro call returned to — and for a resume, which an empty true arm and an
    anchor a run or a call starts at arrive by.
    """

    JUMP = 0
    FALL = 1
    RESUME = 2
    REPLAY = 3


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
    the indentation the branch reports, and the label the first step of the branch carries. A
    frame that replays a false branch onto the marker of its block, and any other frame — the
    branch of a partial `IF`, or the anchor a run or a call starts at — is a resume: the
    arrival a pop derives from the frame follows this rule, it is not an inference about where
    the run came from.
    """

    cursor: XlmCursor
    branch: object | None
    snapshot: XlmSnapshot | None
    indent: int
    desc: str

    @property
    def replays(self) -> bool:
        """
        Whether a pop of the frame replays a false branch onto the marker of its block: it
        rolls a snapshot back and runs the cell it resumes at as its own formula.
        """
        return self.snapshot is not None and self.branch is None


class XlmLoop:
    """
    One `WHILE` or `FOR.CELL` loop on the loop stack: the cursor of the cell that heads it, the
    indentation the loop started at — the `NEXT` that pairs with it restores it, so every pass
    of the body starts at the same indentation, whatever the blocks the body left open —
    whether it still holds — a `WHILE` loop holds when its condition is true, a `FOR.CELL` loop
    until its range runs out, and a loop the engine opened while it skipped the body of
    another never holds — and for a `FOR.CELL`, the addresses of its range with the position
    of the next one. The engine skips the body of every loop that does not hold.
    """

    def __init__(
        self,
        cursor: XlmCursor,
        holds: bool = False,
        cells: tuple[XlmReference, ...] | None = None,
        base: int = 0,
    ):
        self.cursor = cursor
        self.holds = holds
        self.cells = cells
        self.base = base
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
        loop = XlmLoop(self.cursor, self.holds, self.cells, self.base)
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


#: How many addresses a range walk yields between two runs of the guard a caller passes, so
#: that a walk over a rectangle the workbook barely fills still answers to the run.
_GUARD_YIELDS = 4096


def expand_range(
    top_left: XlmReference,
    bottom_right: XlmReference,
    guard: Callable[[], None] | None = None,
) -> Iterator[XlmReference]:
    """
    Every cell address of the rectangle two corners span, in row-major order. The sheet of
    each address is the sheet of the top left corner. The guard a caller passes runs every so
    many addresses, so that a walk over a rectangle the workbook barely fills still answers to
    the deadline of the run.
    """
    row_min = min(top_left.row, bottom_right.row)
    row_max = max(top_left.row, bottom_right.row)
    col_min = min(top_left.col, bottom_right.col)
    col_max = max(top_left.col, bottom_right.col)
    walked = 0
    for row in range(row_min, row_max + 1):
        for col in range(col_min, col_max + 1):
            walked += 1
            if guard is not None and not walked % _GUARD_YIELDS:
                guard()
            yield XlmReference(top_left.sheet, row, col)
