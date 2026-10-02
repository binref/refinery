"""
The resolution of the reference nodes of the formula model against the cell a formula sits in:
the cursor of the running engine turns the offsets of an R1C1-relative reference into absolute
positions and the corners of a range into the cells it spans.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.excel.formula.model import XlA1Reference, XlR1C1Reference
from refinery.lib.scripts.xlm.values import XlmReference


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
