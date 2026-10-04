"""
The block structure of a column of the macro language: which `ELSE`, `ELSE.IF`, and `END.IF`
markers belong to which one-argument block `IF`, computed over the ordered rows of one column.
The pairing is pure — the engine feeds it the live formula rows of a column, so that cells the
program wrote at run time take part, and the listing can later reuse it over the model.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.excel.formula.model import XlFunctionCall


class XlmBlock(NamedTuple):
    """
    One block `IF` of a column: the row of the `IF`, the rows of its `ELSE.IF` and `ELSE`
    markers in row order, and the row of the `END.IF` that closes it — `None` for a block no
    `END.IF` closes.
    """

    if_row: int
    markers: tuple[int, ...]
    end_row: int | None


def marker_of(formula) -> str | None:
    """
    The block marker a formula spells: `IF` for the one-argument block form, and the names of
    `ELSE`, `ELSE.IF`, and `END.IF` for themselves; any other formula spells no marker.
    """
    if not isinstance(formula, XlFunctionCall) or not isinstance(formula.callee, str):
        return None
    name = formula.callee.strip('"')
    if name in ('ELSE', 'ELSE.IF', 'END.IF'):
        return name
    if name == 'IF' and len(formula.arguments) == 1:
        return 'IF'
    return None


def pair_blocks(markers: list[tuple[int, str]]) -> dict[int, XlmBlock]:
    """
    The blocks the markers of a column pair into, in the row order they are given: every
    marker row mapped to the block it belongs to. A block `IF` opens a block, its `END.IF`
    closes it, and every `ELSE` and `ELSE.IF` between the two belongs to it. A marker no open
    block owns, and a block no `END.IF` closes, pair with nothing.
    """
    opens: list[int] = []
    members: list[list[int]] = []
    pairs: dict[int, XlmBlock] = {}
    for row, marker in markers:
        if marker == 'IF':
            opens.append(row)
            members.append([row])
        elif marker == 'END.IF':
            if not opens:
                continue
            rows = members.pop()
            block = XlmBlock(opens.pop(), tuple(rows[1:]), row)
            for member in rows:
                pairs[member] = block
            pairs[row] = block
        elif opens:
            members[-1].append(row)
    return pairs
