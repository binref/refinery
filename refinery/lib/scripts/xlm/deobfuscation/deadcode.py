"""
The removal of the cells no formula leads to: the padding obfuscation scatters over its
macrosheets. Execution enters a column only at a cell a formula references — a jump target, a
write destination, an operand — or at an entry point, and moves down from there, so a cell is
dead when no formula anywhere references it or a cell above it in its column. An address the
program computes at run time is no reference the sweep can see.
"""
from __future__ import annotations

import bisect

from typing import TYPE_CHECKING, Iterator

from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlR1C1Reference,
)
from refinery.lib.scripts import set_body
from refinery.lib.scripts.xlm.deobfuscation.program import program_nodes
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.references import XlmCursor, XlmReference, resolve_reference

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.view import XlmView

_REFERENCES = (XlA1Reference, XlR1C1Reference)


def _spans(formula, cursor: XlmCursor, parsed: dict) -> Iterator[tuple[XlmReference, XlmReference]]:
    """
    The rectangles of cells a formula names, as pairs of corners resolved against the cell it
    belongs to: a reference names its own cell, and a range the cells between its corners —
    in the formula itself and in the formulas its string literals spell.
    """
    for node, _ in program_nodes(formula, parsed):
        if isinstance(node, _REFERENCES):
            reference = resolve_reference(node, cursor)
            yield reference, reference
        elif (
            isinstance(node, XlBinaryExpression)
            and node.operator is XlBinaryOperator.RANGE
            and isinstance(node.left, _REFERENCES)
            and isinstance(node.right, _REFERENCES)
        ):
            yield resolve_reference(node.left, cursor), resolve_reference(node.right, cursor)


def _lowest_rows(spans: list[tuple[int, int, int]], columns: list[int]) -> dict[int, int]:
    """
    The highest row of every column at which a span starts that covers the column, for the
    given spans of a top row and a first and last column, among the given sorted columns. The
    spans are painted top row first, and a column that took a row is skipped from then on, so
    that every span and every column costs one visit however wide the spans are.
    """
    lowest: dict[int, int] = {}
    following = list(range(len(columns) + 1))

    def unpainted(index: int) -> int:
        while following[index] != index:
            following[index] = following[following[index]]
            index = following[index]
        return index

    for top, first, last in sorted(spans):
        index = unpainted(bisect.bisect_left(columns, first))
        while index < len(columns) and columns[index] <= last:
            lowest[columns[index]] = top
            following[index] = index + 1
            index = unpainted(index + 1)
    return lowest


def sweep(view: XlmView, start_point: str = '') -> None:
    """
    Remove the dead cells of every macrosheet of the view. A cell is live when any formula of
    the workbook names it — a reference, a range around it, or a string literal that spells
    either, in a cell of any macrosheet or in a defined name — or when it is an entry point of
    a run, and every cell of a column at or below the highest live cell of that column is live
    too, because the row fall-through reaches it. The sweep keeps worksheets untouched: they
    are data, not program.
    """
    spans: dict[str, list[tuple[int, int, int]]] = {}
    parsed: dict = {}

    def mark(first: XlmReference, last: XlmReference, sheet: str | None) -> None:
        name = first.sheet or sheet
        if name is None:
            return
        spans.setdefault(name.lower(), []).append((
            min(first.row, last.row),
            min(first.col, last.col),
            max(first.col, last.col),
        ))

    sheets = view.macrosheets()
    for macrosheet in sheets:
        sheet = macrosheet.name.lower()
        for cell in macrosheet.body:
            if not isinstance(cell, XlmCell):
                continue
            cursor = XlmCursor(sheet, cell.row, cell.col)
            for first, last in _spans(cell.formula, cursor, parsed):
                mark(first, last, sheet)
    for entry in view.names.entries():
        for first, last in _spans(entry.formula, XlmCursor('', 0, 0), parsed):
            mark(first, last, None)
    for reference in view.entry_points(start_point):
        mark(reference, reference, None)
    for macrosheet in sheets:
        sheet = macrosheet.name.lower()
        columns = sorted({cell.col for cell in macrosheet.body if isinstance(cell, XlmCell)})
        lowest = _lowest_rows(spans.get(sheet, []), columns)
        kept = [
            cell
            for cell in macrosheet.body
            if not isinstance(cell, XlmCell)
            or cell.col in lowest
            and cell.row >= lowest[cell.col]
        ]
        set_body(macrosheet, kept)
