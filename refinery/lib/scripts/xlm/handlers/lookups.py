"""
The lookup commands of the macro language: the addresses they compose, the cells they name,
and the ranges they count and search.
"""
from __future__ import annotations

import re

from typing import TYPE_CHECKING

from refinery.lib.excel import parse_formula, synthesize_formula
from refinery.lib.excel.common import column_letters
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlArrayConstant,
    XlR1C1Reference,
)
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.references import XlmCursor, resolve_reference
from refinery.lib.scripts.xlm.values import (
    XlmOutcome,
    XlmReference,
    XlmValue,
    condition,
    is_number,
)

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine


def _partial(spelled: str) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _corners(engine: XlmEngine, node, cursor: XlmCursor):
    """
    The corners a range argument names: directly when the argument is a range expression, and
    through the value a defined name or another expression resolves to otherwise. An array
    constant names no corners — its elements are values, not addresses.
    """
    corners = engine.range_corners(node, cursor)
    if corners is not None:
        return corners
    if isinstance(node, XlArrayConstant):
        return None
    value = evaluate_expression(engine, node, cursor)
    cells = value.cells
    if cells is not None and len(cells) == 2:
        first, second = cells
        if first.reference is not None and second.reference is not None:
            return first.reference, second.reference
    return None


def _absref(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    offset = evaluate_expression(engine, call.arguments[0], cursor)
    base = call.arguments[1]
    if offset.partial or not isinstance(base, (XlA1Reference, XlR1C1Reference)):
        return _partial(spelled)
    if isinstance(base, XlR1C1Reference) and (base.relative_row or base.relative_col):
        return _partial(spelled)
    offset_node = parse_formula(offset.unwrap())
    if not isinstance(offset_node, XlR1C1Reference):
        return _partial(spelled)
    address = F'{column_letters(base.col + offset_node.col)}{base.row + offset_node.row}'
    return XlmOutcome(value=XlmValue(value=address, text=address))


def _address(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    row = evaluate_expression(engine, call.arguments[0], cursor)
    column = evaluate_expression(engine, call.arguments[1], cursor)
    if (
        row.partial
        or column.partial
        or not is_number(row.value)
        or not is_number(column.value)
    ):
        return _partial(spelled)
    abs_num = 1
    a1 = True
    sheet = cursor.sheet
    if len(call.arguments) >= 3:
        argument = evaluate_expression(engine, call.arguments[2], cursor)
        if argument.partial or not is_number(argument.value):
            return _partial(spelled)
        abs_num = int(float(argument.value))
    if len(call.arguments) >= 4:
        argument = evaluate_expression(engine, call.arguments[3], cursor)
        if argument.partial:
            return _partial(spelled)
        truth = condition(argument)
        if isinstance(truth, XlmValue):
            return XlmOutcome(value=truth)
        a1 = truth
    if len(call.arguments) >= 5:
        argument = evaluate_expression(engine, call.arguments[4], cursor)
        if argument.partial:
            return _partial(spelled)
        sheet = argument.unwrap()
    if a1:
        templates = {1: '${}${}', 2: '{}${}', 3: '${}{}', 4: '{}{}'}
        cell = templates.get(abs_num, '${}${}').format(
            column_letters(int(float(column.value))),
            row.text,
        )
    else:
        templates = {1: 'R{}C{}', 2: 'R{}C[{}]', 3: 'R[{}]C{}', 4: 'R[{}]C[{}]'}
        cell = templates.get(abs_num, 'R{}C{}').format(row.text, column.text)
    address = F'{sheet}!{cell}'
    return XlmOutcome(value=XlmValue(value=address, text=address))


def _hlookup(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    needle = evaluate_expression(engine, call.arguments[0], cursor)
    index = evaluate_expression(engine, call.arguments[2], cursor)
    exact = evaluate_expression(engine, call.arguments[3], cursor)
    corners = _corners(engine, call.arguments[1], cursor)
    if (
        needle.partial
        or index.partial
        or exact.partial
        or corners is None
        or not is_number(index.value)
        or exact.value is not False and str(exact.value).upper() != 'FALSE'
    ):
        return _partial(spelled)
    pattern = needle.unwrap()
    if pattern == '*':
        pattern = '.*'
    first, last = corners
    answer_row = first.row + int(float(index.value)) - 1
    if answer_row > last.row:
        return _partial(spelled)
    try:
        for reference in engine.range_cells(corners):
            if reference.row != first.row:
                break
            value = engine.read_reference(reference, cursor).value
            if value is not None and value != '' and re.match(pattern, str(value)):
                answer = XlmReference(first.sheet, answer_row, reference.col)
                return XlmOutcome(value=engine.read_reference(answer, cursor))
    except re.error:
        return _partial(spelled)
    return _partial(spelled)


def _index(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    index = evaluate_expression(engine, call.arguments[1], cursor)
    if index.partial or not is_number(index.value):
        return _partial(spelled)
    position = int(float(index.value)) - 1
    node = call.arguments[0]
    if isinstance(node, XlArrayConstant):
        cells = evaluate_expression(engine, node, cursor).cells
        if cells is not None and 0 <= position < len(cells):
            return XlmOutcome(value=cells[position])
        return _partial(spelled)
    corners = _corners(engine, node, cursor)
    if corners is not None:
        first, _ = corners
        reference = XlmReference(first.sheet, first.row + position, first.col)
        return XlmOutcome(value=engine.read_reference(reference, cursor))
    return _partial(spelled)


def _indirect(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial or not isinstance(argument.value, str):
        return _partial(spelled)
    parsed = parse_formula(argument.value)
    if not isinstance(parsed, (XlA1Reference, XlR1C1Reference)):
        return _partial(spelled)
    return XlmOutcome(value=engine.read_reference(resolve_reference(parsed, cursor), cursor))


def _rows(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    node = call.arguments[0]
    if isinstance(node, XlArrayConstant):
        cells = evaluate_expression(engine, node, cursor).cells
        if cells is not None:
            return XlmOutcome(value=XlmValue(value=len(cells)))
        return _partial(spelled)
    corners = _corners(engine, node, cursor)
    if corners is not None:
        first, last = corners
        return XlmOutcome(value=XlmValue(value=last.row - first.row + 1))
    return _partial(spelled)


def _counta(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    corners = _corners(engine, call.arguments[0], cursor)
    if corners is None:
        return _partial(spelled)
    count = sum(1 for _ in engine.range_cells(corners))
    return XlmOutcome(value=XlmValue(value=count))


LOOKUP_HANDLERS = {
    'ABSREF': _absref,
    'ADDRESS': _address,
    'COUNTA': _counta,
    'HLOOKUP': _hlookup,
    'INDEX': _index,
    'INDIRECT': _indirect,
    'ROWS': _rows,
}
