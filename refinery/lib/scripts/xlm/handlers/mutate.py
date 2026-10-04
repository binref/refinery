"""
The mutation commands of the macro language: the formulas the program writes into cells, the
names it defines, and the selection it moves through the workbook.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlArrayConstant,
    XlBinaryExpression,
    XlBinaryOperator,
    XlBoolean,
    XlMissingArgument,
    XlNumber,
    XlR1C1Reference,
    XlString,
)
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.names import XlmNameEntry
from refinery.lib.scripts.xlm.references import XlmCursor, expand_range
from refinery.lib.scripts.xlm.values import (
    XlmOutcome,
    XlmReference,
    XlmValue,
    holds,
    is_number,
    unwrap_literal,
)

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine


def _partial(spelled: str) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _absolute_reference(reference: XlmReference) -> XlA1Reference:
    """
    The reference node that names an address absolutely.
    """
    return XlA1Reference(
        sheets=(reference.sheet,) if reference.sheet is not None else None,
        row=reference.row,
        col=reference.col,
        relative_row=False,
        relative_col=False,
    )


def _name_formula(node, value: XlmValue):
    """
    The formula a defined name stands for once a command stores a value under it: numbers,
    texts, and booleans keep their literal shape, a cell address becomes an absolute reference,
    a range spans its corners, and an array constant keeps the node it was spelled as.
    """
    if isinstance(node, (XlA1Reference, XlR1C1Reference, XlArrayConstant)):
        return node
    if isinstance(value.value, XlmReference):
        return _absolute_reference(value.value)
    if value.reference is not None:
        return _absolute_reference(value.reference)
    if value.cells is not None and len(value.cells) == 2:
        first, second = value.cells
        if first.reference is not None and second.reference is not None:
            return XlBinaryExpression(
                left=_absolute_reference(first.reference),
                operator=XlBinaryOperator.RANGE,
                right=_absolute_reference(second.reference),
            )
    if value.cells is not None:
        return XlArrayConstant(rows=[tuple(
            XlString(value=cell.unwrap())
            for cell in value.cells
        )])
    if isinstance(value.value, bool):
        return XlBoolean(value=value.value)
    if is_number(value.value):
        number = float(value.value)
        return XlNumber(value=int(number) if number.is_integer() else number)
    return XlString(value=value.unwrap())


def _write_formula(
    engine: XlmEngine,
    call: XlFunctionCall,
    cursor: XlmCursor,
    value_only: bool = False,
    swapped: bool = False,
) -> XlmOutcome:
    """
    Write what a command's source argument evaluates to into the cells its destination argument
    names; a command that names no destination writes into the cell the program selected. A
    source the program never finishes marks the destination cells as failed instead of writing
    them — a later reference to one of them reads its own address. The command spells its own
    name, because the trace keeps the distinction the spellings of the write commands carry even
    though they share one behavior.
    """
    name = call.callee if isinstance(call.callee, str) else 'FORMULA'
    if not call.arguments or isinstance(call.arguments[0], XlMissingArgument):
        return XlmOutcome(value=XlmValue(value=False, text=F'{name}()'))
    destination_node = None
    if swapped:
        if len(call.arguments) < 2:
            return _partial(synthesize_formula(call))
        destination_node, source_node = call.arguments[0], call.arguments[1]
    else:
        source_node = call.arguments[0]
        if len(call.arguments) > 1 and not isinstance(call.arguments[1], XlMissingArgument):
            destination_node = call.arguments[1]
    source = evaluate_expression(engine, source_node, cursor)
    if destination_node is None:
        if engine.active_cell is None:
            return _partial(synthesize_formula(call))
        corners = (engine.active_cell, engine.active_cell)
        text = F'{name}({source.text})'
    else:
        corners = engine.range_corners(destination_node, cursor)
        if corners is None:
            reference = engine.node_reference(destination_node, cursor)
            if reference is None:
                return _partial(synthesize_formula(call))
            corners = (reference, reference)
        spelled = synthesize_formula(destination_node)
        if swapped:
            text = F'{name}({spelled},{source.text})'
        else:
            text = F'{name}({source.text},{spelled})'
    if source.partial:
        for reference in expand_range(*corners):
            engine.mark_failed(reference)
        return XlmOutcome(value=XlmValue(value=0, text=text, partial=True))
    for reference in expand_range(*corners):
        engine.unmark_failed(reference)
        engine.write_cell(reference, source, cursor, value_only=value_only)
    return XlmOutcome(value=XlmValue(value=0, text=text))


def _set_value(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return _write_formula(engine, call, cursor, value_only=True, swapped=True)


def _set_name(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    Define a name as `SET.NAME` does: a reference is stored as it is spelled, any other value
    as the literal it computes, and a call that names no value deletes the name.
    """
    spelled = synthesize_formula(call)
    label = unwrap_literal(synthesize_formula(call.arguments[0])).lower()
    if len(call.arguments) < 2 or isinstance(call.arguments[1], XlMissingArgument):
        engine.assign_name(label, None, cursor)
        return XlmOutcome(value=XlmValue(value=0, text=F'SET.NAME({label})'))
    node = call.arguments[1]
    if isinstance(node, (XlA1Reference, XlR1C1Reference)):
        engine.assign_name(label, node, cursor)
        return XlmOutcome(value=XlmValue(
            value=0,
            text=F'SET.NAME({label},{synthesize_formula(node)})',
        ))
    value = evaluate_expression(engine, node, cursor)
    if value.partial:
        return _partial(spelled)
    engine.assign_name(label, _name_formula(node, value), cursor)
    return XlmOutcome(value=XlmValue(
        value=0,
        text=F'SET.NAME({label},{value.unwrap()})',
    ))


def _define_name(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    Define a name as `DEFINE.NAME` does: for the whole workbook, or for the sheet of the cell
    that runs the command when its seventh argument asks for a local name.
    """
    spelled = synthesize_formula(call)
    label = evaluate_expression(engine, call.arguments[0], cursor)
    if label.partial:
        return _partial(spelled)
    value = evaluate_expression(engine, call.arguments[1], cursor)
    if value.partial:
        return _partial(spelled)
    sheet = None
    if len(call.arguments) > 6 and not isinstance(call.arguments[6], XlMissingArgument):
        local = evaluate_expression(engine, call.arguments[6], cursor)
        if local.partial:
            return _partial(spelled)
        if holds(local):
            sheet = engine.view.sheet_index(cursor.sheet)
    name = label.unwrap().lower()
    engine.define_name(XlmNameEntry(
        name=name,
        sheet=sheet,
        formula=_name_formula(call.arguments[1], value),
    ))
    return XlmOutcome(value=XlmValue(
        value=value.value,
        text=F'DEFINE.NAME("{name}",{value.value})',
    ))


def _selection_base(engine: XlmEngine, cursor: XlmCursor) -> XlmCursor:
    if engine.active_cell is None:
        return cursor
    return XlmCursor(
        engine.active_cell.sheet or cursor.sheet,
        engine.active_cell.row,
        engine.active_cell.col,
    )


def _select(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    evaluate_expression(engine, call.arguments[0], cursor)
    base = _selection_base(engine, cursor)
    if len(call.arguments) == 2:
        node = call.arguments[1]
    else:
        node = call.arguments[0]
        if isinstance(node, XlBinaryExpression) and node.operator is XlBinaryOperator.RANGE:
            if not isinstance(node.left, XlBinaryExpression):
                return _partial(spelled)
            node = node.right
        elif not isinstance(node, (XlA1Reference, XlR1C1Reference)):
            return _partial(spelled)
    reference = engine.node_reference(node, base)
    if reference is None:
        return _partial(spelled)
    engine.active_cell = reference
    return XlmOutcome(value=XlmValue(value=0, text=spelled))


def _active_cell(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if engine.active_cell is None:
        return _partial(spelled)
    return XlmOutcome(value=engine.read_reference(engine.active_cell, cursor))


MUTATION_HANDLERS = {
    'ACTIVE.CELL': _active_cell,
    'DEFINE.NAME': _define_name,
    'FORMULA': _write_formula,
    'FORMULA.ARRAY': _write_formula,
    'FORMULA.FILL': _write_formula,
    'SELECT': _select,
    'SET.NAME': _set_name,
    'SET.VALUE': _set_value,
}
