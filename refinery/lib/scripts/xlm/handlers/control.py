"""
The control-flow commands of the macro language: the jumps that move execution between cells,
the branches of `IF`, the loops of `WHILE` and `FOR.CELL`, and the returns of a macro call.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import XlA1Reference
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.names import XlmNameEntry
from refinery.lib.scripts.xlm.references import XlmFrame, XlmLoop
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmReference, XlmValue

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine
    from refinery.lib.scripts.xlm.references import XlmCursor

_TRUE_WORDS = frozenset(('y', 'yes', 't', 'true', 'on', '1'))
_FALSE_WORDS = frozenset(('n', 'no', 'f', 'false', 'off', '0'))


def _holds(value: XlmValue) -> bool:
    """
    Whether a condition value decides a branch: the spellings of the two truth values are
    theirs, a number holds when it is not zero, and anything else is taken as it is.
    """
    spelled = str(value.value).lower()
    if spelled in _TRUE_WORDS:
        return True
    if spelled in _FALSE_WORDS:
        return False
    try:
        return int(spelled) != 0
    except ValueError:
        return bool(value.value)


def _goto(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    reference = engine.argument_reference(call, 0, cursor)
    if reference is None or engine.view.macrosheet(reference.sheet) is None:
        return XlmOutcome(value=XlmValue(value=0, text=spelled), status=XlmStatus.Error)
    return XlmOutcome(
        value=XlmValue(value=0, text=spelled),
        jump=engine.anchor(reference),
    )


def _run(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if not 1 <= len(call.arguments) <= 2:
        return XlmOutcome(value=XlmValue(value=1, text=spelled), status=XlmStatus.Error)
    reference = engine.argument_reference(call, 0, cursor)
    if reference is None or engine.view.macrosheet(reference.sheet) is None:
        return XlmOutcome(value=XlmValue(value=1, text=spelled), status=XlmStatus.Error)
    text = F'RUN({reference.a1()})'
    if len(call.arguments) == 2:
        text = F'RUN({reference.a1()}, {synthesize_formula(call.arguments[1])})'
    return XlmOutcome(
        value=XlmValue(value=0, text=text),
        jump=engine.anchor(reference),
    )


def _if(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    for frame in engine.branch_stack:
        if frame.cursor == cursor:
            return XlmOutcome(
                value=XlmValue(value=0, text=F'[[LOOP]]: {spelled}'),
                status=XlmStatus.End,
            )
    if len(call.arguments) != 3:
        return XlmOutcome(value=XlmValue(value=0, text=spelled))
    condition = evaluate_expression(engine, call.arguments[0], cursor)
    if condition.partial:
        engine.branch_stack.append(
            XlmFrame(cursor, call.arguments[2], engine.snapshot(), engine.indent_level, '[FALSE]'),
        )
        engine.branch_stack.append(
            XlmFrame(cursor, call.arguments[1], None, engine.indent_level, '[TRUE]'),
        )
        return XlmOutcome(
            value=XlmValue(value=0, text=spelled),
            status=XlmStatus.FullBranching,
        )
    if _holds(condition):
        branch, desc = call.arguments[1], '[TRUE]'
    else:
        branch, desc = call.arguments[2], '[FALSE]'
    engine.branch_stack.append(XlmFrame(cursor, branch, None, engine.indent_level, desc))
    return XlmOutcome(
        value=XlmValue(value=0, text=spelled),
        status=XlmStatus.Branching,
    )


def _end_if(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    engine.indent_level = max(0, engine.indent_level - 1)
    engine.indent_current_line = True
    return XlmOutcome(value=XlmValue(value='END.IF', text='END.IF'))


def _while(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    condition = evaluate_expression(engine, call.arguments[0], cursor)
    loop = XlmLoop(cursor)
    if not condition.partial and str(condition.value).lower() == 'true':
        loop.holds = True
        text = F'{spelled} -> [{condition.value}]'
    else:
        text = spelled
    engine.while_stack.append(loop)
    if not loop.holds:
        engine.ignore_processing = True
    engine.indent_level += 1
    return XlmOutcome(value=XlmValue(value=0, text=text))


def _for_cell(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    variable = evaluate_expression(engine, call.arguments[0], cursor)
    corners = engine.range_corners(call.arguments[1], cursor)
    if len(call.arguments) >= 3:
        evaluate_expression(engine, call.arguments[2], cursor)
    if engine.while_stack and engine.while_stack[-1].cursor == cursor:
        loop = engine.while_stack[-1]
    else:
        cells = engine.range_cells(corners) if corners is not None else ()
        loop = XlmLoop(cursor, holds=True)
        loop.iterator = iter(cells)
        engine.while_stack.append(loop)
    if loop.iterator is not None:
        try:
            reference = next(loop.iterator)
        except StopIteration:
            loop.holds = False
        else:
            engine.view.names.define(XlmNameEntry(
                name=variable.unwrap().lower(),
                sheet=None,
                formula=XlA1Reference(
                    sheets=(reference.sheet or cursor.sheet,),
                    row=reference.row,
                    col=reference.col,
                    relative_row=False,
                    relative_col=False,
                ),
            ))
    engine.indent_level += 1
    return XlmOutcome(value=XlmValue(value=0, text=spelled))


def _next(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    jump = None
    if engine.indent_level == len(engine.while_stack):
        engine.ignore_processing = False
        if engine.while_stack:
            top = engine.while_stack.pop()
            if top.holds:
                jump = top.cursor
            if top.iterator is not None:
                engine.while_stack.append(top)
        engine.indent_level = max(0, engine.indent_level - 1)
        engine.indent_current_line = True
    if jump is None:
        return XlmOutcome(value=XlmValue(value=0, text='NEXT'), status=XlmStatus.IGNORED)
    return XlmOutcome(value=XlmValue(value=0, text='NEXT'), jump=jump)


def _return(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    if call.arguments:
        value = evaluate_expression(engine, call.arguments[0], cursor)
    else:
        value = XlmValue()
    jump = None
    if engine.call_stack:
        caller = engine.call_stack.pop()
        cell = engine._find_cell(caller.sheet, caller.row, caller.col)
        if cell is not None:
            engine.write_value(cell, value.value)
        jump = engine.next_formula_cell(caller)
    text = value.text if value.text else 'RETURN()'
    return XlmOutcome(value=XlmValue(value=value.value, text=text), jump=jump)


def _halt(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    engine.indent_level = max(0, engine.indent_level - 1)
    spelled = synthesize_formula(call)
    return XlmOutcome(value=XlmValue(value=spelled, text=spelled), status=XlmStatus.End)


def _offset(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    base = engine.argument_reference(call, 0, cursor)
    if base is not None and len(call.arguments) >= 3:
        rows = evaluate_expression(engine, call.arguments[1], cursor)
        cols = evaluate_expression(engine, call.arguments[2], cursor)
        if not rows.partial and not cols.partial:
            reference = XlmReference(
                base.sheet,
                base.row + int(float(str(rows.value))),
                base.col + int(float(str(cols.value))),
            )
            return XlmOutcome(
                value=XlmValue(value=reference, text=spelled, reference=reference),
                jump=engine.anchor(reference),
            )
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _on_time(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if len(call.arguments) != 2:
        return XlmOutcome(value=XlmValue(value=0, text=spelled), status=XlmStatus.Error)
    evaluate_expression(engine, call.arguments[0], cursor)
    reference = engine.argument_reference(call, 1, cursor)
    if reference is None or engine.view.macrosheet(reference.sheet) is None:
        return XlmOutcome(value=XlmValue(value=0, text=spelled), status=XlmStatus.Error)
    return XlmOutcome(
        value=XlmValue(value=0, text=spelled),
        jump=engine.anchor(reference),
    )


CONTROL_HANDLERS = {
    'CLOSE': _halt,
    'END.IF': _end_if,
    'FOR.CELL': _for_cell,
    'GOTO': _goto,
    'HALT': _halt,
    'IF': _if,
    'NEXT': _next,
    'OFFSET': _offset,
    'ON.TIME': _on_time,
    'RETURN': _return,
    'RUN': _run,
    'WHILE': _while,
}
