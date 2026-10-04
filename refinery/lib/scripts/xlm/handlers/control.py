"""
The control-flow commands of the macro language: the jumps that move execution between cells,
the branches of `IF`, the blocks its one-argument form opens over `ELSE` and `ELSE.IF`, the
loops of `WHILE` and `FOR.CELL`, and the returns of a macro call.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlBoolean,
    XlFunctionCall,
    XlMissingArgument,
)
from refinery.lib.scripts.xlm.blocks import XlmBlock
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.references import XlmArrival, XlmCursor, XlmFrame, XlmLoop
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmReference, XlmValue, condition

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.engine import XlmEngine


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


def _first_marker(block: XlmBlock | None) -> int | None:
    """
    The first marker below the head of a block: its first `ELSE` or `ELSE.IF`, or the `END.IF`
    that closes it.
    """
    if block is None:
        return None
    if block.markers:
        return block.markers[0]
    return block.end_row


def _next_marker(block: XlmBlock | None, row: int) -> int | None:
    """
    The first marker below the given row of the block it belongs to: the next `ELSE` or
    `ELSE.IF` of the block, or the `END.IF` that closes it.
    """
    if block is None:
        return None
    for marker in block.markers:
        if marker > row:
            return marker
    return block.end_row


def _marker_jump(
    engine: XlmEngine,
    cursor: XlmCursor,
    block: XlmBlock | None,
    row: int | None,
) -> XlmCursor | None:
    """
    The jump a false head of a block takes onto its first marker, or `None` when the block
    spells no marker below it: a jump onto the `END.IF` of the block takes the indent
    increment the `END.IF` decrements, because no arm above it took one.
    """
    if row is None:
        return None
    if block is not None and row == block.end_row:
        engine.indent_level += 1
    return engine.anchor(XlmReference(cursor.sheet, row, cursor.col))


def _run_block_head(
    engine: XlmEngine,
    call: XlFunctionCall,
    spelled: str,
    cursor: XlmCursor,
    block: XlmBlock | None,
    marker: int | None,
) -> XlmOutcome:
    """
    The head of a block — a one-argument `IF`, or an `ELSE.IF` a jump reached — over the marker
    a false condition branches to. A true condition indents one level and falls through the
    body; a false one jumps to the first marker of the block; a condition the program never
    finished branches into both arms, the true one from the first body cell and the false one
    from the marker, with the snapshot the false branch rolls back to; a condition that spells
    no truth value is an error the macro halts on.
    """
    test = evaluate_expression(engine, call.arguments[0], cursor)
    if test.partial:
        if marker is not None:
            false_indent = engine.indent_level
            if block is not None and marker == block.end_row:
                false_indent += 1
            engine.branch_stack.append(XlmFrame(
                XlmCursor(cursor.sheet, marker, cursor.col),
                None,
                engine.snapshot(),
                false_indent,
                '[FALSE]',
            ))
        body = engine.next_formula_cell(cursor)
        if body is not None:
            engine.branch_stack.append(XlmFrame(
                body,
                None,
                None,
                engine.indent_level + 1,
                '[TRUE]',
            ))
        return XlmOutcome(
            value=XlmValue(value=0, text=spelled),
            status=XlmStatus.FullBranching,
        )
    truth = condition(test)
    if isinstance(truth, XlmValue):
        return XlmOutcome(
            value=XlmValue(value=truth.value, text=spelled),
            status=XlmStatus.Error,
        )
    if truth:
        engine.indent_level += 1
        return XlmOutcome(value=XlmValue(value=0, text=spelled))
    return XlmOutcome(
        value=XlmValue(value=0, text=spelled),
        jump=_marker_jump(engine, cursor, block, marker),
    )


def _skip_to_block_end(
    engine: XlmEngine,
    cursor: XlmCursor,
    block: XlmBlock | None,
    text: str,
) -> XlmOutcome:
    """
    The jump a completed arm of a block takes off its marker: the arm releases the indent it
    took, and the jump onto the `END.IF` of the block takes the indent back for the decrement
    the `END.IF` applies.
    """
    engine.indent_level = max(0, engine.indent_level - 1)
    engine.indent_current_line = True
    if block is None or block.end_row is None:
        return XlmOutcome(value=XlmValue(value=0, text=text))
    engine.indent_level += 1
    return XlmOutcome(
        value=XlmValue(value=0, text=text),
        jump=engine.anchor(XlmReference(cursor.sheet, block.end_row, cursor.col)),
    )


def _if(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    for frame in engine.branch_stack:
        if frame.cursor == cursor:
            return XlmOutcome(
                value=XlmValue(value=0, text=F'[[LOOP]]: {spelled}'),
                status=XlmStatus.End,
            )
    count = len(call.arguments)
    if count == 1:
        block = engine.column_blocks(cursor).get(cursor.row)
        return _run_block_head(engine, call, spelled, cursor, block, _first_marker(block))
    if count != 2 and count != 3:
        return XlmOutcome(value=XlmValue(value=0, text=spelled))
    test = evaluate_expression(engine, call.arguments[0], cursor)
    if test.partial:
        engine.branch_stack.append(
            XlmFrame(
                cursor,
                call.arguments[2] if count == 3 else XlBoolean(value=False),
                engine.snapshot(),
                engine.indent_level,
                '[FALSE]',
            ),
        )
        engine.branch_stack.append(
            XlmFrame(cursor, call.arguments[1], None, engine.indent_level, '[TRUE]'),
        )
        return XlmOutcome(
            value=XlmValue(value=0, text=spelled),
            status=XlmStatus.FullBranching,
        )
    truth = condition(test)
    if isinstance(truth, XlmValue):
        return XlmOutcome(value=truth)
    if truth:
        branch, desc = call.arguments[1], '[TRUE]'
    elif count == 3:
        branch, desc = call.arguments[2], '[FALSE]'
    else:
        return XlmOutcome(value=XlmValue(value=False, text=spelled))
    if isinstance(branch, XlMissingArgument):
        return XlmOutcome(value=XlmValue(value=0, text=spelled))
    engine.branch_stack.append(XlmFrame(cursor, branch, None, engine.indent_level, desc))
    return XlmOutcome(
        value=XlmValue(value=0, text=spelled),
        status=XlmStatus.Branching,
    )


def _if_value(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The `IF` an expression reads rather than runs: the value of the branch its condition selects,
    evaluated in place. A condition the program never finished leaves the whole call unfinished,
    a branch the call leaves empty answers zero, and a false branch the call does not spell at
    all answers `FALSE`.
    """
    spelled = synthesize_formula(call)
    if not call.arguments:
        return XlmOutcome(value=XlmValue(value=spelled, partial=True))
    test = evaluate_expression(engine, call.arguments[0], cursor)
    if test.partial:
        return XlmOutcome(value=XlmValue(value=spelled, partial=True))
    truth = condition(test)
    if isinstance(truth, XlmValue):
        return XlmOutcome(value=truth)
    index = 1 if truth else 2
    if index >= len(call.arguments):
        return XlmOutcome(value=XlmValue(value=False))
    branch = call.arguments[index]
    if isinstance(branch, XlMissingArgument):
        return XlmOutcome(value=XlmValue(value=0))
    return XlmOutcome(value=evaluate_expression(engine, branch, cursor))


def _end_if(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    engine.indent_level = max(0, engine.indent_level - 1)
    engine.indent_current_line = True
    return XlmOutcome(value=XlmValue(value='END.IF', text='END.IF'))


def _else(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The `ELSE` of a block: a false branch of the block jumps onto it and its arm runs,
    indented one level; an arm that ran to its end falls onto it, and the block skips to its
    `END.IF`.
    """
    if engine.arrival is XlmArrival.FALL:
        return _skip_to_block_end(
            engine,
            cursor,
            engine.column_blocks(cursor).get(cursor.row),
            'ELSE',
        )
    engine.indent_level += 1
    return XlmOutcome(value=XlmValue(value=0, text='ELSE'))


def _else_if(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The `ELSE.IF` of a block: a false branch of the block jumps onto it and it branches like
    the head of a block of its own, over the next marker below it; an arm that ran to its end
    falls onto it, and the block skips to its `END.IF`.
    """
    block = engine.column_blocks(cursor).get(cursor.row)
    if engine.arrival is XlmArrival.FALL or not call.arguments:
        return _skip_to_block_end(engine, cursor, block, 'ELSE.IF')
    return _run_block_head(
        engine,
        call,
        'ELSE.IF',
        cursor,
        block,
        _next_marker(block, cursor.row),
    )


def _skipped_loop(engine: XlmEngine, cursor: XlmCursor) -> XlmOutcome:
    """
    The head of a loop inside the body of a loop the engine skips: it opens a loop that never
    holds, so that the `NEXT` of its own body pairs with it rather than with the skipped loop.
    """
    engine.while_stack.append(XlmLoop(cursor))
    engine.indent_level += 1
    return XlmOutcome(value=XlmValue(value=0, text='', partial=True), status=XlmStatus.IGNORED)


def _while(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    if engine.ignore_processing:
        return _skipped_loop(engine, cursor)
    spelled = synthesize_formula(call)
    test = evaluate_expression(engine, call.arguments[0], cursor)
    loop = XlmLoop(cursor)
    text = spelled
    if not test.partial:
        truth = condition(test)
        if isinstance(truth, XlmValue):
            return XlmOutcome(
                value=XlmValue(value=truth.value, text=spelled),
                status=XlmStatus.Error,
            )
        if truth:
            loop.holds = True
            text = F'{spelled} -> [TRUE]'
    engine.while_stack.append(loop)
    engine.indent_level += 1
    return XlmOutcome(value=XlmValue(value=0, text=text))


def _for_cell(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    One pass through the head of a `FOR.CELL` loop: the loop variable names the next cell of
    the range, and once the range ran out, the loop no longer holds and its body is skipped to
    the `NEXT` that pairs with it.
    """
    if engine.ignore_processing:
        return _skipped_loop(engine, cursor)
    spelled = synthesize_formula(call)
    variable = evaluate_expression(engine, call.arguments[0], cursor)
    corners = engine.range_corners(call.arguments[1], cursor)
    if len(call.arguments) >= 3:
        evaluate_expression(engine, call.arguments[2], cursor)
    if engine.while_stack and engine.while_stack[-1].cursor == cursor:
        loop = engine.while_stack[-1]
    else:
        cells = tuple(engine.range_cells(corners)) if corners is not None else ()
        loop = XlmLoop(cursor, holds=True, cells=cells)
        engine.while_stack.append(loop)
    reference = loop.advance()
    if reference is None:
        loop.holds = False
    else:
        engine.assign_name(variable.unwrap().lower(), XlA1Reference(
            sheets=(reference.sheet or cursor.sheet,),
            row=reference.row,
            col=reference.col,
            relative_row=False,
            relative_col=False,
        ), cursor)
    engine.indent_level += 1
    return XlmOutcome(value=XlmValue(value=0, text=spelled))


def _next(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The end of the body of the loop the indentation pairs it with: a loop that holds continues
    at its head, and any other loop is closed, which ends the skipping of its body.
    """
    jump = None
    if engine.indent_level == len(engine.while_stack):
        if engine.while_stack:
            top = engine.while_stack.pop()
            if top.holds:
                jump = top.cursor
                if top.cells is not None:
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
    jump, ended = engine.return_value(value)
    text = value.text if value.text else 'RETURN()'
    return XlmOutcome(
        value=XlmValue(value=value.value, text=text),
        jump=jump,
        status=XlmStatus.End if ended else None,
    )


def _halt(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    engine.indent_level = max(0, engine.indent_level - 1)
    spelled = synthesize_formula(call)
    return XlmOutcome(
        value=XlmValue(value=spelled, text=spelled),
        status=XlmStatus.End,
        halts=True,
    )


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
    'ELSE': _else,
    'ELSE.IF': _else_if,
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

#: The commands an expression reads by another handler than the step whose whole formula they
#: are: such a step runs the command, and an expression only takes the value it computes.
EXPRESSION_HANDLERS = {
    'IF': _if_value,
}
