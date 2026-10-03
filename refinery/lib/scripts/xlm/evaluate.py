"""
The expression evaluator of the emulator: it walks one formula `Expression` of the model to
the `XlmValue` the macro language computes from it, reading cells and defined names through
the engine and dispatching function calls to it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel.common import column_letters
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlArrayConstant,
    XlBinaryExpression,
    XlBinaryOperator,
    XlBoolean,
    XlDefinedName,
    XlError,
    XlFunctionCall,
    XlMissingArgument,
    XlNumber,
    XlParenExpression,
    XlR1C1Reference,
    XlString,
    XlUnaryExpression,
    XlUnaryOperator,
    XlUnparsedFormula,
)
from refinery.lib.scripts.xlm.references import XlmCursor, resolve_reference
from refinery.lib.scripts.xlm.values import XlmReference, XlmValue, apply_binary

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.engine import XlmEngine


def evaluate_expression(
    engine: XlmEngine,
    node,
    cursor: XlmCursor,
) -> XlmValue:
    """
    The value one formula node computes. A function call contributes only its value — the jump
    a control command asks for is a question of the step the engine is running, not of the
    expression it reads. A node the evaluator does not know computes nothing.
    """
    if node is None:
        return XlmValue()
    if isinstance(node, XlNumber):
        return XlmValue(value=node.value)
    if isinstance(node, XlString):
        return XlmValue(value=node.value)
    if isinstance(node, XlBoolean):
        return XlmValue(value=node.value)
    if isinstance(node, XlError):
        return XlmValue(value=node.value, text=node.value)
    if isinstance(node, XlParenExpression):
        return evaluate_expression(engine, node.operand, cursor)
    if isinstance(node, XlUnaryExpression):
        return _evaluate_unary(engine, node, cursor)
    if isinstance(node, XlBinaryExpression):
        if node.operator is XlBinaryOperator.RANGE:
            return _evaluate_range(engine, node, cursor)
        left = evaluate_expression(engine, node.left, cursor)
        right = evaluate_expression(engine, node.right, cursor)
        return apply_binary(node.operator, left, right)
    if isinstance(node, (XlA1Reference, XlR1C1Reference)):
        return engine.read_reference(resolve_reference(node, cursor), cursor)
    if isinstance(node, XlDefinedName):
        return engine.resolve_name(node, cursor)
    if isinstance(node, XlFunctionCall):
        return engine.call(node, cursor).value
    if isinstance(node, XlArrayConstant):
        cells = tuple(
            evaluate_expression(engine, literal, cursor)
            for row in node.rows
            for literal in row
        )
        return XlmValue(cells=cells)
    if isinstance(node, XlMissingArgument):
        return XlmValue()
    if isinstance(node, XlUnparsedFormula):
        return XlmValue(value=node.text, partial=True)
    return XlmValue()


def _evaluate_unary(
    engine: XlmEngine,
    node: XlUnaryExpression,
    cursor: XlmCursor,
) -> XlmValue:
    operand = evaluate_expression(engine, node.operand, cursor)
    if node.operator is XlUnaryOperator.POS:
        return operand
    if node.operator is XlUnaryOperator.PERCENT:
        return apply_binary(XlBinaryOperator.DIV, operand, XlmValue(value=100))
    if operand.partial:
        return XlmValue(value=F'-{operand.unwrap()}', partial=True)
    return apply_binary(XlBinaryOperator.SUB, XlmValue(value=0), operand)


def _evaluate_range(
    engine: XlmEngine,
    node: XlBinaryExpression,
    cursor: XlmCursor,
) -> XlmValue:
    """
    The value a range expression computes: the two corners it spans, spelled as the address of
    the rectangle they name. The corners are addresses rather than values — reading the cells
    a range covers is a question of the command that consumes the range, and a corner that
    holds an unfinished formula does not make the range itself unfinished. A side the cursor
    cannot resolve to an address falls back to the value it computes.
    """
    left = engine.node_reference(node.left, cursor)
    right = engine.node_reference(node.right, cursor)
    if left is None or right is None:
        return apply_binary(
            XlBinaryOperator.RANGE,
            evaluate_expression(engine, node.left, cursor),
            evaluate_expression(engine, node.right, cursor),
        )
    return XlmValue(
        value=_range_spelling(left, right),
        cells=(
            XlmValue(value=_cell_spelling(left), reference=left),
            XlmValue(value=_cell_spelling(right), reference=right),
        ),
    )


def _cell_spelling(reference: XlmReference) -> str:
    return F'{column_letters(reference.col)}{reference.row}'


def _range_spelling(left: XlmReference, right: XlmReference) -> str:
    return F'{left.a1()}:{right.a1()}'
