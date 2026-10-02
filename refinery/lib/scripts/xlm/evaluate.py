"""
The expression evaluator of the emulator: it walks one formula `Expression` of the model to
the `XlmValue` the macro language computes from it, reading cells and defined names through
the engine and dispatching function calls to it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

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
from refinery.lib.scripts.xlm.values import XlmValue, apply_binary

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
