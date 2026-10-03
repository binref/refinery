"""
The constant folding of the macrosheet model: every subtree of a formula that computes from
stored state alone — literals, the operators over them, references to cells that hold only a
value or have folded themselves, and the calls of the pure commands — is replaced by the value
it computes, so the listing shows the strings the program assembles rather than the chains that
assemble them. The pass works to a fixpoint across the sheets, because one cell folding is
what makes the formula that reads it foldable, and it leaves every subtree it cannot finish
computing untouched rather than guessing at what the program would have run.
"""
from __future__ import annotations

from refinery.lib.excel.common import ERROR_TEXT
from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlBinaryExpression,
    XlBoolean,
    XlError,
    XlFunctionCall,
    XlMissingArgument,
    XlNumber,
    XlParenExpression,
    XlR1C1Reference,
    XlString,
    XlUnaryExpression,
    XlUnparsedFormula,
)
from refinery.lib.scripts import set_child, set_child_list
from refinery.lib.scripts.xlm.commands import PURE_COMMANDS
from refinery.lib.scripts.xlm.engine import XlmEngine
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.references import XlmCursor, resolve_reference
from refinery.lib.scripts.xlm.values import is_number

_ERRORS = frozenset(ERROR_TEXT.values())


def fold(view) -> None:
    """
    Rewrite every formula of every macrosheet of the view with its statically computable
    subtrees replaced by the values they compute.
    """
    engine = XlmEngine(view)
    known: set[tuple[str, int, int]] = set()
    for macrosheet in view.macrosheets():
        sheet = macrosheet.name.lower()
        for cell in macrosheet.body:
            if isinstance(cell, XlmCell) and cell.formula is None:
                known.add((sheet, cell.row, cell.col))
    changed = True
    while changed:
        changed = False
        for macrosheet in view.macrosheets():
            sheet = macrosheet.name.lower()
            for cell in macrosheet.body:
                if not isinstance(cell, XlmCell) or cell.formula is None:
                    continue
                cursor = XlmCursor(sheet, cell.row, cell.col)
                formula, cell_changed = _fold(engine, cell.formula, cursor, known)
                if formula is not cell.formula:
                    set_child(cell, 'formula', formula)
                if cell_changed:
                    changed = True
                if isinstance(formula, (XlNumber, XlString, XlBoolean, XlError)):
                    known.add((sheet, cell.row, cell.col))


def _fold(engine: XlmEngine, node, cursor: XlmCursor, known) -> tuple[Expression, bool]:
    """
    The node with every subtree below it that computes statically replaced by the literal it
    computes, and whether anything below the node changed.
    """
    if isinstance(node, (
        XlA1Reference,
        XlBoolean,
        XlError,
        XlMissingArgument,
        XlNumber,
        XlR1C1Reference,
        XlString,
        XlUnparsedFormula,
    )):
        return node, False
    computed = _computed(engine, node, cursor, known)
    if computed is not None:
        return computed, True
    if isinstance(node, (XlParenExpression, XlUnaryExpression)):
        operand, changed = _fold(engine, node.operand, cursor, known)
        set_child(node, 'operand', operand)
        return node, changed
    if isinstance(node, XlBinaryExpression):
        left, left_changed = _fold(engine, node.left, cursor, known)
        right, right_changed = _fold(engine, node.right, cursor, known)
        set_child(node, 'left', left)
        set_child(node, 'right', right)
        return node, left_changed or right_changed
    if isinstance(node, XlFunctionCall):
        arguments: list[Expression] = []
        changed = False
        for argument in node.arguments:
            folded, argument_changed = _fold(engine, argument, cursor, known)
            arguments.append(folded)
            changed = changed or argument_changed
        set_child_list(node, 'arguments', arguments)
        return node, changed
    return node, False


def _computed(engine: XlmEngine, node, cursor: XlmCursor, known) -> Expression | None:
    """
    The literal a subtree computes from stored state alone, or `None` when the subtree reads
    anything the program could have changed before it runs. A value that carries no number,
    text, or error — an empty address, a reference, an array — folds nothing.
    """
    if not _is_static(node, cursor, known, engine.view):
        return None
    try:
        value = evaluate_expression(engine, node, cursor)
    except Exception:
        return None
    if value.partial or value.reference is not None or value.cells is not None:
        return None
    if isinstance(value.value, bool):
        return XlBoolean(value=value.value)
    if is_number(value.value):
        number = float(value.value)
        return XlNumber(value=int(number) if number.is_integer() else number)
    if isinstance(value.value, str):
        if value.value in _ERRORS:
            return XlError(value=value.value)
        return XlString(value=value.value)
    return None


def _is_static(node, cursor: XlmCursor, known, view) -> bool:
    """
    Whether a subtree computes from stored state alone: literals and the operators over them,
    references to cells that hold only a value or have folded to a literal, and the calls of
    the pure commands over static arguments. A cell whose formula the program computes at
    runtime is not static — its stored value is not what a run reads.
    """
    if isinstance(node, (XlNumber, XlString, XlBoolean, XlError, XlMissingArgument)):
        return True
    if isinstance(node, (XlParenExpression, XlUnaryExpression)):
        return _is_static(node.operand, cursor, known, view)
    if isinstance(node, XlBinaryExpression):
        return (
            _is_static(node.left, cursor, known, view)
            and _is_static(node.right, cursor, known, view)
        )
    if isinstance(node, (XlA1Reference, XlR1C1Reference)):
        reference = resolve_reference(node, cursor)
        sheet = (reference.sheet or cursor.sheet).lower()
        if (sheet, reference.row, reference.col) in known:
            return True
        target = view.cell(sheet, reference.row, reference.col)
        return target is None or target.formula is None
    if isinstance(node, XlFunctionCall):
        return (
            isinstance(node.callee, str)
            and node.callee in PURE_COMMANDS
            and all(_is_static(argument, cursor, known, view) for argument in node.arguments)
        )
    return False
