"""
The constant folding of the macrosheet model: every subtree of a formula that computes from
stored state alone — literals, the operators over them, references to cells whose content no
run changes, and the calls of the pure commands — is replaced by the value it computes, so the
listing shows the strings the program assembles rather than the chains that assemble them.

A run changes the macrosheet cells its writes reach. The fold takes a census of the writes the
program can make — in the formulas of the macrosheets and of the defined names, and in the
formulas their string literals spell — and settles the cells they reach before it rewrites
anything; a write whose cells the fold cannot compute, or whose entered formula it cannot tell,
may reach every macrosheet cell. Every other cell keeps the content the workbook stores — no run
writes a worksheet — and a formula cell among them reads as the value its formula computes. A
defined name and a call of a command that is not pure compute nothing the fold can know. Every
subtree the fold cannot finish computing stays as it is, rather than a guess at what the program
would have run.
"""
from __future__ import annotations

import dataclasses
import math

from typing import TYPE_CHECKING, NamedTuple, TypeGuard

from refinery.lib.excel import parse_formula
from refinery.lib.excel.formula.model import (
    Expression,
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
    XlUnparsedFormula,
)
from refinery.lib.scripts import TREE_RECURSION_DEPTH, set_child, set_child_list
from refinery.lib.scripts.xlm.commands import CELL_WRITERS, PURE_COMMANDS, XlmCellWrite
from refinery.lib.scripts.xlm.deobfuscation.program import program_nodes
from refinery.lib.scripts.xlm.engine import XlmEngine, callee_name
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.references import XlmCursor, resolve_reference
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmReference, XlmValue
from refinery.lib.tools import RecursionDepth

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.view import XlmView

_REFERENCES = (XlA1Reference, XlR1C1Reference)

_LITERALS = (XlNumber, XlString, XlBoolean, XlError, XlMissingArgument)

_LEAVES = (*_LITERALS, *_REFERENCES, XlArrayConstant, XlUnparsedFormula)

#: The cursor of a formula that runs in a cell the fold does not know: a formula a string
#: literal spells, or the formula of a defined name.
_NOWHERE = XlmCursor('', 0, 0)

_Key = tuple[str, int, int]


class _Unknown(Exception):
    """
    Raised when an evaluation of the fold depends on anything other than the state the workbook
    stores: a cell a run may change, a defined name, or a command that is not pure or fails.
    """


class _Area(NamedTuple):
    """
    A rectangle of cells on one macrosheet, by the lowercase name of the sheet.
    """

    sheet: str
    top: int
    left: int
    bottom: int
    right: int

    def covers(self, sheet: str, row: int, col: int) -> bool:
        return (
            sheet == self.sheet
            and self.top <= row <= self.bottom
            and self.left <= col <= self.right
        )


class _Reach:
    """
    The macrosheet cells the writes of a program may reach: single cells, rectangles of cells,
    and whether some write may reach any cell of any macrosheet.
    """

    def __init__(self):
        self.cells: set[_Key] = set()
        self.areas: set[_Area] = set()
        self.anywhere = False

    def add(self, sheet: str, first: XlmReference, last: XlmReference) -> None:
        """
        Add the rectangle two corners span on the sheet of the given name.
        """
        sheet = sheet.lower()
        top, bottom = sorted((first.row, last.row))
        left, right = sorted((first.col, last.col))
        if top == bottom and left == right:
            self.cells.add((sheet, top, left))
        else:
            self.areas.add(_Area(sheet, top, left, bottom, right))

    def covers(self, sheet: str, row: int, col: int) -> bool:
        """
        Whether a write may reach the cell at the given position of the sheet of the given
        lowercase name.
        """
        if self.anywhere or (sheet, row, col) in self.cells:
            return True
        return any(area.covers(sheet, row, col) for area in self.areas)

    def merge(self, other: _Reach) -> bool:
        """
        Add the cells another reach covers, and report whether this one grew.
        """
        grown = (
            other.anywhere > self.anywhere
            or not other.cells <= self.cells
            or not other.areas <= self.areas
        )
        self.anywhere |= other.anywhere
        self.cells |= other.cells
        self.areas |= other.areas
        return grown


class _Formula(NamedTuple):
    """
    The formula of a macrosheet cell, with the cell and the cursor it runs at.
    """

    cursor: XlmCursor
    cell: XlmCell
    formula: Expression


class _Writer(NamedTuple):
    """
    One write of the program: the call that makes it, the cursor of the cell whose formula
    holds it, and whether a string literal or a defined name spells it, which leaves the cell
    it runs in unknown.
    """

    call: XlFunctionCall
    cursor: XlmCursor
    spelled: bool


def _is_pure(call: XlFunctionCall) -> bool:
    """
    Whether a call computes from its arguments and stored cells alone: a pure command called by
    its own name, which neither a defined name nor a registered alias can stand for.
    """
    return isinstance(call.callee, str) and callee_name(call) in PURE_COMMANDS


class _StaticEngine(XlmEngine):
    """
    The engine the fold evaluates with, which computes what every run computes from the state
    the workbook stores. A read of a cell a write may reach, a defined name, and a call that is
    not pure or fails end the evaluation; any other formula cell reads as the value its formula
    computes. The engine keeps what every cell and every call computes for every later read
    until the reach of the writes grows.
    """

    def __init__(self, view: XlmView):
        super().__init__(view)
        self.reach = _Reach()
        self._cells: dict[_Key, XlmCell] = {}
        for macrosheet in view.macrosheets():
            sheet = macrosheet.name.lower()
            for cell in macrosheet.body:
                if isinstance(cell, XlmCell):
                    self._cells[sheet, cell.row, cell.col] = cell
        self._macrosheets = {macrosheet.name.lower() for macrosheet in view.macrosheets()}
        self._values: dict[_Key, XlmValue | None] = {}
        self._outcomes: dict[tuple[XlFunctionCall, XlmCursor, bool], XlmOutcome | None] = {}
        self._open: set[_Key] = set()

    def widen(self, reach: _Reach) -> bool:
        """
        Add the cells another reach covers to the cells the writes may reach, and report whether
        the reach grew; a grown reach forgets what the cells and calls computed, because the
        cells it gained may have fed them.
        """
        if not self.reach.merge(reach):
            return False
        self._values.clear()
        self._outcomes.clear()
        return True

    def keeps(self, reference: XlmReference, cursor: XlmCursor) -> bool:
        """
        Whether every run keeps the content the workbook stores in a cell: any cell but the
        macrosheet cells a write may reach.
        """
        sheet = (reference.sheet or cursor.sheet).lower()
        if sheet not in self._macrosheets:
            return True
        return not self.reach.covers(sheet, reference.row, reference.col)

    def read_reference(self, reference: XlmReference, cursor: XlmCursor) -> XlmValue:
        cell = XlmCursor(reference.sheet or cursor.sheet, reference.row, reference.col)
        key = (cell.sheet.lower(), cell.row, cell.col)
        try:
            value = self._values[key]
        except KeyError:
            value = self._values[key] = self._compute(cell, key)
        if value is None:
            raise _Unknown
        return dataclasses.replace(value, reference=XlmReference(*cell))

    def resolve_name(self, node: XlDefinedName, cursor: XlmCursor) -> XlmValue:
        raise _Unknown

    def node_reference(self, node, cursor: XlmCursor) -> XlmReference | None:
        if isinstance(node, XlDefinedName):
            raise _Unknown
        return super().node_reference(node, cursor)

    def call(self, call: XlFunctionCall, cursor: XlmCursor, nested: bool = False) -> XlmOutcome:
        if not _is_pure(call):
            raise _Unknown
        key = (call, cursor, nested)
        try:
            outcome = self._outcomes[key]
        except KeyError:
            try:
                outcome = self.dispatch(callee_name(call), call, cursor, nested)
            except _Unknown:
                outcome = None
            if outcome is not None and outcome.status is XlmStatus.Error:
                outcome = None
            self._outcomes[key] = outcome
        if outcome is None:
            raise _Unknown
        return outcome

    def _compute(self, cursor: XlmCursor, key: _Key) -> XlmValue | None:
        """
        The value the cell at a cursor holds through every run, or `None` when a run may change
        it. A cell whose formula reads itself again before it computes anything holds no such
        value.
        """
        if key[0] in self._macrosheets:
            if self.reach.covers(*key):
                return None
            cell = self._cells.get(key)
        else:
            worksheet = self.view.worksheet(cursor.sheet)
            cell = None if worksheet is None else worksheet.get((cursor.row, cursor.col))
        if cell is None or cell.formula is None:
            return super().read_reference(XlmReference(*cursor), cursor)
        if key in self._open:
            raise _Unknown
        self._open.add(key)
        try:
            return evaluate_expression(self, cell.formula, cursor)
        except _Unknown:
            return None
        finally:
            self._open.discard(key)


def fold(view: XlmView) -> None:
    """
    Rewrite every formula of every macrosheet of the view with its statically computable
    subtrees replaced by the values they compute.
    """
    with RecursionDepth(TREE_RECURSION_DEPTH):
        engine = _StaticEngine(view)
        parsed: dict[str, Expression] = {}
        formulas = [
            _Formula(XlmCursor(macrosheet.name, cell.row, cell.col), cell, cell.formula)
            for macrosheet in view.macrosheets()
            for cell in macrosheet.body
            if isinstance(cell, XlmCell) and cell.formula is not None
        ]
        writers = _census(view, formulas, parsed)
        while engine.widen(_reach(engine, writers, parsed)):
            continue
        for cursor, cell, formula in formulas:
            candidates = _candidates(engine, formula, cursor)
            try:
                folded = _fold(engine, formula, cursor, candidates)
            except RecursionError:
                continue
            if folded is not formula:
                set_child(cell, 'formula', folded)


def _writes(node) -> TypeGuard[XlFunctionCall]:
    """
    Whether a node is a call of a command that writes cells.
    """
    return isinstance(node, XlFunctionCall) and callee_name(node) in CELL_WRITERS


def _census(
    view: XlmView,
    formulas: list[_Formula],
    parsed: dict[str, Expression],
) -> list[_Writer]:
    """
    Every write the program can make: the calls of the commands that write cells in the
    formulas of the macrosheet cells and of the defined names, and in the formulas their string
    literals spell.
    """
    writers: list[_Writer] = []
    for cursor, _, formula in formulas:
        for node, spelled in program_nodes(formula, parsed):
            if _writes(node):
                writers.append(_Writer(node, cursor, spelled))
    for entry in view.names.entries():
        for node, _ in program_nodes(entry.formula, parsed):
            if _writes(node):
                writers.append(_Writer(node, _NOWHERE, True))
    return writers


def _parsed(text: str, parsed: dict[str, Expression]) -> Expression:
    tree = parsed.get(text)
    if tree is None:
        tree = parsed[text] = parse_formula(text)
    return tree


def _reach(engine: _StaticEngine, writers: list[_Writer], parsed: dict[str, Expression]) -> _Reach:
    """
    The cells the writes of the program reach as far as the engine computes them: the cells
    every write names, and the cells named by the writes of every formula a write enters. A
    write that a string literal or a defined name spells and that names no sheet may run on
    any macrosheet.
    """
    reach = _Reach()
    pending = list(writers)
    while pending:
        writer = pending.pop()
        write = CELL_WRITERS[callee_name(writer.call)]
        corners = _destination(engine, writer, write, parsed)
        installed = _installed(engine, writer, write, parsed) if write.installs else []
        if corners is None or installed is None:
            reach.anywhere = True
            return reach
        first, last = corners
        if first.sheet is not None:
            reach.add(first.sheet, first, last)
        else:
            for sheet in engine.view.macrosheets():
                reach.add(sheet.name, first, last)
        pending.extend(installed)
    return reach


def _destination(
    engine: _StaticEngine,
    writer: _Writer,
    write: XlmCellWrite,
    parsed: dict[str, Expression],
) -> tuple[XlmReference, XlmReference] | None:
    """
    The corners of the cells a write names, or `None` when the fold cannot tell which cells a
    run writes. A write in the formula of a macrosheet cell names its cells as the run resolves
    them; a spelled write can only name them by an address that does not depend on the cell it
    runs in.
    """
    arguments = writer.call.arguments
    if write.destination >= len(arguments):
        return None
    node = arguments[write.destination]
    if isinstance(node, XlMissingArgument):
        return None
    if writer.spelled:
        return _spelled_corners(node, parsed)
    try:
        corners = engine.range_corners(node, writer.cursor)
        if corners is not None:
            return corners
        reference = engine.node_reference(node, writer.cursor)
    except Exception:
        return None
    if reference is None:
        return None
    return reference, reference


def _spelled_corners(
    node,
    parsed: dict[str, Expression],
) -> tuple[XlmReference, XlmReference] | None:
    while isinstance(node, XlParenExpression):
        node = node.operand
    if isinstance(node, XlString):
        node = _parsed(node.value, parsed)
    if isinstance(node, _REFERENCES):
        reference = _absolute(node)
        return None if reference is None else (reference, reference)
    if (
        isinstance(node, XlBinaryExpression)
        and node.operator is XlBinaryOperator.RANGE
        and isinstance(node.left, _REFERENCES)
        and isinstance(node.right, _REFERENCES)
    ):
        first = _absolute(node.left)
        last = _absolute(node.right)
        if first is None or last is None:
            return None
        return first, last
    return None


def _absolute(node: XlA1Reference | XlR1C1Reference) -> XlmReference | None:
    """
    The address a reference names independently of the cell its formula sits in, or `None` for
    an R1C1 reference that counts from that cell.
    """
    if isinstance(node, XlR1C1Reference) and (node.relative_row or node.relative_col):
        return None
    return resolve_reference(node, _NOWHERE)


def _installed(
    engine: _StaticEngine,
    writer: _Writer,
    write: XlmCellWrite,
    parsed: dict[str, Expression],
) -> list[_Writer] | None:
    """
    The writes of the formula an installing write enters, or `None` when the fold cannot tell
    what it enters. A literal enters no formula the census has not seen already: a string
    literal is program text the census reads.
    """
    arguments = writer.call.arguments
    if write.source >= len(arguments):
        return []
    source = arguments[write.source]
    if isinstance(source, (*_LITERALS, XlArrayConstant)):
        return []
    if writer.spelled:
        return None
    value = _value_of(engine, source, writer.cursor)
    if value is None or value.partial:
        return None
    if not isinstance(value.value, str) or not value.value.startswith('='):
        return []
    return [
        _Writer(node, writer.cursor, True)
        for node, _ in program_nodes(_parsed(value.value, parsed), parsed)
        if _writes(node)
    ]


def _candidates(engine: _StaticEngine, formula: Expression, cursor: XlmCursor) -> set[int]:
    """
    The identities of the nodes of a formula whose subtrees compute from stored state alone as
    far as their parts tell: literals, references to cells every run keeps, the operators over
    such subtrees that read values those cells compute — a range reads no cell by naming its
    corners — and the calls of pure commands over such subtrees that compute a value. The nodes
    are visited in reverse preorder, which visits every node after its descendants, so that no
    operator over a part that computes nothing is evaluated, and the engine keeps what every
    call computes for the evaluation of the subtrees around it.
    """
    candidates: set[int] = set()

    def computes(operand) -> bool:
        if id(operand) not in candidates:
            return False
        if isinstance(operand, _REFERENCES):
            return _value_of(engine, operand, cursor) is not None
        return True

    for node in reversed(list(formula.walk())):
        if isinstance(node, (*_LITERALS, XlArrayConstant)):
            candidate = True
        elif isinstance(node, (XlParenExpression, XlUnaryExpression)):
            candidate = computes(node.operand)
        elif isinstance(node, XlBinaryExpression) and node.operator is XlBinaryOperator.RANGE:
            candidate = all(
                isinstance(side, _REFERENCES) or id(side) in candidates
                for side in (node.left, node.right)
            )
        elif isinstance(node, XlBinaryExpression):
            candidate = computes(node.left) and computes(node.right)
        elif isinstance(node, _REFERENCES):
            candidate = engine.keeps(resolve_reference(node, cursor), cursor)
        elif isinstance(node, XlFunctionCall):
            candidate = (
                _is_pure(node)
                and all(id(argument) in candidates for argument in node.arguments)
                and _value_of(engine, node, cursor) is not None
            )
        else:
            candidate = False
        if candidate:
            candidates.add(id(node))
    return candidates


def _fold(engine: _StaticEngine, node, cursor: XlmCursor, candidates: set[int]) -> Expression:
    """
    The node with every subtree below it that computes statically replaced by the literal it
    computes. A reference stays as it is, because a command may read it as an address.
    """
    if isinstance(node, _LEAVES):
        return node
    if id(node) in candidates:
        value = _value_of(engine, node, cursor)
        literal = None if value is None else _literal(value)
        if literal is not None:
            return literal
    if isinstance(node, (XlParenExpression, XlUnaryExpression)):
        _install(node, 'operand', _fold(engine, node.operand, cursor, candidates))
    elif isinstance(node, XlBinaryExpression):
        _install(node, 'left', _fold(engine, node.left, cursor, candidates))
        _install(node, 'right', _fold(engine, node.right, cursor, candidates))
    elif isinstance(node, XlFunctionCall):
        arguments = [_fold(engine, argument, cursor, candidates) for argument in node.arguments]
        if any(folded is not argument for folded, argument in zip(arguments, node.arguments)):
            set_child_list(node, 'arguments', arguments)
    return node


def _install(node, attribute: str, child: Expression) -> None:
    """
    Put the folded form of a child of a node in its place, unless the fold left it as it was.
    """
    if child is not getattr(node, attribute):
        set_child(node, attribute, child)


def _value_of(engine: _StaticEngine, node, cursor: XlmCursor) -> XlmValue | None:
    """
    The value a subtree computes from stored state alone, or `None` when it depends on anything
    else or fails to evaluate.
    """
    try:
        return evaluate_expression(engine, node, cursor)
    except Exception:
        return None


def _literal(value: XlmValue) -> Expression | None:
    """
    The literal that spells a value as the type it has: an error value, a truth value, a finite
    number, or a text — and a text that spells a number stays a text. A value the program never
    finished, an address, a range, and an array have no literal.
    """
    if value.partial or value.reference is not None or value.cells is not None:
        return None
    if value.error:
        return XlError(value=str(value.value))
    data = value.value
    if isinstance(data, bool):
        return XlBoolean(value=data)
    if isinstance(data, int):
        return XlNumber(value=data)
    if isinstance(data, float):
        if not math.isfinite(data):
            return None
        return XlNumber(value=int(data) if data.is_integer() else data)
    if isinstance(data, str):
        return XlString(value=data)
    return None
