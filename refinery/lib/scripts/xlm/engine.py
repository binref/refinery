"""
The engine of the emulator: it owns the mutable state of a run — the coordinate indexes the
cell reads and the row fall-through consult, the registered function aliases, and the call
stack of the macro calls — and dispatches the function calls a formula makes to the handlers
that answer them.
"""
from __future__ import annotations

import bisect

from refinery.lib.excel import CellKind, synthesize_formula
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlDefinedName,
    XlFunctionCall,
    XlR1C1Reference,
)
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.references import XlmCursor, resolve_reference
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmReference, XlmValue


def _callee_name(call: XlFunctionCall) -> str:
    """
    The name the callee of a call spells, without the quotes of a string literal; a callee
    that is a reference or another call is not named at all.
    """
    callee = call.callee
    if isinstance(callee, str):
        return callee.strip('"')
    if isinstance(callee, XlDefinedName):
        return callee.name
    return ''


class XlmEngine:
    """
    The interpreter of a workbook view. The macrosheet model is read through coordinate indexes
    the engine maintains itself, so that cells the program writes at run time stay visible to
    every reference that reads them afterwards.
    """

    def __init__(
        self,
        view,
        output_level: int = 0,
        day: int = -1,
        timeout: int = 0,
        max_steps: int = 1_000_000,
    ):
        self.view = view
        self.output_level = output_level
        self.day = day
        self.timeout = timeout
        self.max_steps = max_steps
        self.aliases: dict[str, str] = {}
        self.ignore_processing = False
        self._call_stack: list[XlmCursor] = []
        self._cells: dict[str, dict[tuple[int, int], XlmCell]] = {}
        self._formula_rows: dict[str, dict[int, list[int]]] = {}
        for macrosheet in view.macrosheets():
            for cell in macrosheet.body:
                index = self._cells.setdefault(macrosheet.name.lower(), {})
                index[(cell.row, cell.col)] = cell
                if cell.formula is None:
                    continue
                columns = self._formula_rows.setdefault(macrosheet.name.lower(), {})
                bisect.insort(columns.setdefault(cell.col, []), cell.row)

    def read_reference(self, reference: XlmReference, cursor: XlmCursor) -> XlmValue:
        """
        The value a cell address holds. The sheet the reference fails to name is the sheet the
        cursor sits on. A cell that holds a formula is evaluated with itself as the cursor its
        relative references resolve against; a cell that holds only a value is that value, with
        the date flag a date cell carries; an address the workbook does not hold is empty.
        """
        sheet = reference.sheet or cursor.sheet
        reference = XlmReference(sheet, reference.row, reference.col)
        cell = self._find_cell(sheet, reference.row, reference.col)
        if cell is None:
            return XlmValue(reference=reference)
        if cell.formula is not None:
            spelled = synthesize_formula(cell.formula)
            if spelled != str(cell.value):
                target = XlmCursor(sheet, cell.row, cell.col)
                try:
                    value = evaluate_expression(self, cell.formula, target)
                except RecursionError:
                    return XlmValue(value=spelled)
                value.reference = reference
                return value
        if cell.value is None:
            return XlmValue(reference=reference)
        return XlmValue(
            value=cell.value,
            date=cell.kind is CellKind.DATE,
            reference=reference,
        )

    def resolve_name(self, node: XlDefinedName, cursor: XlmCursor) -> XlmValue:
        """
        The value a defined name stands for: the formula the entry for it holds, evaluated
        through the evaluator with the scope of the reading cell. A name the workbook does not
        define, or one whose formula resolves no further, answers its own spelling.
        """
        if node.sheet is not None:
            scope = self.view.sheet_index(node.sheet)
        else:
            scope = self.view.sheet_index(cursor.sheet)
        entry = self.view.names.resolve(node.name, scope)
        if entry is None or entry.formula is None:
            return XlmValue(value=node.name, text=node.name)
        try:
            return evaluate_expression(self, entry.formula, cursor)
        except RecursionError:
            return XlmValue(value=synthesize_formula(entry.formula))

    def call(self, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
        """
        The outcome of one function call. A call whose callee is itself a call answers what the
        inner call computed, spelled as the outer one; a registered alias dispatches under the
        name it was registered for; a callee that names a cell — directly or through a defined
        name — pushes the cursor on the call stack and jumps there. While the engine ignores
        processing, every command but `NEXT` is ignored.
        """
        if isinstance(call.callee, XlFunctionCall):
            inner = self.call(call.callee, cursor)
            spelled = F'={synthesize_formula(call)}'
            if inner.value.partial:
                return XlmOutcome(value=XlmValue(value=spelled, partial=True))
            inner.value.text = spelled
            return inner
        name = _callee_name(call)
        target = self.aliases.get(name)
        if target is not None:
            return self.dispatch(target, call, cursor)
        if isinstance(call.callee, (XlA1Reference, XlR1C1Reference)):
            return self._call_cell(resolve_reference(call.callee, cursor), cursor)
        if isinstance(call.callee, XlDefinedName):
            reference = self._name_reference(call.callee, cursor)
            if reference is not None:
                return self._call_cell(reference, cursor)
        else:
            reference = self._entry_reference(name, cursor)
            if reference is not None:
                return self._call_cell(reference, cursor)
        if self.ignore_processing and name != 'NEXT':
            return XlmOutcome(value=XlmValue(), status=XlmStatus.IGNORED)
        return self.dispatch(name, call, cursor)

    def dispatch(self, name: str, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
        """
        The outcome of a call under a name no alias rewrote. Every command the handler table
        holds answers through its handler; a command without one answers the spelled fallback.
        """
        return self._unknown_command(name, call, cursor)

    def _unknown_command(self, name: str, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
        """
        The fallback for a command no handler answers: the call spelled unevaluated, with
        every argument evaluated for the side effects it may have had.
        """
        arguments = [
            evaluate_expression(self, argument, cursor).text
            for argument in call.arguments
        ]
        text = F'={name}({",".join(arguments)})'
        return XlmOutcome(value=XlmValue(value=text, partial=True))

    def _call_cell(self, reference: XlmReference, cursor: XlmCursor) -> XlmOutcome:
        self._call_stack.append(cursor)
        return XlmOutcome(jump=reference)

    def _entry_reference(self, name: str, cursor: XlmCursor) -> XlmReference | None:
        entry = self.view.names.resolve(name, self.view.sheet_index(cursor.sheet))
        if entry is None:
            return None
        return self._reference_of(entry.formula, cursor)

    def _name_reference(self, node: XlDefinedName, cursor: XlmCursor) -> XlmReference | None:
        if node.sheet is not None:
            entry = self.view.names.resolve(node.name, self.view.sheet_index(node.sheet))
        else:
            entry = self.view.names.resolve(node.name)
        if entry is None:
            return None
        return self._reference_of(entry.formula, cursor)

    def _reference_of(self, formula, cursor: XlmCursor) -> XlmReference | None:
        if isinstance(formula, (XlA1Reference, XlR1C1Reference)):
            return resolve_reference(formula, cursor)
        return None

    def _find_cell(self, sheet: str, row: int, col: int) -> XlmCell | None:
        index = self._cells.get(sheet.lower())
        if index is not None:
            cell = index.get((row, col))
            if cell is not None:
                return cell
        worksheet = self.view.worksheet(sheet)
        if worksheet is not None:
            return worksheet.get((row, col))
        return None
