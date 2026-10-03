"""
The engine of the emulator: it owns the mutable state of a run — the coordinate indexes the
cell reads and the row fall-through consult, the undo journal behind the branch snapshots,
the registered function aliases, and the branch, loop, and call stacks — runs the program of
a workbook entry point by entry point, and dispatches the function calls a formula makes to
the handlers that answer them.
"""
from __future__ import annotations

import bisect
import time

from typing import Any, Iterator, NamedTuple

from refinery.lib.excel import CellKind, parse_formula, synthesize_formula
from refinery.lib.excel.common import column_letters
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlDefinedName,
    XlFunctionCall,
    XlMissingArgument,
    XlR1C1Reference,
    XlString,
)
from refinery.lib.scripts import BodyEdit, set_body, set_child, set_value
from refinery.lib.scripts.xlm.commands import severity
from refinery.lib.scripts.xlm.environment import XlmEnvironment
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.handlers import HANDLERS
from refinery.lib.scripts.xlm.memory import XlmFiles, XlmMemory
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.references import (
    XlmCursor,
    XlmFrame,
    XlmLoop,
    expand_range,
    resolve_reference,
)
from refinery.lib.scripts.xlm.trace import XlmSeverity, XlmStatus, XlmStep
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmReference, XlmValue

_FALL_THROUGH = frozenset((
    XlmStatus.FullEvaluation,
    XlmStatus.PartialEvaluation,
    XlmStatus.NotImplemented,
    XlmStatus.IGNORED,
))

_ROW_FALL_THROUGH_LIMIT = 10000


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


class _Write(NamedTuple):
    """
    One cell write the journal undoes: the sheet the cell sits on, the cell, the value and the
    formula it carried before, and whether the write created it.
    """

    sheet: str
    cell: XlmCell
    old_value: Any
    old_formula: Any
    created: bool


class XlmEngine:
    """
    The interpreter of a workbook view. The macrosheet model is read through coordinate indexes
    the engine maintains itself, so that cells the program writes at run time stay visible to
    every reference that reads them afterwards; every write lands in an undo journal that a
    false branch of a partial `IF` rolls back from.
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
        self.indent_level = 0
        self.indent_current_line = False
        self.now_count = 0
        self.char_errors = 0
        self.iserror_at: XlmCursor | None = None
        self.iserror_flag = False
        self.iserror_repeats = 0
        self.files = XlmFiles()
        self.memory = XlmMemory()
        self.environment = XlmEnvironment()
        self.active_cell: XlmReference | None = None
        self.failed_writes: set[XlmReference] = set()
        self.call_stack: list[XlmCursor] = []
        self.branch_stack: list[XlmFrame] = []
        self.while_stack: list[XlmLoop] = []
        self._cells: dict[str, dict[tuple[int, int], XlmCell]] = {}
        self._formula_rows: dict[str, dict[int, list[int]]] = {}
        self._sheet_of: dict[int, str] = {}
        self._journal: list[_Write] = []
        for macrosheet in view.macrosheets():
            for cell in macrosheet.body:
                key = macrosheet.name.lower()
                self._sheet_of[id(cell)] = key
                index = self._cells.setdefault(key, {})
                index[(cell.row, cell.col)] = cell
                if cell.formula is None:
                    continue
                columns = self._formula_rows.setdefault(key, {})
                bisect.insort(columns.setdefault(cell.col, []), cell.row)

    def run(self, start_point: str = '') -> Iterator[XlmStep]:
        """
        The trace of running the program: one step per executed cell. The entry points are the
        defined names that fuzzy-spell `auto_open` or `auto_close`; without one, the start point
        a caller named is the only entry. A run that exhausts its step budget or its deadline
        ends with a step that says so.
        """
        deadline = time.monotonic() + self.timeout if self.timeout > 0 else None
        for reference in self._entry_points(start_point):
            anchor = self.anchor(reference)
            if anchor is None:
                continue
            yield from self._run_entry(anchor, deadline)

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
            if reference in self.failed_writes:
                address = F'{column_letters(reference.col)}{reference.row}'
                return XlmValue(value=address, partial=True)
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
        entry = self._resolve_entry(node.name, node.sheet, cursor)
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
            spelled = synthesize_formula(call)
            if inner.value.partial:
                return XlmOutcome(value=XlmValue(value=spelled, partial=True))
            inner.value.text = spelled
            return inner
        name = _callee_name(call)
        target = self.aliases.get(name)
        if target is not None:
            return self.dispatch(target, call, cursor)
        if isinstance(call.callee, (XlA1Reference, XlR1C1Reference)):
            return self._call_cell(resolve_reference(call.callee, cursor), cursor, call)
        if isinstance(call.callee, XlDefinedName):
            reference = self._name_reference(call.callee, cursor)
            if reference is not None:
                return self._call_cell(reference, cursor, call)
        else:
            entry = self._resolve_entry(name, None, cursor)
            reference = self._reference_of(entry.formula if entry else None, cursor)
            if reference is not None:
                return self._call_cell(reference, cursor, call)
        if self.ignore_processing and name != 'NEXT':
            return XlmOutcome(
                value=XlmValue(value=0, text='', partial=True),
                status=XlmStatus.IGNORED,
            )
        return self.dispatch(name, call, cursor)

    def dispatch(self, name: str, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
        """
        The outcome of a call under a name no alias rewrote. Every command the handler table
        holds answers through its handler; a command without one answers the spelled fallback.
        """
        handler = HANDLERS.get(name)
        if handler is not None:
            return handler(self, call, cursor)
        return self._unknown_command(name, call, cursor)

    def anchor(self, reference: XlmReference) -> XlmCursor | None:
        """
        The cursor the program continues at from an address: the first formula cell at or below
        it on the same column of the same macrosheet, or `None` when the sheet is no macrosheet,
        is not named at all, or holds no formula cell within the row bound.
        """
        sheet = reference.sheet
        if sheet is None or self.view.macrosheet(sheet) is None:
            return None
        row = self._fall_through(sheet, reference.col, reference.row)
        if row is None:
            return None
        return XlmCursor(sheet, row, reference.col)

    def next_formula_cell(self, cursor: XlmCursor) -> XlmCursor | None:
        """
        The cursor the row fall-through moves to: the first formula cell below the given one on
        the same column, bounded by the row bound.
        """
        row = self._fall_through(cursor.sheet, cursor.col, cursor.row + 1)
        if row is None:
            return None
        return XlmCursor(cursor.sheet, row, cursor.col)

    def argument_reference(
        self,
        call: XlFunctionCall,
        index: int,
        cursor: XlmCursor,
    ) -> XlmReference | None:
        """
        The cell address one argument of a call names: a reference resolves against the cursor,
        a defined name through its entry, a string literal parses as a formula, and any other
        expression evaluates to whatever reference its value carries.
        """
        if index >= len(call.arguments):
            return None
        return self.node_reference(call.arguments[index], cursor)

    def node_reference(self, node, cursor: XlmCursor) -> XlmReference | None:
        """
        The cell address a node names, with the sheet of a local reference filled in from the
        cursor; a reference resolves against it, a defined name through its entry, a string
        literal parses as a formula, and any other expression evaluates to whatever reference
        its value carries.
        """
        if isinstance(node, (XlA1Reference, XlR1C1Reference)):
            return self._local(resolve_reference(node, cursor), cursor)
        if isinstance(node, XlDefinedName):
            entry = self._resolve_entry(node.name, node.sheet, cursor)
            if entry is None:
                return None
            return self._local(self._reference_of(entry.formula, cursor), cursor)
        if isinstance(node, XlString):
            parsed = parse_formula(node.value)
            if isinstance(parsed, (XlA1Reference, XlR1C1Reference)):
                return self._local(resolve_reference(parsed, cursor), cursor)
            return None
        value = evaluate_expression(self, node, cursor)
        if value.reference is None:
            return None
        return self._local(value.reference, cursor)

    def range_corners(self, node, cursor: XlmCursor) -> tuple[XlmReference, XlmReference] | None:
        """
        The corners a range argument names, or `None` when the argument is no range.
        """
        if not isinstance(node, XlBinaryExpression) or node.operator is not XlBinaryOperator.RANGE:
            return None
        corners = []
        for side in (node.left, node.right):
            reference = self.node_reference(side, cursor)
            if reference is None:
                return None
            corners.append(reference)
        return corners[0], corners[1]

    def range_cells(self, corners: tuple[XlmReference, XlmReference]) -> Iterator[XlmReference]:
        """
        The addresses of the cells a range spans that the workbook holds, in row-major order.
        """
        for reference in expand_range(*corners):
            if reference.sheet is None:
                continue
            if self._find_cell(reference.sheet, reference.row, reference.col) is not None:
                yield reference

    def snapshot(self) -> int:
        """
        The journal position a false branch of a partial `IF` rolls back to.
        """
        return len(self._journal)

    def rollback(self, position: int) -> None:
        """
        Undo every cell write the journal holds past a position: values and formulas return to
        what they carried, and cells the writes created leave their sheet again.
        """
        while len(self._journal) > position:
            sheet, cell, old_value, old_formula, created = self._journal.pop()
            had_formula = cell.formula is not None
            self._update_formula_rows(sheet, cell, had_formula, old_formula is not None)
            set_value(cell, 'value', old_value)
            set_child(cell, 'formula', old_formula)
            if created:
                index = self._cells.get(sheet)
                if index is not None:
                    index.pop((cell.row, cell.col), None)
                self._sheet_of.pop(id(cell), None)
                macrosheet = self.view.macrosheet(sheet)
                if macrosheet is not None:
                    edit = BodyEdit(macrosheet)
                    edit.splice(cell, [])
                    edit.apply()

    def write_value(self, cell: XlmCell, value: object) -> None:
        """
        Write the value a step computed back into the cell it computed it in.
        """
        sheet = self._sheet_of.get(id(cell), '')
        self._journal.append(_Write(sheet, cell, cell.value, cell.formula, False))
        set_value(cell, 'value', value)

    def write_cell(
        self,
        reference: XlmReference,
        text: str,
        cursor: XlmCursor,
        value_only: bool = False,
    ) -> None:
        """
        Write into the macrosheet cell an address names, as the mutation commands do: a cell
        that does not exist is created, the text loses the quotes of a string literal, and a
        formula is installed from the text when it starts with `=` and the write is not
        value-only. An address off every macrosheet is not written at all.
        """
        sheet = reference.sheet or cursor.sheet
        macrosheet = self.view.macrosheet(sheet)
        if macrosheet is None:
            return
        key = macrosheet.name.lower()
        cell = self._cells.setdefault(key, {}).get((reference.row, reference.col))
        created = cell is None
        if cell is None:
            cell = XlmCell(row=reference.row, col=reference.col)
            self._cells[key][(reference.row, reference.col)] = cell
            self._sheet_of[id(cell)] = key
            if macrosheet.body:
                edit = BodyEdit(macrosheet)
                edit.splice(macrosheet.body[-1], [macrosheet.body[-1], cell])
                edit.apply()
            else:
                set_body(macrosheet, [cell])
        text = XlmValue(value=text).unwrap()
        formula = None
        if not value_only and text.startswith('='):
            formula = parse_formula(text)
        self._journal.append(_Write(key, cell, cell.value, cell.formula, created))
        self._update_formula_rows(key, cell, cell.formula is not None, formula is not None)
        set_value(cell, 'value', text)
        set_child(cell, 'formula', formula)

    def _run_entry(self, anchor: XlmCursor, deadline: float | None) -> Iterator[XlmStep]:
        steps = 0
        observed: list[tuple[str, int, int]] = []
        windows: set[tuple[tuple[str, int, int], ...]] = set()
        self.branch_stack = [XlmFrame(anchor, None, None, 0, '')]
        cursor = anchor
        try:
            while self.branch_stack:
                frame = self.branch_stack.pop()
                if frame.journal is not None:
                    self.rollback(frame.journal)
                cursor = frame.cursor
                node = frame.branch
                self.indent_level = frame.indent
                stack_record = True
                while cursor is not None:
                    steps += 1
                    if steps > self.max_steps:
                        yield self._error_step(cursor, F'step budget of {self.max_steps} exhausted')
                        return
                    cell = self._find_cell(cursor.sheet, cursor.row, cursor.col)
                    if cell is None:
                        break
                    if node is None:
                        node = cell.formula
                        if node is None:
                            break
                    if stack_record:
                        previous_indent = self.indent_level - 1 if self.indent_level > 0 else 0
                    else:
                        previous_indent = self.indent_level
                    outcome = self._execute(node, cursor)
                    status = outcome.status
                    if status is None:
                        partial = outcome.value.partial
                        status = (
                            XlmStatus.PartialEvaluation if partial else XlmStatus.FullEvaluation
                        )
                    text = outcome.value.text
                    if not self.while_stack and text != 'NEXT':
                        observed.append((cursor.sheet.lower(), cursor.row, cursor.col))
                        if len(observed) >= 20:
                            window = tuple(observed[-10:])
                            if window in windows:
                                break
                            windows.add(window)
                    if outcome.value.value is not None:
                        self.write_value(cell, str(outcome.value.value))
                    if stack_record:
                        text = (frame.desc + ' ' + text).strip()
                    if self.indent_current_line:
                        previous_indent = self.indent_level
                        self.indent_current_line = False
                    if status is not XlmStatus.IGNORED:
                        yield XlmStep(
                            cursor.sheet,
                            cursor.row,
                            cursor.col,
                            status,
                            text,
                            previous_indent,
                            self._step_severity(node),
                        )
                    if deadline is not None and time.monotonic() > deadline:
                        return
                    if outcome.jump is not None:
                        cursor = outcome.jump
                    elif status in _FALL_THROUGH:
                        cursor = self.next_formula_cell(cursor)
                    else:
                        break
                    node = None
                    stack_record = False
        except Exception as error:
            yield self._error_step(cursor or anchor, F'{type(error).__name__}: {error}')

    def _execute(self, node, cursor: XlmCursor) -> XlmOutcome:
        if isinstance(node, XlFunctionCall):
            return self.call(node, cursor)
        return XlmOutcome(value=evaluate_expression(self, node, cursor))

    def _entry_points(self, start_point: str) -> list[XlmReference]:
        result: list[XlmReference] = []
        for pattern in ('auto_open', 'auto_close'):
            for entry in self.view.names.fuzzy(pattern):
                reference = self._reference_of(entry.formula, XlmCursor('', 0, 0))
                if reference is not None and reference.sheet is not None:
                    result.append(reference)
        if not result and start_point:
            parsed = parse_formula(start_point)
            if isinstance(parsed, (XlA1Reference, XlR1C1Reference)):
                reference = resolve_reference(parsed, XlmCursor('', 0, 0))
                if reference.sheet is not None:
                    result.append(reference)
        return result

    def _step_severity(self, node) -> XlmSeverity:
        if isinstance(node, XlFunctionCall) and isinstance(node.callee, str):
            return severity(node.callee.strip('"'))
        return XlmSeverity.JUMP

    def _error_step(self, cursor: XlmCursor, message: str) -> XlmStep:
        return XlmStep(
            cursor.sheet,
            cursor.row,
            cursor.col,
            XlmStatus.Error,
            message,
            self.indent_level,
            XlmSeverity.JUMP,
        )

    def _unknown_command(self, name: str, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
        """
        The fallback for a command no handler answers: the call spelled unevaluated, with
        every argument evaluated for the side effects it may have had. A missing argument spells
        nothing — the grammar of the retiring port did not materialize one at all.
        """
        arguments = [
            evaluate_expression(self, argument, cursor).text or ''
            for argument in call.arguments
            if not isinstance(argument, XlMissingArgument)
        ]
        text = F'={name}({",".join(arguments)})'
        return XlmOutcome(value=XlmValue(value=text, partial=True))

    def _call_cell(
        self,
        reference: XlmReference,
        cursor: XlmCursor,
        call: XlFunctionCall,
    ) -> XlmOutcome:
        spelled = synthesize_formula(call)
        if reference.sheet is None:
            reference = XlmReference(cursor.sheet, reference.row, reference.col)
        if self.view.macrosheet(reference.sheet) is None:
            return XlmOutcome(value=XlmValue(value=0, text=spelled), status=XlmStatus.Error)
        self.call_stack.append(cursor)
        return XlmOutcome(
            value=XlmValue(value=0, text=spelled),
            jump=self.anchor(reference),
        )

    def _resolve_entry(self, name: str, sheet: str | None, cursor: XlmCursor):
        if sheet is not None:
            return self.view.names.resolve(name, self.view.sheet_index(sheet))
        return self.view.names.resolve(name, self.view.sheet_index(cursor.sheet))

    def _name_reference(self, node: XlDefinedName, cursor: XlmCursor) -> XlmReference | None:
        entry = self._resolve_entry(node.name, node.sheet, cursor)
        if entry is None:
            return None
        return self._reference_of(entry.formula, cursor)

    def _reference_of(self, formula, cursor: XlmCursor) -> XlmReference | None:
        if isinstance(formula, (XlA1Reference, XlR1C1Reference)):
            return resolve_reference(formula, cursor)
        return None

    def _local(self, reference: XlmReference | None, cursor: XlmCursor) -> XlmReference | None:
        if reference is None:
            return None
        if reference.sheet is not None:
            return reference
        return XlmReference(cursor.sheet, reference.row, reference.col)

    def _fall_through(self, sheet: str, col: int, row: int) -> int | None:
        rows = self._formula_rows.get(sheet.lower(), {}).get(col)
        if not rows:
            return None
        position = bisect.bisect_left(rows, row)
        if position >= len(rows):
            return None
        found = rows[position]
        if found - row > _ROW_FALL_THROUGH_LIMIT:
            return None
        return found

    def _update_formula_rows(self, sheet: str, cell: XlmCell, had: bool, has: bool) -> None:
        if had == has:
            return
        rows = self._formula_rows.setdefault(sheet, {}).setdefault(cell.col, [])
        if has:
            bisect.insort(rows, cell.row)
        elif cell.row in rows:
            rows.remove(cell.row)

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
