"""
The engine of the emulator: it owns the mutable state of a run — the coordinate indexes the
cell reads and the row fall-through consult, the values the run left in its cells, the undo
journal behind the branch snapshots, the registered function aliases, and the branch, loop,
and call stacks — runs the program of a workbook entry point by entry point, and dispatches
the function calls a formula makes to the handlers that answer them.
"""
from __future__ import annotations

import bisect
import dataclasses
import hashlib
import time

from typing import Any, Iterator, NamedTuple, Protocol

from refinery.lib.excel import CellKind, parse_formula, synthesize_formula
from refinery.lib.excel.common import column_letters
from refinery.lib.excel.formula.model import (
    XlA1Reference,
    XlBinaryExpression,
    XlBinaryOperator,
    XlDefinedName,
    XlFunctionCall,
    XlR1C1Reference,
    XlString,
)
from refinery.lib.scripts import TREE_RECURSION_DEPTH, BodyEdit, set_body, set_child, set_value
from refinery.lib.scripts.xlm.blocks import XlmBlock, marker_of, pair_blocks
from refinery.lib.scripts.xlm.commands import severity
from refinery.lib.scripts.xlm.environment import XlmEnvironment
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.handlers import EXPRESSION_HANDLERS, HANDLERS
from refinery.lib.scripts.xlm.memory import XlmFiles, XlmMemory
from refinery.lib.scripts.xlm.model import XlmCell
from refinery.lib.scripts.xlm.names import XlmNameEntry
from refinery.lib.scripts.xlm.references import (
    XlmArrival,
    XlmCursor,
    XlmFrame,
    XlmLoop,
    XlmReturnSlot,
    XlmSnapshot,
    resolve_reference,
)
from refinery.lib.scripts.xlm.trace import XlmSeverity, XlmStatus, XlmStep
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmReference, XlmValue
from refinery.lib.tools import RecursionDepth

_FALL_THROUGH = frozenset((
    XlmStatus.FullEvaluation,
    XlmStatus.PartialEvaluation,
    XlmStatus.NotImplemented,
    XlmStatus.IGNORED,
))

_ROW_FALL_THROUGH_LIMIT = 10000

#: The commands that still run while the engine skips the body of a loop: the heads and the end
#: of a loop, because a skipped body ends at the `NEXT` that pairs with its own head.
_LOOP_COMMANDS = frozenset((
    'FOR.CELL',
    'NEXT',
    'WHILE',
))

#: How deeply macro calls inside expressions may nest: a deeper call is left unfinished, which
#: bounds a subroutine that calls itself from inside a formula.
_SUBROUTINE_DEPTH_LIMIT = 64

#: How many formula cells the reads of one evaluation may evaluate: a read past the budget
#: answers the value the cell was stored with, which bounds a formula whose references fan out
#: over cells that read each other.
_READ_BUDGET = 100_000


#: How many steps the loop detector leaves between two computations of the state digest, so
#: that a window that repeats keeps the run cheap until a comparison can tell frozen from
#: moving.
_DIGEST_STEPS = 1000

#: How many addresses a run observes before its window of the last ten addresses starts.
_WINDOW_WARMUP = 20


class _Exhausted(Exception):
    """
    Raised once a run used up its step budget or its deadline: the run of the entry ends at the
    step that exhausted it, even when that step runs inside a subroutine an expression called.
    """


def callee_name(call: XlFunctionCall) -> str:
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


def _blank(reference: XlmReference) -> XlmValue:
    """
    The value of a cell that holds nothing: the empty text, which an arithmetic operator reads
    as zero.
    """
    return XlmValue(value='', text='', reference=reference)


def _held(value: XlmValue) -> XlmValue:
    """
    The value a cell holds once a step, a value command, or a return left a value in it. The
    trace spells a command by its call, but a read of the cell spells what the command computed,
    so a complete value is respelled from the value itself; an unfinished one keeps the spelling
    of what was left unfinished. A value that computes nothing leaves the cell blank.
    """
    if value.partial:
        return XlmValue(
            value=value.value,
            text=value.text,
            partial=True,
            date=value.date,
            cells=value.cells,
        )
    if value.value is None:
        return XlmValue(value='', text='')
    return XlmValue(
        value=value.value,
        date=value.date,
        cells=value.cells,
        error=value.error,
    )


class _CellIndex:
    """
    The coordinate indexes over the macrosheet cells of a view, and the values the runs left in
    them: the cell at every position of every sheet, the rows of every column that hold a
    formula — the rows the fall-through walks — the sheet every cell sits on, and the value a
    step, a value command, or a return left in a cell, which a later read of the cell answers
    instead of evaluating its formula again.
    """

    def __init__(self, view):
        self.cells: dict[str, dict[tuple[int, int], XlmCell]] = {}
        self.formula_rows: dict[str, dict[int, list[int]]] = {}
        self.sheet_of: dict[int, str] = {}
        self.held: dict[int, XlmValue] = {}
        for macrosheet in view.macrosheets():
            sheet = macrosheet.name.lower()
            for cell in macrosheet.body:
                self.insert(sheet, cell)

    def insert(self, sheet: str, cell: XlmCell) -> None:
        self.sheet_of[id(cell)] = sheet
        self.cells.setdefault(sheet, {})[(cell.row, cell.col)] = cell
        if cell.formula is not None:
            rows = self.formula_rows.setdefault(sheet, {}).setdefault(cell.col, [])
            bisect.insort(rows, cell.row)

    def remove(self, sheet: str, cell: XlmCell) -> None:
        cells = self.cells.get(sheet)
        if cells is not None:
            cells.pop((cell.row, cell.col), None)
        self.sheet_of.pop(id(cell), None)
        self.held.pop(id(cell), None)

    def find(self, sheet: str, row: int, col: int) -> XlmCell | None:
        cells = self.cells.get(sheet.lower())
        if cells is None:
            return None
        return cells.get((row, col))

    def hold(self, cell: XlmCell, value: XlmValue | None) -> None:
        if value is None:
            self.held.pop(id(cell), None)
        else:
            self.held[id(cell)] = value

    def update_formula_rows(self, sheet: str, cell: XlmCell, had: bool, has: bool) -> None:
        if had == has:
            return
        rows = self.formula_rows.setdefault(sheet, {}).setdefault(cell.col, [])
        if has:
            bisect.insort(rows, cell.row)
        elif cell.row in rows:
            rows.remove(cell.row)

    def fall_through(self, sheet: str, col: int, row: int) -> int | None:
        rows = self.formula_rows.get(sheet.lower(), {}).get(col)
        if not rows:
            return None
        position = bisect.bisect_left(rows, row)
        if position >= len(rows):
            return None
        found = rows[position]
        if found - row > _ROW_FALL_THROUGH_LIMIT:
            return None
        return found


class _Undo(Protocol):
    """
    One change the journal undoes: every state a run mutates — cells, names, aliases, files,
    memory regions, failed-write marks — lands in the journal as one record that knows how to
    take the state it found back.
    """

    def undo(self, engine: XlmEngine) -> None:
        ...


class _Write(NamedTuple):
    """
    One cell write the journal undoes: the sheet the cell sits on, the cell, the value and the
    formula it carried before, the value the runs had left in it, and whether the write created
    it.
    """

    sheet: str
    cell: XlmCell
    old_value: Any
    old_formula: Any
    old_held: XlmValue | None
    created: bool

    def undo(self, engine: XlmEngine) -> None:
        index = engine._index
        index.update_formula_rows(
            self.sheet,
            self.cell,
            self.cell.formula is not None,
            self.old_formula is not None,
        )
        set_value(self.cell, 'value', self.old_value)
        set_child(self.cell, 'formula', self.old_formula)
        index.hold(self.cell, self.old_held)
        if self.created:
            index.remove(self.sheet, self.cell)
            macrosheet = engine.view.macrosheet(self.sheet)
            if macrosheet is not None:
                edit = BodyEdit(macrosheet)
                edit.splice(self.cell, [])
                edit.apply()


class _NameDefine(NamedTuple):
    """
    One name definition the journal undoes: every entry the table held before the definition.
    """

    before: list[XlmNameEntry]

    def undo(self, engine: XlmEngine) -> None:
        engine.view.names.restore(self.before)


class _AliasRegistration(NamedTuple):
    """
    One registered alias the journal undoes: the target the name dispatched to before, if any.
    """

    name: str
    before: str | None

    def undo(self, engine: XlmEngine) -> None:
        if self.before is None:
            engine.aliases.pop(self.name, None)
        else:
            engine.aliases[self.name] = self.before


class _FileOpen(NamedTuple):
    """
    One file the program opened, the journal undoes by closing it again.
    """

    name: str

    def undo(self, engine: XlmEngine) -> None:
        engine.files.close(self.name)


class _FileWrite(NamedTuple):
    """
    One append to a file the journal undoes: the length of the content before the append.
    """

    name: str
    length: int

    def undo(self, engine: XlmEngine) -> None:
        engine.files.truncate(self.name, self.length)


class _RegionAlloc(NamedTuple):
    """
    One region of memory a command reserved, the journal undoes by releasing it.
    """

    def undo(self, engine: XlmEngine) -> None:
        engine.memory.release()


class _MemoryWrite(NamedTuple):
    """
    One write into a region of memory the journal undoes: the bytes the slice held before.
    """

    base: int
    before: bytes

    def undo(self, engine: XlmEngine) -> None:
        engine.memory.restore(self.base, self.before)


class _FailedMark(NamedTuple):
    """
    One failed-write mark the journal undoes, in the direction the mark was made.
    """

    reference: XlmReference
    added: bool

    def undo(self, engine: XlmEngine) -> None:
        if self.added:
            engine.failed_writes.discard(self.reference)
        else:
            engine.failed_writes.add(self.reference)


class XlmEngine:
    """
    The interpreter of a workbook view. The macrosheet model is read through coordinate indexes
    the engine maintains itself, so that cells the program writes at run time stay visible to
    every reference that reads them afterwards; every write lands in an undo journal that a
    false branch of a partial `IF` rolls back from. The start point and the deadline of the
    latest run are kept on the engine, because the trial runs of the day guess share them.
    """

    def __init__(
        self,
        view,
        output_level: int = 0,
        day: int = -1,
        timeout: int = 0,
        max_steps: int = 1_000_000,
        *,
        cells: _CellIndex | None = None,
    ):
        self.view = view
        self.output_level = output_level
        self.day = day
        self.timeout = timeout
        self.max_steps = max_steps
        self.start_point = ''
        self.deadline: float | None = None
        self.aliases: dict[str, str] = {}
        self.indent_level = 0
        self.indent_current_line = False
        self.arrival = XlmArrival.JUMP
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
        self.call_stack: list[XlmCursor | XlmReturnSlot] = []
        self.branch_stack: list[XlmFrame] = []
        self.while_stack: list[XlmLoop] = []
        self._index = _CellIndex(view) if cells is None else cells
        self._journal: list[_Undo] = []
        self._evaluating: set[int] = set()
        self._resolving: set[tuple[str, int | None]] = set()
        self._buffers: list[list[XlmStep]] = []
        self._depth = 0
        self._steps = 0
        self._reads = 0
        self._halted = False

    @property
    def ignore_processing(self) -> bool:
        """
        Whether the engine skips the body of a loop: true while any open loop does not hold.
        """
        return any(not loop.holds for loop in self.while_stack)

    def run(self, start_point: str = '') -> Iterator[XlmStep]:
        """
        The trace of running the program: one step per executed cell. The entry points are the
        defined names that fuzzy-spell `auto_open` or `auto_close`; without one, the start point
        a caller named is the only entry. The run of an entry that exhausts its step budget ends
        with a step that says so, and a run that exhausts its deadline ends the same way and
        runs no further entry. An engine without a timeout of its own keeps the deadline it was
        given.
        """
        self.start_point = start_point
        if self.timeout > 0:
            self.deadline = time.monotonic() + self.timeout
        return self._run()

    def trial(self, day: int) -> XlmEngine:
        """
        A fresh engine for one trial run of the day guess: it shares this engine's view and the
        index over its cells — the cells, values, and names the runs so far have written — and
        the deadline of this engine's run, and answers the given day, but starts with no files,
        no memory, and no registered names of its own.
        """
        trial = XlmEngine(
            self.view,
            self.output_level,
            day,
            0,
            self.max_steps,
            cells=self._index,
        )
        trial.deadline = self.deadline
        return trial

    def read_reference(self, reference: XlmReference, cursor: XlmCursor) -> XlmValue:
        """
        The value a cell address holds. The sheet the reference fails to name is the sheet the
        cursor sits on. A cell the run left a value in — by a step that executed it, a value
        command, or a return — holds that value. Any other formula cell is evaluated with itself
        as the cursor its relative references resolve against, unless its evaluation is already
        under way, the reads of the running evaluation exhausted their budget, or it nests too
        deeply; such a cell, and a cell that holds only a value, reads as the value it was
        stored with, with the date flag a date cell carries. An address the workbook does not
        hold is blank.
        """
        sheet = reference.sheet or cursor.sheet
        reference = XlmReference(sheet, reference.row, reference.col)
        cell = self._find_cell(sheet, reference.row, reference.col)
        if cell is None:
            if reference in self.failed_writes:
                address = F'{column_letters(reference.col)}{reference.row}'
                return XlmValue(value=address, partial=True)
            return _blank(reference)
        held = self._index.held.get(id(cell))
        if held is not None:
            return dataclasses.replace(held, reference=reference)
        if not self._evaluating:
            self._reads = 0
        if (
            cell.formula is not None
            and id(cell) not in self._evaluating
            and self._reads < _READ_BUDGET
        ):
            self.check_deadline()
            self._reads += 1
            self._evaluating.add(id(cell))
            try:
                value = evaluate_expression(
                    self,
                    cell.formula,
                    XlmCursor(sheet, cell.row, cell.col),
                )
            except RecursionError:
                return self._stored(cell, reference)
            finally:
                self._evaluating.discard(id(cell))
            value.reference = reference
            return value
        return self._stored(cell, reference)

    def resolve_name(self, node: XlDefinedName, cursor: XlmCursor) -> XlmValue:
        """
        The value a defined name stands for: the formula the entry for it holds, evaluated
        through the evaluator with the scope of the reading cell. A name the workbook does not
        define, or one whose formula resolves no further, answers its own spelling; a formula
        that reads the name it defines, or nests too deeply, answers the spelling of the formula.
        """
        entry = self._resolve_entry(node.name, node.sheet, cursor)
        if entry is None or entry.formula is None:
            return XlmValue(value=node.name, text=node.name)
        key = (entry.name.lower(), entry.sheet)
        if key in self._resolving:
            return XlmValue(value=synthesize_formula(entry.formula))
        self._resolving.add(key)
        try:
            return evaluate_expression(self, entry.formula, cursor)
        except RecursionError:
            return XlmValue(value=synthesize_formula(entry.formula))
        finally:
            self._resolving.discard(key)

    def call(self, call: XlFunctionCall, cursor: XlmCursor, nested: bool = False) -> XlmOutcome:
        """
        The outcome of one function call. While the engine skips the body of a loop, every call
        but the heads and ends of loops is ignored. A call whose callee is itself a call answers
        what the inner call computed, spelled as the outer one; a registered alias dispatches
        under the name it was registered for; a callee that names a cell — directly or through
        a defined name — calls the macro there. A call is nested when an expression reads it
        instead of a step running it as the whole formula of its cell: a nested macro call runs
        its subroutine to the value it returns, and a nested command answers through the
        handler an expression reads it by, where it has one. Once the deadline of the run
        passed, no call answers.
        """
        self.check_deadline()
        name = callee_name(call)
        if self.ignore_processing and name not in _LOOP_COMMANDS:
            return XlmOutcome(
                value=XlmValue(value=0, text='', partial=True),
                status=XlmStatus.IGNORED,
            )
        if isinstance(call.callee, XlFunctionCall):
            inner = self.call(call.callee, cursor, nested)
            spelled = synthesize_formula(call)
            if inner.value.partial:
                return XlmOutcome(value=XlmValue(value=spelled, partial=True))
            inner.value.text = spelled
            return inner
        target = self.aliases.get(name)
        if target is not None:
            return self.dispatch(target, call, cursor, nested)
        if isinstance(call.callee, (XlA1Reference, XlR1C1Reference)):
            reference = resolve_reference(call.callee, cursor)
            return self._call_cell(reference, cursor, call, nested)
        if isinstance(call.callee, XlDefinedName):
            reference = self._name_reference(call.callee, cursor)
            if reference is not None:
                return self._call_cell(reference, cursor, call, nested)
        else:
            entry = self._resolve_entry(name, None, cursor)
            reference = self._reference_of(entry.formula if entry else None, cursor)
            if reference is not None:
                return self._call_cell(reference, cursor, call, nested)
        return self.dispatch(name, call, cursor, nested)

    def dispatch(
        self,
        name: str,
        call: XlFunctionCall,
        cursor: XlmCursor,
        nested: bool = False,
    ) -> XlmOutcome:
        """
        The outcome of a call under a name no alias rewrote. A nested call answers through the
        handler an expression reads its command by, where the command has one; every other
        command the handler table holds answers through its handler, and a command without one
        answers the spelled fallback.
        """
        handler = EXPRESSION_HANDLERS.get(name) if nested else None
        if handler is None:
            handler = HANDLERS.get(name)
        if handler is not None:
            return handler(self, call, cursor)
        return self._unknown_command(name, call, cursor)

    def return_value(self, value: XlmValue) -> tuple[XlmCursor | None, bool]:
        """
        Hand the value a `RETURN` computes to the macro call it returns from: a call that is the
        whole formula of its cell leaves the value in that cell and continues below it, and a
        call inside an expression takes the value as its own, which ends the run of the
        subroutine. A return without a call to return from continues below itself. The answer
        is the cursor to continue at and whether the run of a subroutine ended.
        """
        if not self.call_stack:
            return None, False
        caller = self.call_stack.pop()
        if isinstance(caller, XlmReturnSlot):
            caller.value = value
            return None, True
        cell = self._find_cell(caller.sheet, caller.row, caller.col)
        if cell is not None:
            self.write_value(cell, value)
        return self.next_formula_cell(caller), False

    def anchor(self, reference: XlmReference) -> XlmCursor | None:
        """
        The cursor the program continues at from an address: the first formula cell at or below
        it on the same column of the same macrosheet, or `None` when the sheet is no macrosheet,
        is not named at all, or holds no formula cell within the row bound.
        """
        sheet = reference.sheet
        if sheet is None or self.view.macrosheet(sheet) is None:
            return None
        row = self._index.fall_through(sheet, reference.col, reference.row)
        if row is None:
            return None
        return XlmCursor(sheet, row, reference.col)

    def next_formula_cell(self, cursor: XlmCursor) -> XlmCursor | None:
        """
        The cursor the row fall-through moves to: the first formula cell below the given one on
        the same column, bounded by the row bound.
        """
        row = self._index.fall_through(cursor.sheet, cursor.col, cursor.row + 1)
        if row is None:
            return None
        return XlmCursor(cursor.sheet, row, cursor.col)

    def column_blocks(self, cursor: XlmCursor) -> dict[int, XlmBlock]:
        """
        The block structure of the column of the cursor: every marker row mapped to the block
        `IF` it belongs to, paired over the live formula rows of the column, so that cells the
        program wrote at run time take part in the pairing.
        """
        sheet = cursor.sheet.lower()
        markers: list[tuple[int, str]] = []
        for row in self._index.formula_rows.get(sheet, {}).get(cursor.col, ()):
            cell = self._index.find(sheet, row, cursor.col)
            if cell is None or cell.formula is None:
                continue
            marker = marker_of(cell.formula)
            if marker is not None:
                markers.append((row, marker))
        return pair_blocks(markers)

    def argument_reference(
        self,
        call: XlFunctionCall,
        index: int,
        cursor: XlmCursor,
    ) -> XlmReference | None:
        """
        The cell address one argument of a call names, as `XlmEngine.node_reference` reads it.
        """
        if index >= len(call.arguments):
            return None
        return self.node_reference(call.arguments[index], cursor)

    def node_reference(self, node, cursor: XlmCursor) -> XlmReference | None:
        """
        The cell address a node names, with the sheet of a local reference filled in from the
        cursor: a reference resolves against it, a defined name through the reference its entry
        holds, and a string literal parses as a formula. Any other expression evaluates to the
        reference its value carries, or to the address its text spells.
        """
        if isinstance(node, (XlA1Reference, XlR1C1Reference)):
            return self._local(resolve_reference(node, cursor), cursor)
        if isinstance(node, XlDefinedName):
            reference = self._name_reference(node, cursor)
            if reference is not None:
                return self._local(reference, cursor)
        if isinstance(node, XlString):
            return self._spelled_reference(node.value, cursor)
        value = evaluate_expression(self, node, cursor)
        if value.reference is not None:
            return self._local(value.reference, cursor)
        if value.partial or not isinstance(value.value, str):
            return None
        return self._spelled_reference(value.value, cursor)

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
        The addresses of the cells a range spans that the workbook holds, in row-major order:
        the cells the index holds on the sheet of the range, the cells of that sheet where it
        is a worksheet, and the failed writes inside it, which read as the values the program
        left unfinished. The walk counts the cells the workbook holds, not the coordinates the
        rectangle spans.
        """
        first, last = corners
        sheet = first.sheet
        if sheet is None:
            return
        key = sheet.lower()
        row_min = min(first.row, last.row)
        row_max = max(first.row, last.row)
        col_min = min(first.col, last.col)
        col_max = max(first.col, last.col)
        held = self._index.cells.get(key, {})
        worksheet = self.view.worksheet(sheet)
        coordinates = set(held) | set(worksheet or ())
        coordinates.update(
            (reference.row, reference.col)
            for reference in self.failed_writes
            if (reference.sheet or '').lower() == key
        )
        inside = (
            coordinate
            for coordinate in coordinates
            if row_min <= coordinate[0] <= row_max
            and col_min <= coordinate[1] <= col_max
        )
        for row, col in sorted(inside):
            yield XlmReference(sheet, row, col)

    def snapshot(self) -> XlmSnapshot:
        """
        The state a false branch of a partial `IF` rolls back to: the position of the journal,
        and the state of the run the journal does not hold.
        """
        return XlmSnapshot(
            len(self._journal),
            tuple(self.call_stack),
            tuple(loop.copy() for loop in self.while_stack),
            self.active_cell,
        )

    def state_digest(self) -> bytes:
        """
        The digest of the whole state a run can observe: the cells its index holds, with the
        value each holds and the formula it spells, the entries of the name table, the
        registered aliases, the failed-write marks, the content of every open file, every
        region of memory, and the cell the program selected. A run that returns to the digest
        it anchored changes nothing the program can see.
        """
        parts: list[str] = []
        for sheet in sorted(self._index.cells):
            cells = self._index.cells[sheet]
            for row, col in sorted(cells):
                cell = cells[(row, col)]
                held = self._index.held.get(id(cell))
                value = held.text if held is not None else repr(cell.value)
                formula = cell.formula
                spelling = synthesize_formula(formula) if formula is not None else ''
                parts.append(F'{sheet}!{row}!{col}={value}|{spelling}')
        for entry in self.view.names.entries():
            formula = entry.formula
            spelling = synthesize_formula(formula) if formula is not None else ''
            parts.append(F'name:{entry.name.lower()}@{entry.sheet}={spelling}')
        for name in sorted(self.aliases):
            parts.append(F'alias:{name}={self.aliases[name]}')
        for reference in sorted(self.failed_writes):
            parts.append(F'failed:{reference.a1()}')
        for name, content in self.files.snapshot():
            parts.append(F'file:{name}={content}')
        for base, data in self.memory.snapshot():
            parts.append(F'memory:{base}={len(data)}:{data.hex()}')
        parts.append(F'active:{self.active_cell}')
        return hashlib.sha256('\n'.join(parts).encode()).digest()

    def rollback(self, snapshot: XlmSnapshot) -> None:
        """
        Return to a snapshot: every change the journal holds past its position is undone —
        cells, names, aliases, files, memory regions, and failed-write marks return to what they
        carried, and cells the writes created leave their sheet again — and the call stack, the
        open loops, and the selected cell are what they were.
        """
        while len(self._journal) > snapshot.journal:
            self._journal.pop().undo(self)
        self.call_stack = list(snapshot.call_stack)
        self.while_stack = [loop.copy() for loop in snapshot.loops]
        self.active_cell = snapshot.active_cell

    def write_value(self, cell: XlmCell, value: XlmValue) -> None:
        """
        Leave the value a step computed — or a macro call returned — in the cell it belongs to,
        undoable by a branch that rolls back: a later read of the cell answers that value
        instead of evaluating the formula of the cell again.
        """
        self._journal.append(_Write(
            self._index.sheet_of.get(id(cell), ''),
            cell,
            cell.value,
            cell.formula,
            self._index.held.get(id(cell)),
            False,
        ))
        held = _held(value)
        set_value(cell, 'value', held.value)
        self._index.hold(cell, held)

    def write_cell(
        self,
        reference: XlmReference,
        value: XlmValue,
        cursor: XlmCursor,
        value_only: bool = False,
    ) -> None:
        """
        Write a value into the macrosheet cell an address names, as the mutation commands do,
        undoable by a branch that rolls back; a cell that does not exist is created. A
        value-only write changes the value the cell holds and leaves its formula in place. Any
        other write enters the value the way a typed entry does: a text that starts with `=`
        installs a formula, which a later read of the cell evaluates, and anything else replaces
        the formula of the cell by a constant. An address off every macrosheet is not written.
        """
        sheet = reference.sheet or cursor.sheet
        macrosheet = self.view.macrosheet(sheet)
        if macrosheet is None:
            return
        key = macrosheet.name.lower()
        cell = self._index.find(key, reference.row, reference.col)
        created = cell is None
        if cell is None:
            cell = XlmCell(row=reference.row, col=reference.col)
            self._index.insert(key, cell)
            if macrosheet.body:
                edit = BodyEdit(macrosheet)
                edit.splice(macrosheet.body[-1], [macrosheet.body[-1], cell])
                edit.apply()
            else:
                set_body(macrosheet, [cell])
        self._journal.append(_Write(
            key,
            cell,
            cell.value,
            cell.formula,
            self._index.held.get(id(cell)),
            created,
        ))
        held: XlmValue | None = _held(value)
        formula = cell.formula
        if not value_only:
            formula = None
            if isinstance(value.value, str) and value.value.startswith('='):
                formula = parse_formula(value.value)
                held = None
        self._index.update_formula_rows(key, cell, cell.formula is not None, formula is not None)
        set_value(cell, 'value', value.value if held is None else held.value)
        set_child(cell, 'formula', formula)
        self._index.hold(cell, held)

    def define_name(self, entry: XlmNameEntry) -> None:
        """
        Define the name an entry carries, as the name commands do, undoable by a branch that
        rolls back.
        """
        self._journal.append(_NameDefine(self.view.names.entries()))
        self.view.names.define(entry)

    def assign_name(self, name: str, formula, cursor: XlmCursor) -> None:
        """
        Define a name as `SET.NAME` and the `FOR.CELL` loop do, undoable by a branch that rolls
        back: the definition replaces the entry a read on the sheet of the cursor resolves the
        name to, so that the sheet reads back what it assigned, and a name the sheet resolves to
        no entry is defined for the whole workbook. A name assigned no formula reads as one the
        workbook does not define.
        """
        entry = self.view.names.resolve(name, self.view.sheet_index(cursor.sheet))
        sheet = None if entry is None else entry.sheet
        self.define_name(XlmNameEntry(name=name, sheet=sheet, formula=formula))

    def register_alias(self, name: str, target: str) -> None:
        """
        Register the target a command name dispatches to, as `REGISTER` does, undoable by a
        branch that rolls back.
        """
        self._journal.append(_AliasRegistration(name, self.aliases.get(name)))
        self.aliases[name] = target

    def open_file(self, name: str, access: str = '1') -> None:
        """
        Open the name as a file, as `FOPEN` does, undoable by a branch that rolls back; a name
        that already answers a file changes nothing.
        """
        if self.files.opened(name):
            return
        self._journal.append(_FileOpen(name))
        self.files.open(name, access)

    def write_file(self, name: str, text: str) -> bool:
        """
        Append to a file the program opened, as `FWRITE` does, undoable by a branch that rolls
        back, reporting whether the file took the write.
        """
        length = self.files.size(name)
        if length is None:
            return False
        self._journal.append(_FileWrite(name, length))
        self.files.write(name, text)
        return True

    def allocate_memory(self, base: int, size: int) -> int:
        """
        Reserve a region of memory, as `Kernel32.VirtualAlloc` does, undoable by a branch that
        rolls back.
        """
        self._journal.append(_RegionAlloc())
        return self.memory.allocate(base, size)

    def write_memory(self, base: int, data: bytes, size: int) -> bool:
        """
        Write bytes into a region of memory, as the Kernel32 write commands do, undoable by a
        branch that rolls back, reporting whether a region took the whole write.
        """
        before = self.memory.peek(base, size)
        if before is None:
            return False
        self.memory.write(base, data, size)
        self._journal.append(_MemoryWrite(base, before))
        return True

    def mark_failed(self, reference: XlmReference) -> None:
        """
        Mark an address as the destination of a write that never finished, undoable by a
        branch that rolls back.
        """
        if reference in self.failed_writes:
            return
        self._journal.append(_FailedMark(reference, True))
        self.failed_writes.add(reference)

    def unmark_failed(self, reference: XlmReference) -> None:
        """
        Drop the failed-write mark of an address, undoable by a branch that rolls back.
        """
        if reference not in self.failed_writes:
            return
        self._journal.append(_FailedMark(reference, False))
        self.failed_writes.discard(reference)

    def _run(self) -> Iterator[XlmStep]:
        for reference in self.view.entry_points(self.start_point):
            if self._expired():
                return
            anchor = self.anchor(reference)
            if anchor is None:
                continue
            self._steps = 0
            self._halted = False
            self.while_stack.clear()
            self.call_stack.clear()
            yield from self._run_entry(anchor)

    def _run_entry(
        self,
        anchor: XlmCursor,
        caller: XlmReturnSlot | None = None,
    ) -> Iterator[XlmStep]:
        """
        The steps of running the program from one anchor until every branch it opened ran out.
        The run of a subroutine names the call it returns to: its branches are its own, it ends
        with the first value it returns, and a halt ends it together with the branch of every
        run that called it, each after its calling step; a budget or deadline it exhausts ends
        the run that called it at once. The steps of the subroutines a step called precede the
        step.
        """
        observed: list[tuple[str, int, int]] = []
        anchors: dict[tuple[tuple[str, int, int], ...], bytes] = {}
        digest_step = 0
        buffer: list[XlmStep] = []
        branches = self.branch_stack
        indent = 0 if caller is None else self.indent_level
        self.branch_stack = [XlmFrame(anchor, None, None, indent, '')]
        self._buffers.append(buffer)
        cursor = anchor
        self.arrival = XlmArrival.JUMP
        try:
            while self.branch_stack:
                frame = self.branch_stack.pop()
                if frame.snapshot is not None:
                    self.rollback(frame.snapshot)
                    anchors.clear()
                cursor = frame.cursor
                node = frame.branch
                self.indent_level = frame.indent
                self.arrival = (
                    XlmArrival.REPLAY if frame.snapshot is not None else XlmArrival.RESUME
                )
                stack_record = True
                while cursor is not None:
                    self._steps += 1
                    if self._steps > self.max_steps:
                        raise _Exhausted(F'step budget of {self.max_steps} exhausted')
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
                    if caller is None:
                        self._reads = 0
                    self._evaluating.add(id(cell))
                    try:
                        with RecursionDepth(TREE_RECURSION_DEPTH):
                            outcome = self._execute(node, cursor)
                    finally:
                        self._evaluating.discard(id(cell))
                    status = outcome.status
                    if status is None:
                        partial = outcome.value.partial
                        status = (
                            XlmStatus.PartialEvaluation if partial else XlmStatus.FullEvaluation
                        )
                    text = outcome.value.text or ''
                    if not self.while_stack and text != 'NEXT':
                        observed.append((cursor.sheet.lower(), cursor.row, cursor.col))
                        if len(observed) >= _WINDOW_WARMUP:
                            window = tuple(observed[-10:])
                            if window in anchors:
                                if self._steps - digest_step >= _DIGEST_STEPS:
                                    digest_step = self._steps
                                    if self.state_digest() == anchors[window]:
                                        break
                            else:
                                anchors[window] = self.state_digest()
                                digest_step = self._steps
                    if status is not XlmStatus.IGNORED:
                        self.write_value(cell, outcome.value)
                    if stack_record:
                        text = (frame.desc + ' ' + text).strip()
                    if self.indent_current_line:
                        previous_indent = self.indent_level
                        self.indent_current_line = False
                    yield from buffer
                    buffer.clear()
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
                    if caller is not None:
                        if outcome.halts:
                            self._halted = True
                        if caller.value is not None or self._halted:
                            return
                    elif self._halted:
                        self._halted = False
                        break
                    self.check_deadline()
                    if outcome.jump is not None:
                        cursor = outcome.jump
                        self.arrival = XlmArrival.JUMP
                    elif status in _FALL_THROUGH:
                        cursor = self.next_formula_cell(cursor)
                        self.arrival = XlmArrival.FALL
                    else:
                        break
                    node = None
                    stack_record = False
        except _Exhausted as exhausted:
            yield from buffer
            if caller is not None:
                raise
            yield self._error_step(cursor or anchor, str(exhausted))
        except Exception as error:
            yield from buffer
            yield self._error_step(cursor or anchor, F'{type(error).__name__}: {error}')
        finally:
            self._buffers.pop()
            self.branch_stack = branches

    def _subroutine(self, reference: XlmReference, spelled: str) -> XlmValue:
        """
        The value a macro call inside an expression computes: the subroutine runs from where
        the call names it until it returns, its steps join the trace ahead of the step that
        called it, and the value it returns is the value of the call. Calls and loops the
        subroutine leaves open end with it. A subroutine that never returns — it halts, runs out
        of formulas, or nests too deeply — leaves the call unfinished.
        """
        anchor = self.anchor(reference)
        if anchor is None or self._depth >= _SUBROUTINE_DEPTH_LIMIT:
            return XlmValue(value=spelled, partial=True)
        caller = XlmReturnSlot()
        indent = self.indent_level
        calls = len(self.call_stack)
        loops = len(self.while_stack)
        steps: list[XlmStep] = []
        self.call_stack.append(caller)
        self._depth += 1
        try:
            steps.extend(self._run_entry(anchor, caller))
        finally:
            self._depth -= 1
            self.indent_level = indent
            del self.call_stack[calls:]
            del self.while_stack[loops:]
            if self._buffers:
                self._buffers[-1].extend(steps)
        if caller.value is None:
            return XlmValue(value=spelled, partial=True)
        return _held(caller.value)

    def _expired(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def check_deadline(self) -> None:
        """
        Raise the exhaustion of the run's deadline, for the walks a command takes inside one
        step, so that a walk over a rectangle the workbook barely fills still answers to the
        deadline of the run.
        """
        if self._expired():
            raise _Exhausted('the run exceeded its timeout')

    def _execute(self, node, cursor: XlmCursor) -> XlmOutcome:
        """
        The outcome of the step that runs a node as the whole formula of its cell. A call runs
        as a command, and any other expression is evaluated. A step that starts inside the body
        of a loop the engine skips is ignored like every command there, even when the expression
        holds the loop end that stops the skipping.
        """
        if isinstance(node, XlFunctionCall):
            return self.call(node, cursor)
        skipping = self.ignore_processing
        value = evaluate_expression(self, node, cursor)
        if skipping:
            return XlmOutcome(value=value, status=XlmStatus.IGNORED)
        return XlmOutcome(value=value)

    def _stored(self, cell: XlmCell, reference: XlmReference) -> XlmValue:
        if cell.value is None:
            return _blank(reference)
        return XlmValue(
            value=cell.value,
            date=cell.kind is CellKind.DATE,
            reference=reference,
        )

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
        every argument evaluated for the side effects it may have had and a missing argument
        spelling the empty slot the call wrote.
        """
        arguments = [
            evaluate_expression(self, argument, cursor).text or ''
            for argument in call.arguments
        ]
        text = F'={name}({",".join(arguments)})'
        return XlmOutcome(value=XlmValue(value=text, partial=True))

    def _call_cell(
        self,
        reference: XlmReference,
        cursor: XlmCursor,
        call: XlFunctionCall,
        nested: bool,
    ) -> XlmOutcome:
        spelled = synthesize_formula(call)
        if reference.sheet is None:
            reference = XlmReference(cursor.sheet, reference.row, reference.col)
        if self.view.macrosheet(reference.sheet) is None:
            return XlmOutcome(value=XlmValue(value=0, text=spelled), status=XlmStatus.Error)
        if nested:
            return XlmOutcome(value=self._subroutine(reference, spelled))
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

    def _spelled_reference(self, text: str, cursor: XlmCursor) -> XlmReference | None:
        return self._local(self._reference_of(parse_formula(text), cursor), cursor)

    def _local(self, reference: XlmReference | None, cursor: XlmCursor) -> XlmReference | None:
        if reference is None:
            return None
        if reference.sheet is not None:
            return reference
        return XlmReference(cursor.sheet, reference.row, reference.col)

    def _find_cell(self, sheet: str, row: int, col: int) -> XlmCell | None:
        cell = self._index.find(sheet, row, col)
        if cell is not None:
            return cell
        worksheet = self.view.worksheet(sheet)
        if worksheet is not None:
            return worksheet.get((row, col))
        return None
