"""
Windows PowerShell 5.1's handling of an error inside one script, as an executable model: which
handler an error raised at a point is offered to, what that handler does with it, and where the run
carries on. It is written from the 5.1 source (`System.Management.Automation` at commit `60b3b304`)
and from nothing in refinery, so that it judges the analysis rather than repeating it; the tests in
`test.lib.scripts.ps1.test_dispatch` hold it to what 5.1 writes.

A program is a tuple of statements of a small grammar, and `render` spells one as PowerShell. Every
failing point and every `if` test reads one cell of an input array, so one program stands for every
run its inputs choose between, and `vectors` lists them. The rules, each named after the 5.1 code
that holds it:

- `Compiler.CompileStatementListWithTraps`: every statement list catches per statement and carries
  on with the next statement once the error is disposed of. A list that declares a `trap` sets the
  flag that hands an error outward instead, resolves the trap types before its first statement, and
  pushes its traps; a list without traps inside a trapped list of the same body pushes no traps.
- `Compiler.VisitTryStatement`: the flag is set over the `try` body and its `catch` bodies and put
  back before the `finally` body; an error no clause takes goes to the error preference from inside
  the `catch` handler.
- `ExceptionHandlingOps.CheckActionPreference`, `ProcessTraps`, `FindMatchingHandler`: an error
  no trap is in force for is handed outward while the flag is set or once a `Stop` marked it;
  otherwise the traps or the preference dispose of it. A `throw` nothing traps ends the run.
- `Compiler.CompileTrap`: a trap body is a body of its own with no traps in force and no loop to
  leave, so `continue` and `break` in it resume or re-raise, and an error in it leaves the trap.

What a run shows is its trace: the marks it writes, each error it reports, and whether it ran to its
end or ended on an error. `visible` drops the reported errors, because a removal may drop an error
record — see `BEHAVIOUR_DIVERGENCES` in `test.lib.scripts.ps1.test_oracle`.
"""
from __future__ import annotations

import enum
import itertools
import random

from dataclasses import dataclass, field
from typing import Iterator, Union


class Preference(str, enum.Enum):
    """
    The values of `$ErrorActionPreference` the grammar sets.
    """
    CONTINUE = 'Continue'
    SILENTLY_CONTINUE = 'SilentlyContinue'
    STOP = 'Stop'


class Event(enum.Enum):
    """
    What a trace records besides the marks a run writes.
    """
    REPORTED = 'ERROR'
    ENDED = 'END'
    THREW = 'THROW'


@dataclass(frozen=True, eq=False)
class Mark:
    """
    `Write-Host` of a literal name, which is the only thing a run writes.
    """
    name: str


@dataclass(frozen=True, eq=False)
class Fail:
    """
    A cast of input cell `index`, which fails exactly when that cell is switched on.
    """
    index: int


@dataclass(frozen=True, eq=False)
class Throw:
    pass


@dataclass(frozen=True, eq=False)
class If:
    """
    A test of input cell `index`, true exactly when that cell is switched on.
    """
    index: int
    then: tuple[Statement, ...]
    otherwise: tuple[Statement, ...] = ()


@dataclass(frozen=True, eq=False)
class Loop:
    """
    A `foreach` over two items.
    """
    body: tuple[Statement, ...]


@dataclass(frozen=True, eq=False)
class Catch:
    type: str | None
    body: tuple[Statement, ...]


@dataclass(frozen=True, eq=False)
class Try:
    body: tuple[Statement, ...]
    catches: tuple[Catch, ...] = ()
    final: tuple[Statement, ...] | None = None


@dataclass(frozen=True, eq=False)
class Trap:
    type: str | None
    body: tuple[Statement, ...]


@dataclass(frozen=True, eq=False)
class Sub:
    """
    A subexpression whose value is discarded, `$null = $( )`.
    """
    body: tuple[Statement, ...]


@dataclass(frozen=True, eq=False)
class Continue:
    pass


@dataclass(frozen=True, eq=False)
class Break:
    pass


Statement = Union[Mark, Fail, Throw, If, Loop, Try, Trap, Sub, Continue, Break]
Trace = tuple[Union[str, Event], ...]

RUNTIME = 'System.Management.Automation.RuntimeException'

#: Every exception type a filter in the grammar may name, with its base class as .NET defines it.
BASES: dict[str, str | None] = {
    'System.Exception'                                    : None,
    'System.SystemException'                              : 'System.Exception',
    'System.Management.Automation.RuntimeException'       : 'System.SystemException',
    'System.InvalidCastException'                         : 'System.SystemException',
    'System.Management.Automation.PSInvalidCastException' : 'System.InvalidCastException',
    'System.FormatException'                              : 'System.SystemException',
    'System.IO.IOException'                               : 'System.SystemException',
}


def derives(kind: str, base: str) -> bool:
    """
    Whether exception type *kind* is *base* or derives from it.
    """
    cursor: str | None = kind
    while cursor is not None:
        if cursor == base:
            return True
        cursor = BASES.get(cursor)
    return False


class _Error(Exception):
    def __init__(self, kind: str, inner: _Error | None = None, thrown: bool = False):
        super().__init__(kind)
        self.kind = kind
        self.inner = inner
        self.thrown = thrown
        self.marked = False


class _Leave(Exception):
    pass


class _Resume(Exception):
    pass


@dataclass
class _Frame:
    traps: list[Trap]
    types: list[str | None]


@dataclass
class _Run:
    preference: Preference
    on: frozenset[int]
    propagating: bool = False
    events: list[str | Event] = field(default_factory=list)


def _resolve(name: str | None) -> str | None:
    if name is not None and name not in BASES:
        raise _Error(RUNTIME)
    return name


def _by_type(kind: str, types: list[str | None]) -> int:
    """
    `ExceptionHandlingOps.FindMatchingHandlerByType`: a filter naming *kind* itself, else one
    naming a type it derives from, else the first filter naming no type; `-1` where none matches.
    """
    for index, named in enumerate(types):
        if named == kind:
            return index
    for index, named in enumerate(types):
        if named is not None and derives(kind, named):
            return index
    for index, named in enumerate(types):
        if named is None:
            return index
    return -1


def _handler(error: _Error, types: list[str | None]) -> int:
    """
    `ExceptionHandlingOps.FindMatchingHandler`: the inner exception is matched first, and the
    outer one where that finds only a filter naming no type.
    """
    found = -1 if error.inner is None else _by_type(error.inner.kind, types)
    if found == -1 or types[found] is None:
        found = _by_type(error.kind, types)
    return found


def _as_runtime(error: _Error) -> _Error:
    if derives(error.kind, RUNTIME):
        return error
    return _Error(RUNTIME, error)


def _process_traps(frame: _Frame, run: _Run, error: _Error) -> Preference:
    found = _handler(error, frame.types)
    if found == -1:
        return Preference.STOP
    try:
        _run_block(frame.traps[found].body, [], run, 0)
    except _Resume:
        return Preference.SILENTLY_CONTINUE
    except _Leave:
        return Preference.STOP
    return run.preference


def _check_action_preference(frames: list[_Frame | None], run: _Run, error: _Error) -> None:
    error = _as_runtime(error)
    frame = frames[-1] if frames else None
    if frame is None and (run.propagating or error.marked):
        raise error
    preference = run.preference if frame is None else _process_traps(frame, run, error)
    if preference is Preference.SILENTLY_CONTINUE:
        return
    if preference is Preference.STOP:
        error.marked = True
        raise error
    if frame is None and error.thrown:
        raise error
    run.events.append(Event.REPORTED)


def _run_block(statements: tuple[Statement, ...], frames: list[_Frame | None], run: _Run, nest: int) -> None:
    traps = [statement for statement in statements if isinstance(statement, Trap)]
    body = [statement for statement in statements if not isinstance(statement, Trap)]
    if not body:
        return
    saved = run.propagating
    pushed = False
    try:
        if traps:
            run.propagating = True
            frames.append(_Frame(traps, [_resolve(trap.type) for trap in traps]))
            pushed = True
            nest += 1
        elif nest > 0:
            frames.append(None)
            pushed = True
        for statement in body:
            try:
                _execute(statement, frames, run, nest)
            except _Error as error:
                _check_action_preference(frames, run, error)
    finally:
        if traps:
            run.propagating = saved
        if pushed:
            frames.pop()


def _catch_taking(error: _Error, catches: tuple[Catch, ...]) -> Catch | None:
    found = _handler(error, [_resolve(clause.type) for clause in catches])
    return None if found == -1 else catches[found]


def _execute(statement: Statement, frames: list[_Frame | None], run: _Run, nest: int) -> None:
    if isinstance(statement, Mark):
        run.events.append(statement.name)
    elif isinstance(statement, Fail):
        if statement.index in run.on:
            raise _Error('System.Management.Automation.PSInvalidCastException', _Error('System.FormatException'))
    elif isinstance(statement, Throw):
        raise _Error(RUNTIME, _Error(RUNTIME), thrown=True)
    elif isinstance(statement, If):
        _run_block(statement.then if statement.index in run.on else statement.otherwise, frames, run, nest)
    elif isinstance(statement, Loop):
        for _ in range(2):
            try:
                _run_block(statement.body, frames, run, nest)
            except _Leave:
                break
            except _Resume:
                continue
    elif isinstance(statement, Sub):
        _run_block(statement.body, frames, run, nest)
    elif isinstance(statement, Try):
        saved = run.propagating
        run.propagating = True
        try:
            try:
                _run_block(statement.body, frames, run, nest)
            except _Error as error:
                if not statement.catches:
                    raise
                clause = _catch_taking(error, statement.catches)
                if clause is None:
                    _check_action_preference(frames, run, error)
                else:
                    _run_block(clause.body, frames, run, nest)
        finally:
            run.propagating = saved
            if statement.final is not None:
                _run_block(statement.final, frames, run, nest)
    elif isinstance(statement, Continue):
        raise _Resume
    elif isinstance(statement, Break):
        raise _Leave
    else:
        raise TypeError(statement)


def run(program: tuple[Statement, ...], preference: Preference, on: frozenset[int]) -> Trace:
    """
    The trace of *program* run under *preference* with the input cells in *on* switched on.
    """
    state = _Run(preference, on)
    try:
        _run_block(program, [], state, 0)
    except _Error:
        state.events.append(Event.THREW)
    except (_Leave, _Resume):
        state.events.append(Event.ENDED)
    else:
        state.events.append(Event.ENDED)
    return tuple(state.events)


def visible(trace: Trace) -> Trace:
    """
    The trace without the errors that were reported and stepped over.
    """
    return tuple(event for event in trace if event is not Event.REPORTED)


def statements(program: tuple[Statement, ...]) -> Iterator[Statement]:
    """
    Every statement of *program*, nested ones included, in source order.
    """
    for statement in program:
        yield statement
        if isinstance(statement, If):
            yield from statements(statement.then)
            yield from statements(statement.otherwise)
        elif isinstance(statement, (Loop, Sub, Trap)):
            yield from statements(statement.body)
        elif isinstance(statement, Try):
            yield from statements(statement.body)
            for clause in statement.catches:
                yield from statements(clause.body)
            if statement.final is not None:
                yield from statements(statement.final)


def cells(program: tuple[Statement, ...]) -> list[int]:
    """
    The input cells *program* reads, in source order.
    """
    return [s.index for s in statements(program) if isinstance(s, (Fail, If))]


def vectors(program: tuple[Statement, ...]) -> Iterator[frozenset[int]]:
    """
    Every choice of switched-on input cells for *program*.
    """
    read = cells(program)
    for bits in itertools.product((False, True), repeat=len(read)):
        yield frozenset(index for index, bit in zip(read, bits) if bit)


def without(program: tuple[Statement, ...], removed: Statement) -> tuple[Statement, ...]:
    """
    *program* with the statement *removed*, which is compared by identity, taken out.
    """
    def strip(body: tuple[Statement, ...]) -> tuple[Statement, ...]:
        return tuple(rebuilt(statement) for statement in body if statement is not removed)

    def rebuilt(statement: Statement) -> Statement:
        if isinstance(statement, If):
            return If(statement.index, strip(statement.then), strip(statement.otherwise))
        if isinstance(statement, Loop):
            return Loop(strip(statement.body))
        if isinstance(statement, Sub):
            return Sub(strip(statement.body))
        if isinstance(statement, Trap):
            return Trap(statement.type, strip(statement.body))
        if isinstance(statement, Try):
            return Try(
                strip(statement.body),
                tuple(Catch(clause.type, strip(clause.body)) for clause in statement.catches),
                None if statement.final is None else strip(statement.final),
            )
        return statement

    return strip(program)


def render(program: tuple[Statement, ...], preference: Preference, on: frozenset[int] | None = None) -> str:
    """
    PowerShell for *program*. Without *on*, every input cell is read from `$args`, which no analysis
    can know; with it, a first line writes the inputs into `$p` and every cell is read from there,
    a failing point's cell holding text that does not convert where it is switched on.
    """
    source = '$args' if on is None else '$p'

    def block(body: tuple[Statement, ...]) -> str:
        return F'{{ {"; ".join(spell(s) for s in body)} }}' if body else '{ }'

    def spell(statement: Statement) -> str:
        if isinstance(statement, Mark):
            return F"Write-Host '{statement.name}'"
        if isinstance(statement, Fail):
            return F'$null = [int]{source}[{statement.index}]'
        if isinstance(statement, Throw):
            return "throw 'x'"
        if isinstance(statement, If):
            text = F'if ({source}[{statement.index}]) {block(statement.then)}'
            return F'{text} else {block(statement.otherwise)}' if statement.otherwise else text
        if isinstance(statement, Loop):
            return F'foreach ($i in 1, 2) {block(statement.body)}'
        if isinstance(statement, Sub):
            return F'$null = $({"; ".join(spell(s) for s in statement.body)})'
        if isinstance(statement, Trap):
            head = 'trap' if statement.type is None else F'trap [{statement.type}]'
            return F'{head} {block(statement.body)}'
        if isinstance(statement, Try):
            text = F'try {block(statement.body)}'
            for clause in statement.catches:
                head = 'catch' if clause.type is None else F'catch [{clause.type}]'
                text = F'{text} {head} {block(clause.body)}'
            return text if statement.final is None else F'{text} finally {block(statement.final)}'
        if isinstance(statement, Continue):
            return 'continue'
        if isinstance(statement, Break):
            return 'break'
        raise TypeError(statement)

    lines = []
    if preference is not Preference.CONTINUE:
        lines.append(F"$ErrorActionPreference = '{preference.value}'")
    if on is not None:
        values = {s.index: s for s in statements(program) if isinstance(s, (Fail, If))}
        size = 1 + max(values, default=-1)
        array = []
        for index in range(size):
            kind = values.get(index)
            if isinstance(kind, Fail):
                array.append("'a'" if index in on else "'1'")
            elif isinstance(kind, If):
                array.append('$true' if index in on else '$false')
            else:
                array.append('$null')
        lines.append(F'$p = @({", ".join(array)})')
    lines.append('; '.join(spell(s) for s in program))
    return '\n'.join(lines)


def parses_on_51(program: tuple[Statement, ...]) -> bool:
    """
    Whether 5.1 accepts the `catch` clauses of *program*: no clause may name a type an earlier
    clause names or derives from, and a clause naming no type comes last.
    """
    for statement in statements(program):
        if not isinstance(statement, Try):
            continue
        seen: list[str] = []
        for number, clause in enumerate(statement.catches):
            if clause.type is None:
                if number != len(statement.catches) - 1:
                    return False
                continue
            if any(derives(clause.type, earlier) for earlier in seen):
                return False
            seen.append(clause.type)
    return True


class Generator:
    """
    Programs of the grammar drawn from a seed. Only `random.Random.random` is called, the one method
    whose sequence Python keeps the same for a seed across its versions, so a seed names the same
    programs everywhere the tests run.
    """

    CATCH_TYPES = (
        None,
        'System.Exception',
        'System.Management.Automation.RuntimeException',
        'System.InvalidCastException',
        'System.IO.IOException',
    )
    TRAP_TYPES = (
        None,
        None,
        'System.IO.IOException',
        'System.Exception',
    )
    PREFERENCES = (
        Preference.CONTINUE,
        Preference.CONTINUE,
        Preference.SILENTLY_CONTINUE,
        Preference.STOP,
    )

    def __init__(self, seed: int):
        self._random = random.Random(seed)

    def _below(self, count: int) -> int:
        return min(int(self._random.random() * count), count - 1)

    def _pick(self, items: tuple):
        return items[self._below(len(items))]

    def programs(self, count: int) -> Iterator[tuple[tuple[Statement, ...], Preference]]:
        """
        *count* programs, each with the preference it runs under. Every program reads at most six
        input cells, holds a failing point or a `throw`, and parses on 5.1.
        """
        made = 0
        while made < count:
            draft = _Draft(self)
            program = draft.block(3, 2 + self._below(3))
            if (
                draft.cells <= 6
                and any(isinstance(s, (Fail, Throw)) for s in statements(program))
                and parses_on_51(program)
            ):
                made += 1
                yield program, self._pick(self.PREFERENCES)


class _Draft:
    def __init__(self, generator: Generator):
        self.generator = generator
        self.cells = 0
        self.marks = 0
        self.fails = 0
        self.tests = 0

    def _cell(self) -> int:
        self.cells += 1
        return self.cells - 1

    def mark(self) -> Mark:
        self.marks += 1
        return Mark(F'm{self.marks}')

    def block(self, depth: int, size: int) -> tuple[Statement, ...]:
        return tuple(self.statement(depth) for _ in range(size))

    def trap_body(self) -> tuple[Statement, ...]:
        g = self.generator
        body: list[Statement] = []
        for _ in range(g._below(3)):
            roll = g._random.random()
            if roll < 0.4:
                body.append(self.mark())
            elif roll < 0.7 and self.fails < 3:
                self.fails += 1
                body.append(Fail(self._cell()))
            elif roll < 0.8:
                body.append(Throw())
        roll = g._random.random()
        if roll < 0.45:
            body.append(Continue())
        elif roll < 0.65:
            body.append(Break())
        return tuple(body)

    def statement(self, depth: int) -> Statement:
        g = self.generator
        roll = g._random.random()
        if depth <= 0 or roll < 0.25:
            return self.mark()
        if roll < 0.45 and self.fails < 3:
            self.fails += 1
            return Fail(self._cell())
        if roll < 0.5:
            return Throw()
        if roll < 0.6 and self.tests < 2:
            self.tests += 1
            index = self._cell()
            then = self.block(depth - 1, 1 + g._below(3))
            otherwise = self.block(depth - 1, 1 + g._below(3)) if g._random.random() < 0.4 else ()
            return If(index, then, otherwise)
        if roll < 0.68:
            return Loop(self.block(depth - 1, 1 + g._below(3)))
        if roll < 0.85:
            count = (0, 1, 1, 2)[g._below(4)]
            typed = [g._pick(Generator.CATCH_TYPES[1:]) for _ in range(count)]
            untyped = count and g._random.random() < 0.5
            types: list[str | None] = typed[:count - 1] + [None] if untyped else typed
            catches = tuple(Catch(kind, self.block(depth - 1, g._below(3))) for kind in types)
            final = self.block(depth - 1, g._below(2)) if not catches or g._random.random() < 0.3 else None
            return Try(self.block(depth - 1, 1 + g._below(3)), catches, final)
        if roll < 0.95:
            return Trap(g._pick(Generator.TRAP_TYPES), self.trap_body())
        return Sub(self.block(depth - 1, 1 + g._below(2)))


_RT = 'System.Management.Automation.RuntimeException'
_CAST = 'System.InvalidCastException'
_IO = 'System.IO.IOException'


def _places(raise_: Statement) -> dict[str, tuple[Statement, ...]]:
    rest = Mark('rest')
    after = Mark('after')
    return {
        'top'                       : (raise_, rest),
        'if'                        : (If(1, (raise_, rest)), after),
        'loop'                      : (Loop((raise_, rest)), after),
        'try body, finally'         : (Try((raise_, rest), (), (Mark('fin'),)), after),
        'catch body'                : (Try((Throw(),), (Catch(None, (raise_, rest)),)), after),
        'finally body'              : (Try((Mark('t'),), (), (raise_, rest)), after),
        'finally body, error'       : (Try((Try((Throw(),), (), (raise_, rest)),), (Catch(None, (Mark('c'),)),)), after),
        'trap body'                 : (Trap(None, (raise_, Mark('trest'), Continue())), Fail(2), after),
        'subexpression'             : (Sub((raise_, rest)), after),
        'if in a catch body'        : (Try((Throw(),), (Catch(None, (If(1, (raise_, rest)),)),)), after),
        'try in a try body'         : (Try((Try((raise_,), (), ()), rest), (), ()), after),
        'loop in a try body'        : (Try((Loop((raise_, rest)),), (Catch(None, (Mark('c'),)),)), after),
    }


def _filtered_places(raise_: Statement, filter: str | None) -> dict[str, tuple[Statement, ...]]:
    rest = Mark('rest')
    after = Mark('after')
    places: dict[str, tuple[Statement, ...]] = {
        'try body, catch': (Try((raise_, rest), (Catch(filter, (Mark('c'),)),)), after),
    }
    for ending, body in (
        ('continue', (Mark('t'), Continue())),
        ('break', (Mark('t'), Break())),
        ('runs off', (Mark('t'),)),
    ):
        places[F'trapped block, {ending}'] = (If(1, (Trap(filter, body), raise_, rest)), after)
        places[F'under a trapped block, {ending}'] = (Trap(filter, body), If(1, (raise_, rest)), after)
    return places


def _anchors() -> dict[str, tuple[tuple[Statement, ...], Preference, frozenset[int]]]:
    found = {}
    on = frozenset({0, 1, 2})
    for raised, raise_ in (('cast', Fail(0)), ('throw', Throw())):
        for preference in Preference:
            for place, program in _places(raise_).items():
                if place == 'trap body' and preference is Preference.SILENTLY_CONTINUE:
                    continue
                found[F'{place} / {raised} / {preference.value}'] = (program, preference, on)
            for filter in (None, _RT, _CAST, _IO):
                named = 'untyped' if filter is None else filter.rsplit('.', 1)[-1]
                for place, program in _filtered_places(raise_, filter).items():
                    found[F'{place} [{named}] / {raised} / {preference.value}'] = (program, preference, on)
    return found


#: The programs that hold the model to 5.1: every place a failing point or a `throw` can stand,
#: under every preference, each handler filter, and each way a `trap` body ends, with every input
#: cell switched on. Left out: an error inside a `trap` body under `SilentlyContinue`, where 5.1
#: ends the run without writing the error, which `test.lib.scripts.ps1.oracle.behaviour` cannot
#: read.
ANCHORS = _anchors()
