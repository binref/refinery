"""
Where Windows PowerShell 5.1 sends an error raised at a point of a script, read off the tree the way
the engine runs it.

5.1 runs every statement list — a script, a function, the body of an `if`, a loop, a `switch`
clause, a `try`, a `catch`, a `finally` or a `trap`, the statements of a `$( )` — inside one catch
per statement, and decides there what becomes of an error the statement raised. That decision reads
three things: whether the list declares a `trap`, whether the engine is passing errors outward
(`PropagateExceptionsToEnclosingStatementBlock`, set over a `try` body, its `catch` bodies, a list
that declares a `trap` and everything such a list runs, and put back before a `finally` body), and
what kind of error it is. `Ps1Level` is one such list and what it decides from; `Ps1Dispatch`
applies the decision from the list a point stands in outward until something takes the error, and
answers with every place it may end up, as a `Ps1Fate`: where the run carries on, which handlers
run, and whether the error ends the run or is handed to whatever called the body.

The rules, each named after the 5.1 code that holds it:

- `ExceptionHandlingOps.CheckActionPreference`: where no `trap` is declared, an error is handed
  outward while the engine passes errors outward or once it is marked; otherwise the preference
  decides: `SilentlyContinue` carries on after the statement, `Stop` marks the error and hands it
  outward, and anything else reports it and carries on — except the error of a `throw`, which is
  handed outward.
- `ExceptionHandlingOps.ProcessTraps`: where a `trap` is declared, the one that takes the error
  runs; `continue` carries on after the statement, `break` marks the error and hands it outward,
  and a body that runs off its end leaves it to the preference. An error no `trap` takes is marked
  and handed outward.
- `Compiler.VisitTryStatement`: an error leaving a `try` body is offered to its `catch` clauses;
  one no clause takes, and one leaving a `catch` body or a `finally` body, is disposed of by the
  list the `try` statement stands in. An error leaving a `finally` body takes the place of whatever
  was in flight there: an error, or a `return`, `exit`, `break` or `continue`.
- `Compiler.CompileTrap`: a `trap` body runs with no `trap` in force, so an error raised in it
  leaves the list that declared the `trap` — or, where the `trap` ran because no `catch` clause of
  a `try` statement of that list took an error, leaves that `try` statement, and the list disposes
  of it.

Everything here is read off the tree. What a handler means — which errors a filter takes, which
member of a `trap` set is selected, how a `trap` body ends — is
`refinery.lib.scripts.ps1.analysis.handlers`, which the control-flow builder reads as well; the
graphs it draws carry the same routes without the state an error carries along them. A filter
naming a type is read as one that may or may not match.

Every answer is kept, per statement list and per statement, for as long as the tree is the one it
was read from, so that asking of every point of a script costs the size of the script.
"""
from __future__ import annotations

import enum

from functools import partial
from typing import AbstractSet, Callable, Iterable, NamedTuple, Protocol, Sequence

from refinery.lib.scripts import Block, Node, tree_root
from refinery.lib.scripts.ps1.analysis.cfg import trap_disposition
from refinery.lib.scripts.ps1.analysis.handlers import (
    Ps1TrapDisposition,
    Ps1TrapSelection,
    declared_traps,
    handler_acts,
    settled,
    swallows_every_error,
)
from refinery.lib.scripts.ps1.analysis.world import runs_code_it_cannot_read
from refinery.lib.scripts.ps1.ast import STATEMENT_LIST_EXPRESSIONS
from refinery.lib.scripts.ps1.model import (
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1Code,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1ExitStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1InvokeMember,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1SwitchStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1WhileLoop,
)


class Ps1ErrorKind(enum.Flag):
    """
    The kinds of error 5.1 disposes of differently.
    """
    NONE = 0
    #: A statement-terminating error, such as a failed cast: reported where nothing is in force, and
    #: the run carries on with the next statement.
    STATEMENT = enum.auto()
    #: The error of a `throw`: where nothing is in force it ends the run, unless the preference is
    #: `SilentlyContinue`.
    THROWN = enum.auto()
    #: An error no list reports: one a command told to stop raises, and one `Stop`, a `trap` that
    #: re-raises or a `trap` set that declines has handed on. Only a `catch` or a `trap` takes it.
    MARKED = enum.auto()
    #: A statement-terminating error a body the point runs would report: it reaches the list the
    #: point stands in only while the engine passes errors outward there, which it does through
    #: every body a `try`, a `catch` body or a list that declares a `trap` runs, and is a
    #: statement-terminating error of that list once it does. Elsewhere the body reported it and
    #: the point completed.
    CALLED = enum.auto()


#: Every kind of error, one at a time.
ERROR_KINDS = (Ps1ErrorKind.STATEMENT, Ps1ErrorKind.THROWN, Ps1ErrorKind.MARKED, Ps1ErrorKind.CALLED)

#: What a call that may run a body of the script may hand back: whatever that body may raise.
HANDED_BACK = Ps1ErrorKind.CALLED | Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED

#: Every kind of error at once: what a point whose operands cannot be named may raise.
EVERY_KIND = Ps1ErrorKind.STATEMENT | HANDED_BACK


class Ps1Preference(enum.Enum):
    """
    The values of `$ErrorActionPreference` that dispose of an error differently: `CONTINUE` stands
    for every value that reports it.
    """
    CONTINUE = enum.auto()
    SILENT = enum.auto()
    STOP = enum.auto()


def preferences_of(stops: bool, silenced: bool) -> frozenset[Ps1Preference]:
    """
    The values `$ErrorActionPreference` may hold where a script may set `Stop` and where it may set
    a value that silences an error. A script starts out reporting.
    """
    found = {Ps1Preference.CONTINUE}
    if stops:
        found.add(Ps1Preference.STOP)
    if silenced:
        found.add(Ps1Preference.SILENT)
    return frozenset(found)


class Ps1LevelKind(enum.Enum):
    """
    What runs a statement list, which decides where an error leaving it goes and whether the engine
    passes errors outward while it runs.
    """
    #: The statements of a script, a script block or one of its named blocks.
    BODY = enum.auto()
    #: The body of an `if`, a loop or a `switch` clause, or the statements of a `$( )` or `@( )`.
    NESTED = enum.auto()
    TRY = enum.auto()
    CATCH = enum.auto()
    FINALLY = enum.auto()
    TRAP = enum.auto()


class Ps1Level(NamedTuple):
    """
    One statement list as 5.1 runs it, *owner* being the node that holds it. *parent* is the list
    around it and *holder* the statement of that list it belongs to: the `try` for its `try`,
    `catch` and `finally` bodies, the `trap` for a `trap` body, the `if`, loop, `switch` or
    statement holding a `$( )` for a nested list. A body has neither. *traps* is the set of `trap`
    statements the list declares. *passes_on* is whether the engine passes errors outward while
    the statements run, or `None` where that is whatever the caller of the body set: a `try` around
    a call passes them outward through every body the call runs. *called* is whether the list
    belongs to a script block, which a caller runs, rather than to the script, and *preferences*
    holds the values the error preference may hold while the statements run. *guarding* reads the
    values the outward flag may hold where the body holding the list was called.
    """
    kind: Ps1LevelKind
    owner: Node
    parent: Ps1Level | None
    holder: Node | None
    traps: Ps1TrapSelection | None
    passes_on: bool | None
    called: bool
    preferences: frozenset[Ps1Preference]
    guarding: Callable[[], tuple[bool, ...]] = lambda: (False,)

    def guards(self) -> tuple[bool, ...]:
        """
        The values the flag that passes errors outward may hold where the body this list belongs
        to was called: unset for the script; for a script block, set as well only where some call
        that may run it stands where the flag is set.
        """
        return self.guarding()


class Ps1Fate(NamedTuple):
    """
    Every place an error may end up.

    - *carried*: the statements the run may carry on after, each a member of the list that took the
      error, whether it reported it, silenced it or ran a `trap` that carried on;
    - *caught*: the `catch` clauses that may take it;
    - *swallowed*: the `try` statements whose `catch` clause takes it with an empty body, after
      which the run carries on after the `try`;
    - *trapped*: the `trap` statements that may run on it;
    - *acts*: whether one of those clauses or `trap` statements does something a run can see;
    - *offered_to_traps*: whether a `trap` set may be offered it, whether it takes it or not;
    - *ends_run*: whether it may leave the script, which ends the run;
    - *to_caller*: the kinds it may leave a script block with, handed to whatever called it;
    - *replaces*: the `try` statements whose `finally` body it may leave, taking the place of what
      was in flight there;
    - *outermost*: the depth in the tree of the outermost statement the run may carry on after, or
      whose `catch` or acting `trap` may take it.
    """
    carried: frozenset[Node] = frozenset()
    caught: frozenset[Ps1CatchClause] = frozenset()
    swallowed: frozenset[Ps1TryCatchFinally] = frozenset()
    trapped: frozenset[Ps1TrapStatement] = frozenset()
    acts: bool = False
    offered_to_traps: bool = False
    ends_run: bool = False
    to_caller: Ps1ErrorKind = Ps1ErrorKind.NONE
    replaces: frozenset[Ps1TryCatchFinally] = frozenset()
    outermost: float = float('inf')

    @property
    def leaves(self) -> bool:
        """
        Whether the error may get past every handler of the body it was raised in.
        """
        return self.ends_run or bool(self.to_caller)

    def joined(self, other: Ps1Fate) -> Ps1Fate:
        """
        The fate of an error that may end up as this one or as *other* does.
        """
        if other is _NOWHERE:
            return self
        if self is _NOWHERE:
            return other
        return Ps1Fate(
            self.carried | other.carried,
            self.caught | other.caught,
            self.swallowed | other.swallowed,
            _union(self.trapped, other.trapped),
            self.acts or other.acts,
            self.offered_to_traps or other.offered_to_traps,
            self.ends_run or other.ends_run,
            self.to_caller | other.to_caller,
            self.replaces | other.replaces,
            min(self.outermost, other.outermost),
        )

    def renamed(self, statement: Node, to: Node, depth: int) -> Ps1Fate:
        """
        This fate with the run carrying on after *to*, at *depth* in the tree, where it carries on
        after *statement*.
        """
        if statement not in self.carried:
            return self
        return self._replace(
            carried=self.carried - {statement} | {to},
            outermost=min(self.outermost, depth),
        )


_NOWHERE = Ps1Fate()


def _union(first: frozenset, second: frozenset) -> frozenset:
    """
    The union of two sets, the first itself where the second adds nothing, so that a fate joined
    with one that adds no `trap` keeps the very set it had and a reader may key on it.
    """
    if not second or second is first:
        return first
    if not first:
        return second
    return first | second


class _Jump(enum.Flag):
    """
    The jumps that may carry control out of a node: `Ps1Dispatch._leaving_jumps`.
    """
    NONE = 0
    RETURN = enum.auto()
    EXIT = enum.auto()
    #: An unlabelled `break` or `continue`, which the innermost loop or `switch` takes.
    LOOP = enum.auto()
    #: A `break` or `continue` naming a label.
    LABELLED = enum.auto()
    #: Something that may run a body of the script or code it does not spell.
    RUNS_CODE = enum.auto()


_LOOPS = (
    Ps1DoLoop,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1SwitchStatement,
    Ps1WhileLoop,
)


def _list_owner(node: Node) -> bool:
    return isinstance(node, (Block, Ps1Code, *STATEMENT_LIST_EXPRESSIONS))


def member_of(node: Node) -> Node | None:
    """
    The statement of a statement list that holds *node*, *node* itself where it is one.
    """
    cursor: Node | None = node
    while cursor is not None:
        parent = cursor.parent
        if parent is None:
            return None
        if _list_owner(parent) and not isinstance(cursor, Block):
            return cursor
        cursor = parent
    return None


def _last_statement(owner: Node) -> Node | None:
    """
    The last statement of the list *owner* holds that runs, a `trap` being a declaration.
    """
    for statement in reversed(getattr(owner, 'body', ())):
        if not isinstance(statement, Ps1TrapStatement):
            return statement
    return None


def _kind(owner: Node) -> tuple[Ps1LevelKind, Node | None]:
    if isinstance(owner, Ps1Code):
        return Ps1LevelKind.BODY, None
    parent = owner.parent
    if isinstance(owner, Block):
        if parent is None or isinstance(parent, Ps1Code):
            return Ps1LevelKind.BODY, None
        if isinstance(parent, Ps1TryCatchFinally):
            if owner is parent.finally_block:
                return Ps1LevelKind.FINALLY, parent
            return Ps1LevelKind.TRY, parent
        if isinstance(parent, Ps1CatchClause):
            return Ps1LevelKind.CATCH, parent.parent
        if isinstance(parent, Ps1TrapStatement):
            return Ps1LevelKind.TRAP, parent
    holder = member_of(owner)
    if holder is None:
        return Ps1LevelKind.BODY, None
    return Ps1LevelKind.NESTED, holder


def _is_script(owner: Node) -> bool:
    return isinstance(owner, Ps1Script) or isinstance(owner.parent, Ps1Script)


def _runs_code(node: Node) -> bool:
    """
    Whether evaluating *node* may run a body of the script or code it does not spell, which may
    itself jump out of the body it runs in.
    """
    return isinstance(node, (Ps1CommandInvocation, Ps1InvokeMember, Ps1ScriptBlock))


class _Tree:
    """
    What every reading of one tree shares: the depth of each node, the `trap` set each list
    declares, how each `trap` body ends, the preferences the error preference may hold, and the
    values the outward flag may hold where a body was called, which *guards* reads for the body
    holding a list.
    """

    def __init__(
        self,
        preferences: frozenset[Ps1Preference],
        called_preferences: frozenset[Ps1Preference],
        guards: Callable[[Node], tuple[bool, ...]],
        shared: _Tree | None = None,
    ):
        self.preferences = preferences
        self.called = called_preferences
        self.guards = guards
        self._depths: dict[int, int] = {} if shared is None else shared._depths
        self._selections: dict[int, Ps1TrapSelection | None] = {} if shared is None else shared._selections
        self._dispositions: dict[int, Ps1TrapDisposition] = {} if shared is None else shared._dispositions

    def reading(self, preference: Ps1Preference, called_preference: Ps1Preference) -> _Tree:
        """
        This tree under one value of the error preference in the script and one in a called body,
        sharing what no preference changes: the depths, the `trap` sets and how each body ends.
        """
        return _Tree(frozenset((preference,)), frozenset((called_preference,)), self.guards, self)

    def depth_of(self, node: Node) -> int:
        depths = self._depths
        found = depths.get(id(node))
        if found is None:
            climbed: list[Node] = []
            cursor: Node | None = node
            while cursor is not None and (found := depths.get(id(cursor))) is None:
                climbed.append(cursor)
                cursor = cursor.parent
            depth = -1 if found is None else found
            for step in reversed(climbed):
                depth += 1
                depths[id(step)] = depth
            found = depths[id(node)]
        return found

    def traps_of(self, owner: Node) -> Ps1TrapSelection | None:
        key = id(owner)
        if key in self._selections:
            return self._selections[key]
        traps = declared_traps(getattr(owner, 'body', ()))
        found = self._selections[key] = Ps1TrapSelection(traps) if traps else None
        return found

    def disposition(self, trap: Ps1TrapStatement) -> Ps1TrapDisposition:
        return trap_disposition(trap, self._dispositions)


def _unguarded() -> tuple[bool, ...]:
    return (False,)


class Ps1CallSites(Protocol):
    """
    The calls that may run each body of a script, which decide whether a caller may run it with the
    outward flag set.
    """

    def bodies(self) -> Iterable[Node]:
        """
        Every script block of the script.
        """
        ...

    def sites_running(self, body: Node) -> Sequence[Node] | None:
        """
        The calls naming *body* that may run it, or `None` where its callers cannot all be named.
        """
        ...

    def unattributed_sites(self) -> Sequence[Node]:
        """
        The calls that run code nobody can read, each of which may run any function body.
        """
        ...


class _Levels:
    """
    The statement lists of one tree as `Ps1Level` values. Where *moved* is a block and *around* a
    level, the lists are read as though the statements of *moved* stood in the list of *around*:
    the lists written inside *moved* are read anew against that, and every other list is the one
    *real* reads.
    """

    def __init__(
        self,
        tree: _Tree,
        moved: Block | None = None,
        around: Ps1Level | None = None,
        real: _Levels | None = None,
        replaced: tuple[Node, Ps1TrapSelection | None] | None = None,
    ):
        self._tree = tree
        self._moved = moved
        self._around = around
        self._real = real
        self._replaced = replaced
        self._levels: dict[int, Ps1Level] = {}

    def level_of(self, statement: Node) -> Ps1Level | None:
        owner = statement.parent
        if owner is None or not _list_owner(owner) or isinstance(statement, Block):
            return None
        return self.level(owner)

    def level(self, owner: Node) -> Ps1Level:
        level = self._levels.get(id(owner))
        if level is not None:
            return level
        if owner is self._moved and self._around is not None:
            level = self._around
        else:
            kind, holder = _kind(owner)
            parent = None
            if holder is not None:
                parent = self.level_of(holder)
                if parent is None:
                    kind, holder = Ps1LevelKind.BODY, None
            real = self._real
            replaced = self._replaced
            if real is not None and not self._owns(parent) and (replaced is None or replaced[0] is not owner):
                level = real.level(owner)
            else:
                level = self._build(owner, kind, holder, parent)
        self._levels[id(owner)] = level
        return level

    def _owns(self, level: Ps1Level | None) -> bool:
        return level is not None and (level is self._around or self._levels.get(id(level.owner)) is level)

    def _build(
        self,
        owner: Node,
        kind: Ps1LevelKind,
        holder: Node | None,
        parent: Ps1Level | None,
    ) -> Ps1Level:
        tree = self._tree
        replaced = self._replaced
        if replaced is not None and replaced[0] is owner:
            traps = replaced[1]
        else:
            traps = tree.traps_of(owner)
        called = parent.called if parent is not None else not _is_script(owner)
        passes_on: bool | None
        if traps is not None or kind in (Ps1LevelKind.TRY, Ps1LevelKind.CATCH, Ps1LevelKind.TRAP):
            passes_on = True
        elif parent is not None:
            passes_on = parent.passes_on
        else:
            passes_on = None if called else False
        if parent is not None:
            guarding = parent.guarding
        elif not called:
            guarding = _unguarded
        else:
            guarding = partial(tree.guards, owner)
        preferences = tree.called if called else tree.preferences
        return Ps1Level(kind, owner, parent, holder, traps, passes_on, called, preferences, guarding)


class _SetFate(NamedTuple):
    """
    What a `trap` set does with an error of one kind, apart from the statement it was raised in:
    where it may end up when the set does not carry on, and whether the set may carry on after the
    statement.
    """
    fate: Ps1Fate
    carries_on: bool


class Ps1Reading:
    """
    The rules of the module docstring applied over one reading of the lists, *levels*, with every
    answer kept for that reading.
    """

    def __init__(self, tree: _Tree, levels: _Levels):
        self.tree = tree
        self._tree = tree
        self.levels = levels
        self._leaving: dict[tuple[int, Ps1ErrorKind, bool], Ps1Fate] = {}
        self._disposed: dict[tuple[int, Ps1ErrorKind, bool], Ps1Fate] = {}
        self._sets: dict[tuple[int, bool], _SetFate] = {}
        self._out_of_traps: dict[tuple[int, Ps1ErrorKind, bool], Ps1Fate] = {}

    def placed(self, point: Node) -> tuple[Ps1Level, Node] | None:
        statement = member_of(point)
        if statement is None:
            return None
        level = self.levels.level_of(statement)
        if level is None:
            return None
        return level, statement

    def fate(self, point: Node, kinds: Ps1ErrorKind, guarded: bool | None = None) -> Ps1Fate | None:
        placed = self.placed(point)
        if placed is None:
            return None
        level, statement = placed
        fate = _NOWHERE
        for kind in ERROR_KINDS:
            if kind in kinds:
                if guarded is None:
                    fate = fate.joined(self.disposed(level, statement, kind))
                else:
                    fate = fate.joined(self.dispose(level, statement, kind, guarded))
        return fate

    def disposed(self, level: Ps1Level, statement: Node, kind: Ps1ErrorKind) -> Ps1Fate:
        fate = _NOWHERE
        for guarded in level.guards():
            fate = fate.joined(self.dispose(level, statement, kind, guarded))
        return fate

    def dispose(self, level: Ps1Level, statement: Node, kind: Ps1ErrorKind, guarded: bool) -> Ps1Fate:
        key = (id(statement), kind, guarded)
        fate = self._disposed.get(key)
        if fate is None:
            fate = self._disposed[key] = self.dispose_as(level, statement, kind, guarded)
        return fate

    def _carried(self, statement: Node) -> Ps1Fate:
        return Ps1Fate(carried=frozenset((statement,)), outermost=self._tree.depth_of(statement))

    def dispose_as(self, level: Ps1Level, statement: Node, kind: Ps1ErrorKind, guarded: bool) -> Ps1Fate:
        """
        Where an error of *kind* that *statement* raised may end up, were it a member of *level*,
        where the caller of the body passes errors outward exactly when *guarded*. Not kept, since
        a caller may ask it of a statement *level* does not hold.
        """
        traps = level.traps
        passes_on = guarded if level.passes_on is None else level.passes_on
        if kind is Ps1ErrorKind.CALLED:
            if traps is None and not passes_on:
                return _NOWHERE
            kind = Ps1ErrorKind.STATEMENT
        if traps is not None:
            taken = self._taken_by(level, traps, guarded)
            if taken.carries_on:
                return taken.fate.joined(self._carried(statement))
            return taken.fate
        if passes_on or kind is Ps1ErrorKind.MARKED:
            return self.leaving(level, kind, guarded)
        fate = _NOWHERE
        carries_on = False
        for preference in level.preferences:
            if preference is Ps1Preference.STOP:
                fate = fate.joined(self.leaving(level, Ps1ErrorKind.MARKED, guarded))
            elif preference is Ps1Preference.SILENT or kind is not Ps1ErrorKind.THROWN:
                carries_on = True
            else:
                fate = fate.joined(self.leaving(level, kind, guarded))
        if carries_on:
            fate = fate.joined(self._carried(statement))
        return fate

    def _taken_by(self, level: Ps1Level, traps: Ps1TrapSelection, guarded: bool) -> _SetFate:
        key = (id(level.owner), guarded)
        found = self._sets.get(key)
        if found is None:
            found = self._sets[key] = self._take(level, traps, guarded)
        return found

    def _take(self, level: Ps1Level, traps: Ps1TrapSelection, guarded: bool) -> _SetFate:
        tree = self._tree
        fate = Ps1Fate(offered_to_traps=True)
        stops = Ps1Preference.STOP in level.preferences
        carries_on = False
        reraises = not traps.takes_every_error()
        for trap in traps.selectable:
            acting = handler_acts(trap)
            depth = tree.depth_of(trap.parent) if acting and trap.parent is not None else float('inf')
            fate = fate.joined(Ps1Fate(trapped=frozenset((trap,)), acts=acting, outermost=depth))
            disposition = settled(tree.disposition(trap), stops)
            if Ps1TrapDisposition.RESUMES in disposition:
                carries_on = True
            if Ps1TrapDisposition.RETHROWS in disposition:
                reraises = True
        if reraises:
            fate = fate.joined(self.leaving(level, Ps1ErrorKind.MARKED, guarded))
        return _SetFate(fate, carries_on)

    def leaving(self, level: Ps1Level, kind: Ps1ErrorKind, guarded: bool) -> Ps1Fate:
        key = (id(level.owner), kind, guarded)
        fate = self._leaving.get(key)
        if fate is None:
            fate = self._leaving[key] = self._leave(level, kind, guarded)
        return fate

    def _leave(self, level: Ps1Level, kind: Ps1ErrorKind, guarded: bool) -> Ps1Fate:
        parent = level.parent
        holder = level.holder
        if parent is None or holder is None:
            if level.called:
                return Ps1Fate(to_caller=kind)
            return Ps1Fate(ends_run=True)
        if level.kind is Ps1LevelKind.TRAP:
            return self._out_of_a_trap(parent, kind, guarded)
        if level.kind is Ps1LevelKind.TRY:
            assert isinstance(holder, Ps1TryCatchFinally)
            return self._offered(parent, holder, kind, guarded)
        fate = self.dispose(parent, holder, kind, guarded)
        if level.kind is Ps1LevelKind.FINALLY:
            assert isinstance(holder, Ps1TryCatchFinally)
            fate = fate.joined(Ps1Fate(replaces=frozenset((holder,))))
        return fate

    def _out_of_a_trap(self, level: Ps1Level, kind: Ps1ErrorKind, guarded: bool) -> Ps1Fate:
        """
        Where an error of *kind* raised in the body of a `trap` that *level* declares may end up.
        It leaves *level*, except where the `trap` ran because no `catch` clause of a `try`
        statement of *level* took an error: 5.1 runs the `trap` from inside that `try`, so the error
        leaves the `try` statement, and *level* disposes of it as one the statement raised, which
        may run the `trap` again. Every `trap` of *level* shares the answer.
        """
        key = (id(level.owner), kind, guarded)
        fate = self._out_of_traps.get(key)
        if fate is None:
            fate = self.leaving(level, kind, guarded)
            for statement in getattr(level.owner, 'body', ()):
                if (
                    isinstance(statement, Ps1TryCatchFinally)
                    and statement.catch_clauses
                    and not swallows_every_error(statement)
                ):
                    fate = fate.joined(self.dispose(level, statement, kind, guarded))
            self._out_of_traps[key] = fate
        return fate

    def _offered(
        self,
        level: Ps1Level,
        statement: Ps1TryCatchFinally,
        kind: Ps1ErrorKind,
        guarded: bool,
    ) -> Ps1Fate:
        """
        Where an error of *kind* leaving the `try` body of *statement*, a member of *level*, may end
        up: in any of its `catch` clauses, or, where none is certain to take it, wherever *level*
        disposes of an error of the `try` statement itself.

        5.1 matches the exception an error wraps before the error itself, against every clause, so
        a clause naming `RuntimeException`, which every error is, may still lose a failed cast to a
        later clause naming `InvalidCastException`: no clause is passed over.
        """
        fate = _NOWHERE
        depth = self._tree.depth_of(statement)
        for clause in statement.catch_clauses:
            empty = clause.body is None or not clause.body.body
            fate = fate.joined(Ps1Fate(
                caught=frozenset((clause,)),
                swallowed=frozenset((statement,)) if empty else frozenset(),
                acts=handler_acts(clause),
                outermost=depth,
            ))
        if swallows_every_error(statement):
            return fate
        return fate.joined(self.dispose(level, statement, kind, guarded))


class Ps1Lift:
    """
    The body of one `catch` clause read as though its statements stood in place of the `try` the
    clause belongs to, with the run carrying on after the `try` wherever it would carry on after
    the last of them: the reading the `catch` lift asks whether an error raised in the body ends
    up where it does now.

    Two things change for such an error. What a statement of the body lets out is disposed of by
    the list around the `try` rather than handed out of the `catch` body, which passes every error
    outward; and the lists written inside the body run with errors passed outward only where the
    list around the `try` passes them. Where it passes them whatever called the body,
    `keeps_the_flag` holds, every list inside the body runs alike in both readings, and only the
    first change is left: `member_alike` weighs it at the cost of one disposal per statement.
    Otherwise `point_alike` reads a point through the lists read anew.
    """

    def __init__(
        self,
        real: Ps1Reading,
        tree: _Tree,
        catch: Ps1Level,
        around: Ps1Level,
        body: Block,
        statement: Ps1TryCatchFinally,
    ):
        self._real = real
        self._tree = tree
        self._catch = catch
        self._around = around
        self._body = body
        self._statement = statement
        self._last = _last_statement(body)
        self.keeps_the_flag = around.passes_on is True
        self._lifted: Ps1Reading | None = None

    def member_alike(self, member: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether an error of any of *kinds* that *member*, a statement of the body, raises or lets out
        of a list it holds ends up where it does now. Read only where `keeps_the_flag` holds.
        """
        if not self.keeps_the_flag:
            raise ValueError('the lists inside the body run otherwise once it stands in place')
        if member is self._last:
            return True
        real = self._real
        for kind in ERROR_KINDS:
            if kind not in kinds:
                continue
            for guarded in self._catch.guards():
                if real.dispose(self._around, self._statement, kind, guarded).carried:
                    return False
        return True

    def point_alike(self, point: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether an error of any of *kinds* raised at *point*, inside the body, ends up where it does
        now, under every value of the flag a caller of the body may have set.
        """
        lifted = self._lifted
        if lifted is None:
            levels = _Levels(self._tree, self._body, self._around, self._real.levels)
            lifted = self._lifted = Ps1Reading(self._tree, levels)
        depth = self._tree.depth_of(self._statement)
        for kind in ERROR_KINDS:
            if kind not in kinds:
                continue
            for guarded in self._catch.guards():
                before = self._real.fate(point, kind, guarded)
                after = lifted.fate(point, kind, guarded)
                if before is None or after is None:
                    return False
                if self._last is not None:
                    after = after.renamed(self._last, self._statement, depth)
                if before != after:
                    return False
        return True


class Ps1Dispatch:
    """
    The dispatch of one script's errors, read off its tree. *preferences* holds the values
    `$ErrorActionPreference` may hold in the script's own body, *called_preferences* those it may
    hold in a script block, which a call may hand a preference of its own.

    A script block is read as a body some caller may guard: an error its lists hand outward leaves
    it, and so may one its body would report, since a `try` around the call passes errors outward
    through every body the call runs. Which callers guard a body is read off the call sites *sites*
    names for it; without *sites*, every caller may. The script is read as run on its own, which
    reports what its body would report.
    """

    def __init__(
        self,
        preferences: AbstractSet[Ps1Preference],
        called_preferences: AbstractSet[Ps1Preference],
        sites: Ps1CallSites | None = None,
    ):
        self._sites = sites
        self._guarded: set[int] | None = None
        self._readings: list[Ps1Reading] | None = None
        self._tree = _Tree(
            frozenset(preferences) | {Ps1Preference.CONTINUE},
            frozenset(called_preferences) | {Ps1Preference.CONTINUE},
            self._body_guards,
        )
        self._evaluation = Ps1Reading(self._tree, _Levels(self._tree))
        self._tails: dict[int, frozenset[Node]] = {}
        self._jumping: dict[int, bool] = {}
        self._jumps: dict[int, _Jump] = {}

    def depth_of(self, node: Node) -> int:
        """
        How many ancestors *node* has in its tree.
        """
        return self._tree.depth_of(node)

    def level_of(self, statement: Node) -> Ps1Level | None:
        """
        The statement list *statement* is a member of, or `None` where it is a member of none.
        """
        return self._evaluation.levels.level_of(statement)

    def fate(self, point: Node, kinds: Ps1ErrorKind) -> Ps1Fate | None:
        """
        Where an error of any of *kinds* raised at *point* may end up, under every caller of the
        body, or `None` where *point* stands in no statement list this reads.
        """
        return self._evaluation.fate(point, kinds)

    def disposed(self, level: Ps1Level, statement: Node, kind: Ps1ErrorKind) -> Ps1Fate:
        """
        Where an error of *kind* that *statement*, a member of *level*, raised may end up, under
        every caller of the body.
        """
        return self._evaluation.disposed(level, statement, kind)

    def tail_of(self, statement: Node) -> frozenset[Node]:
        """
        The statements a run on which *statement* completes goes on after doing nothing else on
        the way, where every statement around it completes as well: *statement* itself, and where it
        is the last of its list, the statement that list belongs to as well, and so on outward,
        through lists that end where the statement holding them ends — the body of an `if`, a
        `try`, a `catch` or a `finally`. A `finally` body entered with an error or a jump in flight
        goes on with that instead, which is not a completion; see `jumps_through`. A `$( )` written
        as the test of an `if` ends where the test is made, not where the `if` ends.
        """
        found = self._tails.get(id(statement))
        if found is None:
            found = frozenset((statement,))
            level = self.level_of(statement)
            if (
                level is not None
                and level.holder is not None
                and _last_statement(level.owner) is statement
                and (
                    level.kind in (Ps1LevelKind.TRY, Ps1LevelKind.CATCH, Ps1LevelKind.FINALLY)
                    or (
                        isinstance(level.holder, Ps1IfStatement)
                        and isinstance(level.owner, Block)
                        and level.owner.parent is level.holder
                    )
                )
            ):
                found = found | self.tail_of(level.holder)
            self._tails[id(statement)] = found
        return found

    def jumps_through(self, statement: Ps1TryCatchFinally) -> bool:
        """
        Whether the `finally` body of *statement* may be entered with a jump in flight: a `return`
        or an `exit` in the `try` body or one of its `catch` bodies, a `break` or `continue` there
        that leaves it, or a call there that may run a body able to jump out of itself — which some
        body of the script is where it writes an `exit` anywhere, or a `break` or `continue` that
        leaves a script block, or runs code it does not spell. 5.1 carries the jump through the
        `finally` body, and an error leaving that body takes its place.
        """
        regions: list[Node] = [clause.body for clause in statement.catch_clauses if clause.body is not None]
        if statement.try_block is not None:
            regions.append(statement.try_block)
        return any(self.may_jump_out_of(region) for region in regions)

    def may_jump_out_of(self, node: Node) -> bool:
        """
        Whether a jump may carry control out of *node* to somewhere other than what follows it: a
        `return` or an `exit`, a `break` or `continue` nothing in *node* takes, or a call that may run
        a body able to jump out of itself.
        """
        leaving = self._leaving_jumps(node)
        if leaving & ~_Jump.RUNS_CODE:
            return True
        return _Jump.RUNS_CODE in leaving and self._a_body_jumps_out(node)

    def _leaving_jumps(self, node: Node) -> _Jump:
        """
        The jumps that may carry control out of *node*, read bottom up and kept for every node: what
        its children let out, less what a loop or `switch` takes, what a `trap` body turns into a
        resumption or a re-raise, and the `return` of a script block; `RUNS_CODE` where something in
        it may run a body that jumps on its own. A labelled `break` or `continue` is not matched
        against the constructs it passes, and a script block lets out a `break` or `continue`
        nothing in it takes, which 5.1 hands to the code that ran the block.
        """
        memo = self._jumps
        stack: list[tuple[Node, bool]] = [(node, False)]
        while stack:
            current, expanded = stack.pop()
            if id(current) in memo:
                continue
            children = list(current.children())
            if not expanded:
                stack.append((current, True))
                stack.extend((child, False) for child in children if id(child) not in memo)
                continue
            leaving = _Jump.NONE
            for child in children:
                leaving |= memo[id(child)]
            if isinstance(current, Ps1ExitStatement):
                leaving |= _Jump.EXIT
            elif isinstance(current, Ps1ReturnStatement):
                leaving |= _Jump.RETURN
            elif isinstance(current, (Ps1BreakStatement, Ps1ContinueStatement)):
                leaving |= _Jump.LABELLED if current.label is not None else _Jump.LOOP
            elif isinstance(current, _LOOPS):
                leaving &= ~_Jump.LOOP
            elif isinstance(current, Ps1TrapStatement):
                leaving &= ~(_Jump.LOOP | _Jump.LABELLED)
            if isinstance(current, Ps1ScriptBlock):
                leaving &= ~_Jump.RETURN
            if _runs_code(current):
                leaving |= _Jump.RUNS_CODE
            memo[id(current)] = leaving
        return memo[id(node)]

    def _a_body_jumps_out(self, node: Node) -> bool:
        """
        Whether some body of the tree *node* stands in may jump out of itself into the code that
        ran it: a script block lets out an `exit`, or a `break` or `continue` nothing in it takes,
        or the tree runs code it does not spell.
        """
        root = tree_root(node)
        found = self._jumping.get(id(root))
        if found is None:
            escaping = _Jump.EXIT | _Jump.LOOP | _Jump.LABELLED
            found = self._jumping[id(root)] = any(
                runs_code_it_cannot_read(inner)
                or isinstance(inner, Ps1ScriptBlock) and bool(self._leaving_jumps(inner) & escaping)
                for inner in root.walk()
            )
        return found

    @property
    def evaluation(self) -> Ps1Reading:
        """
        The reading of the tree as it stands, under every value the error preference may hold.
        """
        return self._evaluation

    def _body_guards(self, owner: Node) -> tuple[bool, ...]:
        """
        The values the outward flag may hold where the body holding the list *owner* was called.
        Without call sites to read, every body may be called with the flag set.
        """
        if self._sites is None:
            return (False, True)
        block = owner if isinstance(owner, Ps1ScriptBlock) else owner.parent
        guarded = self._guarded
        if guarded is None:
            guarded = self._guarded = self._guarded_bodies(self._sites)
        return (False, True) if block is None or id(block) in guarded else (False,)

    def _guarded_bodies(self, sites: Ps1CallSites) -> set[int]:
        """
        The bodies some call site may run with the outward flag set: one called from a site whose
        list passes errors outward, from a site *sites* cannot name, or from a site whose list
        leaves the flag as the caller of its own body set it, where that body is one of these. A
        call *sites* cannot attribute is a site of every function body. One table for the tree, read
        breadth-first rather than by recursion over the call chain.
        """
        levels = self._evaluation.levels
        direct: set[int] = set()
        inherits: dict[int, list[int]] = {}
        every_function = -1

        def read(key: int, callers: Sequence[Node]) -> None:
            for site in callers:
                statement = member_of(site)
                level = None if statement is None else levels.level_of(statement)
                if level is None or level.passes_on is True:
                    direct.add(key)
                    return
                if level.passes_on is None:
                    root = level
                    while root.parent is not None:
                        root = root.parent
                    owner = root.owner
                    caller = owner if isinstance(owner, Ps1ScriptBlock) else owner.parent
                    inherits.setdefault(id(caller), []).append(key)

        functions: list[int] = []
        for body in sites.bodies():
            if isinstance(body.parent, Ps1FunctionDefinition):
                functions.append(id(body))
            named = sites.sites_running(body)
            if named is None:
                direct.add(id(body))
                continue
            read(id(body), named)
        read(every_function, sites.unattributed_sites())
        guarded: set[int] = set()
        stack = list(direct)
        while stack:
            key = stack.pop()
            if key in guarded:
                continue
            guarded.add(key)
            if key == every_function:
                stack.extend(functions)
                continue
            stack.extend(inherits.get(key, ()))
        guarded.discard(every_function)
        return guarded

    def level(self, owner: Node) -> Ps1Level:
        """
        The statement list *owner* holds.
        """
        return self._evaluation.levels.level(owner)

    def without(self, reading: Ps1Reading, owner: Node, removed: AbstractSet[int]) -> Ps1Reading:
        """
        *reading* as though the `trap` statements of the list *owner* holds whose identities
        *removed* names were not written.
        """
        tree = reading.tree
        traps = tree.traps_of(owner)
        kept = [] if traps is None else [trap for trap in traps.members if id(trap) not in removed]
        selection = Ps1TrapSelection(kept) if kept else None
        levels = _Levels(tree, real=reading.levels, replaced=(owner, selection))
        return Ps1Reading(tree, levels)

    def readings(self) -> list[Ps1Reading]:
        """
        One reading of the tree per pair of values the error preference may hold in the script and
        in a called body, each under that pair alone. Comparing two readings joined over the values
        would compare an error one value takes with one another value leaves.
        """
        found = self._readings
        if found is None:
            tree = self._tree
            if len(tree.preferences) == 1 and len(tree.called) == 1:
                found = [self._evaluation]
            else:
                found = []
                for preference in sorted(tree.preferences, key=lambda p: p.name):
                    for called in sorted(tree.called, key=lambda p: p.name):
                        single = tree.reading(preference, called)
                        found.append(Ps1Reading(single, _Levels(single)))
            self._readings = found
        return found

    def lifted(self, clause: Ps1CatchClause) -> Ps1Lift | None:
        """
        The body of *clause* read as standing in place of its `try`; `None` where it cannot stand
        there: the clause has no body, its `try` stands in no statement list this reads, or the body
        declares a `trap`, which would then guard the list around the `try`.
        """
        body = clause.body
        statement = clause.parent
        if body is None or not isinstance(statement, Ps1TryCatchFinally):
            return None
        around = self.level_of(statement)
        catch = self._evaluation.levels.level(body)
        if around is None or catch.traps is not None:
            return None
        return Ps1Lift(self._evaluation, self._tree, catch, around, body, statement)
