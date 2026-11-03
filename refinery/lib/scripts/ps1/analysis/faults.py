"""
Where a terminating error raised at a point in a PowerShell script goes.

Where an error raised at a point ends up — which handlers take it, where the run carries on, and
whether it ends the run or is handed to a caller — is answered by
`refinery.lib.scripts.ps1.analysis.dispatch`, and every question about a point here reads it there.
The control-flow graph of `refinery.lib.scripts.ps1.analysis.cfg` draws the same routes without the
state an error carries along them; it places the points, and it walks the regions one run executes
and another skips.

This module answers three questions. *Does an error raised here change which code runs* is a
property of a **position**. *Would deleting this statement change which handler runs* is a
property of a **statement**, and it additionally needs to know whether the statement can raise at
all — `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` asks that one, reading what a
point raises off `refinery.lib.scripts.ps1.analysis.raising`. *Does deleting this `trap` change
what runs* is asked of the evaluator itself: the tree is read once with the `trap` set and once
without it, for every point the set is offered, and the two readings have to agree on everything
but where the run carries on; where that differs, the stretch one run executes and the other skips
is read for anything a run can see.

A body boundary is where the position question stops. An error that leaves a function reaches
whatever guards the *call*, and no reading here holds both: `Ps1Fate.to_caller` reports that rather
than guessing, and a caller reads it as *unknown* wherever a caller might be guarding.
"""
from __future__ import annotations

import enum

from typing import AbstractSet, Callable, Iterator, NamedTuple, Protocol, Sequence

from refinery.lib.scripts import Node, tree_root, tree_version
from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    Projection,
    plain_successors,
)
from refinery.lib.scripts.analysis.components import Condensation
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1BodyCallers, Ps1CallGraph
from refinery.lib.scripts.ps1.analysis.cfg import (
    Ps1ControlFlowModel,
    Ps1ReportNode,
    Ps1TrapSet,
    build_control_flow_model,
    dispatch_for,
)
from refinery.lib.scripts.ps1.analysis.dispatch import (
    ERROR_KINDS,
    Ps1Dispatch,
    Ps1ErrorKind,
    Ps1Fate,
    Ps1Reading,
    member_of,
)
from refinery.lib.scripts.ps1.analysis.handlers import (
    Ps1TrapDisposition,
    handler_acts,
    names_every_error,
    settled,
)
from refinery.lib.scripts.ps1.analysis.session import (
    session_of,
    stops_on_error,
    writes_stop_to_the_default_table,
)
from refinery.lib.scripts.ps1.ast import (
    STATEMENT_LIST_EXPRESSIONS,
    bound_argument_value,
    fault_operand,
    is_soft_error_source,
    point_operands,
    raises_a_caught_terminating_error,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CatchClause,
    Ps1CommandInvocation,
    Ps1FunctionDefinition,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1ThrowStatement,
    Ps1TrapStatement,
)

#: The commands that arm strict mode, in the spelling `resolve_command_name` answers with. Two
#: rather than one, because two commands write the same engine slot: `Set-StrictMode -Version`
#: writes the scope it stands in and `Set-PSDebug -Strict` writes the global scope, and 5.1
#: documents the second as the first at version 1. Neither carries an alias in the collected
#: surface, and every other way of arming either arrives as a string these are matched inside.
_STRICT_MODE_COMMANDS = frozenset({
    'set-psdebug',
    'set-strictmode',
})


def _arms_strict_mode(node: Node) -> bool:
    """
    Whether *node* may turn a read of a variable that was never set into an error.

    A command is the spelling that matters, resolved the deny-list way through
    `refinery.lib.scripts.ps1.ast.resolve_command_name`, so that a module- or scope-qualified
    spelling of one arms strict mode as the bare word does. The argument is not read: a
    `Set-StrictMode -Off` and a `Set-PSDebug -Trace 1` are armings here like every other spelling,
    and what that costs is the recall of a script that names either command for another purpose.

    A string value need only *contain* a name, which is the asymmetry
    `refinery.lib.scripts.ps1.analysis.worldflow._names_own_path` makes and that
    `refinery.lib.scripts.ps1.analysis.session.a_stop_may_be_in_force` makes beside it.
    `Invoke-Expression 'Set-StrictMode -Version 1'` arms it as surely as writing the command does,
    and a script that spells either name anywhere is read as arming it — the direction that refuses
    a removal rather than granting one.
    """
    if (
        isinstance(node, Ps1CommandInvocation)
        and resolve_command_name(node) in _STRICT_MODE_COMMANDS
    ):
        return True
    written = string_value(node)
    if written is None:
        return False
    written = written.lower()
    return any(command in written for command in _STRICT_MODE_COMMANDS)


def _arms_strict_mode_v2(node: Node) -> bool:
    """
    Whether *node* may arm strict mode at version 2 or above, under which the object adapter's
    faked `Count` and `Length` on a scalar or `$null` become terminating errors rather than a
    value. This is narrower than `_arms_strict_mode`: `Set-PSDebug -Strict` is documented as
    `Set-StrictMode -Version 1`, where those fakes still read, so only `Set-StrictMode` can arm the
    version this asks about.

    The argument *is* read here, unlike in `_arms_strict_mode`, because version 1 and version 2 are
    the two cases this distinguishes. Only a `-Version` that is provably the integer `1` is read as
    not arming version 2; every other spelling — a higher or non-constant version, `Latest`, `-Off`,
    or no readable value — is read as arming it, the direction that refuses a fold rather than
    granting one. A string value need only *contain* the command name, the way
    `_arms_strict_mode` reads one, since the version inside it cannot be told apart.
    """
    if isinstance(node, Ps1CommandInvocation):
        if resolve_command_name(node) != 'set-strictmode':
            return False
        version = bound_argument_value(node, 'version')
        return not (isinstance(version, Ps1IntegerLiteral) and version.value == 1)
    written = string_value(node)
    if written is None or 'set-strictmode' not in written.lower():
        return False
    parent = node.parent
    if isinstance(parent, Ps1CommandInvocation) and parent.name is node:
        # A bareword command name parses as a string literal too, so a genuine `Set-StrictMode`
        # invocation reaches this the way a concealed one does. Its version is read on the
        # invocation above; reading the version-less name here would refuse every `-Version 1`.
        return False
    return True


def ends_the_script(
    element: Node,
    stop_default: bool = False,
    *,
    converts: Callable[[Ps1TrapStatement], bool],
) -> bool:
    """
    Whether an error raised at *element* stops the script, rather than being reported and stepped
    over, where no handler takes it.

    PowerShell has two kinds of error a `trap` sees, and they are disposed of differently where
    there is no `trap`. A **statement-terminating** error ends the statement it was raised in and
    the next statement runs: a failing cast, a division by zero, a member access on `$null`, an
    exception out of a .NET method, an unresolved command name. A **terminating** error ends the
    script, and only `throw` and a command told to stop raise one. Both halves are measured.

    *stop_default* is whether the script binds `Stop` into every command through
    `$PSDefaultParameterValues`, which makes any command a subtree runs report a terminating error
    the way `-ErrorAction Stop` on the command does — and only a command, since the default table
    binds a parameter and a failing cast takes none. A subtree that runs no command is unchanged by
    it, so a cast stays the stepped-over error it is; the caller reads the whole-script fact off
    `Ps1FaultReach._a_stop_default_is_in_force` and every subtree is judged against it.

    `exit` is neither, and is deliberately absent: it ends the script by an exception no `trap`
    catches, so a handler over one disposes of nothing and reading `exit` as a raise would keep a
    handler no run reaches. `trap { 'T' }; exit 3` writes neither `T` nor anything else, which the
    executable corpus cannot hold as a row because a snippet that exits takes the measuring host
    with it.

    The whole subtree is read, because a construct raises wherever its parts do:

        1..2 | ForEach-Object { throw }

    ends the script although the `throw` stands in a body of its own. That reaches into a `function`
    definition written inside the statement as well, whose `throw` runs only once something calls
    it — an over-approximation, and one that keeps a handler rather than dropping it.

    A `trap` inside the subtree that re-raises is read the same way, because it *converts*: an error
    a nested block would have reported and stepped over ends the script once such a handler takes
    it. *converts* says which `trap` does: one 5.1 may select whose body may re-raise.
    """
    for node in element.walk():
        if isinstance(node, Ps1ThrowStatement):
            return True
        if isinstance(node, Ps1TrapStatement) and converts(node):
            return True
        if isinstance(node, Ps1CommandInvocation) and (stop_default or stops_on_error(node)):
            return True
    return False


def _normal_successors(node: CfgNode) -> frozenset[CfgNode]:
    """
    The nodes control reaches from *node* along a plain fall-through edge — where a soft error at
    *node* steps over to, which is the same node its value flows to when it does not fail.
    """
    return frozenset(plain_successors(node))


def _enclosing_trap_body(node: Node, memo: dict[int, Ps1TrapStatement | None]) -> Ps1TrapStatement | None:
    """
    The `trap` whose body *node* stands in, or `None` where *node* is in no trap body. Assumes
    *node* is a body statement — a `trap`'s own type filter is not one, and the veto that reaches
    here has already restricted itself to a statement with a `fault_operand`.

    The walk stops at the first `Ps1ScriptBlock` because a `trap` reached only across a function or a
    stored scriptblock boundary does not guard the scope *node* runs in: a raise there ends the inner
    scope, and whatever the outer `trap` does is a question about the call, not about deleting the
    raise. The bodies of `if`/`while`/`for`/`switch`/`try` and of a named block (`begin`/`process`/
    `end`) are a `Block` rather than a `Ps1ScriptBlock`, so a raise nested in one still finds the
    `trap` it shares a scope with.

    *memo* holds the answer for every node a walk has climbed through, so that asking of every
    node of a nest costs its size rather than its size times its depth; the caller keeps it no
    longer than the tree stays as it is.
    """
    climbed: list[Node] = []
    found: Ps1TrapStatement | None = None
    cursor = node.parent
    while cursor is not None:
        if id(cursor) in memo:
            found = memo[id(cursor)]
            break
        if isinstance(cursor, Ps1TrapStatement):
            found = cursor
            break
        if isinstance(cursor, Ps1ScriptBlock):
            break
        climbed.append(cursor)
        cursor = cursor.parent
    for step in climbed:
        memo[id(step)] = found
    return found


class Ps1StepOverRegion:
    """
    What one run makes that another, carrying on at `resumed`, does not: the stretch of a statement
    that the run without a `trap` executes from where it carries on after an inner statement, up to
    where both runs go on alike, `resumed`.

    The walk follows every forward edge — a later statement that fails runs a `catch` body the other
    run never reaches — and stays inside the statements *within* holds, the ones it measures. A run
    that leaves them does not come back to `resumed`: it breaks out of a loop, returns, or takes an
    error further out, while the other run carries on in place. So a node outside them is not walked
    past and is read as observed, except a `trap` entry, which is read by what its body does. A
    `trap` entry inside them is followed along the error edges it hands an error on by, and its body
    is not walked.

    Built once for every start it is asked from, because the starts of one region skip overlapping
    stretches of the same statement — the second of two inner statements skips a suffix of what the
    first skips — and a walk per start costs the square of the statement. The region is condensed
    from every start, never entering a node of `resumed`, so that whether a start reaches something
    observable is one look at the components it reaches. What runs from `resumed` on is shared by
    both runs, so a write skipped is observable exactly when something reached from there reads it.
    Whether a statement is observable is not this class's to say; `query` pairs the region with a
    reader that says it.
    """

    def __init__(
        self,
        steps: list[frozenset[CfgNode]],
        resumed: frozenset[CfgNode],
        within: Callable[[CfgNode], bool],
    ):
        self.resumed = resumed

        def leaves(node: CfgNode) -> bool:
            return not isinstance(node.element, Ps1TrapStatement) and not within(node)

        def flows(node: CfgNode) -> list[CfgNode]:
            if not within(node):
                return []
            if isinstance(node.element, Ps1TrapStatement):
                return [
                    target for target in node.successors
                    if node.graph.is_exceptional(node, target) and target not in resumed
                ]
            return [
                target for target in Projection.FORWARD.successors(node) if target not in resumed
            ]

        starts = [node for step in steps for node in step if node not in resumed]
        self.condensation = Condensation(starts, flows)
        self.members = [member for component in self.condensation.components for member in component]
        self._leaves = leaves

    def query(self, observed: Callable[[CfgNode], bool]) -> Ps1SkipQuery:
        """
        The question whether a raiser of this region skips a statement *observed* reports, with the
        answers it learns kept beside that reader.
        """
        leaves = self._leaves
        return Ps1SkipQuery(self, lambda node: leaves(node) or observed(node))


class Ps1SkipQuery:
    """
    One reader of observability asked over one `Ps1StepOverRegion`, keeping what it learns per
    component. A raiser is never counted as skipping itself — its own statement is the one that
    raised — and a raiser on a loop inside the region reaches its whole component again; that one
    case is answered from up to two observed members of the component: two settle it for every
    member, one settles it for every member but itself.
    """

    def __init__(self, region: Ps1StepOverRegion, observed: Callable[[CfgNode], bool]):
        self._condensation = region.condensation
        self._observed = observed
        self._members: dict[int, tuple[int, ...]] = {}
        self._reaches: dict[int, bool] = {}

    def _observed_members(self, number: int) -> tuple[int, ...]:
        found = self._members.get(number)
        if found is None:
            hits: list[int] = []
            for member in self._condensation.components[number]:
                if self._observed(member):
                    hits.append(id(member))
                    if len(hits) > 1:
                        break
            found = self._members[number] = tuple(hits)
        return found

    def reaches_observed(self, node: CfgNode) -> bool:
        """
        Whether a statement *observed* reports is reached from *node* within the region.
        """
        number = self._condensation.number_of(node)
        return number is not None and self._reaches_observed(number)

    def _reaches_observed(self, number: int) -> bool:
        def observed(other: int) -> bool:
            return bool(self._observed_members(other))
        return self._condensation.holds(number, observed, self._reaches, downstream=True)


class _Fate(enum.Enum):
    """
    What becomes of an error handed to one member of a `trap` set: the set declines it, the member
    acts on it, or the member only jumps — resumes the block or re-raises the error.
    """
    DECLINED = enum.auto()
    ACTS = enum.auto()
    JUMPS = enum.auto()


class _Kind(enum.Enum):
    """
    The kinds of `trap` set member that 5.1 tries in turn: untyped, typed, and typed naming a type
    every error is.
    """
    UNTYPED = enum.auto()
    TYPED = enum.auto()
    UNIVERSAL = enum.auto()


class _SetFacts:
    """
    What the question whether deleting some members of one `trap` set changes anything reads of the
    set, read once: which members are typed, and how the members 5.1 may select dispose of an
    error, so that each question costs the members it removes and the members naming every error.

    Where no typed member goes, an error a typed member matches goes to the same member either way,
    and every other error goes to the members that take an error no narrower member names
    (`refinery.lib.scripts.ps1.analysis.handlers.Ps1TrapSelection.catching`) or past the set, so the two sets
    agree when those agree. Where a typed member goes, the errors it took may go to any member the
    smaller set may select: a typed member the whole set may select as well, or a member taking
    every error, which may be the first untyped member left; and past the set where it keeps no
    member taking every error. All of those and every member the whole set may select have to
    dispose of an error alike. A body that runs off its end hands the error to
    `$ErrorActionPreference`, so it resumes like `continue`; where a `Stop` may be in force it may
    re-raise like `break` instead, and since the script may set it after the raise or never run the
    write at all, such a body is alike neither one.
    """

    def __init__(self, trap_set: Ps1TrapSet, stop: bool):
        self._trap_set = trap_set
        self._stop = stop
        self._typed = {id(trap) for trap in trap_set.members if trap.type_name.strip()}
        self._selectable = {self._key(trap) for trap in trap_set.selectable}
        self._catching = self._catching_without(frozenset())
        self.acts = any(handler_acts(trap) for trap in trap_set.selectable)

    def keepers(self, proposed: Sequence[Ps1TrapStatement]) -> list[Ps1TrapStatement]:
        """
        The members of *proposed* worth keeping back, one at a time, where not all of *proposed*
        can go, in the order they are tried: the last proposed member 5.1 may select of each kind —
        untyped, typed, typed naming every error. Keeping back any one member of a kind leaves the
        same members of the other kinds, so the members taking every error differ only by that
        member where it is one of them, and the whole set may select it as well; every member of one
        kind answers alike, and the last of them is the one a search from the end would keep.
        """
        chosen = {id(trap) for trap in proposed}
        kinds: set[_Kind] = set()
        keepers: list[Ps1TrapStatement] = []
        for trap in reversed(self._trap_set.selectable):
            if id(trap) in chosen and (kind := self._kind(trap)) not in kinds:
                kinds.add(kind)
                keepers.append(trap)
        return keepers

    @staticmethod
    def _kind(trap: Ps1TrapStatement) -> _Kind:
        if not trap.type_name.strip():
            return _Kind.UNTYPED
        if names_every_error(trap.type_name):
            return _Kind.UNIVERSAL
        return _Kind.TYPED

    def _key(self, trap: Ps1TrapStatement) -> tuple[_Fate, int]:
        """
        What *trap* does with an error, as a value two members that dispose of it alike share: a
        member that acts shares it with no other, since what it writes is its own.
        """
        if handler_acts(trap):
            return _Fate.ACTS, id(trap)
        return _Fate.JUMPS, settled(self._trap_set.disposition(trap), self._stop).value

    def _catching_without(self, removed: AbstractSet[int]) -> set[tuple[_Fate, int]]:
        """
        What becomes of an error no narrower member names once the members *removed* holds are gone.
        """
        keys = {self._key(trap) for trap in self._trap_set.catching(removed)}
        return keys or {(_Fate.DECLINED, 0)}

    @property
    def selectable_alike(self) -> bool:
        """
        Whether every member 5.1 may select disposes of an error alike.
        """
        return len(self._selectable) <= 1

    def disposes_alike_without(self, removed: set[int]) -> bool:
        catching = self._catching_without(removed)
        if self._typed.isdisjoint(removed):
            return catching == self._catching
        return len(self._selectable) == 1 and catching <= self._selectable


class RaiseVerdicts(Protocol):
    """
    What the points of one tree may raise under one reading of the world, and which bodies its calls
    run: the half of every question here that reads values, which this module holds none of.
    `refinery.lib.scripts.ps1.analysis.raising.Ps1RaiseModel` answers it.
    """

    def kinds(self, point: Node) -> Ps1ErrorKind:
        """
        The kinds of error *point* may raise, judged where it stands.
        """
        ...

    def bodies_run_by(self, call: Node) -> tuple[Ps1ScriptBlock, ...] | None:
        """
        The bodies of the script *call* may run, or `None` where it may run one that cannot be
        named.
        """
        ...

    def bodies_consulted(self, node: Node) -> tuple[tuple[Ps1ScriptBlock, ...], bool]:
        """
        The bodies evaluating *node* may run, and whether it may run one that cannot be named.
        """
        ...

    def is_recursive(self, body: Node) -> bool:
        """
        Whether *body* may run itself again through the calls its points make.
        """
        ...


class SkipVerdicts(Protocol):
    """
    The semantic half of the region question: whether a statement one run executes and the other
    does not does something a run can see.
    """

    def observers(
        self,
        graph: ControlFlowGraph,
        regions: Sequence[Ps1StepOverRegion],
    ) -> list[Callable[[CfgNode], bool]]:
        """
        For each of *regions* of *graph*, whether a member of it is observed by a run that rejoins
        the other where the region resumes.
        """
        ...


class Ps1FaultReach:
    """
    The fault routing of one script, read off its control-flow graphs.

    Built over `refinery.lib.scripts.ps1.analysis.cfg.Ps1ControlFlowModel`: where an error goes is
    decided by the evaluator of `refinery.lib.scripts.ps1.analysis.dispatch`, over the lists the
    graphs place, so this needs no semantic model and no world; what the points raise is handed in
    by the caller as `RaiseVerdicts`. It reads the call graph for one fact only, which calls may run
    a body, since that decides whether a caller may guard the body. Every answer is kept for the
    life of the model, and the model itself is discarded whenever the tree moves. The graph it reads
    is the sub-statement one `refinery.lib.scripts.ps1.analysis.cfg.build_control_flow_model` draws
    with `descend`, so that a soft error stepping over inside a `$( )` or `@( )` — and a `trap`
    written among those inner statements — is a point it places rather than detail hidden in the one
    node the coarse graph gives the whole statement. It draws that itself from its own root on first
    demand, so no caller can hand it a graph too coarse to see the step-over and remove a
    load-bearing trap. *dispatch* is the evaluator the graphs were drawn from; without it, the
    reader builds its own, with the bodies a guarded call may run read off the call graph.
    """

    def __init__(
        self,
        control_flow: Ps1ControlFlowModel,
        calls: Callable[[], Ps1CallGraph],
        dispatch: Ps1Dispatch | None = None,
    ):
        self._given = control_flow
        self._calls = calls
        self._model: Ps1ControlFlowModel | None = None
        self._version: int | None = None
        self._set_facts: dict[int, _SetFacts] = {}
        self._ending: dict[int, bool] = {}
        self._stop_default: bool | None = None
        self._strict: bool | None = None
        self._strict_v2: bool | None = None
        self._dispatch = dispatch
        self._trap_bodies: dict[int, Ps1TrapStatement | None] = {}
        self._kept_for: int | None = None
        self._unattributed_holders_found: tuple[frozenset[int] | None] | None = None
        self._offered: _OfferedScan | None = None
        self._shared_queries: dict[tuple[int, int, int, int], Ps1SkipQuery] = {}
        self._carry_ons: dict[int, _CarryOns] = {}

    @property
    def call_graph(self) -> Ps1CallGraph:
        """
        The call graph of the script, read for which calls may run a body.
        """
        return self._calls()

    @property
    def dispatch(self) -> Ps1Dispatch:
        """
        Where 5.1 sends an error raised at a point of this script, under the error preferences the
        script's session may hold, with the bodies a guarded call may run read off the call sites.
        """
        dispatch = self._dispatch
        if dispatch is None:
            root = self._script
            if root is None:
                raise ValueError('the fault reach was handed no graph to read a script from')
            dispatch = self._dispatch = dispatch_for(root, Ps1BodyCallers(root, self._calls))
        return dispatch

    def fate_of(self, node: Node, kinds: Ps1ErrorKind) -> tuple[ControlFlowGraph, CfgNode, Ps1Fate] | None:
        """
        The graph and node of the point *node* stands at, and where an error of *kinds* raised there
        may end up; `None` where the graphs or the dispatch place it nowhere.
        """
        located = self.control_flow.locate(node)
        if located is None:
            return None
        graph, start = located
        point = start.element
        if point is None:
            return None
        fate = self.dispatch.fate(point, kinds)
        if fate is None:
            return None
        return graph, start, fate

    def _replaces_what_is_in_flight(self, graph: ControlFlowGraph, fate: Ps1Fate) -> bool:
        """
        Whether an error routed like *fate* leaves the `finally` body of a `try` that something
        other than the completed `try` may enter, where the error takes the place of what was in
        flight and the two may end up apart: a jump, which goes wherever it was going and never
        where an error does (`refinery.lib.scripts.ps1.analysis.dispatch.Ps1Dispatch.jumps_through`),
        or an error, where the `try` statement disposes of errors of one kind otherwise than of
        another, so that whichever kind the error in flight is, the one taking its place may be
        another.
        """
        dispatch = self.dispatch
        for statement in fate.replaces:
            if dispatch.jumps_through(statement):
                return True
            final = statement.finally_block
            entry = None if final is None else graph.node_of(final)
            if entry is None:
                return True
            if not any(graph.is_exceptional(source, entry) for source in entry.predecessors):
                continue
            level = dispatch.level_of(statement)
            if level is None:
                return True
            if len({dispatch.disposed(level, statement, kind) for kind in ERROR_KINDS}) > 1:
                return True
        return False

    @property
    def control_flow(self) -> Ps1ControlFlowModel:
        """
        The one graph every question is read off, descended so that a `$( )` or `@( )` shows its
        inner statements as points of their own. Built once from this reader's own root — the tree
        the model passed to the constructor was drawn over — and only where the script writes such a
        bracket at all: a script that writes none draws an identical graph under `descend`, which
        expands only those constructs, so the passed model is the descended one already and is reused
        unchanged. The empty model a caller may construct owns no root and is likewise returned as it
        is.
        """
        if self._model is None:
            root = self._script
            if root is not None:
                self._version = tree_version(tree_root(root))
            self._model = self._given
            if isinstance(root, Ps1Script) and any(
                isinstance(node, STATEMENT_LIST_EXPRESSIONS) for node in root.walk()
            ):
                self._model = build_control_flow_model(root, descend=True, dispatch=self.dispatch)
        return self._model

    def points_in(self, node: Node) -> Iterator[Node]:
        """
        The points inside *node* at which the graphs say something is evaluated, *node* itself
        included where it is one.

        Deleting a construct deletes everything it holds, so the errors it stops raising are its
        body's as well as its own — and each is at a position of its own, since a `try` nested in it
        routes its body's errors to its own `catch`. What the graphs place is exactly the list of
        such positions, which is why it is read off them rather than guessed from the node types: a
        `for` loop is three points and a body, an `if` is one point per test, and neither construct
        has a node standing for the statement as a whole.

        A construct that yields nothing at all is one the graphs model nowhere, and a caller reads
        that as a subtree it cannot judge rather than as one that raises nothing.
        """
        for inner in node.walk():
            if self.control_flow.node_of(inner) is not None:
                yield inner

    def places(self, node: Node) -> bool:
        """
        Whether the graphs evaluate something at *node*, which makes it a point of its own.
        """
        return self.control_flow.node_of(node) is not None

    def escapes_the_body(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether an error of *kinds* raised at *node* gets past every handler written in the body
        *node* stands in, so that where it goes next is decided by whatever ran that body and not by
        anything the body itself says.

        A position the graphs place nowhere settles nothing and escapes nothing; `False` is the
        answer that leaves such a node to the position question, which reads an unplaced node as
        observed.
        """
        found = self.fate_of(node, kinds)
        if found is None:
            return False
        _, _, fate = found
        if fate.acts or fate.leaves and fate.offered_to_traps:
            return False
        return not (fate.caught or fate.offered_to_traps) or bool(fate.leaves)

    def observed_at(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether an error of *kinds* raised at *node* changes which code runs: some handler it
        reaches acts, it may end the run, a `trap` set may decline it and end the body, or the
        graphs place *node* nowhere.

        This is the question about the **position** and not about the statement standing there —
        it answers the same for a statement that cannot raise at all, which is what a caller
        weighing whether a guarded body may be emptied wants to know.

        **An error that ends the run is observed**: deleting its raise would start the tail that
        never ran. That is a `throw` or an error a `Stop` marked that nothing takes, and an error
        raised in the body of a `trap` written in the script's own lists, which leaves the script
        whatever its kind.

        **An error that gets past a function's own handlers is the caller's**, and nothing here
        holds both ends of a call. Measured: the same function whose error is reported and stepped
        over when called at script scope abandons its remaining statements and runs the `catch` of a
        `try` written around the *call*, however many bodies deep the raise is. So an error handed to
        a caller is observed. The dispatch hands an error the body would report to its caller only
        where some call of the body may stand where errors are passed outward, or one that cannot be
        named may; an error of a `throw` or one no list reports leaves the body either way, and ends
        the caller's run unless the caller takes it.
        """
        found = self.fate_of(node, kinds)
        if found is None:
            return True
        _, _, fate = found
        if fate.acts or fate.ends_run:
            return True
        return bool(fate.to_caller)

    def lands_past_a_live_tail(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether an error of *kinds* raised at *node* may carry the run on somewhere a run on which
        *node* completed does not go next — the position fact behind the body-tail keep. The run
        carries on after a statement where an error is reported, silenced or taken by a `trap` that
        carries on, and after a `try` whose empty `catch` takes it; either is where *node*'s own run
        goes next only where nothing else runs on the way there
        (`refinery.lib.scripts.ps1.analysis.dispatch.Ps1Dispatch.tail_of`). An error that takes the
        place of an error or a jump in flight, leaving a `finally` body, lands there too where the
        two may end up apart.

        A position question and nothing more: it says where a fault at *node* would go, never
        whether *node* can raise. The caller pairs it with the raise predicate, the way every
        removal site pairs a position with a fault of its own. A handler that *acts* is not among
        them: it makes the fault observable through `observed_at`. Emptiness of a `catch` is read
        from its body, so the answer is a property of where the handler sits and not of a
        predicate a caller may be mutating.
        """
        found = self.fate_of(node, kinds)
        if found is None:
            return False
        graph, start, fate = found
        point = start.element
        if point is None or not _normal_successors(start):
            return False
        tail = self.dispatch.tail_of(point)
        if not fate.carried <= tail or not fate.swallowed <= tail:
            return True
        return self._replaces_what_is_in_flight(graph, fate)

    def _landing_depth(self, element: Node, kinds: Ps1ErrorKind) -> float:
        located = self.control_flow.locate(element)
        if located is None or located[1].element is not element:
            return float('inf')
        fate = self.dispatch.fate(element, kinds)
        if fate is None:
            return float('-inf')
        return fate.outermost

    def raises_past(
        self,
        statement: Node,
        raises: Callable[[Node], Ps1ErrorKind],
        memo: dict[int, float],
    ) -> bool:
        """
        Whether an error raised at a point inside *statement* may be taken past it: carried on after
        a statement holding it, or taken by a handler that acts and is written around it. *raises*
        says which points raise, and *memo* is the table its first question fills for the whole tree
        from the leaves up, so that a nest of depth d costs d; the caller owns both, so a table is
        never read under a test other than the one it was filled with.
        """
        table = memo
        if not table:
            root = self._script
            if root is not None:
                order = list(root.walk())
                for node in reversed(order):
                    lowest = float('inf')
                    if self.control_flow.node_of(node) is not None and (kinds := raises(node)):
                        lowest = self._landing_depth(node, kinds)
                    for child in node.children():
                        lowest = min(lowest, table.get(id(child), float('inf')))
                    table[id(node)] = lowest
        lowest = table.get(id(statement))
        if lowest is None:
            return True
        return lowest < self.dispatch.depth_of(statement)

    def raises_out_of_the_body(
        self,
        statement: Node,
        raises: Callable[[Node], Ps1ErrorKind],
        memo: dict[int, bool],
    ) -> bool:
        """
        Whether an error raised at a point inside *statement* may leave the body it stands in for
        whatever called that body (`refinery.lib.scripts.ps1.analysis.dispatch.Ps1Fate.to_caller`),
        or stands where the dispatch places it nowhere. A point of a script block written inside
        *statement* stands in that block's body, and an error leaving it arrives where something
        runs the block, which is a point of its own. *raises* and *memo* are what `raises_past`
        takes, and the table is filled the same way, once for the tree from the leaves up.
        """
        table = memo
        if not table:
            root = self._script
            if root is not None:
                for node in reversed(list(root.walk())):
                    found = False
                    if self.control_flow.node_of(node) is not None and (kinds := raises(node)):
                        fate = self.dispatch.fate(node, kinds)
                        found = fate is None or bool(fate.to_caller)
                    table[id(node)] = found or any(
                        table.get(id(child), False)
                        for child in node.children()
                        if not isinstance(child, Ps1ScriptBlock)
                    )
        return table.get(id(statement), True)

    def kinds_the_try_catches(
        self,
        operand: Node,
        cleared: Callable[[Node], bool],
        handed_back: Callable[[Node], Ps1ErrorKind],
    ) -> Ps1ErrorKind:
        """
        The kinds of terminating error evaluating *operand* may raise that a `try` catches. A cast,
        a fallible operator and a method call raise a statement-terminating one whatever the error
        preferences say; a command raises one no list reports only where the script makes its error
        terminating, which `error_is_terminating` reads from `Stop`; and a call that may run a body
        of the script raises whatever *handed_back* says the bodies it runs hand back. The default
        command error is non-terminating — reported and stepped over — so the `try` does not catch
        it and a statement after it still runs.

        It is the fault model's rather than the effect layer's because its command arm reads the
        script's error preferences, a judgment `error_is_terminating` already owns here; the
        expression arm is the pure `raises_a_caught_terminating_error` shape from `ast`. A part of
        *operand* that *cleared* answers for cannot raise, and what a body hands back is read off
        the bodies themselves: both judgments read values, which this module holds none of, so the
        caller hands them in.
        """
        kinds = Ps1ErrorKind.NONE
        if raises_a_caught_terminating_error(operand, cleared):
            kinds |= Ps1ErrorKind.STATEMENT
        if is_soft_error_source(operand, cleared) and self.error_is_terminating(operand):
            kinds |= Ps1ErrorKind.MARKED
        return kinds | handed_back(operand)

    def never_runs(self, node: Node, raises: RaiseVerdicts) -> bool:
        """
        Whether *node* stands in the body of a `trap` no point of the script may fire, so that no run
        reaches it and deleting it changes nothing. What may fire it is what *raises* reads as
        raising at a point the dispatch hands to the `trap`, or any point the dispatch places
        nowhere.
        """
        self._forget_a_moved_tree()
        trap = _enclosing_trap_body(node, self._trap_bodies)
        if trap is None:
            return False
        scan = self._offered_scan(raises)
        if self._moved():
            return False
        return not scan.may_run(trap)

    def escapes_a_trap_body(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether *node* is a raise of *kinds* in the body of a `trap` whose error leaves that body and
        ends the scope the `trap` belongs to. A `trap` does not guard its own body, so an error raised
        among its statements leaves the list that declares the `trap`: it ends the script at script
        scope, or the function where the `trap` is written inside one, except where the `trap` ran
        for a `try` statement of that list whose clauses took no error, which disposes of it as an
        error of that statement (`refinery.lib.scripts.ps1.analysis.dispatch.Ps1Dispatch`). Deleting
        such a raise runs the remainder of the body — and the scope past it — that the original
        abandoned, which is why it is the position half of a keep. Whether the `trap` fires at all
        is `never_runs`, which a caller holding what may fire it asks first.
        """
        self._forget_a_moved_tree()
        return _enclosing_trap_body(node, self._trap_bodies) is not None and self.escapes_the_body(node, kinds)

    def deleting_the_raise_resurrects_a_continuation(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether a live continuation runs only because a raise of *kinds* at *node* pre-empts it, so
        deleting the raise starts that continuation. The one position predicate the removal veto
        pairs with its raise half, `refinery.lib.scripts.ps1.analysis.raising.point_raise_kinds`.
        Two mechanisms resurrect a continuation and both are the same observable: the run carries
        on somewhere else (`lands_past_a_live_tail`), and a `trap` body raise ends the scope the
        tail would otherwise have kept running in (`escapes_a_trap_body`).
        """
        return (
            self.lands_past_a_live_tail(node, kinds)
            or self.escapes_a_trap_body(node, kinds)
        )

    def error_is_terminating(self, node: Node) -> bool:
        """
        Whether a fault raised at *node* is terminating rather than reported and stepped over — the
        script writes `Stop` to `$ErrorActionPreference`, or the raise is one of the terminating
        shapes `ends_the_script` names: a command with `-ErrorAction Stop`, and any command at all
        where `$PSDefaultParameterValues` binds `Stop` into it. It is what makes a command's error
        one a `try` catches, and it is `_terminates` under a name a caller outside the module may
        read.
        """
        return self._terminates(node)

    def removable_traps(
        self,
        traps: Sequence[Ps1TrapStatement],
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> list[Ps1TrapStatement]:
        """
        The largest part of *traps* this reader finds can be deleted together without changing
        what runs: per set, all of them; else all but one member 5.1 may select, tried in turn; else
        those 5.1 never selects. A `trap` the graphs hold in no set is kept.
        """
        by_set: dict[int, tuple[Ps1TrapSet, list[Ps1TrapStatement]]] = {}
        for trap in traps:
            trap_set = self._trap_set_of(trap)
            if trap_set is not None:
                by_set.setdefault(id(trap_set), (trap_set, []))[1].append(trap)
        removable: list[Ps1TrapStatement] = []
        for trap_set, proposed in by_set.values():
            removable.extend(self._removable_from(trap_set, proposed, raises, skips))
        return removable

    def _removable_from(
        self,
        trap_set: Ps1TrapSet,
        proposed: list[Ps1TrapStatement],
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> list[Ps1TrapStatement]:
        if not self._removing_matters(trap_set, proposed, raises, skips):
            return proposed
        for keeper in self._facts(trap_set).keepers(proposed):
            rest = [trap for trap in proposed if trap is not keeper]
            if rest and not self._removing_matters(trap_set, rest, raises, skips):
                return rest
        spare = [trap for trap in proposed if not trap_set.is_selectable(trap)]
        if spare and not self._removing_matters(trap_set, spare, raises, skips):
            return spare
        return []

    def removing_traps_is_observed(
        self,
        traps: Sequence[Ps1TrapStatement],
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> bool:
        """
        Whether deleting *traps*, members of one block's `trap` set, may change which code runs —
        the question asked before any `trap` is deleted.

        A `trap` cannot itself raise, so the forward question answers nothing about removing one:
        what changes is where the errors of *other* statements go. The set is the unit of the
        answer, because 5.1 hands an error to one member by the error's type and not by where the
        member is written (`refinery.lib.scripts.ps1.analysis.handlers.Ps1TrapSelection`), so a member
        alone says nothing about what its block does.

        **Something that may actually raise has to be offered to the set.** *raises* says what each
        point raises, and the dispatch where it goes; a `trap` beside a bare constant guards
        nothing, and one left behind by the removal of the only raise in its block becomes
        removable in turn. A point the dispatch places nowhere inside the block keeps the set.

        **Deleting some of the members** changes nothing exactly when every error still goes to a
        member that disposes of it alike; `_SetFacts` says when.

        **Deleting every member** is read off the evaluator. A set with a member 5.1 may select that
        acts, or whose selectable members dispose of an error differently, is kept. Otherwise, for
        each reading per pair of preference values, each point offered to the set, each kind it may
        raise and each value of the outward flag its body may be called under, the reading without
        the set has to agree with the reading with it on the handlers that act, whether the run
        ends, what is handed to the caller and which `finally` bodies it leaves. Where only the
        statement the run carries on after differs, the stretch between the two is a region, and
        *skips* reads whether a statement of it does something a run can see; an error a body run
        at the point hands back, taken in one reading and arriving nowhere in the other, makes the
        rest of that body a region, collected body by body.

        A `trap` the graphs hold in no set, and any question asked after the tree moved, is read as
        observed.
        """
        if not traps:
            raise ValueError('no trap was named')
        trap_set = self._trap_set_of(traps[0])
        if trap_set is None:
            return True
        if any(self._trap_set_of(trap) is not trap_set for trap in traps):
            raise ValueError('the traps named belong to more than one set')
        return self._removing_matters(trap_set, traps, raises, skips)

    def _trap_set_of(self, trap: Ps1TrapStatement) -> Ps1TrapSet | None:
        return self.control_flow.trap_set_of(trap)

    def _forget_a_moved_tree(self) -> None:
        """
        Drop the answers kept by node identity once the tree has moved since they were read: an
        edited subtree answers differently, and a node made by the edit may take the identity of
        one it freed. A pass may go on asking this reader after it edited the tree.
        """
        root = self._script
        version = None if root is None else tree_version(tree_root(root))
        if version != self._kept_for:
            self._trap_bodies.clear()
            self._offered = None
            self._shared_queries.clear()
            self._carry_ons.clear()
            self._unattributed_holders_found = None
            self._kept_for = version

    def _moved(self) -> bool:
        """
        Whether the tree has changed since the graphs this reader holds were built from it, or no
        graph was built yet: either way the trap sets it would read are not the tree's.
        """
        root = self._script
        if self._version is None or root is None:
            return True
        return tree_version(tree_root(root)) != self._version

    def _facts(self, trap_set: Ps1TrapSet) -> _SetFacts:
        facts = self._set_facts.get(id(trap_set))
        if facts is None:
            facts = _SetFacts(trap_set, self._stops_on_every_error())
            self._set_facts[id(trap_set)] = facts
        return facts

    def _dispose_alike(self, trap_set: Ps1TrapSet, removed: set[int]) -> bool:
        return self._facts(trap_set).disposes_alike_without(removed)

    def edits_that_wait(
        self,
        deleted: Sequence[Sequence[Node]],
        touched: Sequence[Sequence[Node]],
        raises: RaiseVerdicts,
    ) -> tuple[set[int], set[int]]:
        """
        Of edits judged apart, group *i* deleting the `trap` statements `deleted[i]` and touching
        the statements `touched[i]`, the indices of the groups that wait for the others to land and
        are judged again, and the statements of a group that wait for the `trap` deletions of their
        own group. An edit waits where it touches a statement in the scope of a `trap` set the batch
        deletes, and that set is offered an error: the list the set is written in, every body a
        point of that list may run, at any depth, and every site that may run the body the set is
        written in, at any height. That is every point whose error can end up anywhere else once the
        set is gone, so a verdict read anywhere else holds whatever that deletion does. A `trap`
        deletion is the exception: its verdict reads where its set's errors go without it, which is
        the sets around it whether or not they are offered anything while it stands, so it waits
        wherever it stands in the scope of another deleted set and its own set is offered an error.
        A deletion of a set offered nothing changes no error's fate.
        """
        is_offered = self._offered_scan(raises).is_offered
        scopes = _Scopes(self._unattributed_holders() or frozenset())
        for index, traps in enumerate(deleted):
            owners = {id(trap.parent): trap.parent for trap in traps if trap.parent is not None}
            for owner in owners.values():
                scopes.add(_Scope(
                    index,
                    owner,
                    is_offered(owner),
                    self._bodies_run_within(owner, raises),
                    self._site_holders_above(owner),
                ))
        waiting: set[int] = set()
        withheld: set[int] = set()
        for index, statements in enumerate(touched):
            own = {id(trap) for trap in deleted[index]}
            for statement in statements:
                if id(statement) in own:
                    parent = statement.parent
                    if parent is None or not is_offered(parent):
                        continue
                    if any(found.another(index, id(parent)) for found in scopes.holding(statement)):
                        waiting.add(index)
                    continue
                for found in scopes.holding(statement):
                    if found.offered_besides(index):
                        waiting.add(index)
                    if found.offered_to(index):
                        withheld.add(id(statement))
        return waiting, withheld

    def _site_holders_above(self, owner: Node) -> _Holders | None:
        """
        The statements holding a site that may run the body *owner* is written in, or a site that
        may run a body holding one of those, at any height; `None` where a site cannot be named.
        What a body hands back to such a site is read off the fates inside it, so a verdict about
        the site reads the body. The calls the call graph cannot attribute run every function body,
        so the statements holding them, and what runs those, are collected once per tree version and
        shared by every set written in a function body (`_unattributed_holders`); collected or even
        copied per set, a script with many such calls beside many trapped functions costs their
        product.
        """
        climbed = self._climb_to_sites([owner])
        if climbed is None:
            return None
        sites, runs_a_function = climbed
        holders = _holders_of(sites)
        if not runs_a_function:
            return _Holders(holders, False)
        if self._unattributed_holders() is None:
            return None
        return _Holders(holders, True)

    def _unattributed_holders(self) -> frozenset[int] | None:
        """
        The statements holding a call the call graph cannot attribute, or a site that may run a body
        holding one of those, at any height; `None` where a site cannot be named.
        """
        self._forget_a_moved_tree()
        found = self._unattributed_holders_found
        if found is None:
            unattributed = list(self.call_graph.unattributed_sites)
            climbed = self._climb_to_sites(unattributed)
            holders = None if climbed is None else _holders_of([*unattributed, *climbed[0]])
            found = self._unattributed_holders_found = (holders,)
        return found[0]

    def _climb_to_sites(self, starts: Sequence[Node]) -> tuple[list[Node], bool] | None:
        """
        The named sites that may run a body holding one of *starts*, and those running a body
        holding one of them, at any height, with whether one of those bodies is a function's;
        `None` where a site cannot be named.
        """
        found: dict[int, Node] = {}
        seen: set[int] = set()
        pending: list[Node] = list(starts)
        runs_a_function = False
        while pending:
            cursor: Node | None = pending.pop()
            while cursor is not None and not isinstance(cursor, Ps1ScriptBlock):
                cursor = cursor.parent
            if cursor is None or id(cursor) in seen:
                continue
            seen.add(id(cursor))
            sites = self.call_graph.sites_running(cursor, attributed_only=True)
            if sites is None:
                return None
            if isinstance(cursor.parent, Ps1FunctionDefinition):
                runs_a_function = True
            for site in sites:
                if id(site) not in found:
                    found[id(site)] = site
                    pending.append(site)
        return list(found.values()), runs_a_function

    def _bodies_run_within(self, owner: Node, raises: RaiseVerdicts) -> frozenset[int] | None:
        """
        Every body a point written in the list *owner* holds may run, at any depth; `None` where one
        of them may run a body *raises* cannot name.
        """
        located = self.control_flow.locate(owner)
        graph = located[0] if located is not None else self.control_flow.graph_of(owner)
        if graph is None:
            return None
        found: dict[int, Node] = {}
        pending: list[ControlFlowGraph] = []
        points = [node.element for node in graph.nodes if node.element is not None and _descends(node.element, owner)]
        while True:
            for point in points:
                for operand in point_operands(point) or ():
                    bodies, unknown = raises.bodies_consulted(operand)
                    if unknown:
                        return None
                    for body in bodies:
                        if id(body) in found:
                            continue
                        found[id(body)] = body
                        body_graph = self.control_flow.graph_of(body)
                        if body_graph is None:
                            return None
                        pending.append(body_graph)
            if not pending:
                return frozenset(found)
            points = [node.element for node in pending.pop().nodes if node.element is not None]

    def _offered_scan(self, raises: RaiseVerdicts) -> _OfferedScan:
        """
        The scan of the points *raises* reads as raising, kept for this tree version and that
        reading.
        """
        self._forget_a_moved_tree()
        found = self._offered
        if found is not None and found.raises is raises:
            return found
        found = self._offered = _OfferedScan(self, raises)
        return found

    def _removing_matters(
        self,
        trap_set: Ps1TrapSet,
        traps: Sequence[Ps1TrapStatement],
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> bool:
        """
        Whether deleting *traps*, members of *trap_set*, changes what runs: nothing is offered to the
        set, or every reading of the tree without them runs what the reading with them runs, and no
        point inside the block is one the dispatch places nowhere.
        """
        if self._moved():
            return True
        owner = traps[0].parent
        if owner is None:
            return True
        dispatch = self.dispatch
        if dispatch.level(owner).traps is None:
            return True
        removed = {id(trap) for trap in traps}
        scan = self._offered_scan(raises)
        if not scan.is_offered(owner):
            return False
        return (
            self._removal_differs(trap_set, owner, removed, scan, raises, skips)
            or scan.unplaced_within(owner)
        )

    def _removal_differs(
        self,
        trap_set: Ps1TrapSet,
        owner: Node,
        removed: set[int],
        scan: _OfferedScan,
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> bool:
        """
        Whether a run of the tree without the members of *trap_set* that *removed* names differs
        from a run with them. Removing some members changes nothing where the rest disposes of every
        error alike (`_SetFacts`). Removing every member is read off the evaluator: for each reading
        per pair of preference values, each point offered to the set, each kind it raises and each
        value of the outward flag its body may be called under, the fate with the set and the fate
        without it have to agree, except in where the run carries on; where it carries on differs,
        the stretch one run executes and the other skips is a region, and the removal is observed
        only where a region runs something a run can see.
        """
        dispatch = self.dispatch
        if len(removed) < len(trap_set.members):
            return not self._dispose_alike(trap_set, removed)
        facts = self._facts(trap_set)
        if facts.acts or not facts.selectable_alike:
            return True
        regions = _Regions()
        for real in dispatch.readings():
            without = dispatch.without(real, owner, removed)
            for point in scan.offered_to(owner):
                if _inside_one_of(point, removed):
                    continue
                kinds = raises.kinds(point)
                statement = member_of(point)
                level = None if statement is None else real.levels.level_of(statement)
                located = self.control_flow.locate(point)
                if level is None or located is None:
                    return True
                graph = located[0]
                for kind in ERROR_KINDS:
                    if kind not in kinds:
                        continue
                    for guarded in level.guards():
                        before = real.fate(point, kind, guarded)
                        after = without.fate(point, kind, guarded)
                        if before is None or after is None:
                            return True
                        if before == after:
                            continue
                        if kind is Ps1ErrorKind.CALLED and _arrives_nowhere(after):
                            if not self._called_tails_collected(point, before, graph, without, regions, raises, real):
                                return True
                            continue
                        if _differs_beyond_regions(before, after):
                            return True
                        if not _collect_regions(graph, before, after, real, without, regions):
                            return True
        return self._regions_observed(regions, raises, skips)

    def _called_tails_collected(
        self,
        point: Node,
        before: Ps1Fate,
        graph: ControlFlowGraph,
        reading: _Reading,
        regions: _Regions,
        raises: RaiseVerdicts,
        real: Ps1Reading,
    ) -> bool:
        """
        Where an error a body run at *point* hands back is taken in one reading (*before*) and stays
        inside the body in the other, the second run executes the rest of the body and of the
        statement holding *point*; and where a call in that body hands back an error the same way,
        the rest of that body as well. Collect those stretches into *regions*, one body at a time
        from a worklist, and answer whether that could be done; `False` where it cannot, and where a
        body runs itself again.

        At every level below the first, the run that keeps the `trap` hands the error on to the
        caller, which is how it reaches the `trap`; the rest of that body after the inner call is
        then a region, read in the run without the `trap`.
        """
        unguarded = _Unguarded(real)
        pending: list[tuple[Node, Ps1Fate, ControlFlowGraph, _Reading, bool]] = [
            (point, before, graph, reading, False)
        ]
        visited: set[int] = set()
        while pending:
            point, before, graph, reading, nested = pending.pop()
            if _acting(before) or before.ends_run or before.replaces:
                return False
            if before.to_caller and not nested:
                return False
            statement = member_of(point)
            call = _bare_call(point)
            if statement is None or call is None or statement is not point:
                return False
            for landed in _landed(before):
                if landed is statement:
                    continue
                if not _descends(statement, landed):
                    return False
                regions.add(landed, graph, reading, statement)
            if call.arguments:
                return False
            if isinstance(call.name, Ps1ScriptBlock):
                if call.invocation_operator != '&':
                    return False
            elif call.invocation_operator not in ('', '&'):
                return False
            bodies = raises.bodies_run_by(call)
            if not bodies:
                return False
            for body in bodies:
                if raises.is_recursive(body):
                    return False
                if id(body) in visited:
                    continue
                visited.add(id(body))
                body_graph = self.control_flow.graph_of(body)
                if body_graph is None:
                    return False
                for cfg_node in body_graph.nodes:
                    inner = cfg_node.element
                    if inner is None or isinstance(inner, (Ps1CatchClause, Ps1TrapStatement)):
                        continue
                    kinds = raises.kinds(inner)
                    for kind in ERROR_KINDS:
                        if kind not in kinds:
                            continue
                        left = real.fate(inner, kind, False)
                        taken = real.fate(inner, kind, True)
                        if left is None or taken is None:
                            return False
                        if left == taken:
                            continue
                        if kind is Ps1ErrorKind.CALLED and _arrives_nowhere(left):
                            calling = member_of(inner)
                            if calling is None:
                                return False
                            regions.add(body, body_graph, unguarded, calling)
                            pending.append((inner, taken, body_graph, unguarded, True))
                            continue
                        if _acting(left) or left.ends_run or left.to_caller or left.replaces:
                            return False
                        for landed in _landed(left):
                            if not _descends(landed, body):
                                return False
                            regions.add(body, body_graph, unguarded, landed)
        return True

    def _shared_query(
        self,
        graph: ControlFlowGraph,
        outer: Node,
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> Ps1SkipQuery | None:
        """
        The walk of the whole of *outer* as the run that keeps every `trap` executes it, built once
        and shared by every question whose region it is.
        """
        self._forget_a_moved_tree()
        key = (id(graph), id(outer), id(raises), id(skips))
        found = self._shared_queries.get(key)
        if found is not None:
            return found
        built = graph.built_for(outer)
        within = graph.builder_of([outer])
        resumed = _after(graph, outer, self._carry_on_index(graph))
        if built is None or within is None or resumed is None:
            return None
        region = Ps1StepOverRegion([frozenset(built)], resumed, within)
        semantic, = skips.observers(graph, [region])
        real = self.dispatch.evaluation
        memo: dict[int, bool] = {}

        def observed(member: CfgNode) -> bool:
            hit = memo.get(id(member))
            if hit is None:
                hit = memo[id(member)] = (
                    semantic(member) or _raise_leaves_region(member, outer, real, raises))
            return hit

        found = self._shared_queries[key] = region.query(observed)
        return found

    def _carry_on_index(self, graph: ControlFlowGraph) -> _CarryOns:
        """
        For each statement of *graph* a run may carry on after when an error lands on it, the node
        standing for that: the slot of a resuming `trap` set, or the node 5.1 reports at where
        nothing is in force; and for each statement of a block a set resumes, where it completes.
        """
        self._forget_a_moved_tree()
        found = self._carry_ons.get(id(graph))
        if found is None:
            found = _CarryOns({}, {})
            for trap_set in self.control_flow.trap_sets_in(graph):
                found.slots.update(trap_set.slots)
                found.completions.update(trap_set.completions)
            for node in graph.nodes:
                if isinstance(node, Ps1ReportNode):
                    found.slots.setdefault(id(node.carries_on_after), node)
            self._carry_ons[id(graph)] = found
        return found

    def _regions_observed(
        self,
        regions: _Regions,
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> bool:
        """
        Whether a statement of one of *regions* does something a run can see, or raises an error
        whose fate leaves the region. A region in the run that keeps every `trap`, of a statement
        inside its graph's body, is read off the one walk of that statement every such question
        shares (`_shared_query`); the rest are walked from the places their run carries on.
        """
        built: list[tuple[_Region, list[frozenset[CfgNode]], Ps1StepOverRegion]] = []
        real = self.dispatch.evaluation
        for region in regions:
            graph = region.graph
            outer = region.outer
            if region.reading is real and outer is not graph.owner:
                query = self._shared_query(graph, outer, raises, skips)
                if query is None:
                    return True
                for inner in region.inners.values():
                    after = _after(graph, inner, self._carry_on_index(graph))
                    if after is None:
                        return True
                    if any(query.reaches_observed(node) for node in after):
                        return True
                continue
            within: Callable[[CfgNode], bool] | None
            resumed: frozenset[CfgNode] | None
            if outer is graph.owner:
                within = _anything_but(graph.exit)
                resumed = frozenset((graph.exit,))
            else:
                within = graph.builder_of([outer])
                resumed = _after(graph, outer, self._carry_on_index(graph))
            if within is None or resumed is None:
                return True
            starts: list[frozenset[CfgNode]] = []
            for inner in region.inners.values():
                after = _after(graph, inner, self._carry_on_index(graph))
                if after is None:
                    return True
                starts.append(after)
            built.append((region, starts, Ps1StepOverRegion(starts, resumed, within)))
        by_graph: dict[int, list[Ps1StepOverRegion]] = {}
        for region, _, walk in built:
            by_graph.setdefault(id(region.graph), []).append(walk)
        observers: dict[int, Callable[[CfgNode], bool]] = {}
        for region, _, walk in built:
            if id(walk) not in observers:
                walks = by_graph[id(region.graph)]
                for other, made in zip(walks, skips.observers(region.graph, walks)):
                    observers[id(other)] = made
        for region, starts, walk in built:
            semantic = observers[id(walk)]
            memo: dict[int, bool] = {}

            def observed(
                member: CfgNode,
                semantic: Callable[[CfgNode], bool] = semantic,
                region: _Region = region,
                memo: dict[int, bool] = memo,
            ) -> bool:
                found = memo.get(id(member))
                if found is None:
                    found = memo[id(member)] = (
                        semantic(member) or _raise_leaves_region(member, region.outer, region.reading, raises))
                return found

            query = walk.query(observed)
            if any(query.reaches_observed(node) for start in starts for node in start):
                return True
        return False

    def _converts(self, trap: Ps1TrapStatement) -> bool:
        """
        Whether *trap* turns an error it takes into one that ends the body: 5.1 may select it and
        its body may re-raise. A `trap` the graphs hold in no set is read as converting.
        """
        trap_set = self._trap_set_of(trap)
        if trap_set is None:
            return True
        return trap_set.is_selectable(trap) and Ps1TrapDisposition.RETHROWS in trap_set.disposition(trap)

    def _ends_the_script(self, element: Node) -> bool:
        """
        `ends_the_script` for *element*, remembered for the life of this model. Every handler judged
        against the same block is offered the same statements, so the subtree behind each one is
        read once however many removals ask about it. A `Stop` bound through
        `$PSDefaultParameterValues` is a whole-script fact folded in here rather than at each call
        site, so the same subtree is not re-scanned for it per element.
        """
        remembered = self._ending.get(id(element))
        if remembered is None:
            remembered = self._ending[id(element)] = ends_the_script(
                element, self._a_stop_default_is_in_force(), converts=self._converts)
        return remembered

    def _terminates(self, element: Node) -> bool:
        """
        Whether an error raised at *element* ends the run rather than being reported and stepped
        over: the script writes `Stop` to `$ErrorActionPreference` anywhere, or the raise is one of
        the terminating shapes `_ends_the_script` names — a `throw`, a rethrowing `trap`, a command
        told to stop, or any command at all where `$PSDefaultParameterValues` binds `Stop` into it.
        `error_is_terminating` reads it, which decides whether a command's error is one a `try`
        catches.
        """
        return self._stops_on_every_error() or self._ends_the_script(element)

    @property
    def _script(self) -> Node | None:
        """
        The tree the graphs were built over, read off the passed model's owner rather than taken as
        an argument: a graph owner is a node of that tree, and a whole-script fact has to be asked of
        the whole script rather than of the statements the graphs happen to place. It reads the model
        the constructor was handed, not the descended one `control_flow` derives, so the root the
        descended build needs is available without asking the build for it.
        """
        for graph in self._given.graphs.values():
            return tree_root(graph.owner)
        return None

    def _stops_on_every_error(self) -> bool:
        """
        Whether this script writes `Stop` to `$ErrorActionPreference` anywhere at all, which makes
        every error terminating — a failing cast, a division by zero and a member access on `$null`
        among them, not only what a command reports. The session reads it
        (`refinery.lib.scripts.ps1.analysis.session.Ps1Session.stops`), counting an assignment and
        a cmdlet that writes the variable by name alike.

        This is the wider of the two whole-script arming gates. `$PSDefaultParameterValues` binds an
        action into commands and reaches no cast, so it is read on the per-command path
        `_a_stop_default_is_in_force` feeds rather than here.

        Position is deliberately not asked. The preference is a variable of the session rather than
        of a block, so a write in one body governs a raise in another and a write inside a branch
        governs everything that runs after it; a script that arms it at all is therefore read as
        arming it throughout. That direction keeps handlers, and what it costs — junk `trap` beside
        a script that arms `Stop` — is a shape an obfuscator has no reason to emit.

        The tree is read rather than the graphs. What the graphs place is statements, and their
        elements nest, so a walk per placed element reads an inner subtree once per level of
        nesting around it and still misses what stands at no point they model — a `param` block
        default among it.
        """
        root = self._script
        return root is not None and session_of(root).stops

    def _a_stop_default_is_in_force(self) -> bool:
        """
        Whether this script binds `Stop` into every command through `$PSDefaultParameterValues`,
        which makes any command's reported error terminating while leaving a failing cast the
        stepped-over error it is. This is why it is read on the per-command terminating path
        `_ends_the_script` follows rather than in `_stops_on_every_error`: that gate escalates every
        error, casts included, and the default table does not reach a cast.

        Position is not asked, for the reason `_stops_on_every_error` gives: the table is a variable
        of the session, so a write in one body governs a command in another, and a script that arms
        it at all is read as arming it throughout. The tree is read rather than the graphs, so a
        write standing at a point no graph models is not missed.
        """
        if self._stop_default is None:
            root = self._script
            self._stop_default = root is not None and any(
                writes_stop_to_the_default_table(node) for node in root.walk()
            )
        return self._stop_default

    def strict_mode_may_be_in_force(self) -> bool:
        """
        Whether this script may arm strict mode anywhere at all, which makes reading a variable that
        was never set an error instead of a `$null`.

        Two consumers, both reading it as the one model of whether the script arms strict mode.
        `refinery.lib.scripts.ps1.analysis.effects.expression_cannot_fault` is the single place
        deciding whether a bare variable read can raise before a removal site deletes it;
        `refinery.lib.scripts.ps1.deobfuscation.constants.Ps1NullVariableInlining` stands its whole
        pass down where this holds, because a never-assigned read it would rewrite to `$null` is a
        terminating error under strict mode and the value would decide a branch the script never
        reaches. Measured on 5.1: under the default semantics `$unset | ForEach-Object { [void]$_ }`
        writes nothing and the script runs on, so removing it is invisible; under
        `Set-StrictMode -Version 1` the same line raises a statement-terminating error that a
        `catch` and a `trap` both take, so removing it is exactly what
        `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` exists to refuse.

        Position is not asked, and the reason is not the one `_stops_on_every_error` gives. Which
        scopes an arming covers is not one rule: `Set-StrictMode` writes the scope it stands in and
        `Set-PSDebug -Strict` writes the global one, so the first arms nothing outside the function
        it is written in and the second arms everything that runs anywhere afterwards. Reading the
        whole script is what covers both without deciding which was meant. `Set-StrictMode -Off` is
        not distinguished from an arming either, since reading the argument buys back only the
        recall of a script that turns strict mode off again.

        **What this cannot see is an arming that is not in the script.** Strict mode is resolved by
        walking the scope chain to the global scope, so a script dot-sourced from a session that
        armed it — a profile, a stage-1 loader, an analyst's console — runs strict while spelling
        nothing. Nothing readable says whether that happened, so the grant this feeds assumes the
        entry scope runs the default semantics, the way
        `refinery.lib.scripts.ps1.analysis.worldflow` assumes a leak does not re-run the statements
        above it. A fragment carved out of a larger script is the case where the assumption is worth
        doubting.

        Where the graphs place no script this refuses rather than reading as the lax default.
        `_stops_on_every_error` answers `False` there safely, because a missed arming only keeps a
        handler; this one grants a *removal*, so a script the graphs hold nothing of has to refuse it
        rather than read as running under the lax default.
        """
        if self._strict is None:
            root = self._script
            self._strict = root is None or any(
                _arms_strict_mode(node) for node in root.walk()
            )
        return self._strict

    def strict_mode_v2_may_be_in_force(self) -> bool:
        """
        Whether this script may arm strict mode at version 2 or above, under which the `Count` and
        `Length` the object adapter fakes onto a scalar or `$null` raise `PropertyNotFoundStrict`
        rather than answering. Folding one of those to its value would stand a number where the
        script terminated and decide a branch it never reaches, so the fold in
        `refinery.lib.scripts.ps1.deobfuscation.folding` stands down where this holds and keeps the
        real members — a `String`'s own `Length`, an array's own `Count` — that read on regardless.

        This is the version-sensitive sibling of `strict_mode_may_be_in_force`: that one refuses a
        removal wherever any strict mode is armed, because reading an unset variable raises under
        version 1 too, and so treats `Set-PSDebug -Strict` and every `-Version` alike. The fake
        adapter members survive version 1, so this asks the narrower question, and everything the
        two share — position not asked, an arming outside the script not seen, an empty script
        refusing — is shared for the reasons written there.
        """
        if self._strict_v2 is None:
            root = self._script
            self._strict_v2 = root is None or any(
                _arms_strict_mode_v2(node) for node in root.walk()
            )
        return self._strict_v2


class _OfferedScan:
    """
    Which points are offered to the `trap` sets of which block, which `trap` statements may run, and
    which points the dispatch places nowhere, judged in graph order and only as far as a question
    needs: every line of a script is judged after every edit otherwise, where the first line that
    raises into a set usually answers the question. Every question is an existence question or a
    walk over one block's offered points in that order, so each answer equals the one a scan judging
    every point first would give. The graphs are listed when the scan is made, so that what it reads
    is the graphs of the tree it was made for.
    """

    def __init__(self, faults: Ps1FaultReach, raises: RaiseVerdicts):
        self.raises = raises
        self._by_owner: dict[int, list[Node]] = {}
        self._traps_run: set[int] = set()
        self._unplaced: list[Node] = []
        self._owners_of: dict[int, tuple[frozenset[Ps1TrapStatement], set[int]]] = {}
        self._dispatch = faults.dispatch
        self._points = self._every_point(list(faults.control_flow.graphs.values()))
        self._done = False

    @staticmethod
    def _every_point(graphs: list[ControlFlowGraph]) -> Iterator[Node]:
        for graph in graphs:
            for cfg_node in graph.nodes:
                point = cfg_node.element
                if point is None or isinstance(point, (Ps1CatchClause, Ps1TrapStatement)):
                    continue
                yield point

    def _advance(self) -> bool:
        """
        Judge points until one raises, and record where the dispatch offers it; `False` once every
        point is judged.
        """
        if self._done:
            return False
        for point in self._points:
            kinds = self.raises.kinds(point)
            if not kinds:
                continue
            fate = self._dispatch.fate(point, kinds)
            if fate is None:
                self._unplaced.append(point)
                return True
            trapped = fate.trapped
            known = self._owners_of.get(id(trapped))
            if known is None:
                owners: set[int] = set()
                for trap in trapped:
                    self._traps_run.add(id(trap))
                    if trap.parent is not None:
                        owners.add(id(trap.parent))
                known = self._owners_of[id(trapped)] = (trapped, owners)
            for owner in known[1]:
                self._by_owner.setdefault(owner, []).append(point)
            return True
        self._done = True
        return False

    def offered_to(self, owner: Node) -> Iterator[Node]:
        """
        The points offered to the `trap` set *owner* holds, in graph order.
        """
        index = 0
        while True:
            points = self._by_owner.get(id(owner), ())
            if index < len(points):
                yield points[index]
                index += 1
            elif not self._advance():
                return

    def is_offered(self, owner: Node) -> bool:
        """
        Whether a point is offered to a set *owner* holds, or one the dispatch places nowhere stands
        inside *owner*.
        """
        while True:
            if self._by_owner.get(id(owner)) or any(_descends(point, owner) for point in self._unplaced):
                return True
            if not self._advance():
                return False

    def unplaced_within(self, owner: Node) -> bool:
        """
        Whether a point the dispatch places nowhere stands inside *owner*.
        """
        while self._advance():
            pass
        return any(_descends(point, owner) for point in self._unplaced)

    def may_run(self, trap: Node) -> bool:
        """
        Whether *trap* may run, or the dispatch places some point nowhere.
        """
        while True:
            if id(trap) in self._traps_run or self._unplaced:
                return True
            if not self._advance():
                return False


class _Reading(Protocol):
    """
    One reading of where an error goes, asked under every value of the outward flag it reads.
    """

    def fate(self, point: Node, kinds: Ps1ErrorKind) -> Ps1Fate | None:
        ...


class _Unguarded:
    """
    A reading of a called body by a caller that does not pass errors outward: the run a removed
    `trap` leaves, where the called body's error stays in the body.
    """

    def __init__(self, reading: Ps1Reading):
        self._reading = reading

    def fate(self, point: Node, kinds: Ps1ErrorKind) -> Ps1Fate | None:
        return self._reading.fate(point, kinds, False)


class _Region:
    """
    The stretch of the statement *outer* of *graph* that one run executes from the statements in
    *inners* on and the other does not, read in the run *reading* describes.
    """

    def __init__(self, outer: Node, graph: ControlFlowGraph, reading: _Reading):
        self.outer = outer
        self.graph = graph
        self.reading = reading
        self.inners: dict[int, Node] = {}


class _Regions:
    """
    The regions a removal makes, one per statement and reading, each gathering the statements its
    run carries on after.
    """

    def __init__(self):
        self._regions: dict[tuple[int, int], _Region] = {}

    def add(self, outer: Node, graph: ControlFlowGraph, reading: _Reading, inner: Node) -> None:
        key = (id(outer), id(reading))
        region = self._regions.get(key)
        if region is None:
            region = self._regions[key] = _Region(outer, graph, reading)
        region.inners[id(inner)] = inner

    def __iter__(self) -> Iterator[_Region]:
        return iter(self._regions.values())


class _Holders(NamedTuple):
    """
    The statements holding a site that may run a body: those *own* names, and, where *shared*, the
    ones holding a call the call graph cannot attribute.
    """
    own: frozenset[int]
    shared: bool


class _Scope(NamedTuple):
    """
    The scope of the `trap` set the list *owner* holds, deleted by group *group* of a batch:
    whether the set is offered an error, the bodies a point of the list may run (`None` for every
    body), and the statements holding a site that may run the body the list is written in (`None`
    for every statement holding a call). A statement stands in it where it stands in the list, in
    one of the bodies, or is one of the statements.
    """
    group: int
    owner: Node
    offered: bool
    bodies: frozenset[int] | None
    holders: _Holders | None


class _Found:
    """
    The scopes a statement stands in by one route, counted so that whether one of another group, or
    one the statement's own list does not hold, is among them is a lookup rather than a walk.
    """

    def __init__(self):
        self._total = 0
        self._groups: dict[int, int] = {}
        self._owners: dict[int, int] = {}
        self._pairs: dict[tuple[int, int], int] = {}
        self._offered_total = 0
        self._offered: dict[int, int] = {}

    def add(self, scope: _Scope) -> None:
        group, owner = scope.group, id(scope.owner)
        self._total += 1
        self._groups[group] = self._groups.get(group, 0) + 1
        self._owners[owner] = self._owners.get(owner, 0) + 1
        self._pairs[group, owner] = self._pairs.get((group, owner), 0) + 1
        if scope.offered:
            self._offered_total += 1
            self._offered[group] = self._offered.get(group, 0) + 1

    @property
    def empty(self) -> bool:
        return not self._total

    def another(self, group: int, owner: int) -> bool:
        """
        Whether a scope of a group other than *group*, of a list other than *owner*, is among these.
        """
        return (
            self._total
            - self._groups.get(group, 0)
            - self._owners.get(owner, 0)
            + self._pairs.get((group, owner), 0)
        ) > 0

    def offered_besides(self, group: int) -> bool:
        """
        Whether a scope offered an error, of a group other than *group*, is among these.
        """
        return self._offered_total > self._offered.get(group, 0)

    def offered_to(self, group: int) -> bool:
        """
        Whether a scope offered an error, of the group *group*, is among these.
        """
        return self._offered.get(group, 0) > 0


class _Scopes:
    """
    The scopes of the `trap` sets one batch deletes, indexed by every route by which a statement
    may stand in one: the list a scope's set is written in, the bodies it runs, and the statements
    holding a site of its body, among them those holding a call nobody can attribute, *shared*. A
    statement is then asked once of each of its ancestors rather than once per scope.
    """

    def __init__(self, shared: frozenset[int]):
        self._shared = shared
        self._by_owner: dict[int, _Found] = {}
        self._by_body: dict[int, _Found] = {}
        self._by_holder: dict[int, _Found] = {}
        self._every_body = _Found()
        self._every_call = _Found()
        self._sharing = _Found()

    def add(self, scope: _Scope) -> None:
        self._by_owner.setdefault(id(scope.owner), _Found()).add(scope)
        if scope.bodies is None:
            self._every_body.add(scope)
        else:
            for body in scope.bodies:
                self._by_body.setdefault(body, _Found()).add(scope)
        holders = scope.holders
        if holders is None:
            self._every_call.add(scope)
            return
        for holder in holders.own:
            self._by_holder.setdefault(holder, _Found()).add(scope)
        if holders.shared:
            self._sharing.add(scope)

    def holding(self, statement: Node) -> Iterator[_Found]:
        """
        The scopes *statement* stands in, by every route it stands in them by.
        """
        cursor: Node | None = statement
        while cursor is not None:
            if (found := self._by_owner.get(id(cursor))) is not None:
                yield found
            cursor = cursor.parent
        in_a_body = False
        cursor = statement.parent
        while cursor is not None:
            if isinstance(cursor, Ps1ScriptBlock):
                in_a_body = True
                if (found := self._by_body.get(id(cursor))) is not None:
                    yield found
            cursor = cursor.parent
        if in_a_body:
            yield self._every_body
        if (found := self._by_holder.get(id(statement))) is not None:
            yield found
        if id(statement) in self._shared:
            yield self._sharing
        if self._every_call.empty:
            return
        if any(isinstance(node, (Ps1CommandInvocation, Ps1InvokeMember)) for node in statement.walk()):
            yield self._every_call


class _CarryOns(NamedTuple):
    """
    For the statements of one graph: where a run carries on after one when an error lands on it,
    and where one in a block a `trap` set resumes completes.
    """
    slots: dict[int, CfgNode]
    completions: dict[int, list[CfgNode]]


def _descends(node: Node, ancestor: Node) -> bool:
    cursor: Node | None = node
    while cursor is not None:
        if cursor is ancestor:
            return True
        cursor = cursor.parent
    return False


def _anything_but(excluded: CfgNode) -> Callable[[CfgNode], bool]:
    return lambda node: node is not excluded


def _bare_call(point: Node) -> Ps1CommandInvocation | None:
    """
    The command a statement consists of and does nothing else with, a discard included.
    """
    operand = fault_operand(point)
    while True:
        if isinstance(operand, Ps1Pipeline) and len(operand.elements) == 1:
            element = operand.elements[0]
            if element.redirections:
                return None
            operand = element.expression
            continue
        if isinstance(operand, Ps1PipelineElement) and not operand.redirections:
            operand = operand.expression
            continue
        break
    if isinstance(operand, Ps1CommandInvocation) and not operand.redirections:
        return operand
    return None


def _inside_one_of(node: Node, ancestors: AbstractSet[int]) -> bool:
    cursor: Node | None = node
    while cursor is not None:
        if id(cursor) in ancestors:
            return True
        cursor = cursor.parent
    return False


def _acting(fate: Ps1Fate) -> frozenset[Node]:
    return frozenset(handler for handler in (*fate.caught, *fate.trapped) if handler_acts(handler))


def _landed(fate: Ps1Fate) -> frozenset[Node]:
    return fate.carried | fate.swallowed


def _holders_of(sites: Sequence[Node]) -> frozenset[int]:
    """
    The identities of every node holding one of *sites*, each site included.
    """
    found: set[int] = set()
    for site in sites:
        cursor: Node | None = site
        while cursor is not None and id(cursor) not in found:
            found.add(id(cursor))
            cursor = cursor.parent
    return frozenset(found)


def _arrives_nowhere(fate: Ps1Fate) -> bool:
    """
    Whether the error *fate* is the fate of never arrives where it is asked about: no handler is
    offered it, no statement takes it, and it does not leave.
    """
    return not (
        fate.carried
        or fate.caught
        or fate.swallowed
        or fate.trapped
        or fate.offered_to_traps
        or fate.replaces
        or fate.leaves
    )


def _differs_beyond_regions(before: Ps1Fate, after: Ps1Fate) -> bool:
    """
    Whether the fates *before* and *after* differ in something other than where the run carries
    on: the handlers that act, whether the run ends, what is handed to the caller, the `finally`
    bodies left, or a place to carry on on one side only.
    """
    if _acting(before) != _acting(after):
        return True
    if before.ends_run != after.ends_run:
        return True
    if before.to_caller != after.to_caller:
        return True
    if before.replaces != after.replaces:
        return True
    first = _landed(before)
    second = _landed(after)
    return first != second and (not first or not second)


def _collect_regions(
    graph: ControlFlowGraph,
    before: Ps1Fate,
    after: Ps1Fate,
    real: Ps1Reading,
    without: Ps1Reading,
    regions: _Regions,
) -> bool:
    """
    Add to *regions* the stretch between where the run with the `trap` carries on and where the run
    without it does: one place holds the other, and the run carrying on at the inner one executes
    the rest of the outer one. `False` where neither holds the other.
    """
    first = _landed(before)
    second = _landed(after)
    for a in first:
        for b in second:
            if a is b:
                continue
            if _descends(a, b):
                inner, outer, reading = a, b, real
            elif _descends(b, a):
                inner, outer, reading = b, a, without
            else:
                return False
            regions.add(outer, graph, reading, inner)
    return True


def _after(
    graph: ControlFlowGraph,
    statement: Node,
    carry_ons: _CarryOns,
) -> frozenset[CfgNode] | None:
    """
    The nodes a run enters where it carries on after the member *statement* of a list: past the
    slot a resuming `trap` set holds for it, past the node 5.1 reports at and carries on after it,
    or else past its own normal completion; `None` where none of these places it.
    """
    within = graph.builder_of([statement])
    if within is None:
        return None
    reached: set[CfgNode] = set()
    carry_on = carry_ons.slots.get(id(statement))
    if carry_on is not None:
        for successor in carry_on.successors:
            if not graph.is_exceptional(carry_on, successor) and not within(successor):
                reached.add(successor)
    found = graph.completion_of(statement)
    if found is None:
        found = carry_ons.completions.get(id(statement))
    for node in found or ():
        for successor in node.successors:
            if graph.completes_into(node, successor) and not within(successor):
                reached.add(successor)
    return frozenset(reached) if reached else None


def _raise_leaves_region(member: CfgNode, outer: Node, reading: _Reading, raises: RaiseVerdicts) -> bool:
    """
    Whether the point *member* stands for raises an error whose fate in *reading* leaves the
    statement *outer*: a handler acts, the run ends, the error goes to the caller or replaces what
    a `finally` had in flight, the dispatch places it nowhere, or the run carries on outside.
    """
    element = member.element
    if element is None or isinstance(element, (Ps1CatchClause, Ps1TrapStatement)):
        return False
    kinds = raises.kinds(element)
    if not kinds:
        return False
    fate = reading.fate(element, kinds)
    if fate is None:
        return True
    if fate.acts or fate.ends_run or fate.to_caller or fate.replaces:
        return True
    return any(
        statement is not outer and not _descends(statement, outer)
        for statement in _landed(fate)
    )


def build_fault_reach(
    control_flow: Ps1ControlFlowModel,
    calls: Callable[[], Ps1CallGraph],
    dispatch: Ps1Dispatch | None = None,
) -> Ps1FaultReach:
    """
    The `Ps1FaultReach` over one script. The reader reads its own root off *control_flow* and draws
    the sub-statement graph it answers from there, so the coarse model is passed only to locate the
    root — and reused unchanged for a script that writes no `$( )` or `@( )`, whose graph is the same
    under `descend`. *calls* is the call graph of the same root, asked only whether a call may run
    a body. *dispatch* is the evaluator *control_flow* was drawn from, where the caller holds it.
    """
    return Ps1FaultReach(control_flow, calls, dispatch)
