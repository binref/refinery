"""
Where a terminating error raised at a point in a PowerShell script goes.

Where an error raised at a point ends up — which handlers take it, where the run carries on, and
whether it ends the run or is handed to a caller — is answered by
`refinery.lib.scripts.ps1.analysis.dispatch`, and every question about a point here reads it there.
The control-flow graph of `refinery.lib.scripts.ps1.analysis.cfg` draws the same routes without the
state an error carries along them; what is read off it here is the transpose, which points a
handler is reachable from, and the step-over and landing regions the `trap` removal weighs.

This module answers three questions. *Does an error raised here change which code runs* is a
property of a **position**. *Would deleting this statement change which handler runs* is a
property of a **statement**, and it additionally needs to know whether the statement can raise at
all — `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` asks that one, because the
predicate that answers it lives there. *Is this handler still reachable from anything that raises*
is the **transpose**, and it is what a pass asks before deleting a `trap`, where the statement being
removed cannot itself raise and every error it re-routes belongs to something else. The transpose
still reads its routes off the graph rather than off the evaluator, and so reads the escalation
state the graph does not carry by rules of its own (`_SetFacts`, `_reraises`), each of which reads
what a handler means from `refinery.lib.scripts.ps1.analysis.handlers` as the evaluator does.

A body boundary is where the position question stops. An error that leaves a function reaches
whatever guards the *call*, and no reading here holds both: `Ps1Fate.to_caller` reports that rather
than guessing, and a caller reads it as *unknown* wherever a caller might be guarding.
"""
from __future__ import annotations

import enum

from typing import AbstractSet, Callable, Iterator, NamedTuple, Protocol, Sequence

from refinery.lib.scripts import Node, tree_root, tree_version
from refinery.lib.scripts.analysis.cfg import (
    CfgEdge,
    CfgNode,
    ControlFlowGraph,
    Projection,
    distinct,
    plain_successors,
)
from refinery.lib.scripts.analysis.components import Condensation
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1CallGraph
from refinery.lib.scripts.ps1.analysis.cfg import (
    Ps1ControlFlowModel,
    Ps1ReportNode,
    Ps1TrapSet,
    build_control_flow_model,
)
from refinery.lib.scripts.ps1.analysis.dispatch import (
    ERROR_KINDS,
    HANDED_BACK,
    Ps1Dispatch,
    Ps1ErrorKind,
    Ps1Fate,
    preferences_of,
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
    writes_stop_to_the_preference,
)
from refinery.lib.scripts.ps1.ast import (
    STATEMENT_LIST_EXPRESSIONS,
    bound_argument_value,
    fault_operand,
    is_soft_error_source,
    raises_a_caught_terminating_error,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
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



class _EmptyCatch(NamedTuple):
    """
    A place an error may reach that takes it and carries on after a statement: an empty `catch`
    clause, which carries on after its `try`, or a report node, which carries on after the statement
    `refinery.lib.scripts.ps1.analysis.cfg.Ps1ReportNode.carries_on_after` names. Kept with the
    nodes control reaches from there, and that statement.
    """
    clause: CfgNode
    resumes: frozenset[CfgNode]
    statement: Node | None


class _Route(NamedTuple):
    """
    What the readers of a routing ask of it, settled once for a stretch of error-carrying edges
    rather than recounted from its handler list by every position that shares the stretch: whether
    some handler on it acts, whether it passes a `trap`, whether it offers the error to any handler
    at all, whether the error may leave the body, and where the empty `catch` clauses it passes
    resume.

    Every statement of a guarded block has the same edge out — into the first handler of the set
    guarding it — so all of them share one of these, where a handler list per statement costs the
    length of the handler chain once per statement: a script that writes a hundred `trap` lines
    among four thousand statements pays four hundred thousand steps to say the same thing four
    thousand times. For the same reason a route is of fixed size: the one question asked of the
    empty clauses is whether one resumes somewhere other than a given position steps over to, and
    two clauses resuming at distinct slots settle that for every position, so no more than two are
    kept. A clause is kept beside its slot because a reader measuring the run up to that slot needs
    the `try` the clause belongs to.
    """
    acts: bool
    passes_a_trap: bool
    offers_a_handler: bool
    leaves_the_body: bool
    empty_catches: tuple[_EmptyCatch, ...]

    def joined(self, other: _Route) -> _Route:
        """
        The route of an error that may take either this stretch or *other*.
        """
        catches = self.empty_catches
        if other.empty_catches and len(catches) < 2:
            for catch in other.empty_catches:
                if len(catches) > 1:
                    break
                if all(catch.resumes != kept.resumes for kept in catches):
                    catches = (*catches, catch)
        return _Route(
            self.acts or other.acts,
            self.passes_a_trap or other.passes_a_trap,
            self.offers_a_handler or other.offers_a_handler,
            self.leaves_the_body or other.leaves_the_body,
            catches,
        )


#: The route of an error that reaches nothing: no handler and no way out of the body.
_NOWHERE = _Route(False, False, False, False, ())


def _arrival(
    graph: ControlFlowGraph,
    node: CfgNode,
    reraises: Callable[[CfgNode], bool],
) -> _Route:
    """
    What an error arriving at *node* contributes to a route through it: the handler it is offered
    to there, or the body exit. *reraises* names the `trap` entries that hand the error back up
    although the graph draws no edge for it — a body that runs off its end where a `Stop` preference
    may be in force — and the error is read as leaving the body there.
    """
    element = node.element
    if isinstance(node, Ps1ReportNode):
        catch = _EmptyCatch(node, _normal_successors(node), node.carries_on_after)
        return _Route(False, False, False, False, (catch,))
    if isinstance(element, Ps1CatchClause):
        empty = element.body is None or not element.body.body
        catches = (_EmptyCatch(node, _normal_successors(node), element.parent),) if empty else ()
        return _Route(handler_acts(element), False, True, False, catches)
    if isinstance(element, Ps1TrapStatement):
        return _Route(handler_acts(element), True, True, reraises(node), ())
    if node is graph.exit:
        return _Route(False, False, False, True, ())
    return _NOWHERE


def _handled_in_the_body(route: _Route) -> bool:
    """
    Whether a handler of the body the error was raised in disposes of it in a way a run can see: a
    `catch` or `trap` that acts, or a `trap` set the error may get past, which 5.1 answers by ending
    the body.

    A `catch` that misses does not end the body, but a `trap` the error gets past does, so the
    escalation reading is keyed to the `trap` and not to the escape.
    """
    return route.acts or route.leaves_the_body and route.passes_a_trap


def _escapes(route: _Route) -> bool:
    """
    Whether an error routed like *route* gets past every handler of the body it was raised in. A
    handler set it cannot leave settles it there; an empty set settles nothing, which the graphs
    spell as no handlers and no exceptional edge out of the body.
    """
    return not route.offers_a_handler or route.leaves_the_body


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



def _resumption_slot(graph: ControlFlowGraph, node: CfgNode) -> CfgNode | None:
    """
    The slot a resuming handler carries *node*'s error to — the `CfgEdge.RESUMPTION_FORWARD`
    successor — or `None` where nothing resumes this node.
    """
    for successor in node.successors:
        if graph.edge_kind(node, successor) & CfgEdge.RESUMPTION_FORWARD:
            return successor
    return None


class Ps1StepOverRegion:
    """
    What one run makes that another, carrying on at `resumed`, does not: the code a resuming `trap`
    skips for every soft raiser that resumes at one slot, which the untrapped run executes from the
    raiser's step-over up to `resumed`, the nodes control reaches from the slot; or, for a `trap`
    set whose errors would land at `resumed` without it, the code its own resumption runs first.

    The walk follows every forward edge — a later statement that fails runs a `catch` body the
    trapped run never reaches — and stays inside the statements *within* holds, the ones it
    measures. A run that leaves them does not come back to `resumed`: it breaks out of a loop,
    returns, or takes an error further out, while the other run carries on in place. So a node
    outside them is not walked past and is read as observed, except a `trap` entry, which is read by
    what its body does. Such an entry belongs to the set whose skip a step-over region measures,
    whose edges the untrapped run it walks does not take, or to a set around the statements that a
    later error of the trapped run a landing region walks is offered to; where that set may hand the
    error further out, `Ps1ErrorPaths.landings` names the place it lands as a landing of its own,
    whose region walks the run up to there. A `trap` entry inside them is followed along the error
    edges it hands an error on by, and its body is not walked.

    Built once per slot for all its raisers, because raisers resuming at the same slot skip
    overlapping stretches of the same statement — the second of two raisers in a block skips a
    suffix of what the first skips — and a walk per raiser costs the square of the block. The region
    is condensed from every step-over, never entering a node of `resumed`, so that whether a raiser
    skips something observable is one look at the components its step-over reaches. What runs from
    `resumed` on is shared by both runs, so a write skipped is observable exactly when something
    reached from there reads it. Whether a statement is observable is not this class's to say;
    `query` pairs the region with a reader that says it.
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

    def skips(self, raiser: CfgNode, step: frozenset[CfgNode]) -> bool:
        """
        Whether a statement on the fall-through from *step*, the local step-over of *raiser*, up to
        where the trap resumes is observed, *raiser* itself excepted.
        """
        condensation = self._condensation
        number = condensation.number_of(raiser)
        if number is not None and condensation.looped(number):
            members = self._observed_members(number)
            if len(members) > 1 or members and members[0] != id(raiser):
                return True
            return any(self._reaches_observed(other) for other in condensation.downstream(number))
        for node in step:
            reached = condensation.number_of(node)
            if reached is not None and self._reaches_observed(reached):
                return True
        return False

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


class Ps1Divergence(NamedTuple):
    """
    A soft raiser whose local step-over lands off where a resuming `trap` carries on: the step-over,
    and the slot the trap resumes at.
    """
    step: frozenset[CfgNode]
    slot: CfgNode


def _is_a_trap_entry(node: CfgNode) -> bool:
    """
    Whether *node* is the entry of a `trap`. Behind a set's chain on the error edges, such an entry
    belongs to an inner set that re-raises or declines the errors it is offered, past any `finally`
    between the two.
    """
    return isinstance(node.element, Ps1TrapStatement)


def raiser_of(node: CfgNode) -> Node | None:
    """
    The statement *node* stands for when a handler behind it may be offered that statement's own
    errors, as opposed to a handler entry a walk passes through or a point standing for no element.
    """
    element = node.element
    if element is None or isinstance(element, (Ps1CatchClause, Ps1TrapStatement)):
        return None
    return element


class Ps1Landing(NamedTuple):
    """
    One place the errors a resuming `trap` set takes would land were none of the set written: the
    region a run covers before it gets there, shared by every set landing at the same place, and the
    steps this set resumes at, from which it runs into that region.
    """
    region: Ps1StepOverRegion
    steps: tuple[frozenset[CfgNode], ...]


class Ps1LandingSite(NamedTuple):
    """
    Where control carries on after an error a `trap` set takes, were the set not written: the
    nodes reached from there, and the statement a run that carries on there leaves to reach them,
    within which the run the set makes instead is measured.
    """
    resumed: frozenset[CfgNode]
    statement: Node


class _Landings(NamedTuple):
    """
    The landings of every `trap` set of one graph, keyed by the set's identity, `None` for a set
    whose landings cannot all be named, and the distinct regions they share.
    """
    by_set: dict[int, list[Ps1Landing] | None]
    regions: list[Ps1StepOverRegion]


class _Divergences(NamedTuple):
    """
    Every soft raiser of one graph whose step-over lands off where its trap resumes, and the
    step-overs of those raisers grouped by the slot they resume at.
    """
    by_raiser: dict[CfgNode, Ps1Divergence]
    steps_by_slot: dict[CfgNode, list[frozenset[CfgNode]]]


class Ps1ErrorPaths:
    """
    The error-carrying edges of one graph, condensed once into strongly connected components, so
    that what a position, a handler or a raiser asks of them is read off a component rather than
    walked again from every node that asks. Everything here is a fact of the graph; a question that
    needs the semantic model is asked through `behind` with a test and a memo the asker owns.

    Forward, every component carries the `_Route` of an error that arrives at it: what its own
    members offer the error, joined with the routes of the components it hands the error on to.
    Backward, a question about the statements whose errors a handler may be offered is an
    existential over everything behind the handler's component, decided once per component for one
    test.

    The `trap` sets the builder wired into the graph are what the landing questions read: where the
    errors a set takes would land were it not written, and what the run the set makes instead
    covers before it gets there.
    """

    def __init__(
        self,
        graph: ControlFlowGraph,
        trap_sets: Sequence[Ps1TrapSet],
        reraises: Callable[[CfgNode], bool] = lambda node: False,
    ):
        self.graph = graph
        self._reraises = reraises
        self._trap_sets = tuple(trap_sets)
        self._landings: _Landings | None = None
        self._holders: dict[int, tuple[Node, Ps1TrapSet]] | None = None
        onward = {
            node: distinct(target for target in node.successors if graph.is_exceptional(node, target))
            for node in graph.nodes
        }
        self._onward = onward
        self._condensation = Condensation(graph.nodes, onward.__getitem__)
        components = self._condensation.components

        def own(number: int) -> _Route:
            route = _NOWHERE
            for member in components[number]:
                route = route.joined(_arrival(graph, member, reraises))
            return route

        self._routes = self._condensation.accumulate(own, _Route.joined, downstream=True)
        self._from: dict[CfgNode, _Route] = {}
        self._handlers: dict[CfgNode, tuple[Ps1CatchClause | Ps1TrapStatement, ...]] = {}
        self._divergences: _Divergences | None = None
        self._regions: dict[CfgNode, Ps1StepOverRegion] = {}

    def route_from(self, start: CfgNode) -> _Route:
        """
        The route of an error raised at *start*: everything its error-carrying edges reach, *start*
        itself excluded even where a cycle would lead back to it.
        """
        route = self._from.get(start)
        if route is None:
            condensation = self._condensation
            number = condensation.number_of(start)
            assert number is not None
            route = _NOWHERE
            if condensation.looped(number):
                for member in condensation.components[number]:
                    if member is not start:
                        route = route.joined(_arrival(self.graph, member, self._reraises))
            for other in condensation.downstream(number):
                route = route.joined(self._routes[other])
            self._from[start] = route
        return route

    def handlers_from(self, start: CfgNode) -> tuple[Ps1CatchClause | Ps1TrapStatement, ...]:
        """
        The handlers an error raised at *start* may be offered, in the order a depth-first walk over
        the error-carrying edges first meets them. Spelled out only for a caller that asks for the
        list itself; every reading inside this module asks `route_from`.
        """
        handlers = self._handlers.get(start)
        if handlers is None:
            found: list[Ps1CatchClause | Ps1TrapStatement] = []
            seen = {start}
            stack = [start]
            while stack:
                for node in self._onward[stack.pop()]:
                    if node in seen:
                        continue
                    seen.add(node)
                    stack.append(node)
                    if isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement)):
                        found.append(node.element)
            handlers = self._handlers[start] = tuple(found)
        return handlers

    def behind(self, start: CfgNode, member: Callable[[CfgNode], bool], memo: dict[int, bool]) -> bool:
        """
        Whether *member* holds of some node whose errors may reach *start*, *start* itself excluded.
        *memo* is filled per component and belongs to the caller beside *member*: the same memo
        handed in with another test answers for the first one.
        """
        condensation = self._condensation
        number = condensation.number_of(start)
        assert number is not None
        components = condensation.components
        others = (node for node in components[number] if node is not start)
        if condensation.looped(number) and any(member(node) for node in others):
            return True

        def test(other: int) -> bool:
            return any(member(node) for node in components[other])

        return any(
            condensation.holds(other, test, memo, downstream=False)
            for other in condensation.upstream(number)
        )

    def divergence(self, node: CfgNode) -> Ps1Divergence | None:
        """
        Where the soft error a raise at *node* would step over lands off where the trap resuming it
        carries on, or `None` where *node* is no soft raiser or its step-over lands where the trap
        resumes anyway — a raiser standing at statement level of the guarded block is one.
        """
        return self._table().by_raiser.get(node)

    def region(self, slot: CfgNode) -> Ps1StepOverRegion:
        """
        The region every soft raiser resuming at *slot* skips into.
        """
        region = self._regions.get(slot)
        if region is None:
            steps = self._table().steps_by_slot.get(slot, [])
            region = self._regions[slot] = Ps1StepOverRegion(
                steps, _normal_successors(slot), self._within([self.holder_of(slot)]))
        return region

    def holder_of(self, slot: CfgNode) -> Node:
        """
        The statement of a resuming block that *slot* resumes past.
        """
        return self._resumed_by(slot)[0]

    def _resumed_by(self, slot: CfgNode) -> tuple[Node, Ps1TrapSet]:
        """
        The statement of a resuming block that *slot* resumes past, and the `trap` set of that block
        which resumes there.
        """
        holders = self._holders
        if holders is None:
            holders = self._holders = {
                id(resumes_at): (statement, trap_set)
                for trap_set in self._trap_sets
                for statement in trap_set.statements
                if (resumes_at := trap_set.slots.get(id(statement))) is not None
            }
        return holders[id(slot)]

    def _within(self, statements: list[Node]) -> Callable[[CfgNode], bool]:
        """
        The test for a node built for one of *statements*. Each is a statement of a resuming block
        or the `try` of an empty `catch`, both members of a sequence the graph was built from, so
        one the graph did not record is a contradiction of the builder.
        """
        within = self.graph.builder_of(statements)
        if within is None:
            raise LookupError('the graph built no statement sequence holding one of the statements')
        return within

    def regions(self) -> list[Ps1StepOverRegion]:
        """
        The region of every slot some soft raiser of this graph diverges to, and every region a
        resuming `trap` set of this graph skips relative to where its errors would land without it.
        """
        regions = [self.region(slot) for slot in self._table().steps_by_slot]
        regions.extend(self._landing_table().regions)
        return regions

    def arrival_at(self, node: CfgNode) -> _Route:
        """
        The route of an error offered to *node*: what *node* itself does with it, joined with
        everything it may hand the error on to.
        """
        return _arrival(self.graph, node, self._reraises).joined(self.route_from(node))

    def landings(self, trap_set: Ps1TrapSet) -> list[Ps1LandingSite] | None:
        """
        Where control carries on after an error *trap_set* takes, were none of its members written
        and the error taken further out instead: after the `try` of an empty `catch` the error
        reaches, and at the slot an enclosing resuming `trap` set resumes the statement holding this
        block — the slot the set's own entries are wired to, since they are statements of the block
        around it. Where that enclosing set may hand the error on in turn, by a typed member that
        declines it or a member that re-raises it, the error lands at the slot of the resuming set
        around that one as well, and so on outward. `None` where the route keeps fewer empty catches
        than it passes, or reaches one whose `try` the graph built no statement for.
        """
        outward = trap_set.outward
        if outward is None:
            return None
        route = self.arrival_at(outward)
        if len(route.empty_catches) > 1:
            return None
        landings: list[Ps1LandingSite] = []
        for catch in route.empty_catches:
            statement = catch.statement
            if statement is None or self.graph.builder_of([statement]) is None:
                return None
            landings.append(Ps1LandingSite(catch.resumes, statement))
        entry = trap_set.chain[0]
        passes = route.passes_a_trap
        while passes and (slot := _resumption_slot(self.graph, entry)) is not None:
            holder, resuming = self._resumed_by(slot)
            landings.append(Ps1LandingSite(_normal_successors(slot), holder))
            entry = resuming.chain[0]
            passes = self.route_from(resuming.chain[-1]).passes_a_trap
        return landings

    def landing_regions(self, trap_set: Ps1TrapSet) -> list[Ps1Landing] | None:
        """
        For each landing of *trap_set*, the region a run covers when the set takes an error — from
        the slot it resumes at after the statement holding each soft raiser behind it — before it
        reaches that landing. `None` where the landings cannot all be named.
        """
        return self._landing_table().by_set[id(trap_set)]

    def _landing_table(self) -> _Landings:
        """
        The landings of every `trap` set of this graph. One region is built per landing for all
        the sets that land there, because sets in sibling blocks of one statement all land past
        that statement, and sets nested in statements that end together land at the same place, and
        each would otherwise walk the rest of it again. The region is bounded by all the statements
        those sets leave to land there: statements that end at one place are nested, or lie apart
        where no run passes from one to the other without leaving both.
        """
        table = self._landings
        if table is None:
            found: dict[int, list[tuple[frozenset[CfgNode], list[frozenset[CfgNode]]]] | None] = {}
            steps_by_landing: dict[frozenset[CfgNode], list[frozenset[CfgNode]]] = {}
            left: dict[frozenset[CfgNode], dict[int, Node]] = {}
            for trap_set in self._trap_sets:
                landings = self.landings(trap_set)
                if landings is None:
                    found[id(trap_set)] = None
                    continue
                steps = self._resume_points(trap_set)
                found[id(trap_set)] = [(site.resumed, steps) for site in landings if steps]
                for site in landings:
                    steps_by_landing.setdefault(site.resumed, []).extend(steps)
                    left.setdefault(site.resumed, {})[id(site.statement)] = site.statement
            regions = {
                landing: Ps1StepOverRegion(steps, landing, self._within([*left[landing].values()]))
                for landing, steps in steps_by_landing.items() if steps
            }
            by_set = {
                key: None if pairs is None else [
                    Ps1Landing(regions[landing], tuple(steps)) for landing, steps in pairs
                ]
                for key, pairs in found.items()
            }
            table = self._landings = _Landings(by_set, list(regions.values()))
        return table

    def _resume_points(self, trap_set: Ps1TrapSet) -> list[frozenset[CfgNode]]:
        """
        Where *trap_set* carries on after the soft raisers behind it: for each statement of its
        block that holds one, the nodes the slot after that statement reaches. Each statement is
        found once however many raisers it holds, by climbing from the raiser and remembering every
        element climbed through.
        """
        condensation = self._condensation
        start = trap_set.chain[0]
        number = condensation.number_of(start)
        assert number is not None
        block = {id(statement): statement for statement in trap_set.statements}
        holders: dict[int, Node | None] = {}

        def holder(element: Node) -> Node | None:
            climbed: list[int] = []
            cursor: Node | None = element
            found: Node | None = None
            while cursor is not None:
                key = id(cursor)
                if key in holders:
                    found = holders[key]
                    break
                if key in block:
                    found = cursor
                    break
                climbed.append(key)
                cursor = cursor.parent
            for key in climbed:
                holders[key] = found
            return found

        seen: set[int] = {number}
        stack = list(condensation.upstream(number))
        steps: dict[int, frozenset[CfgNode]] = {}
        while stack:
            other = stack.pop()
            if other in seen:
                continue
            seen.add(other)
            stack.extend(condensation.upstream(other))
            for node in condensation.components[other]:
                element = raiser_of(node)
                if element is None or not is_soft_error_source(element):
                    continue
                statement = holder(element)
                if statement is None:
                    continue
                slot = trap_set.slots.get(id(statement))
                if slot is not None and id(slot) not in steps:
                    steps[id(slot)] = _normal_successors(slot)
        return list(steps.values())

    def _table(self) -> _Divergences:
        table = self._divergences
        if table is None:
            by_raiser: dict[CfgNode, Ps1Divergence] = {}
            steps_by_slot: dict[CfgNode, list[frozenset[CfgNode]]] = {}
            for node in self.graph.nodes:
                found = self._diverges(node)
                if found is not None:
                    by_raiser[node] = found
                    steps_by_slot.setdefault(found.slot, []).append(found.step)
            table = self._divergences = _Divergences(by_raiser, steps_by_slot)
        return table

    def _diverges(self, node: CfgNode) -> Ps1Divergence | None:
        """
        The divergence of *node*. Whether a trap resumes it at all is asked first, because that
        reads the node's own edges where the soft-error test walks its whole statement.
        """
        slot = _resumption_slot(self.graph, node)
        if slot is None:
            return None
        element = node.element
        if element is None or not is_soft_error_source(element):
            return None
        step = _normal_successors(node)
        resumed = _normal_successors(slot)
        if not resumed or step == resumed:
            return None
        return Ps1Divergence(step, slot)


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

    def disposes_alike_without(self, removed: set[int]) -> bool:
        catching = self._catching_without(removed)
        if self._typed.isdisjoint(removed):
            return catching == self._catching
        return len(self._selectable) == 1 and catching <= self._selectable


class RaiseVerdicts(Protocol):
    """
    The semantic half of the transpose's first two questions, which this module cannot answer
    because whether a statement can raise is a fact of the semantic model: whether something behind
    a handler may raise at all, and whether something behind it may raise an error that ends the
    run.
    """

    def may_raise_behind(self, paths: Ps1ErrorPaths, start: CfgNode) -> bool:
        ...

    def may_end_the_run_behind(self, paths: Ps1ErrorPaths, start: CfgNode) -> bool:
        ...


class SkipVerdicts(Protocol):
    """
    The semantic half of the step-over question: whether some soft raiser behind a resuming handler
    would, untrapped, run a statement a run can see before reaching where the trap resumes.
    """

    def skip_observed_behind(self, paths: Ps1ErrorPaths, start: CfgNode) -> bool:
        ...

    def landing_observed(self, paths: Ps1ErrorPaths, trap_set: Ps1TrapSet) -> bool:
        ...


class Ps1FaultReach:
    """
    The fault routing of one script, read off its control-flow graphs.

    Built over `refinery.lib.scripts.ps1.analysis.cfg.Ps1ControlFlowModel`: where an error goes is
    decided by the graph the builder already wired and the `trap` sets it wired into it, so this
    needs no semantic model, no call graph and no world. It is a view rather than a solver — every
    answer is read off the error-carrying edges of a graph condensed once (`Ps1ErrorPaths`) and kept
    for the life of the model, and the model itself is discarded whenever the tree moves. The graph it reads is the sub-statement one
    `refinery.lib.scripts.ps1.analysis.cfg.build_control_flow_model` draws with `descend`, so that a
    soft error stepping over inside a `$( )` or `@( )` — and a `trap` written among those inner
    statements — is a point it places rather than detail hidden in the one node the coarse graph
    gives the whole statement. It draws that itself from its own root on first demand, so no caller
    can hand it a graph too coarse to see the step-over and remove a load-bearing trap.
    """

    def __init__(self, control_flow: Ps1ControlFlowModel, calls: Callable[[], Ps1CallGraph]):
        self._given = control_flow
        self._calls = calls
        self._model: Ps1ControlFlowModel | None = None
        self._paths: dict[ControlFlowGraph, Ps1ErrorPaths] = {}
        self._fires: dict[ControlFlowGraph, dict[int, bool]] = {}
        self._escalating: dict[ControlFlowGraph, dict[int, bool]] = {}
        self._version: int | None = None
        self._set_facts: dict[int, _SetFacts] = {}
        self._handled: set[int] | None = None
        self._ending: dict[int, bool] = {}
        self._stopping: bool | None = None
        self._stop_default: bool | None = None
        self._strict: bool | None = None
        self._strict_v2: bool | None = None
        self._dispatch: Ps1Dispatch | None = None
        self._trap_bodies: dict[int, Ps1TrapStatement | None] = {}

    @property
    def dispatch(self) -> Ps1Dispatch:
        """
        Where 5.1 sends an error raised at a point of this script, under the error preferences the
        script's session may hold.
        """
        dispatch = self._dispatch
        if dispatch is None:
            root = self._script
            session = session_of(root) if root is not None else None
            stops = self._stops_on_every_error()
            silenced = session is not None and session.silenced
            called = session is not None and (session.silenced or session.silenced_by_a_call)
            dispatch = self._dispatch = Ps1Dispatch(
                preferences_of(stops, silenced),
                preferences_of(stops, called),
            )
        return dispatch

    def fate_of(self, node: Node, kinds: Ps1ErrorKind) -> tuple[ControlFlowGraph, CfgNode, Ps1Fate] | None:
        """
        The graph and node of the point *node* stands at, and where an error of *kinds* raised there
        may end up; `None` where the graphs or the dispatch place it nowhere.
        """
        located = self._control_flow.locate(node)
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
    def _control_flow(self) -> Ps1ControlFlowModel:
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
                self._model = build_control_flow_model(root, descend=True)
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
            if self._control_flow.node_of(inner) is not None:
                yield inner

    def places(self, node: Node) -> bool:
        """
        Whether the graphs evaluate something at *node*, which makes it a point of its own.
        """
        return self._control_flow.node_of(node) is not None

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

    def kinds_a_point_may_raise(self, node: Node) -> Ps1ErrorKind:
        """
        The kinds of error the position question reads a point *node* as raising, whatever stands
        there: a statement-terminating one, and where `_terminates` names a raise at *node* fatal,
        the error of a `throw` and one no list reports as well. The removal veto's own reading of
        what a point raises is `refinery.lib.scripts.ps1.analysis.effects.point_raise_kinds`, which
        reads the operands and grants what they clear; the two meet in the one answer to whether a
        line can fail.
        """
        kinds = Ps1ErrorKind.STATEMENT
        if self._ends_the_script(node):
            kinds |= Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED
        return kinds

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
        `try` written around the *call*, however many bodies deep the raise is. So a raise in a body
        something may call is refused wherever the script holds a handler that acts — and granted
        where it holds none, since a `catch` that is not written cannot be the one guarding the
        call. An error of a `throw` or one no list reports, handed to the caller, ends the caller's
        run unless it takes it, and is observed either way.
        """
        found = self.fate_of(node, kinds)
        if found is None:
            return True
        graph, _, fate = found
        if fate.acts or fate.ends_run:
            return True
        if not fate.to_caller:
            return False
        if fate.offered_to_traps or fate.to_caller & (Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED):
            return True
        return self._handled_elsewhere(graph)

    def _reading_is_observed(self, graph: ControlFlowGraph, route: _Route) -> bool:
        """
        Whether an error routed like *route* out of *graph* changes what runs: the reading of a
        routing the set question asks where the errors of a deleted `trap` set arrive.
        """
        if _handled_in_the_body(route):
            return True
        if not _escapes(route):
            return False
        return not isinstance(graph.owner, Ps1Script) and self._handled_elsewhere(graph)

    def _handled_elsewhere(self, body: ControlFlowGraph) -> bool:
        """
        Whether this script writes a handler that acts in some body other than *body*. What guards
        a call is unknowable from the called body's graph, and this is what settles it in the
        direction of a grant: a handler written in the very body that raises is one the error has
        already got past, and a script with none anywhere else has no call site the raise could
        matter at.

        A named block is not a body of its own here, which is why the comparison is per graph: a
        `trap` in `begin` and a raise in `process` share one script block, and neither guards the
        other.
        """
        if self._handled is None:
            self._handled = {
                id(graph)
                for graph in self._control_flow.graphs.values()
                if any(
                    isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement))
                    and handler_acts(node.element)
                    for node in graph.nodes
                )
            }
        return bool(self._handled - {id(body)})

    def guarded_by_a_resuming_trap(self, node: Node) -> bool:
        """
        Whether a `trap` set that *resumes* guards *node* — one that, after taking a terminating
        error, carries execution on at the statement after the one that raised, rather than
        re-raising it (`trap { break }`) or letting it leave the body.

        The control-flow builder draws a `RESUMPTION_FORWARD` edge out of a guarded statement only
        where its block's trap set resumes — a `trap { continue }`, or a trap whose body runs off its
        end — and draws none for a re-raising set, so the mere existence of that edge answers the
        question. This is why a splice into such a body is load bearing: the edge lands on the next
        statement of the block, and splicing more statements after a raiser moves what that next
        statement is.

        Read off the descended graph the reader already holds. A `for` loop and a `try` are keyed to
        no node of their own — the builder gives each of their parts a node and names the statement
        after none of them — so `locate` places the construct itself nowhere, where an `if`, a
        `switch` and a `while` are each keyed to their head. The resumption of the block still reaches
        those parts: every point the construct owns that sits at the block's level draws the same edge
        to the same slot, so where the construct itself is placed nowhere, a point inside it that
        resumes answers for it. A construct the graph places nothing of, parts included, is guarded by
        nothing here.
        """
        located = self._control_flow.locate(node)
        if located is not None:
            return _resumption_slot(*located) is not None
        for inner in self.points_in(node):
            placed = self._control_flow.locate(inner)
            if placed is not None and _resumption_slot(*placed) is not None:
                return True
        return False

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
        located = self._control_flow.locate(element)
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
                    if self._control_flow.node_of(node) is not None and (kinds := raises(node)):
                        lowest = self._landing_depth(node, kinds)
                    for child in node.children():
                        lowest = min(lowest, table.get(id(child), float('inf')))
                    table[id(node)] = lowest
        lowest = table.get(id(statement))
        if lowest is None:
            return True
        return lowest < self.dispatch.depth_of(statement)

    def fault_the_try_catches(
        self,
        operand: Node,
        cleared: Callable[[Node], bool] | None = None,
    ) -> bool:
        """
        Whether evaluating *operand* may raise a terminating error a `try` catches. A cast, a
        fallible operator and a method call raise one whatever the error preferences say; a command
        raises one only where the script makes its error terminating, which `error_is_terminating`
        reads from `Stop`. The default command error is non-terminating — reported and stepped over —
        so the `try` does not catch it and a statement after it still runs.

        It is the fault model's rather than the effect layer's because its command arm reads the
        script's error preferences, a judgment `error_is_terminating` already owns here; the
        expression arm is the pure `raises_a_caught_terminating_error` shape from `ast`. A part of
        *operand* that *cleared* answers for cannot raise: that judgment reads values, which this
        module holds none of, so the caller hands it in.
        """
        return bool(self.kinds_the_try_catches(operand, cleared))

    def kinds_the_try_catches(
        self,
        operand: Node,
        cleared: Callable[[Node], bool] | None = None,
    ) -> Ps1ErrorKind:
        """
        The kinds of error `fault_the_try_catches` reads evaluating *operand* as raising: a
        statement-terminating one for a cast, a fallible operator and a method call, one no list
        reports for a command whose error the script makes terminating, and for a call that may run
        a body of the script, whatever that body hands back (`hands_back_a_body_error`).
        """
        kinds = Ps1ErrorKind.NONE
        if raises_a_caught_terminating_error(operand, cleared):
            kinds |= Ps1ErrorKind.STATEMENT
        if is_soft_error_source(operand, cleared) and self.error_is_terminating(operand):
            kinds |= Ps1ErrorKind.MARKED
        if self.hands_back_a_body_error(operand):
            kinds |= HANDED_BACK
        return kinds

    def hands_back_a_body_error(self, node: Node) -> bool:
        """
        Whether evaluating *node* may run a body of the script, or code the script does not spell,
        whose error then arrives where *node* stands: a command or a call there may run one
        (`refinery.lib.scripts.ps1.analysis.callgraph.Ps1CallGraph.may_run_a_body`), or a command
        there is handed a script block it may run. A script block written as a value runs only where
        something runs it, so what it holds is not read here.
        """
        calls = self._calls()
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, (Ps1CommandInvocation, Ps1InvokeMember)) and calls.may_run_a_body(current):
                return True
            for child in current.children():
                if isinstance(child, Ps1ScriptBlock):
                    if isinstance(current, (Ps1CommandInvocation, Ps1CommandArgument)):
                        return True
                    continue
                stack.append(child)
        return False

    def _fires_a_trap(self, raiser: Node) -> bool:
        """
        Whether *raiser* may fire the `trap` its block is guarded by — with a statement-terminating
        or terminating error, the only errors a `trap` runs on. A cast, a fallible operator, a method
        call or a command a `Stop` makes terminating is read through `fault_the_try_catches` over the
        raiser's `fault_operand`; a bare `throw` or a global `Stop` is read through
        `error_is_terminating`. A raiser that may run a body of the script — a function it defines, a
        script block, code it does not spell — may fire it too: a list that declares a `trap` passes
        errors outward through every body it runs, so the called body's error leaves it and arrives
        at the `trap`, as the one of a statement written there would (`hands_back_a_body_error`).

        A plain command is not counted. Its default error is non-terminating and does not fire the
        `trap`, so counting it would keep the junk a `trap` body holds that no run reaches, which the
        deletion pass is written to drop. A command whose error is terminating although no `Stop`
        is in force is a gap this shares with every other reading of whether a line can fail.
        """
        operand = fault_operand(raiser)
        if operand is not None and self.fault_the_try_catches(operand):
            return True
        return self.error_is_terminating(raiser) or self.hands_back_a_body_error(raiser)

    def never_runs(self, node: Node) -> bool:
        """
        Whether *node* stands in the body of a `trap` nothing its block holds may fire
        (`_fires_a_trap` over the statements behind the set), so that no run reaches it and deleting
        it changes nothing. A `trap` the graph places nowhere is read as one that may fire.
        """
        trap = _enclosing_trap_body(node, self._trap_bodies)
        if trap is None:
            return False
        located = self._control_flow.locate(trap)
        if located is None:
            return False
        graph, start = located
        memo = self._fires.setdefault(graph, {})
        return not self.paths_of(graph).behind(start, self._fires_a_trap_at, memo)

    def escapes_a_trap_body(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether *node* is a raise of *kinds* in the body of a `trap` whose error leaves that body and
        ends the scope the `trap` belongs to. A `trap` does not guard its own body, so a raise among
        its statements is not offered back to it: it ends the script at script scope, or the
        function where the `trap` is written inside one. Deleting such a raise runs the remainder of
        the body — and the scope past it — that the original abandoned, which is why it is the
        position half of a keep. Whether the `trap` fires at all is `never_runs`, which the caller
        asks first.
        """
        return _enclosing_trap_body(node, self._trap_bodies) is not None and self.escapes_the_body(node, kinds)

    def _fires_a_trap_at(self, node: CfgNode) -> bool:
        """
        `_fires_a_trap` asked of the statement *node* stands for, where it stands for one that
        raises at all rather than for a handler entry.
        """
        raiser = raiser_of(node)
        return raiser is not None and self._fires_a_trap(raiser)

    def deleting_the_raise_resurrects_a_continuation(self, node: Node, kinds: Ps1ErrorKind) -> bool:
        """
        Whether a live continuation runs only because a raise of *kinds* at *node* pre-empts it, so
        deleting the raise starts that continuation. The one position predicate the removal veto
        pairs with its raise half, `refinery.lib.scripts.ps1.analysis.effects.point_raise_kinds`.
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
        the transpose, and the question asked before any `trap` is deleted.

        A `trap` cannot itself raise, so the forward question answers nothing about removing one:
        what changes is where the errors of *other* statements go. The set is the unit of the
        answer, because 5.1 hands an error to one member by the error's type and not by where the
        member is written (`refinery.lib.scripts.ps1.analysis.handlers.Ps1TrapSelection`), so a member
        alone says nothing about what its block does.

        **Something that may actually raise has to still reach the set.** Walking the error edges
        backwards from the head of its chain finds the statements whose errors it may be offered,
        and *raises* keeps only those that can raise a terminating error at all: a `trap` beside a
        bare constant guards nothing, and one left behind by the removal of the only raise in its
        block becomes removable in turn. That judgment is handed in rather than made here, because
        whether an expression can fault is a fact of the semantic model this module holds none of;
        `refinery.lib.scripts.ps1.analysis.effects.Ps1HandlerVerdicts` makes it and keeps its
        answers per component of `Ps1ErrorPaths`, so that a hundred `trap` lines guarding one
        block are answered by one walk.

        **Deleting some of the members** changes nothing exactly when every error still goes to a
        member that disposes of it alike; `_SetFacts` says when.

        **Deleting every member** sends the errors the set took to whatever guards its block, and
        each of the following makes that observable:

        - a raise behind the set that would end the run untrapped;
        - a member 5.1 may select that acts: `trap { 'h' }` puts `h` on the output stream where an
          unhandled error writes only its record;
        - the set letting an error past it, by a typed member declining or a `break` re-raising,
          to a handler that acts or out of the body, which 5.1 answers by ending the body:

              trap [System.IO.IOException] { }

          guards nothing, yet it is still why the script stops where it does;
        - an inner set behind it that re-raises or declines into it, past any `finally` between the
          two, where the error would then leave the body;
        - what guards the block taking the error in a way a run can see (`_reading_is_observed`);
        - where the error would leave the body untrapped, the code the set's resumption skips that
          the untrapped run executes — read by *skips* over the `Ps1StepOverRegion` of each raiser;
        - and where the error would land instead, after the `try` of an empty `catch` or at the slot
          of an enclosing resuming set, the code the set's own resumption runs before it gets
          there (`Ps1ErrorPaths.landings`), read by *skips* as well.

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
        return self._control_flow.trap_set_of(trap)

    def _moved(self) -> bool:
        """
        Whether the tree has changed since the graphs this reader holds were built from it, or no
        graph was built yet: either way the trap sets it would read are not the tree's.
        """
        root = self._script
        if self._version is None or root is None:
            return True
        return tree_version(tree_root(root)) != self._version

    def _handler_node(self, handler: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The graph *handler* is written in and the node of the handler itself, or `None` when the
        graph has no node for it. Locating climbs to the nearest element that has one, and a node
        that stands for the statement around the handler would have every question about the
        handler read the wrong element.
        """
        located = self._control_flow.locate(handler)
        if located is None or located[1].element is not handler:
            return None
        return located

    def removals_that_wait(
        self,
        groups: Sequence[Sequence[Node]],
        raises: RaiseVerdicts,
    ) -> set[int]:
        """
        Of `trap` deletions judged apart, one group to each verdict, the indices of the groups whose
        deletions have to wait until the others have landed and they are judged again.

        `removing_traps_is_observed` reads one graph, the body the set is written in, and within it
        the blocks around the set and the blocks inside it: the handlers around it decide where its
        errors go once it is gone and where they land, and the sets inside it decide whether errors
        reach it escalated. Beyond that body it reads only whether a handler that acts is written
        anywhere else, and a deletion can only make that answer more permissive. Nothing of this is
        read unless something may raise into the set, and a deletion elsewhere puts a raiser behind
        a set only by deleting a set inside it that took the raiser's errors. So of two deletions
        judged apart, only one inside a block that loses a `trap` to the other may stop holding once
        both land, and only where it may be offered an error. That inner group waits; the outer one
        was judged with the inner one standing, and it still does. The members of one group were
        weighed against each other by their own verdict and are not asked about here.
        """
        written: dict[int, set[int]] = {}
        for index, group in enumerate(groups):
            for handler in group:
                if (block := handler.parent) is not None:
                    written.setdefault(id(block), set()).add(index)
        waiting: set[int] = set()
        for index, group in enumerate(groups):
            if any(self._waits(handler, index, written, raises) for handler in group):
                waiting.add(index)
        return waiting

    def _waits(
        self,
        handler: Node,
        index: int,
        written: dict[int, set[int]],
        raises: RaiseVerdicts,
    ) -> bool:
        """
        Whether the deletion of *handler*, one of group *index*, waits for a group that deletes a
        handler in a block around it; *written* maps each block to the groups deleting a handler
        written directly in it.
        """
        if (located := self._handler_node(handler)) is None:
            return True
        graph, start = located
        if not raises.may_raise_behind(self.paths_of(graph), start):
            return False
        block = handler.parent
        while block is not None and block is not graph.owner:
            block = block.parent
            if block is not None and any(other != index for other in written.get(id(block), ())):
                return True
        return False

    def _removing_matters(
        self,
        trap_set: Ps1TrapSet,
        traps: Sequence[Ps1TrapStatement],
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> bool:
        if self._moved():
            return True
        first = trap_set.chain[0]
        graph = first.graph
        paths = self.paths_of(graph)
        if not raises.may_raise_behind(paths, first):
            return False
        removed = {id(trap) for trap in traps}
        if len(removed) < len(trap_set.members):
            return not self._dispose_alike(trap_set, removed)
        return self._removing_the_set_matters(graph, paths, trap_set, raises, skips)

    def _facts(self, trap_set: Ps1TrapSet) -> _SetFacts:
        facts = self._set_facts.get(id(trap_set))
        if facts is None:
            facts = _SetFacts(trap_set, self._stops_on_every_error())
            self._set_facts[id(trap_set)] = facts
        return facts

    def _dispose_alike(self, trap_set: Ps1TrapSet, removed: set[int]) -> bool:
        return self._facts(trap_set).disposes_alike_without(removed)

    def _removing_the_set_matters(
        self,
        graph: ControlFlowGraph,
        paths: Ps1ErrorPaths,
        trap_set: Ps1TrapSet,
        raises: RaiseVerdicts,
        skips: SkipVerdicts,
    ) -> bool:
        """
        Whether deleting every member of *trap_set* changes what runs: the errors it took go to
        what guards the block instead, and land wherever that handler carries on.
        """
        first = trap_set.chain[0]
        last = trap_set.chain[-1]
        if raises.may_end_the_run_behind(paths, first):
            return True
        if self._facts(trap_set).acts:
            return True
        route = paths.route_from(last)
        if route.leaves_the_body or route.acts:
            return True
        outward = trap_set.outward
        if outward is None:
            return True
        arrival = paths.arrival_at(outward)
        escalating = self._escalating.setdefault(graph, {})
        if arrival.leaves_the_body and paths.behind(first, _is_a_trap_entry, escalating):
            return True
        if self._reading_is_observed(graph, arrival):
            return True
        if (
            (outward is graph.exit or arrival.leaves_the_body)
            and skips.skip_observed_behind(paths, first)
        ):
            return True
        return skips.landing_observed(paths, trap_set)

    def paths_of(self, graph: ControlFlowGraph) -> Ps1ErrorPaths:
        """
        The condensed error-carrying edges of *graph*, built on the first question about it and kept
        for the life of this model.
        """
        paths = self._paths.get(graph)
        if paths is None:
            trap_sets = self._control_flow.trap_sets_in(graph)
            paths = self._paths[graph] = Ps1ErrorPaths(graph, trap_sets, self._reraises)
        return paths

    def _reraises(self, node: CfgNode) -> bool:
        """
        Whether a `trap` entry hands the errors it takes back up although the graph draws no edge
        for it: a member 5.1 may select whose body runs off its end, where a `Stop` preference may
        be in force, which `refinery.lib.scripts.ps1.analysis.handlers.settled` reads as a re-raise.
        """
        trap = node.element
        if not isinstance(trap, Ps1TrapStatement) or not self._stops_on_every_error():
            return False
        trap_set = self._trap_set_of(trap)
        if trap_set is None or not trap_set.is_selectable(trap):
            return False
        ran_off = trap_set.disposition(trap) & Ps1TrapDisposition.FALLS_THROUGH
        return Ps1TrapDisposition.RETHROWS in settled(ran_off, True)

    def _converts(self, trap: Ps1TrapStatement) -> bool:
        """
        Whether *trap* turns an error it takes into one that ends the body: 5.1 may select it and
        its body may re-raise. A `trap` the graphs hold in no set is read as converting.
        """
        trap_set = self._trap_set_of(trap)
        if trap_set is None:
            return True
        return trap_set.is_selectable(trap) and trap_set.may_rethrow(trap)

    def _route(self, graph: ControlFlowGraph, start: CfgNode) -> _Route:
        """
        The route of an error raised at *start*. Every reader goes through here, so that what a
        stretch of error edges says is settled once however many positions share it.
        """
        return self.paths_of(graph).route_from(start)

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
        The one predicate the position question and the transpose both read, so a raise the
        trap-removal side reads as script-ending is read the same way on the path that weighs
        deleting the raise itself.
        """
        return self._stops_on_every_error() or self._ends_the_script(element)

    @property
    def _script(self) -> Node | None:
        """
        The tree the graphs were built over, read off the passed model's owner rather than taken as
        an argument: a graph owner is a node of that tree, and a whole-script fact has to be asked of
        the whole script rather than of the statements the graphs happen to place. It reads the model
        the constructor was handed, not the descended one `_control_flow` derives, so the root the
        descended build needs is available without asking the build for it.
        """
        for graph in self._given.graphs.values():
            return tree_root(graph.owner)
        return None

    def _stops_on_every_error(self) -> bool:
        """
        Whether this script writes `Stop` to `$ErrorActionPreference` anywhere at all, which makes
        every error terminating — a failing cast, a division by zero and a member access on `$null`
        among them, not only what a command reports. The write is read through
        `refinery.lib.scripts.ps1.analysis.session.writes_stop_to_the_preference`, which counts an
        assignment and a cmdlet that writes the variable by name alike.

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
        if self._stopping is None:
            root = self._script
            self._stopping = root is not None and any(
                writes_stop_to_the_preference(node) for node in root.walk()
            )
        return self._stopping

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


def build_fault_reach(control_flow: Ps1ControlFlowModel, calls: Callable[[], Ps1CallGraph]) -> Ps1FaultReach:
    """
    The `Ps1FaultReach` over one script. The reader reads its own root off *control_flow* and draws
    the sub-statement graph it answers from there, so the coarse model is passed only to locate the
    root — and reused unchanged for a script that writes no `$( )` or `@( )`, whose graph is the same
    under `descend`. *calls* is the call graph of the same root, asked only whether a call may run
    a body.
    """
    return Ps1FaultReach(control_flow, calls)
