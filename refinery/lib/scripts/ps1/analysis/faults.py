"""
Where a terminating error raised at a point in a PowerShell script goes.

The routing itself is already in the control-flow graph:
`refinery.lib.scripts.ps1.analysis.cfg` joins every statement of a guarded region to the handler
that may be offered its errors, chains `catch` clauses and `trap` sets in the order the engine
consults them, and edges to the body exit where the error gets past all of them. What is here is
the reading of that graph — which handlers a point reaches, whether the error may leave the body,
and the transpose, which points a handler is reachable from.

**Three questions, and the difference between them is the whole of this module.** *Does an error
raised here reach a handler that acts* is a property of a **position**, and it is what a pass asks
before it empties a guarded body. *Would deleting this statement change which handler runs* is a
property of a **statement**, and it additionally needs to know whether the statement can raise at
all — `refinery.lib.scripts.ps1.analysis.effects.fault_is_observed` asks that one, because the
predicate that answers it lives there. *Is this handler still reachable from anything that raises*
is the **transpose**, and it is what a pass asks before deleting a `trap`, where the statement being
removed cannot itself raise and every error it re-routes belongs to something else.

A body boundary is where this stops. The graphs are per body, so an error that leaves a function
reaches whatever guards the *call*, and no graph here holds both. `leaves_the_body` reports that
rather than guessing, and a caller reads it as *unknown* wherever a caller might be guarding.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

from refinery.lib.scripts import Node, tree_root
from refinery.lib.scripts.analysis.cfg import (
    CfgEdge,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
)
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.ast import (
    STATEMENT_LIST_EXPRESSIONS,
    argument_text,
    assignment_target_variables,
    binding_key,
    binds_parameter,
    bound_argument_value,
    is_soft_error_source,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.data import COMMON_PARAMETERS
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1IntegerLiteral,
    Ps1RealLiteral,
    Ps1Script,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1Variable,
)

#: The names the `-ErrorAction` parameter answers to, lowercased and without the dash: the parameter
#: itself and every alias the collected command data records for it. The alias is subscripted rather
#: than defaulted, so that a collected surface which stops carrying this parameter fails the load
#: rather than silently dropping the spelling, as `refinery.lib.scripts.ps1.data` does for its own
#: derived sets.
_ERROR_ACTION_NAME = 'erroraction'
_ERROR_ACTION = frozenset((_ERROR_ACTION_NAME, *COMMON_PARAMETERS[_ERROR_ACTION_NAME]))

#: Every name a *common* parameter answers to, so that an abbreviation of one can be told from an
#: abbreviation that reaches several. A command carrying `-ErrorAction` carries the whole set of
#: them — that is what makes a command advanced — so a prefix reaching another member of this set
#: reaches it on the very commands the question is about.
_COMMON_SURFACES = frozenset(
    surface
    for parameter, aliases in COMMON_PARAMETERS.items()
    for surface in (parameter, *aliases)
)

#: The `ActionPreference` member that makes an error terminating, and the number that member is.
#: `Stop` and `1` are the two spellings the corpus measures directly.
#:
#: Neither is read literally. The ordinal is read as a *number* rather than as a numeral, because
#: what selects the member is its value and `0x1`, `01` and `1` all denote it. The name is read by
#: prefix, because 5.1 resolves `-ErrorAction St` to `Stop`.
#:
#: An **ambiguous** member prefix is a third thing, and the reading costs recall rather than
#: correctness. `-ErrorAction S` reaches `SilentlyContinue`, `Stop` and `Suspend`, and 5.1 answers
#: it with a `ParameterBindingException` — `CannotConvertArgumentNoMessage`, measured — so the
#: command never runs at all and the error it reports instead is statement-terminating: the script
#: carries on. Reading the prefix as `Stop` keeps a handler over that, which is the safe direction
#: and is what `TestPs1AnAmbiguousActionPrefixKeepsTheTrapOverIt` records.
_STOP = 'stop'
_STOP_ORDINAL = 1

#: The automatic variable that decides what a command does with an error it reports. Set to `Stop`
#: it makes every one of them terminating — a failing cast included, which is otherwise reported
#: and stepped over.
_ERROR_ACTION_PREFERENCE = 'erroractionpreference'


class Ps1FaultRouting(NamedTuple):
    """
    Where a terminating error raised at one point may go: the handlers it may be offered to, in no
    particular order, and whether it may get past all of them and leave the body.

    `handlers` holds `Ps1CatchClause` and `Ps1TrapStatement` nodes and is a *may* set — a type
    filter is matched by inheritance at run time, so a clause that cannot be shown to miss is
    reported alongside the one after it.

    The two fields answer different questions and a caller reads both. A handler that acts makes the
    error observable however the rest of the routing looks; `leaves_the_body` beside a `trap` is the
    escalation that ends the body, and beside nothing at all it is the ordinary unhandled error that
    5.1 reports and steps over.
    """
    handlers: tuple[Ps1CatchClause | Ps1TrapStatement, ...]
    leaves_the_body: bool


#: What the graphs place nothing for, and therefore claim nothing about. Every query answers `None`
#: for a node it cannot place, and every caller reads that as *the error may go anywhere*.
UNPLACED = None


def _binds_the_error_action(written: str) -> bool:
    """
    Whether the parameter name *written* at a call site binds `-ErrorAction` and nothing else.

    5.1 binds a parameter by any prefix of its name that no other parameter of the command answers
    to, which `refinery.lib.scripts.ps1.ast.binds_parameter` reads. What it cannot read on its own
    is the *ambiguity*, and here that is decidable: every command carrying `-ErrorAction` carries
    every common parameter, so a prefix reaching a second common name reaches it on exactly the
    commands this asks about. `-e`, `-er` and `-erro` all reach `-ErrorVariable` as well and are
    measured not to stop; `-errora` reaches this one alone and is measured to stop.

    Refusing an ambiguous prefix is also what keeps a native command out: `powershell.exe -e <b64>`
    hands `-e` to a program rather than to a parameter binder, and reading it as an error action
    pins every handler in the script around the commonest shape in this project's corpus.
    """
    reached = {surface for surface in _COMMON_SURFACES if binds_parameter(written, surface)}
    return bool(reached) and reached <= _ERROR_ACTION


def _rethrows(handler: Ps1TrapStatement) -> bool:
    """
    Whether *handler* disposes of an error by re-raising it, which a `trap` spells as an unlabelled
    `break` — measured: `& { trap { break }; [int]'a' }` ends the script where the same block
    without the handler reports the cast and carries on.

    A `break` written inside a loop of the trap's own body leaves that loop instead and is read here
    as a rethrow all the same, because the statement list is read rather than the control flow. That
    keeps a handler rather than dropping one, and the exact reading is the builder's
    `refinery.lib.scripts.ps1.analysis.cfg` already makes for the block the `trap` is written in.
    """
    body = handler.body.body if handler.body is not None else ()
    return any(
        isinstance(statement, Ps1BreakStatement) and statement.label is None
        for statement in body
    )


def _selects_stop(value: Node | None) -> bool:
    """
    Whether *value* selects `Stop`, as the argument of `-ErrorAction` or as what a write to
    `$ErrorActionPreference` stores. A value this cannot read is read as selecting it: the question
    decides whether a handler is load bearing, and a value computed at run time may be anything.

    A numeral is read for the number it denotes rather than for the text it is written as, because
    what selects the member is the ordinal and `0x1`, `01` and `1` all denote it.
    `refinery.lib.scripts.ps1.ast.argument_text` deliberately answers a numeral's spelling, which
    is the right reading where a bare word names something and the wrong one here. A name is
    matched by prefix, for the same reason a parameter name is.
    """
    if isinstance(value, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return value.value == _STOP_ORDINAL
    text = argument_text(value)
    if text is None:
        return True
    text = text.strip().lower()
    return bool(text) and (text == str(_STOP_ORDINAL) or _STOP.startswith(text))


def _stops_on_error(command: Ps1CommandInvocation) -> bool:
    """
    Whether *command* carries `-ErrorAction Stop`, which turns every error it reports into one that
    ends the script wherever nothing handles it.

    The parameter and its argument are two arguments rather than one: 5.1 binds a bare `-Name value`
    pair by position and only the `-Name:value` spelling arrives as a single named argument, so both
    shapes are read here. A parameter written last with nothing after it binds no value at all,
    which 5.1 rejects, and is read as `Stop` for the same reason an unreadable value is.

    Every occurrence is read rather than the first, so that a name bound by a prefix 5.1 would in
    fact reject cannot hide the parameter written after it — reading such a name as this one is
    then the over-approximation the name set claims it is, rather than a verdict on the command. A
    command carrying a splat is read as carrying the parameter for the same reason: the names it
    binds are in a table this cannot see into.
    """
    arguments = [
        argument for argument in command.arguments
        if isinstance(argument, Ps1CommandArgument)
    ]
    for index, argument in enumerate(arguments):
        value = argument.value
        if isinstance(value, Ps1Variable) and value.splatted:
            return True
        if not _binds_the_error_action(argument.name):
            continue
        if argument.kind is not Ps1CommandArgumentKind.NAMED:
            following = arguments[index + 1] if index + 1 < len(arguments) else None
            value = None
            if following is not None and following.kind is Ps1CommandArgumentKind.POSITIONAL:
                value = following.value
        if _selects_stop(value):
            return True
    return False


def _writes_stop_to_the_preference(node: Node) -> bool:
    """
    Whether *node* assigns `$ErrorActionPreference` a value that may be `Stop`.

    The target is read through `refinery.lib.scripts.ps1.ast.assignment_target_variables`, so that
    a type-constrained, parenthesized or multi-assignment target is the same write as a bare one,
    and keyed through `refinery.lib.scripts.ps1.ast.binding_key`, so that the unrelated
    process-global `$env:ErrorActionPreference` is not read as this variable.
    """
    if not isinstance(node, Ps1AssignmentExpression):
        return False
    if not any(
        binding_key(variable) == _ERROR_ACTION_PREFERENCE
        for variable in assignment_target_variables(node.target)
    ):
        return False
    return _selects_stop(node.value)


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
    `a_stop_may_be_in_force` makes beside it. `Invoke-Expression 'Set-StrictMode -Version 1'`
    arms it as surely as writing the command does, and a script that spells either name anywhere is
    read as arming it — the direction that refuses a removal rather than granting one.
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
    the two poles of the question. Only a `-Version` that is provably the integer `1` is read as
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


#: The automatic variables through which a `Stop` can be armed for commands that did not ask for
#: one: the preference itself, and the table that binds `-ErrorAction` into every command that takes
#: it. Spelled as names rather than as assignment shapes because `a_stop_may_be_in_force` asks
#: whether either is *touched* at all, however it is spelled.
_STOP_BEARING_NAMES = frozenset({
    _ERROR_ACTION_PREFERENCE,
    'psdefaultparametervalues',
})


def a_stop_may_be_in_force(root: Node) -> bool:
    """
    Whether anything in *root* may make an error a command reports into a terminating one — the
    strict counterpart of the whole-script question `Ps1FaultReach` asks itself, and a different
    question from it.

    That one reads an assignment of `Stop` to `$ErrorActionPreference`, and reads it *laxly* on
    purpose: it decides whether a handler may be removed, where a missed arming keeps a handler that
    could have gone and costs recall on junk. Two spellings it is known to miss are ledgered as
    behaviour defects — `New-Variable ErrorActionPreference Stop -Force`, and a `-ErrorAction` entry
    written into `$PSDefaultParameterValues`.

    A caller asking whether a *statement completed* cannot inherit those. Reading a script as arming
    nothing where it does says a command that in fact raised ran to its end, and a value it was going
    to establish is then resolved through at every use below it — which rewrites calls a run never
    makes. So this asks the wider question: does the script touch either name at all, in any way,
    including naming one in a string that a command could set it through. What that costs is the
    recall of every script that so much as mentions the preference, which is a shape worth refusing.

    A variable occurrence must carry the name exactly; a string value need only *contain* one,
    which is the same asymmetry `refinery.lib.scripts.ps1.analysis.worldflow._names_own_path`
    makes, and for the same reason. A provider path spells the name inside a larger word, and
    `Set-Item Variable:ErrorActionPreference Stop` arms it as surely as the assignment does — as
    does a payload handed to `Invoke-Expression`. Matching the whole literal instead reads a script
    that really arms `Stop` as arming nothing, which is the one direction that rewrites a call the
    run does not make.
    """
    for node in root.walk():
        if isinstance(node, Ps1Variable) and binding_key(node) in _STOP_BEARING_NAMES:
            return True
        written = string_value(node)
        if written is not None and any(
            name in written.lower() for name in _STOP_BEARING_NAMES
        ):
            return True
    return False


def ends_the_script(element: Node) -> bool:
    """
    Whether an error raised at *element* stops the script, rather than being reported and stepped
    over, where no handler takes it.

    PowerShell has two kinds of error a `trap` sees, and they are disposed of differently where
    there is no `trap` — which is the whole reason this question is worth asking. A
    **statement-terminating** error ends the statement it was raised in and the next statement runs:
    a failing cast, a division by zero, a member access on `$null`, an exception out of a .NET
    method, an unresolved command name. A **terminating** error ends the script, and only `throw`
    and a command told to stop raise one. Both halves are measured.

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
    it. See `_rethrows`.
    """
    for node in element.walk():
        if isinstance(node, Ps1ThrowStatement):
            return True
        if isinstance(node, Ps1TrapStatement) and _rethrows(node):
            return True
        if isinstance(node, Ps1CommandInvocation) and _stops_on_error(node):
            return True
    return False


def handler_acts(handler: Ps1CatchClause | Ps1TrapStatement) -> bool:
    """
    Whether running *handler* changes what the script does.

    An empty `catch { }` swallows the error and lets execution resume after the construct, so a
    script that never raises reaches the same next statement — which is why an obfuscator writes one
    and why removing what it guards costs nothing. A `trap` is the same rule with one more spelling:
    a body holding only an unlabelled `break` or `continue` decides how the error is disposed of and
    emits nothing, while a body holding anything else — a call, an assignment, or a bare value the
    engine writes to the output stream — is a handler whose running is observable.
    """
    body = handler.body.body if handler.body is not None else ()
    if isinstance(handler, Ps1CatchClause):
        return bool(body)
    for statement in body:
        if isinstance(statement, (Ps1BreakStatement, Ps1ContinueStatement)):
            if statement.label is not None:
                return True
            continue
        return True
    return False


def _handled_in_the_body(routing: Ps1FaultRouting) -> bool:
    """
    Whether a handler of the body the error was raised in disposes of it in a way a run can see: a
    `catch` or `trap` that acts, or a `trap` set the error may get past, which 5.1 answers by ending
    the body rather than by reporting the error and stepping over it.

    A `catch` that misses does not end the body — the sharp asymmetry between the two keywords — so
    the escalation reading is keyed to the `trap` and not to the escape.
    """
    if any(handler_acts(handler) for handler in routing.handlers):
        return True
    return routing.leaves_the_body and any(
        isinstance(handler, Ps1TrapStatement) for handler in routing.handlers
    )


def _escapes(routing: Ps1FaultRouting) -> bool:
    """
    Whether an error routed like *routing* gets past every handler of the body it was raised in. A
    handler set it cannot leave settles it there; an empty set settles nothing, which the graphs
    spell as no handlers and no exceptional edge out of the body.
    """
    return not routing.handlers or routing.leaves_the_body


def _normal_successors(graph: ControlFlowGraph, node: CfgNode) -> frozenset[CfgNode]:
    """
    The nodes control reaches from *node* along a plain fall-through edge — where a soft error at
    *node* steps over to, which is the same node its value flows to when it does not fail.
    """
    return frozenset(
        successor for successor in node.successors
        if graph.edge_kind(node, successor) == CfgEdge.NORMAL
    )


def _resumption_slot(graph: ControlFlowGraph, node: CfgNode) -> CfgNode | None:
    """
    The slot a resuming handler carries *node*'s error to — the `CfgEdge.RESUMPTION_FORWARD`
    successor — or `None` where nothing resumes this node.
    """
    for successor in node.successors:
        if graph.edge_kind(node, successor) & CfgEdge.RESUMPTION_FORWARD:
            return successor
    return None


class Ps1FaultReach:
    """
    The fault routing of one script, read off its control-flow graphs.

    Built over `refinery.lib.scripts.analysis.cfg.ControlFlowModel`: where an error goes is decided
    by the graph the builder already wired, so this needs no semantic model, no call graph and no
    world. It is a view rather than a solver — every answer is one walk over the exceptional edges,
    memoized per node for the life of the model, and the model itself is discarded whenever the tree
    moves. The graph it reads is the sub-statement one
    `refinery.lib.scripts.ps1.analysis.cfg.build_control_flow_model` draws with `descend`, so that a
    soft error stepping over inside a `$( )` or `@( )` — and a `trap` written among those inner
    statements — is a point it places rather than detail hidden in the one node the coarse graph
    gives the whole statement. It draws that itself from its own root on first demand, so no caller
    can hand it a graph too coarse to see the step-over and remove a load-bearing trap.
    """

    def __init__(self, control_flow: ControlFlowModel):
        self._given = control_flow
        self._model: ControlFlowModel | None = None
        self._forward: dict[int, Ps1FaultRouting] = {}
        self._backward: dict[int, bool] = {}
        self._handled: set[int] | None = None
        self._ending: dict[int, bool] = {}
        self._stopping: bool | None = None
        self._strict: bool | None = None
        self._strict_v2: bool | None = None

    @property
    def _control_flow(self) -> ControlFlowModel:
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
            self._model = self._given
            if isinstance(root, Ps1Script) and any(
                isinstance(node, STATEMENT_LIST_EXPRESSIONS) for node in root.walk()
            ):
                self._model = build_control_flow_model(root, descend=True)
        return self._model

    def routing_at(self, node: Node) -> Ps1FaultRouting | None:
        """
        Where an error raised at *node* may go, or `None` when the graphs place *node* nowhere —
        a body they do not descend into, or an expression evaluated at no point they model.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return UNPLACED
        return self._routing(*located)

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

    def escapes_the_body(self, node: Node) -> bool:
        """
        Whether an error raised at *node* gets past every handler written in the body *node* stands
        in, so that where it goes next is decided by whatever ran that body and not by anything the
        body itself says.

        A position the graphs place nowhere settles nothing and escapes nothing; `False` is the
        answer that leaves such a node to the position question, which reads an unplaced node as
        observed.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return False
        routing = self._routing(*located)
        return not _handled_in_the_body(routing) and _escapes(routing)

    def observed_at(self, node: Node) -> bool:
        """
        Whether an error raised at *node* changes which code runs: some handler it reaches acts, a
        `trap` set may decline it and end the body, or the graphs place *node* nowhere.

        This is the question about the **position** and not about the statement standing there —
        it answers the same for a statement that cannot raise at all, which is what a caller
        weighing whether a guarded body may be emptied wants to know.

        What the body itself decides is `_handled_in_the_body`; what is left over once the error
        gets past it is this.

        **An error that gets past a function's own handlers is the caller's**, and no graph here
        holds both ends of a call. Measured: the same function whose error is reported and stepped
        over when called at script scope abandons its remaining statements and runs the `catch` of a
        `try` written around the *call*, however many bodies deep the raise is. So a raise in a body
        something may call is refused wherever the script holds a handler that acts — and granted
        where it holds none, since a `catch` that is not written cannot be the one guarding the
        call.

        **A terminating error that escapes the script scope ends the run**, so deleting its raise
        would start the tail that never ran. `_reading_is_observed` reads a raise escaping to the
        script owner as unobserved — right for the statement-terminating errors 5.1 reports and steps
        over, wrong for the terminating ones. So when the error gets past the body unhandled and
        `_terminates` names the raise fatal, it is observed. This is the forward reading of the same
        termination the transpose `_removal_matters` already weighs.
        """
        located = self._control_flow.locate(node)
        if located is None:
            return True
        graph, start = located
        routing = self._routing(graph, start)
        if self._reading_is_observed(graph, routing):
            return True
        return _escapes(routing) and self._terminates(node)

    def _reading_is_observed(self, graph: ControlFlowGraph, routing: Ps1FaultRouting) -> bool:
        """
        Whether an error routed like *routing* out of *graph* changes what runs. The one reading of
        a routing there is, so that the position question, the arrival question `_observed_from`
        asks of a fallback, and anything later that reads a routing cannot answer it three ways.
        """
        if _handled_in_the_body(routing):
            return True
        if not _escapes(routing):
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

    def leaves_the_body(self, node: Node) -> bool:
        """
        Whether an error raised at *node* may get past every handler of the body it is in, so that
        where it goes next is a question about the caller. `True` for a node the graphs cannot
        place, which is the same answer for the same reason.
        """
        routing = self.routing_at(node)
        return routing is None or routing.leaves_the_body

    def removing_a_handler_is_observed(self, handler: Node) -> bool:
        """
        Whether deleting *handler* may change which code runs — the transpose, and the question
        asked before a `trap` is deleted.

        A `trap` cannot itself raise, so the forward question answers nothing about removing one:
        what changes is where the errors of *other* statements go. Two things have to be true for
        that to matter, and asking only one gets it wrong in either direction.

        **Something has to still reach it.** Walking the exceptional edges backwards from the
        handler's own node finds exactly the statements whose errors it may be offered, and a
        handler nothing reaches is one whose deletion re-routes nothing — which is how a `trap` left
        behind by the removal of the only raise in its block becomes removable in turn. The walk
        crosses other handlers, because a `catch` that misses hands the error on and the statement
        that raised it is behind that clause rather than at it.

        **What the handler itself emits is deliberately not asked here**, and it is a hole: a body
        that writes runs exactly when the handler is offered an error, so `trap { 'h' }` beside a
        raise puts `h` on the output stream where an unhandled error writes only its record — and
        this reports it removable. Asking `handler_acts` of the handler under test closes it and
        costs the injected-noise shape `refinery.lib.scripts.ps1.deobfuscation.deadcode`
        deliberately drops, because `_raisers` counts every statement the block offers rather than
        every statement that may raise. The two are one question and it is not settled here.

        **And what it would fall back to has to act.** Deleting a handler sends its errors to
        whatever the graph records as its fallback, so the question is asked again there: an empty
        `catch` beside it swallows exactly as it did, and a `trap` at script scope with nothing
        outside it lets an error be reported and stepped over, which is what an unhandled error
        already did. A fallback the graph does not record is refused, because a handler whose
        counterfactual is unknown is one whose removal cannot be judged.

        **A `trap` set that may decline is load bearing for declining**, not only for handling. It
        is what turns an error 5.1 would report and step over into one that ends the body, so
        deleting it starts running everything written after the raise:

            trap [System.IO.IOException] { }

        guards nothing and is still the whole reason a script stops where it does.
        """
        located = self._control_flow.locate(handler)
        if located is None:
            return True
        graph, start = located
        if start.element is not handler:
            # The climb left the handler behind, so the node this would answer about stands for the
            # statement around it and every question below reads the wrong element.
            return True
        remembered = self._backward.get(id(start))
        if remembered is None:
            remembered = self._backward[id(start)] = self._removal_matters(graph, start)
        return remembered

    def _removal_matters(self, graph: ControlFlowGraph, start: CfgNode) -> bool:
        raisers = self._raisers(graph, start)
        if not raisers:
            return False
        if any(self._terminates(raiser) for raiser in raisers):
            return True
        element = start.element
        routing = self._routing(graph, start)
        if isinstance(element, Ps1TrapStatement) and routing.leaves_the_body:
            return True
        if any(handler_acts(handler) for handler in routing.handlers):
            return True
        if isinstance(element, Ps1TrapStatement) and self._soft_step_over_is_observed(element):
            return True
        fallback = graph.fallback_of(start)
        if fallback is None:
            return True
        return self._observed_from(graph, fallback)

    def _soft_step_over_is_observed(self, handler: Node) -> bool:
        """
        Whether removing a resuming `trap` changes what runs because it catches a
        statement-terminating error whose local step-over differs from where the trap resumes.

        A failed cast inside `$( )` steps over to the next statement *within* the subexpression, and
        the subexpression then yields that value; the trap instead resumes past the whole statement
        the `$( )` sits in. Where those two land differently the trap is load-bearing, and a coarse
        graph could not tell them apart because the whole statement is one node there. On the
        sub-statement graph this reader reads, the raiser has both edges: a `NORMAL` one to its local
        step-over and a `RESUMPTION_FORWARD` one to the slot the trap resumes at. A soft raiser
        standing at statement level has those two edges land on the same slot, so it never keeps the
        trap; only one inside a `$( )` or `@( )` can differ. Existential over the soft raisers the
        handler catches, because one redirected raiser is enough to keep the trap; equal successors
        share all downstream behaviour, so this only ever keeps a trap — never removes a load-bearing
        one — which is the sound direction for a may-analysis.
        """
        located = self._control_flow.locate(handler)
        if located is None or located[1].element is not handler:
            return False
        graph, start = located
        for raiser in self._exceptional_closure(graph, start, forward=False):
            element = raiser.element
            if element is None or not is_soft_error_source(element):
                continue
            local = _normal_successors(graph, raiser)
            slot = _resumption_slot(graph, raiser)
            resumed = _normal_successors(graph, slot) if slot is not None else frozenset()
            if local != resumed:
                return True
        return False

    def _observed_from(self, graph: ControlFlowGraph, arrival: CfgNode) -> bool:
        """
        Whether an error arriving at *arrival* changes what runs: *arrival* is a handler that acts,
        or the routing onward from it is one `_reading_is_observed` calls observable — including the
        body boundary, because an error that gets past *arrival* is the caller's exactly as one
        raised at a position is.
        """
        element = arrival.element
        if isinstance(element, (Ps1CatchClause, Ps1TrapStatement)) and handler_acts(element):
            return True
        return self._reading_is_observed(graph, self._routing(graph, arrival))

    def _routing(self, graph: ControlFlowGraph, start: CfgNode) -> Ps1FaultRouting:
        """
        The routing out of *start*, remembered for the life of this model. Every reader goes through
        here so that a node's closure is walked once however many questions are asked about it.
        """
        remembered = self._forward.get(id(start))
        if remembered is None:
            remembered = self._forward[id(start)] = self._route(graph, start)
        return remembered

    def _route(self, graph: ControlFlowGraph, start: CfgNode) -> Ps1FaultRouting:
        handlers: list[Ps1CatchClause | Ps1TrapStatement] = []
        leaves = False
        for node in self._exceptional_closure(graph, start, forward=True):
            if node is graph.exit:
                leaves = True
            elif isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement)):
                handlers.append(node.element)
        return Ps1FaultRouting(tuple(handlers), leaves)

    def _raisers(self, graph: ControlFlowGraph, start: CfgNode) -> list[Node]:
        """
        The statements whose errors *start* may be offered, which is the backward walk over the
        exceptional edges. They are reported rather than counted, because what would become of an
        error if this handler were gone is a question about the statement that raises it.
        """
        return [
            node.element
            for node in self._exceptional_closure(graph, start, forward=False)
            if node.element is not None
            and not isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement))
        ]

    def _ends_the_script(self, element: Node) -> bool:
        """
        `ends_the_script` for *element*, remembered for the life of this model. Every handler judged
        against the same block is offered the same statements, so the subtree behind each one is
        read once however many removals ask about it.
        """
        remembered = self._ending.get(id(element))
        if remembered is None:
            remembered = self._ending[id(element)] = ends_the_script(element)
        return remembered

    def _terminates(self, element: Node) -> bool:
        """
        Whether an error raised at *element* ends the run rather than being reported and stepped
        over: the script writes `Stop` to `$ErrorActionPreference` anywhere, or the raise is one of
        the terminating shapes `_ends_the_script` names. The one predicate the position question and
        the transpose both read, so a raise the trap-removal side reads as script-ending is read the
        same way on the path that weighs deleting the raise itself.
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
        every error a command reports a terminating one.

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
                _writes_stop_to_the_preference(node) for node in root.walk()
            )
        return self._stopping

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

        **The empty pole is the opposite of the sibling's, and it is why this is not a copy of it.**
        `_stops_on_every_error` answers `False` where the graphs place no script, which is safe
        because a missed arming there only keeps a handler. This one grants a *removal*, so a script
        the graphs hold nothing of has to refuse it rather than read as running under the lax
        default.
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

    @staticmethod
    def _exceptional_closure(
        graph: ControlFlowGraph, start: CfgNode, *, forward: bool,
    ) -> Iterator[CfgNode]:
        """
        The nodes reachable from *start* over exceptional edges alone, in either direction, without
        *start* itself. One sweep rather than a walk per edge kind: the graph marks an edge by the
        pair of nodes it joins, so the direction decides only which end of the pair the walk holds.
        """
        seen = {id(start)}
        stack = [start]
        while stack:
            current = stack.pop()
            adjacent = current.successors if forward else current.predecessors
            for node in adjacent:
                edge = (current, node) if forward else (node, current)
                if not graph.is_exceptional(*edge) or id(node) in seen:
                    continue
                seen.add(id(node))
                yield node
                stack.append(node)


def build_fault_reach(control_flow: ControlFlowModel) -> Ps1FaultReach:
    """
    The `Ps1FaultReach` over one script. The reader reads its own root off *control_flow* and draws
    the sub-statement graph it answers from there, so the coarse model is passed only to locate the
    root — and reused unchanged for a script that writes no `$( )` or `@( )`, whose graph is the same
    under `descend`.
    """
    return Ps1FaultReach(control_flow)
