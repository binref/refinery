"""
PowerShell's contribution to the shared control-flow substrate: which node types are which
control-flow shape, and where the parts of each are stored.

Everything structural lives in `refinery.lib.scripts.analysis.cfg`. What is here is the dispatch, the
accessors, and the places PowerShell's answer differs from the shape JavaScript established:

- **`switch` does not fall through, it keeps matching.** Every clause is tested against the value and
  every matching one runs, so an arm's exits may reach any *later* arm rather than only the next.
  That is `refinery.lib.scripts.analysis.cfg.ArmFlow.CUMULATIVE`, and reading it as C-style
  fallthrough would drop the path in which the first and third clauses match and the second does not.
  It also *enumerates its input*, so `continue` inside it advances to the next input value rather
  than to an enclosing loop, and a `default` clause does not make it exhaustive: over an empty
  collection no clause runs at all.
- **`if`/`elseif` is one flat statement**, not a nest, so the chain of tests is built through
  `branch_chain` and each `elseif` condition gets a node of its own.
- **`trap` guards the statement block it is written in**, not the scope around it: it catches for
  that block entire, statements written above it included, and for nothing outside it, so one
  written inside an `if` body is no handler for the body around it. Where blocks nest, the innermost
  block declaring one is the only set consulted, and a set that may fail to match passes the error
  outward rather than letting it resume. `continue` inside it resumes at the statement after the one
  that threw. See `_Builder.block`.
- **`exit` is a terminator like `return`**, modelled as one: control does not continue in this body.
  That it leaves the *script* rather than the function is a claim about the caller's body, which a
  per-body graph does not make; keeping the caller's paths is the conservative reading.
- **A label is a field of the construct**, not a statement wrapping it, so `park_label` is called
  from the dispatch rather than through `labelled`, and the `:` the lexer keeps on the declaration
  is stripped before a jump can be matched against it.

`Ps1Code` also splits one body across `begin`/`process`/`end`/`dynamicparam` blocks, so `owner.body`
alone is not what an advanced function runs.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field
from functools import partial
from typing import AbstractSet, Sequence

from refinery.lib.scripts import Block, Node
from refinery.lib.scripts.analysis.cfg import (
    ArmFlow,
    CfgBuilder,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_control_flow,
)
from refinery.lib.scripts.ps1.analysis.session import session_of
from refinery.lib.scripts.ps1.analysis.values import is_fault_free
from refinery.lib.scripts.ps1.ast import (
    STATEMENT_LIST_EXPRESSIONS,
    get_named_blocks,
    point_operands,
    string_value,
)
from refinery.lib.scripts.ps1.model import (
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1Code,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1ExitStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1Jump,
    Ps1PropertyMember,
    Ps1ReturnStatement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1WhileLoop,
)

#: The nodes that own a control-flow graph of their own, beside the script itself. A script block is
#: PowerShell's anonymous function: it is a *value* where it is written and runs somewhere else
#: entirely — as the body of `ForEach-Object`, through `&` or `.`, or as the body of a function,
#: which is the only script block a `Ps1FunctionDefinition` has and why keying on the definition
#: instead adds no graph but leaves every other block without one. A block with no graph is climbed
#: out of, so its statements are reported as running where the block is *written*: they claim to
#: precede everything after that point and lose their order among themselves.
#:
#: This is the same partition `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel.scope_of`
#: makes — one body, one scope, one graph. A `trap` divides more finely still: it belongs to the
#: statement block it is written in, of which a body is only the outermost.
FUNCTION_NODES = (Ps1ScriptBlock,)

#: The nodes whose content runs at a time of its own and outside every body a graph is drawn for.
#: A class property's initializer runs each time the class is constructed, or when the type is first
#: used for a `static` one, and never at the class statement it is written in.
DEFERRED_NODES = (Ps1PropertyMember,)

_LOOP_NODES = (
    Ps1WhileLoop,
    Ps1DoLoop,
    Ps1ForLoop,
    Ps1ForEachLoop,
)


#: The type names a `catch` clause may carry that take every terminating error Windows PowerShell
#: 5.1 raises, in the spellings 5.1 resolves. `System.Exception` is the root of the .NET hierarchy
#: and matches by definition; `RuntimeException` is what the engine wraps a terminating error in,
#: measured to match a failed cast, a division by zero, `throw` of a string, `throw` of a .NET
#: exception, a method that threw, a member access on `$null`, and a cmdlet stopped by
#: `-ErrorAction Stop`.
#:
#: The spellings are the measurement too, and they are not symmetric: a bare name is resolved
#: against `System` alone, so `[Exception]` names `System.Exception` while `[RuntimeException]`
#: names nothing at all and the clause it filters matches no error whatsoever. Listing the short
#: form of the second would grant a clause that in fact declines everything, which is the one
#: direction that deletes code.
_CATCHES_EVERY_ERROR = frozenset({
    'exception',
    'system.exception',
    'management.automation.runtimeexception',
    'system.management.automation.runtimeexception',
})


def names_every_error(name: str) -> bool:
    """
    Whether *name* is a type filter every terminating error matches. An empty name is a `trap`
    carrying no type filter, which takes every error the way a bare `catch` does. A `catch` clause
    reaches this only with the names it could read: whether it carried a filter at all is
    `Ps1CatchClause.filtered`, so an unreadable one is never spelled here as the empty name.
    """
    return not name.strip() or name.strip().lower() in _CATCHES_EVERY_ERROR


def _catch_takes_every_error(clause: Ps1CatchClause) -> bool:
    """
    Whether *clause* is certain to be the one that takes a throw the guarded block makes: it carries
    no type filter at all, or one of the filters it carries names a type every terminating error is.

    A clause carrying several types matches when *any* of them does, so one universal name among
    them settles it however narrow the others are. A clause whose filter was written but could not
    be read carries an empty `types` for a different reason than an unfiltered clause does, and
    `filtered` is what tells the two apart: erring towards *takes everything* would close the
    exceptional edge an enclosing handler still needs, so the unread filter takes nothing certain.
    """
    if not clause.filtered:
        return True
    return any(names_every_error(name) for name in clause.types)


def swallows_every_error(statement: Ps1TryCatchFinally) -> bool:
    """
    Whether every terminating error the `try` body of *statement* raises is certain to land in one
    of that statement's own `catch` clauses.

    The quantifier is the whole question, and it is an `any`: one clause that takes everything
    settles it however narrow the others are, and a construct carrying no `catch` at all swallows
    nothing, which an `all` reads as vacuously true. Answering it wrong in that direction hands a
    caller a raise it believes confined.

    What this licenses is confinement and not invisibility. A caught error is still recorded, and
    whether the script reads that record back is a different question with a different owner.
    """
    return any(_catch_takes_every_error(clause) for clause in statement.catch_clauses)


def certain_catch_all(statement: Ps1TryCatchFinally) -> Ps1CatchClause | None:
    """
    The one `catch` clause certain to take every terminating error the `try` body of *statement*
    raises, or `None` when no clause is certain to. It is the first clause, and only when that
    clause takes every error: a clause is tried in order, so a narrower one written first might
    take a specific error before the catch-all is offered it, and which handler runs then depends
    on the error's type rather than on the text. That is the reading `swallows_every_error` does not
    make — it asks only whether *some* clause is a catch-all — and it is the one a caller that lifts
    a handler body out needs, since it names *which* body runs.
    """
    clauses = statement.catch_clauses
    if not clauses:
        return None
    first = clauses[0]
    return first if _catch_takes_every_error(first) else None


def _jump_label(statement: Ps1Jump) -> str | None:
    """
    The label a `break` or `continue` names, or `None` when it names none or names one this cannot
    read. PowerShell allows the label to be any expression — `break $name` is legal — and a label
    that is not a static string is one no lexical target can be matched against, so it is treated as
    unlabelled, which resolves to the innermost enclosing target and is the conservative reading.
    """
    return string_value(statement.label) if statement.label is not None else None


def _construct_label(label: str | None) -> str | None:
    """
    The name a labelled loop or `switch` declares, without the `:` the lexer keeps on the token.

    A jump names its target without the colon, so the declaration and the reference are two
    spellings of one name and comparing them unnormalized never matches — which resolves every
    labelled jump to nothing and sends it out of the body instead of out of the construct it names.
    """
    return label[1:] if label is not None and label.startswith(':') else label


def _declared_traps(statements: Sequence[Node]) -> list[Ps1TrapStatement]:
    """
    The `trap` statements *statements* declares, in source order.

    A `trap` belongs to the statement block it is written in and to no other: it catches for that
    block entire, including the statements written above it, and an error raised outside the block
    is never offered to it. Collecting the traps of a nested block for the block around it hands
    those errors to a handler no run reaches, and — where the nested one is typed — reports a filter
    that may miss as guarding statements it does not guard at all.
    """
    return [statement for statement in statements if isinstance(statement, Ps1TrapStatement)]


class Ps1TrapDisposition(enum.Flag):
    """
    What running a `trap` body may do with the error it took, read by the builder off the body it
    builds. A body that branches may do several.
    """
    NONE = 0
    #: An unlabelled `continue` resumes the block at the statement after the one that raised.
    RESUMES = enum.auto()
    #: The body runs off its end, which writes the error record and hands the decision to
    #: `$ErrorActionPreference`: the block resumes, unless the preference is `Stop`.
    FALLS_THROUGH = enum.auto()
    #: A `break` that leaves the body re-raises the error to whatever guards the block.
    RETHROWS = enum.auto()


class Ps1TrapSet:
    """
    The `trap` statements one block declares, as the builder wired them: each member's entry and
    disposition, the members 5.1 may select in the order it tries them, and — where the set
    resumes the block — the slot it resumes at after each statement of the block. `outward` is where
    an error goes that the set does not take, and where the errors it takes would go if none of it
    were written.

    5.1 picks the member by the error's type and not by where it is written: a member naming the
    error's own type, then one naming a type the error derives from, and only then the first member
    carrying no type at all. So every typed member may take an error, in source order, and after
    them the first untyped member takes whatever no typed member matched; an untyped member after
    that one takes nothing. A typed member naming a type every terminating error is takes everything
    before the untyped members are tried at all. `selectable` holds the members 5.1 may select, in
    the order it tries them, and `catching` says which of them take an error no narrower member
    names.
    """

    def __init__(
        self,
        graph: ControlFlowGraph,
        statements: Sequence[Node],
        entries: dict[int, CfgNode],
        traps: Sequence[Ps1TrapStatement],
    ):
        self.graph = graph
        self.statements = tuple(statements)
        self.members = tuple(traps)
        self.entries = entries
        typed = tuple(trap for trap in traps if trap.type_name.strip())
        self._universal = tuple(trap for trap in typed if names_every_error(trap.type_name))
        self._untyped = tuple(trap for trap in traps if not trap.type_name.strip())
        self.selectable = (*typed, *(trap for trap in self.catching() if not trap.type_name.strip()))
        self._chosen = {id(trap) for trap in self.selectable}
        self.never_selected = tuple(trap for trap in traps if id(trap) not in self._chosen)
        self.chain = tuple(entries[id(trap)] for trap in self.selectable)
        self.dispositions: dict[int, Ps1TrapDisposition] = {}
        self.slots: dict[int, CfgNode] = {}
        self.outward: CfgNode | None = None

    def entry(self, trap: Ps1TrapStatement) -> CfgNode:
        return self.entries[id(trap)]

    def disposition(self, trap: Ps1TrapStatement) -> Ps1TrapDisposition:
        return self.dispositions[id(trap)]

    def catching(self, removed: AbstractSet[int] = frozenset()) -> tuple[Ps1TrapStatement, ...]:
        """
        The members that take an error no narrower member names, once the members whose identities
        *removed* holds are gone: every typed member left naming a type every error is, which of
        them depending on the error's type, or where none is left, the first untyped member left.
        Empty where what is left lets such an error past. Costs the members naming every error and
        the untyped members removed ahead of the first one left, not the whole set.
        """
        universal = tuple(trap for trap in self._universal if id(trap) not in removed)
        if universal:
            return universal
        return next(((trap,) for trap in self._untyped if id(trap) not in removed), ())

    def is_selectable(self, trap: Ps1TrapStatement) -> bool:
        """
        Whether 5.1 may hand *trap* an error.
        """
        return id(trap) in self._chosen

    def may_rethrow(self, trap: Ps1TrapStatement) -> bool:
        """
        Whether running the body of *trap* may hand the error it took back up with a `break`.
        """
        return Ps1TrapDisposition.RETHROWS in self.disposition(trap)


@dataclass(eq=False, repr=False)
class Ps1ReportNode(CfgNode):
    """
    The node standing for 5.1 reporting an error that leaves a `try` body, a `catch` body or a
    `trap` body where nothing is in force, and carrying on after the statement `carries_on_after`
    names. It is not a handler: an edge into it makes what follows that statement reachable, and the
    error a `Stop` makes terminating ends the run from it.
    """
    carries_on_after: Node = field(kw_only=True)


@dataclass
class _ReportFrame:
    """
    A statement being built where no `try` and no `trap` is in force, and the `Ps1ReportNode` that
    carries on after it. The node joins the graph once an error edge enters it, or once a `trap` set
    names it as its `outward`, which is `named`: where the errors that set takes would go were none
    of it written is a position the landing questions read, whether or not any error reaches it as
    written.
    """
    statement: Node
    node: CfgNode | None = None
    named: bool = False


@dataclass
class _TrapBody:
    """
    What building one `trap` body reported back: the nodes at which control resumes the block the
    `trap` guards, and whether the body reaches the `break` that rethrows.

    `resumes` collects the explicit `continue` spellings only. A body that runs off its end resumes
    too — the error record is written and the block carries on — but that is its exit frontier,
    which the caller already holds.

    `rethrows` is decided through the builder's jump-target stack rather than by finding the
    keyword: a `break` naming a loop written inside the body leaves that loop, and the `trap` goes
    on swallowing. The stack the body is built against holds nothing from outside it — see
    `_Builder.block` — because a `trap` body is a scope of its own and a jump in it can name no
    construct the block is written inside.
    """
    resumes: list[CfgNode] = field(default_factory=list)
    rethrows: bool = False


def _descended_bodies(statement: Node) -> list[list[Node]]:
    """
    The statement lists of the `STATEMENT_LIST_EXPRESSIONS` written in *statement*'s expression tree,
    in source order — the sub-statement granularity the fault reader needs and no coarser consumer
    wants.

    Only the outermost such construct on each path is collected: one nested inside another is reached
    when the outer body's statements are built, each of which passes back through `statement` and this
    descent again, so the nesting is handled by recursion through the builder rather than flattened
    here. A nested script block is its own graph and is left to it.
    """
    bodies: list[list[Node]] = []

    def collect(node: Node) -> None:
        for child in node.children():
            if isinstance(child, Ps1ScriptBlock):
                continue
            if isinstance(child, STATEMENT_LIST_EXPRESSIONS):
                bodies.append(list(child.body))
                continue
            collect(child)

    collect(statement)
    return bodies


class _Builder(CfgBuilder):
    def __init__(
        self,
        owner: Node,
        descend: bool = False,
        trap_sets: dict[int, Ps1TrapSet] | None = None,
    ):
        super().__init__(owner)
        self._trap_body: _TrapBody | None = None
        self._descend = descend
        self._trap_sets = {} if trap_sets is None else trap_sets
        session = session_of(owner)
        self._throws_step_over = (
            session.silenced
            or session.silenced_by_a_call and not isinstance(owner, Ps1Script)
        )
        self._open_sets: list[Ps1TrapSet] = []
        self._frames: list[_ReportFrame] = []

    def escape(self) -> CfgNode:
        """
        Where nothing is in force, the report node of the statement being built: 5.1 reports an
        error that leaves a `try`, `catch` or `trap` body there and carries on after the statement.
        """
        if self._handlers or not self._frames:
            return self.unwinding()
        frame = self._frames[-1]
        if frame.node is None:
            frame.node = Ps1ReportNode(self.cfg, None, carries_on_after=frame.statement)
        return frame.node

    def handler_body_guard(self) -> CfgNode | None:
        """
        A `catch` body is guarded where its `try` stands: an error leaving it is reported after the
        statement that holds the `try` where nothing is in force, which `escape` names.
        """
        return self.escape()

    def member(self, statement: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        A statement of a block, with its report frame open where nothing is in force. The report
        node joins the graph where an error edge entered it or a `trap` set named it: it carries on
        after the statement, and the error a `Stop` makes terminating ends the run from there.
        """
        if self._handlers:
            return super().member(statement, frontier)
        frame = _ReportFrame(statement)
        self._frames.append(frame)
        try:
            exits = super().member(statement, frontier)
        finally:
            self._frames.pop()
        report = frame.node
        if report is not None and (report.predecessors or frame.named):
            self.cfg.nodes.append(report)
            self.exceptional_edge(report, self.cfg.exit)
            exits = [*exits, report]
        return exits

    def offers(self, element: Node, target: CfgNode) -> bool:
        """
        A report node is not a handler: it stands for 5.1 reporting an error that was raised, and an
        edge into it makes what follows the statement it carries on after reachable. So only a point
        that may fail is joined to one: a point evaluating nothing, as a `break` does, or only what
        `refinery.lib.scripts.ps1.analysis.values.is_fault_free` clears, is not.
        """
        if not isinstance(target, Ps1ReportNode):
            return True
        operands = point_operands(element)
        return operands is None or not all(is_fault_free(operand) for operand in operands)

    def _throw_target(self) -> CfgNode | None:
        """
        Where the error a `throw` raises goes: to the `try` or `trap` in force, else where its body
        may run silently to the report node or past the `throw`, which is `None`, and else to the
        body exit, since 5.1 ends the run on a `throw` nothing takes.
        """
        handler = self._handlers[-1] if self._handlers else None
        if handler is not None and not isinstance(handler, Ps1ReportNode):
            return handler
        if self._throws_step_over:
            return handler
        return self.cfg.exit

    def _outward(self) -> CfgNode:
        """
        What guards a `trap` set being closed, which `Ps1TrapSet.outward` names. Where that is a
        report node, its frame is marked so the node joins the graph: a set that takes every error
        draws no edge into it, and the landing questions still ask where it carries on.
        """
        outward = self.unwinding()
        for frame in self._frames:
            if frame.node is outward:
                frame.named = True
        return outward

    def block(self, statements: Sequence[Node], frontier: list[CfgNode]) -> list[CfgNode]:
        """
        One statement block, with every `trap` it declares installed as a handler over the whole of
        it.

        A `trap` is not a guarded block. It is declared somewhere in the block and catches for that
        block entire, including the statements written above it, so it cannot be pushed at the point
        it appears the way a `try` is — it is pushed before the block is walked at all. Several
        traps in one block are peers and are chained the way
        `refinery.lib.scripts.analysis.cfg.CfgBuilder.guarded` chains several `catch` clauses,
        because which one runs depends on the type of the error and none of them is guaranteed.

        Where blocks nest, the innermost one declaring a `trap` is the only set the error is offered
        to, which pushing that set on the handler stack already says. The set passes the error
        outward — to the `catch` or `trap` guarding the block, and to the body exit when nothing
        guards it — exactly when it may fail to take it: every `trap` in it carrying a filter no
        error is known to match, or one of them reaching the `break` that runs the body and
        rethrows. Nothing else in a body reaches the exit on an exceptional edge without a handler
        having been offered the error, which is what tells an error that ends the script apart from
        one that is reported and stepped over.

        A trap does not guard itself: an error raised inside a trap body is offered to whatever
        the set itself unwinds to, so the trap bodies are built under that and only the block's own
        statements are built under the set. Building them under the set instead gives every node of
        every trap body an exceptional edge back to a handler that already has a normal edge into
        it, which is a cycle through the trap that no run can take — and reads as a body that
        repeats. `refinery.lib.scripts.analysis.cfg.CfgBuilder.guarded` pops before building its
        `catch` bodies for the same reason. Where nothing guards the block, the trap body is built
        under `escape`: 5.1 reports an error raised in it and carries on after the statement holding
        the block, as it does for one leaving a `try` or `catch` body.

        **A trap body is built against an empty jump-target stack**, because 5.1 compiles one as a
        scope of its own: `break` in it ends the trap and rethrows, and `continue` in it resumes the
        guarded block, whatever loop or `switch` the block itself is written inside. Leaving the
        enclosing construct's targets in place resolves both keywords to that construct instead —
        the `break` stops being a rethrow, so the set reads as swallowing an error that in fact ends
        the body, and the `continue` becomes a back-jump, so the resumption the trap exists to
        create is never wired at all.

        The *resumption* stack is deliberately not cleared the same way. A jump names a construct and
        a trap body encloses none of them; a resumption names a place control carries on at, and a
        trap body written inside a block some outer set resumes is a place that outer set carries on
        from. Clearing it would leave the body's nodes on neither projection of the level that does
        guard them.

        `continue` inside a trap resumes at the statement following the one that threw, which is a
        shape no single edge set expresses. It is therefore carried twice, as
        `refinery.lib.scripts.analysis.cfg.CfgEdge` describes: every resumption point is taken to
        reach *every* node the block owns, through the hub
        `refinery.lib.scripts.analysis.cfg.CfgBuilder.resumption` wires — the over-approximation
        an analysis asking whether any resumption path exists must read, since claiming fewer paths
        would let one call a statement after a trap unreachable, or let a store before one look dead
        because the resumption that reads it was never modelled — and, alongside it, the precise
        forward-only half (`_resumable_sequence`), which joins each statement to the one control
        actually resumes at and is what a flood reads.

        The set is opened after its own handler entries and bodies are built. A `trap` declared in
        a nested block is a statement of the block around it, so its entries and body belong to the
        *enclosing* resumable level and are wired against that one. Opening this level first would
        take them, and the forward projection would then have no
        edge saying where control goes when the inner set *declines* an error — the enclosing set
        takes it and resumes past the whole nested block, which is the one path a typed inner trap
        makes observable.
        """
        traps = _declared_traps(statements)
        if not traps:
            return self.sequence(statements, frontier)
        entries = {id(trap): self.detached_node(trap) for trap in traps}
        trap_set = Ps1TrapSet(self.cfg, statements, entries, traps)
        for trap in traps:
            self._trap_sets[id(trap)] = trap_set
        chain = trap_set.chain
        for before, after in zip(chain, chain[1:]):
            self.exceptional_edge(before, after)
        handling = list(entries.values())
        resumes: list[CfgNode] = []
        enclosing = self._trap_body
        outer_targets = self._targets
        outer_labels = self._pending_labels
        self._targets = []
        self._pending_labels = frozenset()
        self._handlers.append(self.escape())
        for trap in traps:
            self._trap_body = built = _TrapBody()
            body_from = len(self.cfg.nodes)
            falls_through = self._body(trap.body, [trap_set.entry(trap)])
            handling += self.cfg.nodes[body_from:]
            disposition = Ps1TrapDisposition.NONE
            if built.resumes:
                disposition |= Ps1TrapDisposition.RESUMES
            if falls_through:
                disposition |= Ps1TrapDisposition.FALLS_THROUGH
            if built.rethrows:
                disposition |= Ps1TrapDisposition.RETHROWS
            trap_set.dispositions[id(trap)] = disposition
            if trap_set.is_selectable(trap):
                resumes += falls_through + built.resumes
        escapes = (
            not any(names_every_error(trap.type_name) for trap in traps)
            or any(trap_set.may_rethrow(trap) for trap in trap_set.selectable)
        )
        self._handlers.pop()
        self._trap_body = enclosing
        self._targets = outer_targets
        self._pending_labels = outer_labels
        trap_set.outward = self._outward()
        self.close_handler_set(list(chain), escapes=escapes)
        self._handlers.append(chain[0])
        if not resumes:
            exits = self.sequence(statements, frontier)
        else:
            self.mark_hub_bound(handling)
            self._open_sets.append(trap_set)
            with self.resumption(resumes):
                exits = self._resumable_sequence(statements, frontier)
            self._open_sets.pop()
        self._handlers.pop()
        return exits

    def _resumable_sequence(
        self, statements: Sequence[Node], frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        The guarded statements of a block whose `trap` set resumes it, threaded as `sequence` does,
        with the precise forward-only half of resumption drawn against the open block as each node
        appears.

        What finds the point control resumes at is one elementless slot per statement, which
        `refinery.lib.scripts.analysis.cfg.CfgBuilder.resume_past` reports once the statement is
        built. The slot is then passed in the frontier the *next* statement is built from, so that
        whatever that statement control-*enters* gains an edge from it — its own node, the condition
        of an `if`, the first guarded statement of a nested block. Reading the entry off the nodes a
        statement created instead answers the wrong one for every construct that builds something
        before what it runs first: a `try` builds its handler entry first, so the forward edge would
        reach the `catch` clause and leave the body it guards reachable only through the hub, which
        is exactly the backward reach the forward half exists to avoid.

        The last statement's slot goes into the returned frontier rather than to the body exit.
        Control resuming past the end of a guarded block carries on with whatever follows the
        *block*, and for a nested one that is not the end of the body; only the caller threading
        this frontier knows where it is.

        A statement inside a nested resumable block claims that block's slot and not this one's,
        which is what makes the edge count linear in the nesting depth rather than quadratic. It
        loses no path: the nested block hands its own last slot back in the frontier this loop
        threads on, so a statement inside it still reaches the statement after the nested block. The
        slot a node draws to is the *representative* of a resumption, not the exact statement control
        lands at — no graph knows which statement threw — and what every consumer reads off it is
        where the resumption can go, not where it went.
        """
        trap_set = self._open_sets[-1]
        for statement in statements:
            built = self.member(statement, frontier)
            slot = self._resumptions[-1].slot
            if slot is not None:
                trap_set.slots[id(statement)] = slot
            frontier = self.resume_past(built)
        return frontier

    def body_blocks(self, owner: Node) -> Sequence[Sequence[Node]]:
        """
        The statement blocks *owner* runs, in the order it runs them.

        An advanced function fills `begin`/`process`/`end`/`dynamicparam` instead of `body`, and
        reading only `body` for one would report an empty graph for a function that runs a great
        deal — the same trap `refinery.lib.scripts.ps1.ast.get_named_blocks` exists to warn about.
        `dynamicparam` is pulled to the front because the engine evaluates it during parameter
        binding, before `begin`, while that accessor reports the blocks in the order they are
        declared in.

        They are kept apart rather than concatenated because each is a statement block of its own: a
        `trap` written in `begin` is offered nothing that `process` raises, and joining them hands
        it errors no run ever will.
        """
        if not isinstance(owner, Ps1Code):
            return []
        blocks = sorted(
            get_named_blocks(owner),
            key=lambda block: block is not owner.dynamicparam_block,
        )
        return [block.body for block in blocks] + [owner.body]

    def statement(self, statement: Node, frontier: list[CfgNode]) -> list[CfgNode]:
        if isinstance(statement, Block):
            return self.block(statement.body, frontier)
        if isinstance(statement, _LOOP_NODES):
            self.park_label(_construct_label(statement.label))
        if isinstance(statement, Ps1IfStatement):
            return self._if(statement, frontier)
        if isinstance(statement, Ps1WhileLoop):
            return self.loop_head_tested(statement, statement.body, frontier)
        if isinstance(statement, Ps1DoLoop):
            return self.loop_tail_tested(statement, statement.body, frontier)
        if isinstance(statement, Ps1ForLoop):
            return self.loop_counted(
                statement.initializer,
                statement.condition,
                statement.iterator,
                statement.body,
                frontier,
            )
        if isinstance(statement, Ps1ForEachLoop):
            return self.loop_head_tested(statement, statement.body, frontier)
        if isinstance(statement, Ps1SwitchStatement):
            return self._switch(statement, frontier)
        if isinstance(statement, Ps1TryCatchFinally):
            return self._try(statement, frontier)
        if isinstance(statement, Ps1TrapStatement):
            return list(frontier)
        if isinstance(statement, Ps1ExitStatement):
            return self.terminate(statement, frontier, exceptional=False)
        if isinstance(statement, Ps1ThrowStatement):
            node = self.node(statement)
            self.link(frontier, node)
            target = self._throw_target()
            if target is None:
                return [node]
            self.exceptional_edge(node, target)
            return []
        if isinstance(statement, Ps1ReturnStatement):
            return self.terminate(statement, frontier, exceptional=False)
        if isinstance(statement, Ps1BreakStatement):
            label = _jump_label(statement)
            trap = self._trap_body
            if trap is not None and not self.has_break_target(label):
                trap.rethrows = True
            return self.jump_out(statement, label, frontier)
        if isinstance(statement, Ps1ContinueStatement):
            label = _jump_label(statement)
            trap = self._trap_body
            if trap is not None and not self.has_continue_target(label):
                return self._resume(trap.resumes, statement, frontier)
            return self.jump_back(statement, label, frontier)
        if self._descend:
            descended = self._descend_statement(statement, frontier)
            if descended is not None:
                return descended
        return self.opaque(statement, frontier)

    def _descend_statement(
        self, statement: Node, frontier: list[CfgNode],
    ) -> list[CfgNode] | None:
        """
        A leaf statement carrying a value construct whose operand is a statement list — a `$( )` or a
        `@( )` — modelled at sub-statement granularity so the fault reader sees a statement-terminating
        error step over to the next statement *inside* the construct. `None` when it carries none, so
        the caller falls back to `opaque`.

        Each inner statement list is built through `block`, so a `trap` declared inside the construct
        installs as a handler over its siblings, not as noise the enclosing block owns. The inner
        frontier then feeds the outer statement's own node: the construct yields its value, then the
        statement consuming it runs. This inner-then-outer order matters: a soft raiser that is the
        last inner statement has the outer node as its successor, which keeps a trap that guards it,
        where the reverse order would drop it.

        Reached only where `descend` is set, which is only the fault reader's own graph; every other
        consumer reads the coarse model, in which this statement is one atomic node.
        """
        bodies = _descended_bodies(statement)
        if not bodies:
            return None
        for body in bodies:
            frontier = self.block(body, frontier)
        node = self.node(statement)
        self.link(frontier, node)
        return [node]

    def _resume(
        self, resumes: list[CfgNode], statement: Node, frontier: list[CfgNode],
    ) -> list[CfgNode]:
        """
        A `continue` inside a `trap` body, which is not a back-jump: it resumes the guarded block at
        the statement after the one that threw. The node is recorded for `block` to link to every
        landing point once that block exists, and control does not fall through it here.

        Reading it as a loop back-jump instead resolves it to nothing and wires it to the body exit,
        which deletes the one path the trap exists to create — and leaves the whole resumption model
        unexercised, because this is the spelling that resumes.
        """
        node = self.node(statement)
        self.link(frontier, node)
        resumes.append(node)
        return []

    def _if(self, statement: Ps1IfStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        The chain, keyed so that the whole statement is the first test's node: a caller that locates
        the `if` itself must reach a node, and the first condition is where control first arrives.
        """
        clauses: list[tuple[Node, Node | None]] = []
        for index, (condition, block) in enumerate(statement.clauses):
            clauses.append((statement if index == 0 else condition, block))
        if not clauses:
            return self.opaque(statement, frontier)
        return self.branch_chain(clauses, statement.else_block, frontier)

    def _switch(self, statement: Ps1SwitchStatement, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        The clauses as arms of an iterated, cumulative dispatch.

        A `default` clause does not make the construct exhaustive the way it does in a language
        whose `switch` tests one value: PowerShell's enumerates its input, and over an empty
        collection no clause runs at all — not even `default`. Reporting it exhaustive drops the
        edge that leaves the switch without entering any arm, which is what makes the statement
        after it look unreachable.

        An arm is handed over as the block it is rather than as the statements in it, because a
        clause body is a statement block of its own and a `trap` written in one guards that clause
        and nothing else.
        """
        arms: list[Sequence[Node]] = [
            [block] if block is not None else [] for _, block in statement.clauses
        ]
        self.park_label(_construct_label(statement.label))
        return self.dispatch(
            statement,
            arms,
            frontier,
            arm_flow=ArmFlow.CUMULATIVE,
            exhaustive=False,
            iterated=True,
        )

    def _try(self, statement: Ps1TryCatchFinally, frontier: list[CfgNode]) -> list[CfgNode]:
        """
        PowerShell allows several typed `catch` clauses where JavaScript allows one binding, so the
        clauses are chained: the guarded block reaches the first, and each clause reaches the next,
        because which one runs depends on the exception type and none of them is guaranteed.

        A clause certain to take every error leaves nothing to pass outward — which is what makes
        an empty `catch` shield the `catch` or `trap` around it where a typed one hands the error
        straight on to it. Carrying no type is one way to be certain and naming `System.Exception`
        is another; see `_catch_takes_every_error`.

        The `finally` body travels as its block for the same reason a `switch` arm does: it is a
        statement block, and a `trap` written in one guards it alone.
        """
        clauses = statement.catch_clauses
        finalizer = statement.finally_block
        return self.guarded(
            statement.try_block,
            [(clause, clause.body) for clause in clauses],
            finalizer,
            (finalizer,) if finalizer is not None else (),
            frontier,
            escapes=not swallows_every_error(statement),
        )


def build_ps1_control_flow(root: Ps1Script, descend: bool = False) -> dict[int, ControlFlowGraph]:
    """
    One control-flow graph per script block — see `FUNCTION_NODES` — and one for the script itself.

    With *descend* set, a statement carrying a `STATEMENT_LIST_EXPRESSIONS` construct is modelled at
    sub-statement granularity rather than as one atomic node — the finer graph the fault reader needs
    to see a statement-terminating error step over inside a `$( )` or `@( )`. It is off by default
    because every consumer but the fault reader wants the coarse one-statement-one-node graph, and
    turning it on changes only the graph the caller who asks for it reads.
    """
    return _build(root, descend, {})


def _build(
    root: Ps1Script,
    descend: bool,
    trap_sets: dict[int, Ps1TrapSet],
) -> dict[int, ControlFlowGraph]:
    builder = partial(_Builder, descend=descend, trap_sets=trap_sets)
    return build_control_flow(root, builder, FUNCTION_NODES)


class Ps1ControlFlowModel(ControlFlowModel):
    """
    The control-flow graphs of one script, with the `trap` sets the builder wired into them.
    """

    def __init__(self, graphs: dict[int, ControlFlowGraph], trap_sets: dict[int, Ps1TrapSet]):
        super().__init__(graphs, DEFERRED_NODES)
        self._trap_sets = trap_sets
        by_graph: dict[ControlFlowGraph, list[Ps1TrapSet]] = {}
        for trap_set in {id(trap_set): trap_set for trap_set in trap_sets.values()}.values():
            by_graph.setdefault(trap_set.graph, []).append(trap_set)
        self._by_graph = by_graph

    def trap_set_of(self, trap: Node) -> Ps1TrapSet | None:
        """
        The set of `trap` statements *trap* belongs to, or `None` where the graphs hold none.
        """
        return self._trap_sets.get(id(trap))

    def trap_sets_in(self, graph: ControlFlowGraph) -> list[Ps1TrapSet]:
        """
        The `trap` sets the builder wired into *graph*.
        """
        return self._by_graph.get(graph, [])


def build_control_flow_model(root: Ps1Script, descend: bool = False) -> Ps1ControlFlowModel:
    trap_sets: dict[int, Ps1TrapSet] = {}
    return Ps1ControlFlowModel(_build(root, descend, trap_sets), trap_sets)
