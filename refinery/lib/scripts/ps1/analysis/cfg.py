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

from dataclasses import dataclass, field
from functools import partial
from typing import Sequence

from refinery.lib.scripts import Block, Node
from refinery.lib.scripts.analysis.cfg import (
    ArmFlow,
    CfgBuilder,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_control_flow,
)
from refinery.lib.scripts.ps1.ast import (
    STATEMENT_LIST_EXPRESSIONS,
    get_named_blocks,
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


def _names_every_error(name: str) -> bool:
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
    return any(_names_every_error(name) for name in clause.types)


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
    def __init__(self, owner: Node, descend: bool = False):
        super().__init__(owner)
        self._trap_body: _TrapBody | None = None
        self._descend = descend

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
        `catch` bodies for the same reason. Where nothing guards the block, the trap body unwinds to
        the body exit: the error ends the body, which is the one place a `trap` turns a fault that
        would have been reported and stepped over into one that stops everything after it.

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
        entries: list[CfgNode] = []
        for trap in traps:
            handler = self.detached_node(trap)
            if entries:
                self.exceptional_edge(entries[-1], handler)
            entries.append(handler)
        handling = list(entries)
        resumes: list[CfgNode] = []
        escapes = True
        enclosing = self._trap_body
        outer_targets = self._targets
        outer_label = self._pending_label
        self._targets = []
        self._pending_label = None
        self._handlers.append(self.unwinding())
        for trap, handler in zip(traps, entries):
            self._trap_body = built = _TrapBody()
            body_from = len(self.cfg.nodes)
            resumes += self._body(trap.body, [handler]) + built.resumes
            handling += self.cfg.nodes[body_from:]
            if _names_every_error(trap.type_name) and not built.rethrows:
                escapes = False
        self._handlers.pop()
        self._trap_body = enclosing
        self._targets = outer_targets
        self._pending_label = outer_label
        self.close_handler_set(entries, escapes=escapes)
        self._handlers.append(entries[0])
        if not resumes:
            exits = self.sequence(statements, frontier)
        else:
            self.mark_hub_bound(handling)
            with self.resumption(resumes):
                exits = self._resumable_sequence(statements, frontier)
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
        for statement in statements:
            frontier = self.resume_past(self.statement(statement, frontier))
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
            return self.terminate(statement, frontier, exceptional=True)
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
        statement consuming it runs. This inner-then-outer order is the soundness hinge — a soft raiser
        that is the last inner statement has the outer node as its successor, which keeps a trap that
        guards it, where the reverse order would drop it.

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
    return build_control_flow(root, partial(_Builder, descend=descend), FUNCTION_NODES)


def build_control_flow_model(root: Ps1Script, descend: bool = False) -> ControlFlowModel:
    return ControlFlowModel(build_ps1_control_flow(root, descend))
