"""
The single route by which a PowerShell cleanup pass removes or rewrites statements in a body: every
edit of a statement list lands through `land`, and every removal is judged by a `Ps1RemovalPlan`.
"""
from __future__ import annotations

from typing import NamedTuple, Sequence

from refinery.lib.scripts import (
    BodyEdit,
    ListIndex,
    Node,
    Statement,
    _replace_in_parent,
    mutation_epoch,
    owning_field,
    reattach,
)
from refinery.lib.scripts.ps1.analysis.cfg import list_may_carry_on
from refinery.lib.scripts.ps1.analysis.effects import (
    Ps1HandlerVerdicts,
    deletion_is_observable,
    emptying_unhooks_a_handler,
)
from refinery.lib.scripts.ps1.analysis.errorstate import Ps1ErrorStateReach
from refinery.lib.scripts.ps1.analysis.raising import may_raise_where_spliced, statement_raise_kinds
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ExpressionStatement,
    Ps1TrapStatement,
)


class _Proposal(NamedTuple):
    """
    One intended edit: the statement to change, and what stands in its place afterwards.
    """
    statement: Statement
    replacement: list[Statement]


def _removes_a_handler(statement: Node) -> bool:
    """
    Whether the statement *is* fault-handling machinery rather than something that might fault.

    A `trap` intercepts a terminating error that would otherwise reach the enclosing `catch`, so
    deleting one re-routes the fault although the deleted statement cannot itself raise.
    `removals_may_fault` answers only the first half of the fault question — can what this pass
    removes throw — and says nothing about this half, so this half is asked of every pass, and it is
    asked in reverse: not where an error raised here would go, but whether anything is left that
    could offer this handler one. Its semantic half comes from the handler verdicts a plan holds.
    """
    return isinstance(statement, Ps1TrapStatement)


def rescopes_a_handler(replacement: Sequence[Statement]) -> bool:
    """
    Whether installing *replacement* would move a `trap` into a statement block other than the one
    it was written in, which re-aims a handler rather than removing or rewriting one.

    A `trap` guards the block it stands in and nothing around it, so a pass that dissolves a
    construct and carries its statements outward carries the handler's *scope* outward with them:
    `if ($True) { trap { <payload> }; ... }` hoisted to the body around it makes every later
    statement of that body reach a handler no run reached before. Every statement of a replacement
    becomes a direct member of this plan's list, so the top level is the whole of what moves — a
    `trap` nested deeper inside one keeps the block it is written in and is not this.
    """
    return any(isinstance(statement, Ps1TrapStatement) for statement in replacement)


def raisers_a_splice_moves(statements: Sequence[Node], replacement: Sequence[Statement]) -> list[Statement]:
    """
    The lines of *replacement* other than the last that may raise where they are spliced into the
    list *statements* in place of one of its statements, where that list declares a `trap` set
    that may carry the run on after a statement
    (`refinery.lib.scripts.ps1.analysis.cfg.list_may_carry_on`); none where it does not.

    A raise inside the statement replaced abandoned the rest of it and carried on after it, and the
    same raise in a spliced line carries on at the next line of the splice: measured on 5.1 as
    `trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'`, which
    writes `next` alone, where resolving the `if` into its statements writes `tail` too. The last
    line moves nothing, since what follows it is what followed the statement. Read without a model,
    the lines first (`refinery.lib.scripts.ps1.analysis.raising.may_raise_where_spliced`) and the
    `trap` set only where one of them may raise; a caller holding a raise model of the tree the
    splice lands in clears what it can of the lines found here.
    """
    raisers = [line for line in replacement[:-1] if may_raise_where_spliced(line)]
    if raisers and list_may_carry_on(statements):
        return raisers
    return []


def _install(parent: Node, attr: str, edits: Sequence[_Proposal]) -> tuple[bool, list[Node]]:
    """
    Apply *edits* to the list `parent.<attr>` as one edit, reporting whether the list moved and which
    nodes it now holds because of it, without repairing them: see `_restore` for why a batch
    repairs once every edit of it has landed.

    What landed is decided per splice rather than taken from *edits*, because the two are not the
    same set. `BodyEdit` ignores a splice for a node its list does not hold — the class describes an
    edit to one list and nothing else — so a replacement can be allowed and still never be
    installed. Repairing that one would hand it the children it is still not holding, which is the
    corruption `Ps1RemovalPlan.propose` undoes at registration, reintroduced by the repair.

    The question a splice was honoured is asked of the statement it names and not of the resulting
    list, and only the first is the same question: a replacement that already stands in the list is
    carried over by an edit that ignored its splice, so reading the result back reports it installed
    by an edit that installed nothing.
    """
    if not edits:
        return False, []
    held = {id(item) for item in getattr(parent, attr, None) or []}
    edit = BodyEdit(parent, attr)
    for proposal in edits:
        edit.splice(proposal.statement, proposal.replacement)
    if not edit.apply():
        return False, []
    return True, [
        statement
        for proposal in edits
        if id(proposal.statement) in held
        for statement in proposal.replacement
    ]


def land(parent: Node, attr: str, statement: Statement, replacement: Sequence[Statement]) -> bool:
    """
    Put *replacement* where *statement* stands in the list `parent.<attr>`, or remove it where
    *replacement* is empty, and report whether the list moved; the parts of *statement* the
    replacement does not take are put back in order where it does not land. The route every edit of
    a statement list takes: a `Ps1RemovalPlan` lands its batch the same way, and
    `refinery.lib.scripts.ps1.deobfuscation.substitution.substitute_statement` lands through this.
    """
    reattach(statement)
    moved, landed = _install(parent, attr, [_Proposal(statement, list(replacement))])
    _restore(landed)
    return moved


def _restore(landed: list[Node]) -> None:
    """
    Put the parent pointers inside everything the batch has just left standing back in agreement
    with the tree.

    Building a replacement adopts the parts of the original it reuses, and `Ps1RemovalPlan.propose`
    undoes that at once, so the batch decides against a tree whose pointers are true. Installing one
    names its new holder and nothing below it, so what the build claimed has to be claimed again
    here.

    This runs **after** the whole batch is in place, never between two of its edits. `reattach`
    walks a subtree, and until the last edit has landed a replacement's subtree can still contain a
    statement another replacement is about to take: repairing then asserts a structure that is not
    the final one, and which of the two claims survives is decided by the order the batch happened
    to visit them in. Once nothing is left to install, every walk asserts the same structure, and
    the order stops mattering.
    """
    for node in landed:
        reattach(node)


def _fits_a_field(proposal: _Proposal) -> Node | None:
    """
    The single node a direct field can take from `proposal`, or `None` when the proposal cannot be
    written into one at all.

    A field holds what the model declares it holds, and a statement in an `Expression` slot leaves a
    tree whose shape contradicts its own declaration: every `unwrap_parens` and every
    `isinstance(paren.expression, ...)` gate downstream stops seeing through the parenthesis. The
    statement wrapper a pass builds for a body — `refinery.lib.scripts.ps1.model` spells it
    `Ps1ExpressionStatement` — carries no meaning a field needs, so it is peeled off rather than
    installed.
    """
    if len(proposal.replacement) != 1:
        return None
    replacement = proposal.replacement[0]
    if not isinstance(proposal.statement, Expression):
        return replacement
    if isinstance(replacement, Expression):
        return replacement
    if isinstance(replacement, Ps1ExpressionStatement):
        return replacement.expression
    return None


class _Nearest:
    """
    The nearest of the given nodes at or above a node, climbing parent pointers. Every node a
    question climbs through keeps its answer, so a batch asking about every list it touches climbs
    each node of the tree at most once, however deep the lists are nested.
    """

    def __init__(self, marked: dict[int, Node]):
        self._marked = marked
        self._known: dict[int, Node | None] = {}

    def __call__(self, node: Node | None) -> Node | None:
        climbed: list[int] = []
        found: Node | None = None
        while node is not None:
            key = id(node)
            if key in self._known:
                found = self._known[key]
                break
            climbed.append(key)
            if (marked := self._marked.get(key)) is not None:
                found = marked
                break
            node = node.parent
        for key in climbed:
            self._known[key] = found
        return found


class _Edit(NamedTuple):
    """
    One edit a batch would land: the statement it changes, the node whose list or field holds that
    statement, what stands in its place, and whether its own plan lets it land at all.
    """
    statement: Node
    holder: Node
    replacement: Sequence[Node]
    free: bool


class _Composition:
    """
    Which edits of one batch land in a tree that still holds the list or field they edit.

    An edit is made against its holder. Inside a statement another edit of the batch replaces, that
    holder survives only when the replacement carries it, as

        $Null = ($y = Start-Process a)

    carries the parenthesis an inner rewrite of `$y = Start-Process a` edits. A replacement that
    dissolves the holder and takes its statements instead, as resolving `if ($True) { <body> }`
    into the statements of its body does, leaves an edit of that body splicing a block the tree no
    longer holds, and re-parents the statements it took into that block. An edit that does not
    land replaces nothing, so what stands inside its statement stands wherever that statement
    does.
    """

    def __init__(self, edits: list[_Edit]):
        self._edits = {id(edit.statement): edit for edit in edits}
        self._enclosing = _Nearest({key: edit.statement for key, edit in self._edits.items()})
        self._lands: dict[int, bool] = {}
        self._frontiers: dict[int, set[int]] = {}

    def lands(self, statement: Node) -> bool:
        """
        Whether the edit of `statement` lands: its plan lets it, and the tree the batch leaves still
        holds its holder.
        """
        key = id(statement)
        if (known := self._lands.get(key)) is None:
            edit = self._edits[key]
            known = self._lands[key] = edit.free and self._stands(edit.holder)
        return known

    def _stands(self, node: Node) -> bool:
        outer = self._enclosing(node)
        while outer is not None and not self.lands(outer):
            node = outer
            outer = self._enclosing(outer.parent)
        return outer is None or self._carries(outer, node)

    def _carries(self, outer: Node, holder: Node) -> bool:
        frontier = self._frontier(outer)
        node: Node | None = holder
        while node is not None and node is not outer:
            if id(node) in frontier:
                return True
            node = node.parent
        return False

    def _frontier(self, outer: Node) -> set[int]:
        """
        The nodes of the tree as written below `outer` that its replacement holds, directly or
        through nodes the replacement built.
        """
        if (frontier := self._frontiers.get(id(outer))) is None:
            frontier = self._frontiers[id(outer)] = set()
            pending = list(self._edits[id(outer)].replacement)
            while pending:
                node = pending.pop()
                if node.is_descendant_of(outer):
                    frontier.add(id(node))
                else:
                    pending.extend(node.children())
        return frontier


class Ps1RemovalPlan:
    """
    A batch of proposed edits to one statement list, committed as a single mutation.

    A pass proposes each edit it wants, consults the set-level guards it is responsible for against
    `survivors`, and calls `commit`. What the class owns is the part every pass has to get right the
    same way: the per-statement veto, and the fact that the whole batch lands as one tree edit.

    Every verdict reads the handler verdicts of the tree the plan edits, *handlers*, and one raise
    model of them, which *under_the_world* picks: the model reading the flow-sensitive world, which
    a pass holding the world reads, or the one without it. *error_state* answers the reads of `$?`
    and of the error record a removal may change.

    **Which set a guard must be shown is decided by its polarity.** A guard *permissive* in the
    survivor set — more survivors makes a removal more likely — must see the **pre-veto** set,
    `survivors`; the veto therefore runs inside `commit`, after such a guard has had its answer, so a
    vetoed statement is never read as cover for deleting its neighbour. A guard *restrictive* in it —
    more survivors makes a removal **less** likely — must see the post-veto set, which
    `Ps1RemovalPlans.accepted` reports, or a vetoed statement's dependencies are deleted out from
    under it; a pass with such a guard opens its plans through that class. Set-level guards stay
    with the passes, because they are not the same from one pass to the next.

    `removals_may_fault` is the one thing about a pass this class must be told: whether what the pass
    removes can raise. It is passed to
    `refinery.lib.scripts.ps1.analysis.effects.deletion_is_observable`, which weighs the fault
    statement by statement; a pass that removes only things that cannot raise
    (`Ps1DeadCodeElimination`) sets it `False` and skips the veto. The set-level refusal that a batch
    must not leave a protected body empty is asked of every pass whatever this flag says.

    A veto normally skips the proposal it lands on and lets the rest through, which is wrong when a
    partly applied batch is broken rather than smaller: `Ps1ControlFlowDeflattening` deleting a
    dispatcher loop but not its `$state` seeding leaves a state machine half dissolved. The class
    cannot tell the two cases apart, so a pass files such edits with `propose_together`.
    """

    def __init__(
        self,
        parent: Node,
        attr: str = 'body',
        removals_may_fault: bool = True,
        *,
        handlers: Ps1HandlerVerdicts,
        under_the_world: bool,
        error_state: Ps1ErrorStateReach,
    ):
        self.parent = parent
        self.attr = attr
        self.removals_may_fault = removals_may_fault
        self.handlers = handlers
        self.faults = handlers.faults
        self.raises = handlers.raises(under_the_world)
        self.error_state = error_state
        self._proposals: dict[int, _Proposal] = {}
        self._groups: list[tuple[Statement, ...]] = []
        self._vetoes: dict[int, tuple[_Proposal, bool]] = {}
        self._vetoes_read_at: int | None = None
        self._verdict: tuple[int, list[_Proposal]] | None = None

    def propose(
        self,
        statement: Statement,
        replacement: list[Statement] | None = None,
    ) -> None:
        """
        Register that `statement` is to be replaced by `replacement`, or removed when that is `None`
        or empty. Proposing the same statement twice keeps the later proposal.

        A replacement is not a weaker removal: `Ps1DeadCodeElimination` resolves a constant `if`
        into the statements of the branch that runs, and a dead store becomes `$Null = <rhs>` so
        the value is still computed. A pass that could only delete could express neither.

        **A registered replacement holds no claim on the tree until `commit` grants it one.**
        Building one adopts the parts of the original it reuses, so it leaves nodes naming a holder
        that is not theirs; the statement is put back in order here, before this call returns, so
        everything between a proposal and the verdict reads a tree whose pointers are true. The
        repair is owed by every registration, not only one that carries a replacement — a pass
        routinely builds a replacement and then decides against installing it — so a pass may build a
        whole batch up front and withdraw or abandon it without owing anything.
        """
        proposal = _Proposal(statement, list(replacement or ()))
        try:
            self._proposals[id(statement)] = proposal
            self._verdict = None
        finally:
            reattach(statement)

    def propose_together(self, edits: Sequence[tuple[Statement, list[Statement] | None]]) -> bool:
        """
        Register *edits*, each as `propose` would, as one group that stands or falls together: a
        veto on any of them keeps every one of them standing. A group naming a statement this plan
        already holds a proposal for is refused, since the edit it would take over belongs to
        another; reports whether the group was registered.
        """
        if any(id(statement) in self._proposals for statement, _ in edits):
            for statement, _ in edits:
                reattach(statement)
            return False
        for statement, replacement in edits:
            self.propose(statement, replacement)
        self._groups.append(tuple(statement for statement, _ in edits))
        return True

    def withdraw(self, statement: Statement) -> None:
        """
        Drop a registered proposal, leaving `statement` where it stands. A pass that shrinks its own
        batch after reading `Ps1RemovalPlans.accepted` uses this. Nothing needs putting back, because
        `propose` never let the replacement take anything in the first place.
        """
        self._proposals.pop(id(statement), None)
        self._groups = [group for group in self._groups if not any(member is statement for member in group)]
        self._verdict = None

    def abandon(self) -> None:
        """
        Drop every proposal, leaving the tree as it was. Same contract as `withdraw`, for a pass
        that built a whole batch and then decided against all of it.
        """
        self._proposals.clear()
        self._groups.clear()
        self._verdict = None

    @property
    def survivors(self) -> list[Statement]:
        """
        The list as it would stand if every proposal were applied, the veto ignored. This is what
        the set-level guards must be shown; see the class docstring for why the post-veto set must
        not reach them.
        """
        return self._edit(self._proposals.values()).result()

    def _edit(self, proposals) -> BodyEdit:
        edit = BodyEdit(self.parent, self.attr)
        for proposal in proposals:
            edit.splice(proposal.statement, proposal.replacement)
        return edit

    def _vetoed(self, proposal: _Proposal) -> bool:
        """
        Whether a single proposal must be skipped although the guards allowed the batch.

        **A rewrite is refused for one reason: it relocates a handler.** A replacement keeps
        evaluating the original expression and throws where the original threw, leaving an enclosing
        handler as reachable as before. What that does not cover is a `trap` carried out of the block
        it was written in (`rescopes_a_handler`), which re-aims that handler over the rest of the
        target body.

        **A replacement spliced into a list whose `trap` set may carry the run on is refused too**
        where a spliced line other than the last may raise: see `raisers_a_splice_moves`, whose
        lines the raise model of this plan then judges where the replaced statement stands
        (`refinery.lib.scripts.ps1.analysis.raising.statement_raise_kinds`).

        **A handler and a statement that might fault are opposite questions.** Deleting a `trap`
        re-routes errors it did not raise, so what decides it is whether anything is left that can
        reach it, not `deletion_is_observable` (which asks where an error raised *at* the `trap`
        would go, a position nothing raises at). Deleting anything else is `deletion_is_observable`,
        and only for a pass that cannot rule the fault out itself.

        **The success flag is answered separately from the fault question**, ahead of the fault gate
        and of `removals_may_fault`. Every leaf statement writes `$?` whether or not it can raise,
        and a script can read the flag back, so removing a statement a live `$?` read observes
        changes what that read sees. `refinery.lib.scripts.ps1.analysis.errorstate` answers it
        positionally through `success_flag_write_observed`.
        """
        if proposal.replacement:
            if rescopes_a_handler(proposal.replacement):
                return True
            raisers = raisers_a_splice_moves(getattr(self.parent, self.attr, None) or (), proposal.replacement)
            return any(statement_raise_kinds(raiser, proposal.statement, self.raises) for raiser in raisers)
        if self.error_state.success_flag_write_observed(proposal.statement):
            return True
        if not self.removals_may_fault:
            return False
        return deletion_is_observable(proposal.statement, self.raises, self.error_state)

    def _vetoed_at(self, epoch: int, proposal: _Proposal) -> bool:
        """
        `_vetoed`, kept per proposal until it or the tree changes: a verdict reads the proposal and
        the tree alone, so a batch that grows one proposal at a time asks it once per proposal.
        """
        if self._vetoes_read_at != epoch:
            self._vetoes.clear()
            self._vetoes_read_at = epoch
        found = self._vetoes.get(id(proposal.statement))
        if found is None or found[0] is not proposal:
            found = self._vetoes[id(proposal.statement)] = proposal, self._vetoed(proposal)
        return found[1]

    def _allowed(self) -> list[_Proposal]:
        """
        The proposals that survive the veto and every set-level refusal this class owns. Kept
        apart from `commit` so that `Ps1RemovalPlans.accepted` is a query over the decision rather
        than a second copy of it. It is kept until the proposals or any tree change, because the batch that holds
        this plan asks for it while the pass is still walking and again when it commits.
        """
        epoch = mutation_epoch()
        if self._verdict is not None and self._verdict[0] == epoch:
            return self._verdict[1]
        proposals = list(self._proposals.values())
        traps = [p for p in proposals if not p.replacement and _removes_a_handler(p.statement)]
        weighed = {id(p) for p in traps}
        granted = {id(p) for p in self._trap_removals_allowed(traps)}
        allowed = [
            p for p in proposals
            if id(p) in granted or id(p) not in weighed and not self._vetoed_at(epoch, p)
        ]
        if self._groups:
            kept = {id(p.statement) for p in allowed}
            broken = {
                id(member) for group in self._groups
                if not all(id(member) in kept for member in group)
                for member in group
            }
            allowed = [p for p in allowed if id(p.statement) not in broken]
        if self._empties_a_protected_body(allowed):
            allowed = []
        self._verdict = epoch, allowed
        return allowed

    def _trap_removals_allowed(self, traps: list[_Proposal]) -> list[_Proposal]:
        """
        The `trap` deletions of this batch that may land, asked of the fault model as one
        question so that two copies of one handler are never each deleted on the strength of the
        other.
        """
        candidates = [p for p in traps if not self.error_state.success_flag_write_observed(p.statement)]
        statements = [p.statement for p in candidates if isinstance(p.statement, Ps1TrapStatement)]
        granted = {id(trap) for trap in self.faults.removable_traps(statements, self.raises, self.handlers.skips)}
        return [p for p in candidates if id(p.statement) in granted]

    def commit(self) -> bool:
        """
        Apply every proposal no veto blocks, as one edit, and report whether the tree moved.
        """
        moved, landed = self._apply(self._allowed())
        _restore(landed)
        return moved

    def _apply(self, allowed: list[_Proposal]) -> tuple[bool, list[Node]]:
        """
        Land one already-reached verdict through `_install`, reporting whether the tree moved and
        which nodes the list now holds because of it. Split out for `Ps1RemovalPlans`, which has to
        reach every verdict before it lands any of them, and land every edit before it repairs any
        of them.
        """
        return _install(self.parent, self.attr, allowed)

    def _empties_a_protected_body(self, allowed: list[_Proposal]) -> bool:
        """
        Whether committing `allowed` would clear a `try` body beside a handler that acts.

        Asked of every pass. The per-statement veto lets a statement that cannot raise be removed —
        which is what lets the padding inside a `try` go — so what keeps the body itself from
        emptying is this and only this.

        `emptying_unhooks_a_handler` is a policy about the listing rather than a claim about what
        runs; the emptiness test lives here so that the two halves of the name are decided in one
        place. It is asked first because it is two attribute reads against a body that is almost
        never a guarded one, where the emptiness test copies the whole list — and this now runs for
        every pass rather than for the few that used to reach it.
        """
        if not allowed or not emptying_unhooks_a_handler(self.parent):
            return False
        return not self._edit(allowed).result()


class _Decision(NamedTuple):
    """
    What `Ps1RemovalPlans.commit` does: the plans whose edits land, each beside the proposals it
    allows, the direct-field rewrites that land, and the plans whose edits it holds back.
    """
    landing: list[tuple[Ps1RemovalPlan, list[_Proposal]]]
    rewrites: list[tuple[_Proposal, Node]]
    held_back: set[int]


class Ps1RemovalPlans:
    """
    One `Ps1RemovalPlan` per statement list, for a pass that finds its removals by walking the whole
    tree rather than by descending body by body. Each list still commits as a single edit, so a pass
    scattering removals across a script advances the mutation counter once per body it touches
    instead of once per statement.

    A whole-tree walk also reaches statements that sit in no list at all: the inner store of
    `($y = ($z = 1))` is a statement to every pass that finds it and a direct field to its parent.
    Those are carried here too, because a pass that finds one has no other route left — but only as
    rewrites. A field cannot lose its statement without the parent losing its shape, so a proposal
    to remove one outright is registered and then declined at commit, which is also why the fault
    veto has nothing to say about them: it declines deletions, and none of these is one.

    Every verdict of a batch is reached against one tree, before any of its edits lands, so a pass
    pays for one build of the models however many lists it edits. Two kinds of edit cannot be judged
    that way and are held back for the pass to propose again: see `_decide`.
    """

    def __init__(
        self,
        *,
        handlers: Ps1HandlerVerdicts,
        under_the_world: bool,
        error_state: Ps1ErrorStateReach,
        removals_may_fault: bool = True,
    ):
        self.handlers = handlers
        self.under_the_world = under_the_world
        self.faults = handlers.faults
        self.raises = handlers.raises(under_the_world)
        self.error_state = error_state
        self.removals_may_fault = removals_may_fault
        #: Every plan this opens may remove, so unlike `Ps1RemovalPlan` there is no
        #: substitution-only spelling of this class: a caller holding one is a pass that deletes.
        self._plans: dict[tuple[int, str], Ps1RemovalPlan] = {}
        self._rewrites: dict[int, _Proposal] = {}
        #: The filed statement is kept beside its plan, and not only its `id`, for the reason
        #: `refinery.lib.scripts.BodyEdit` keeps a spliced node beside its own: a statement that is
        #: collected while its entry stands would let the next object at that address be withdrawn
        #: from a plan that never held it.
        self._filed: dict[int, tuple[Statement, Ps1RemovalPlan]] = {}
        self._lists = ListIndex()

    def propose_in(
        self,
        parent: Node,
        statement: Statement,
        replacement: list[Statement] | None = None,
        attr: str = 'body',
    ) -> None:
        """
        Register an edit against the list `parent.<attr>`, which the caller states holds
        `statement`.

        `propose` has to find that list, and finding it is an identity scan over the list — the cost
        of one proposal is the length of the body, so the cost of a pass is the square of it. A pass
        that walks bodies to find its removals is already holding the list, and says so here.

        Nothing checks the claim, so a caller that names the wrong list files a proposal `commit`
        will silently drop and `accepted` will still report; see `accepted` for what rests on it. Filing the same statement a second time drops the first proposal rather than
        leaving it standing, because the alternative is a statement `withdraw` can only reach one of
        — a withdrawal that half happens is what remembering where a proposal landed exists to
        rule out.
        """
        plan = self._plan_for(parent, attr)
        filed = self._filed.get(id(statement))
        if filed is not None and filed[1] is not plan:
            filed[1].withdraw(statement)
        plan.propose(statement, replacement)
        self._filed[id(statement)] = (statement, plan)

    def _plan_for(self, parent: Node, attr: str) -> Ps1RemovalPlan:
        key = (id(parent), attr)
        try:
            return self._plans[key]
        except KeyError:
            plan = self._plans[key] = Ps1RemovalPlan(
                parent,
                attr,
                self.removals_may_fault,
                handlers=self.handlers,
                under_the_world=self.under_the_world,
                error_state=self.error_state,
            )
            return plan

    def propose(
        self,
        statement: Statement,
        replacement: list[Statement] | None = None,
    ) -> bool:
        """
        Register an edit with the plan for the list holding `statement`, opening one if this is the
        first edit against that list, or as a direct-field rewrite when `statement` sits in no list.
        Reports whether the statement can be edited at all.

        A refusal releases the proposal rather than handing it back: the caller has already built
        its replacement, and building one adopts parts of the statement, so a refusal the caller has
        to remember to undo is a refusal that gets forgotten. See `Ps1RemovalPlan.propose` for why
        no registered replacement holds a claim before `commit` either, and for why the release is
        owed whatever the `replacement` argument turns out to hold.
        """
        owner = self._lists.owning_list(statement)
        if owner is None:
            if owning_field(statement) is None:
                reattach(statement)
                return False
            self._rewrites[id(statement)] = _Proposal(statement, list(replacement or ()))
            reattach(statement)
            return True
        parent, attr = owner
        self.propose_in(parent, statement, replacement, attr)
        return True

    def withdraw(self, statement: Node) -> None:
        """
        Drop a registered proposal wherever it landed. Same contract as `Ps1RemovalPlan.withdraw`.

        Where it landed is remembered rather than looked up again. Rediscovering the owning list
        reports nothing when it fails, and a withdrawal that quietly does not happen is a proposal
        the caller has already written off and `commit` still applies — half of a group edit whose
        other half is gone.
        """
        if self._rewrites.pop(id(statement), None) is not None:
            return
        filed = self._filed.pop(id(statement), None)
        if filed is not None:
            filed[1].withdraw(filed[0])

    def abandon(self) -> None:
        """
        Drop every proposal in every plan. Same contract as `Ps1RemovalPlan.abandon`.
        """
        for plan in self._plans.values():
            plan.abandon()
        self._rewrites.clear()
        self._filed.clear()

    def allowed_in(self, parent: Node, attr: str = 'body') -> list[Statement]:
        """
        The statements of the list `parent.<attr>` whose proposals its own plan lets through. The
        batch may still hold the whole list back at `commit`; what it never does is land a proposal
        of this list that is not reported here.
        """
        plan = self._plans.get((id(parent), attr))
        if plan is None:
            return []
        return [proposal.statement for proposal in plan._allowed()]

    def survivors(self, parent: Node, attr: str = 'body') -> list[Statement]:
        """
        The pre-veto survivors of one of the lists this batch touches, or its current contents when
        no edit was registered against it. Same contract as `Ps1RemovalPlan.survivors`.
        """
        plan = self._plans.get((id(parent), attr))
        if plan is None:
            return list(getattr(parent, attr, None) or [])
        return plan.survivors

    @property
    def accepted(self) -> list[Statement]:
        """
        The statements `commit` would edit across every list this batch touches, plus the
        direct-field rewrites it would install, without editing them.

        This is for the *restrictive* guards — the ones that allow **fewer** removals as more
        statements survive, the opposite polarity to `survivors`' readers. Reachability is the
        example: it concludes a function is dead from the call sites going away, so a vetoed caller
        it never heard about leaves the emitted script calling a function it does not define. Such a
        guard asks this, drops what it now forbids with `withdraw`, and asks again; the loop
        terminates because the batch only shrinks — except for a group a withdrawal breaks, against a
        protected body, or where withdrawing an edit that the batch holds another list back for
        releases that list (see `_decide`), where a withdrawal can grow this set, so a pass that
        loops on `accepted` owes its own termination argument.

        This must not edit the tree: installing a replacement's claim would decide a batch the guard
        asking has not decided. A caller reads membership as exact — *this is going away* — so a
        statement reported here that `commit` then leaves standing is a dependency deleted out from
        under its keeper, the failure the restrictive polarity exists to prevent. That exactness
        rests on each plan's list actually holding what was proposed: `propose` establishes it by
        finding the list, and `propose_in` moves it to the caller.

        A pass that scatters one logical removal across several lists needs this rather than the
        per-plan answer: `refinery.lib.scripts.ps1.deobfuscation.unused.Ps1JunkStatementRemoval`
        drops an inert definition and the bare calls to it, and those routinely land in different
        plans, so a veto on either half is only visible here.
        """
        decision = self._decide()
        accepted = [proposal.statement for _, allowed in decision.landing for proposal in allowed]
        accepted.extend(proposal.statement for proposal, _ in decision.rewrites)
        return accepted

    def _decide(self) -> _Decision:
        """
        What `commit` does, read by `accepted` as well, so the two cannot drift.

        Each list's verdict is reached against the tree as written, and so assumes that every other
        list stands as written. Two kinds of edit break that. An edit in a list or field that a
        larger edit of the batch takes apart is one; see `_Composition`. A handler deletion whose
        verdict read a handler that another list deletes is the other, and which deletions those
        are is the fault model's to say:
        `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.edits_that_wait`. Every edit of
        such a list is held back, because its plan judged them as one, and is judged again by the
        pass's next batch, against the tree this one leaves; an edit of the list a deletion of its
        own plan reads is withheld alone.
        """
        verdicts = [(plan, allowed) for plan in self._plans.values() if (allowed := plan._allowed())]
        rewrites = self._installable()
        waiting, waiting_rewrites, withheld = self._waiting_for_handler_removals(verdicts, rewrites)
        if withheld:
            verdicts = [
                (plan, kept) for plan, allowed in verdicts
                if (kept := [proposal for proposal in allowed if id(proposal.statement) not in withheld])
            ]
            rewrites = [
                (proposal, replacement) for proposal, replacement in rewrites
                if id(proposal.statement) not in withheld
            ]
        if len(verdicts) + len(rewrites) <= 1:
            return _Decision(verdicts, rewrites, set())
        edits: list[_Edit] = []
        for plan, allowed in verdicts:
            free = id(plan) not in waiting
            edits.extend(
                _Edit(proposal.statement, plan.parent, proposal.replacement, free)
                for proposal in allowed
            )
        for proposal, replacement in rewrites:
            holder = proposal.statement.parent
            assert holder is not None
            edits.append(_Edit(proposal.statement, holder, [replacement], id(proposal.statement) not in waiting_rewrites))
        composition = _Composition(edits)
        landing: list[tuple[Ps1RemovalPlan, list[_Proposal]]] = []
        held_back: set[int] = set()
        for plan, allowed in verdicts:
            if composition.lands(allowed[0].statement):
                landing.append((plan, allowed))
            else:
                held_back.add(id(plan))
        rewrites = [
            (proposal, replacement) for proposal, replacement in rewrites
            if composition.lands(proposal.statement)
        ]
        return _Decision(landing, rewrites, held_back)

    def _waiting_for_handler_removals(
        self,
        verdicts: list[tuple[Ps1RemovalPlan, list[_Proposal]]],
        rewrites: list[tuple[_Proposal, Node]],
    ) -> tuple[set[int], set[int], set[int]]:
        """
        The plans among *verdicts*, and the statements of *rewrites*, whose edits the fault model
        says have to wait for a `trap` deletion another plan makes, and the statements that wait for
        one their own plan makes: one rule for every edit,
        `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.edits_that_wait`.
        """
        deleted: list[list[Node]] = []
        touched: list[list[Node]] = []
        for _, allowed in verdicts:
            deleted.append([
                proposal.statement for proposal in allowed
                if _removes_a_handler(proposal.statement) and not proposal.replacement
            ])
            touched.append([proposal.statement for proposal in allowed])
        for proposal, _ in rewrites:
            deleted.append([])
            touched.append([proposal.statement])
        if not any(deleted):
            return set(), set(), set()
        waiting, withheld = self.faults.edits_that_wait(deleted, touched, self.raises)
        count = len(verdicts)
        plans = {id(verdicts[index][0]) for index in waiting if index < count}
        rewritten = {id(rewrites[index - count][0].statement) for index in waiting if index >= count}
        return plans, rewritten, withheld

    def _installable(self) -> list[tuple[_Proposal, Node]]:
        """
        The direct-field rewrites this batch would install, each beside the node the field takes.
        One decision, read by `accepted` and applied by `commit`, so the two cannot drift.
        """
        installable = []
        for proposal in self._rewrites.values():
            replacement = _fits_a_field(proposal)
            if replacement is None:
                continue
            installable.append((proposal, replacement))
        return installable

    def commit(self) -> bool:
        """
        Commit every plan and report whether any of them moved the tree.

        Every verdict is reached before the first edit lands, and every edit lands before the first
        repair. A veto is a question about the tree —
        `refinery.lib.scripts.ps1.analysis.effects.deletion_is_observable` reads it through the
        control-flow graphs, which are built from the tree as it stands and are dropped the moment
        it moves — so a plan that emptied a `catch` body would change the answer for the `try`
        body's plan, and which plan that is would be decided by nothing better than the order the
        batch happened to open them in. That is also what makes `accepted` exact: what it
        reported is what commits. `_restore` says why the repairs come last.

        Nothing that did not land is repaired. A rewrite the field refused is a replacement that was
        released when it was registered and has taken nothing since, so its original owes nothing
        either — and asserting an uninstalled statement's structure here is the one walk that could
        assert it over a node the tree holds somewhere else.
        """
        decision = self._decide()
        landed: list[Node] = []
        moved = False
        for plan, allowed in decision.landing:
            was_moved, installed = plan._apply(allowed)
            moved = moved or was_moved
            landed.extend(installed)
        for proposal, replacement in decision.rewrites:
            if not _replace_in_parent(proposal.statement, replacement):
                continue
            landed.append(replacement)
            moved = True
        _restore(landed)
        return moved
