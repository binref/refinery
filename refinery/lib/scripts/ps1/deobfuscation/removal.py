"""
The single route by which a PowerShell cleanup pass removes or rewrites statements in a body.
"""
from __future__ import annotations

from typing import Callable, NamedTuple

from refinery.lib.scripts import (
    BodyEdit,
    Node,
    Statement,
    _replace_in_parent,
    owning_field,
    owning_list,
    reattach,
)
from refinery.lib.scripts.ps1.analysis.effects import (
    deletion_is_observable,
    emptying_unhooks_a_handler,
    statement_can_raise,
)
from refinery.lib.scripts.ps1.analysis.errorstate import Ps1ErrorStateReach
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
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
    could offer this handler one.
    """
    return isinstance(statement, Ps1TrapStatement)


def _rescopes_a_handler(replacement: list[Statement]) -> bool:
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


class Ps1RemovalPlan:
    """
    A batch of proposed edits to one statement list, committed as a single mutation.

    A pass proposes each edit it wants, consults the set-level guards it is responsible for against
    `survivors`, and calls `commit`. What the class owns is the part every pass has to get right the
    same way: the per-statement veto, and the fact that the whole batch lands as one tree edit.

    **Which set a guard must be shown is decided by its polarity.** A guard *permissive* in the
    survivor set — more survivors makes a removal more likely — must see the **pre-veto** set,
    `survivors`; the veto therefore runs inside `commit`, after such a guard has had its answer, so a
    vetoed statement is never read as cover for deleting its neighbour. A guard *restrictive* in it —
    more survivors makes a removal **less** likely — must see the post-veto set, and reads `accepted`
    rather than `survivors`, or a vetoed statement's dependencies are deleted out from under it.
    Set-level guards stay with the passes, because they are not the same from one pass to the next.

    `removals_may_fault` is the one thing about a pass this class must be told: whether what the pass
    removes can raise. It is passed to
    `refinery.lib.scripts.ps1.analysis.effects.deletion_is_observable`, which weighs the fault
    statement by statement; a pass that removes only things that cannot raise
    (`Ps1DeadCodeElimination`) sets it `False` and skips the veto. The set-level refusal that a batch
    must not leave a protected body empty is asked of every pass whatever this flag says.

    `all_or_nothing` is the second: a veto normally skips the proposal it lands on and lets the rest
    through, which is wrong when a partly applied batch is broken rather than smaller —
    `Ps1ControlFlowDeflattening` deleting a dispatcher loop but not its `$state` seeding leaves a
    state machine half dissolved. The class cannot tell the two cases apart, so the pass says which.
    """

    def __init__(
        self,
        parent: Node,
        attr: str = 'body',
        removals_may_fault: bool = True,
        all_or_nothing: bool = False,
        *,
        faults: Ps1FaultReach | None,
        world: Ps1WorldReach | None = None,
        error_state: Ps1ErrorStateReach | None = None,
        soft_step_over_observed: Callable[[Node], bool] | None = None,
    ):
        """
        `faults` is the model the removal verdicts are reached against, and `None` says this plan
        installs replacements and removes nothing. A caller that has no removal to file has no
        verdict to reach and nothing to reach it with, and filing a removal against such a plan is
        refused at `propose` rather than let through unchecked. The one such caller is
        `refinery.lib.scripts.ps1.deobfuscation.substitution.substitute_statement`.

        `world` is the second model the veto may need, and it is optional because only one half of
        one question reads it: whether a variable read can raise depends on the semantics in force,
        and a payload the analysis cannot read may change those. Without it that half is refused and
        the veto asks the context-free question alone, which is what every pass got before the
        world was offered — see
        `refinery.lib.scripts.ps1.analysis.effects.expression_cannot_fault`.

        `error_state` is the third model the veto may consult, a sibling of `world`: whether a read
        of the record a raise leaves in `$Error`/`$StackTrace` is reachable after the raiser, which
        keeps a raise no handler took but a later read observes. Optional and threaded exactly
        where `world` is, because it answers the same removals — those a pass cannot rule out as
        fault-free. Absent, that channel is skipped and the veto asks the handler question alone,
        which is what every pass got before the model existed — see
        `refinery.lib.scripts.ps1.analysis.effects.deletion_is_observable`.

        `soft_step_over_observed` answers, for the `trap` step-over branch, whether the region a
        resuming `trap` skips is observable. It is injected rather than read off `world` because that
        judgment is one of emission and liveness the fault reader holds none of, and it is kept apart
        from `world` so that it does not change what the `may_raise` half or the replacement veto ask
        of `statement_can_raise`. Absent, the branch keeps a resuming trap rather than removing it on
        a guess.
        """
        self.parent = parent
        self.attr = attr
        self.removals_may_fault = removals_may_fault
        self.all_or_nothing = all_or_nothing
        self.faults = faults
        self.world = world
        self.error_state = error_state
        self._soft_step_over_observed = soft_step_over_observed
        self._proposals: dict[int, _Proposal] = {}

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
            if not proposal.replacement and self.faults is None:
                raise ValueError('this plan was opened to substitute and holds no fault model')
            self._proposals[id(statement)] = proposal
        finally:
            reattach(statement)

    def withdraw(self, statement: Statement) -> None:
        """
        Drop a registered proposal, leaving `statement` where it stands. A pass that shrinks its own
        batch after reading `accepted` uses this. Nothing needs putting back, because `propose`
        never let the replacement take anything in the first place.
        """
        self._proposals.pop(id(statement), None)

    def abandon(self) -> None:
        """
        Drop every proposal, leaving the tree as it was. Same contract as `withdraw`, for a pass
        that built a whole batch and then decided against all of it.
        """
        self._proposals.clear()

    @property
    def survivors(self) -> list[Statement]:
        """
        The list as it would stand if every proposal were applied, the veto ignored. This is what
        the set-level guards must be shown; see the class docstring for why the post-veto set must
        not reach them.
        """
        return self._edit(self._proposals.values()).result()

    @property
    def accepted(self) -> list[Statement]:
        """
        The statements `commit` would edit, without editing them.

        This is for the *restrictive* guards — the ones that allow **fewer** removals as more
        statements survive, the opposite polarity to `survivors`' readers. Reachability is the
        example: it concludes a function is dead from the call sites going away, so a vetoed caller
        it never heard about leaves the emitted script calling a function it does not define. Such a
        guard asks this, drops what it now forbids with `withdraw`, and asks again; the loop
        terminates because the batch only shrinks — except under `all_or_nothing`, or against a
        protected body, where a withdrawal can grow this set, so a pass that loops on `accepted` owes
        its own termination argument.

        This must not edit the tree: installing a replacement's claim would decide a batch the guard
        asking has not decided. A caller reads membership as exact — *this is going away* — so a
        statement reported here that `commit` then leaves standing is a dependency deleted out from
        under its keeper, the failure the restrictive polarity exists to prevent. That exactness
        rests on the plan's list actually holding what was proposed: `Ps1RemovalPlans.propose`
        establishes it by finding the list, and `propose_in` moves it to the caller.
        """
        return [proposal.statement for proposal in self._allowed()]

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
        it was written in (`_rescopes_a_handler`), which re-aims that handler over the rest of the
        target body.

        **A replacement spliced *into* a block a resuming `trap` guards is refused too**: a raise
        inside a nested block abandons the rest of that block and resumes after it, so resolving the
        block into its statements puts them where the handler resumes — measured on 5.1 as
        `trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'`, which
        writes `next` alone while the unrefused splice would write `tail` too. The refusal fires when
        the target body is guarded by a resuming trap set and a spliced statement other than the last
        can raise (`statement_can_raise`); a one-statement replacement, or one whose raiser is last,
        moves nothing. A plan opened to substitute holds no fault model, so this half is skipped
        there — a stated follow-on.

        **A handler and a statement that might fault are opposite questions.** Deleting a `trap`
        re-routes errors it did not raise, so what decides it is whether anything is left that can
        reach it, not `deletion_is_observable` (which asks where an error raised *at* the `trap`
        would go, a position nothing raises at). Deleting anything else is `deletion_is_observable`,
        and only for a pass that cannot rule the fault out itself.

        **The success flag is answered separately from the fault question**, ahead of the fault gate
        and of `removals_may_fault`. Every leaf statement writes `$?` whether or not it can raise,
        and a script can read the flag back, so removing a statement a live `$?` read observes
        changes what that read sees. `refinery.lib.scripts.ps1.analysis.errorstate` answers it
        positionally through `success_flag_write_observed`; absent that model the channel is skipped.
        """
        if proposal.replacement:
            if _rescopes_a_handler(proposal.replacement):
                return True
            faults = self.faults
            return (
                faults is not None
                and faults.guarded_by_a_resuming_trap(proposal.statement)
                and any(
                    statement_can_raise(raiser, faults, self.world)
                    for raiser in proposal.replacement[:-1]
                )
            )
        if (
            self.error_state is not None
            and self.error_state.success_flag_write_observed(proposal.statement)
        ):
            return True
        faults = self.faults
        if faults is None:
            return True
        if _removes_a_handler(proposal.statement):
            return faults.removing_a_handler_is_observed(
                proposal.statement,
                lambda raiser: statement_can_raise(raiser, faults, self.world),
                self._soft_step_over_observed or (lambda _handler: True),
            )
        if not self.removals_may_fault:
            return False
        return deletion_is_observable(
            proposal.statement, faults, self.world, self.error_state)

    def _allowed(self) -> list[_Proposal]:
        """
        The proposals that survive the veto and every set-level refusal this class owns. Kept
        apart from `commit` so that `accepted` is a query over the decision rather than a second
        copy of it.
        """
        proposals = list(self._proposals.values())
        allowed = [p for p in proposals if not self._vetoed(p)]
        if self.all_or_nothing and len(allowed) != len(proposals):
            allowed = []
        if self._empties_a_protected_body(allowed):
            allowed = []
        return allowed

    def commit(self) -> bool:
        """
        Apply every proposal no veto blocks, as one edit, and report whether the tree moved.
        """
        moved, landed = self._apply(self._allowed())
        _restore(landed)
        return moved

    def _apply(self, allowed: list[_Proposal]) -> tuple[bool, list[Statement]]:
        """
        Land one already-reached verdict, reporting whether the tree moved and which nodes the list
        now holds because of it. Split out for `Ps1RemovalPlans`, which has to reach every verdict
        before it lands any of them, and land every edit before it repairs any of them.

        What landed is decided per splice rather than taken from `allowed`, because the two are not
        the same set. `BodyEdit` ignores a splice for a node its list does not hold — the class
        describes an edit to one list and nothing else — so a replacement can be allowed and still
        never be installed. Repairing that one would hand it the children it is still not holding,
        which is the corruption `propose` undoes at registration, reintroduced by the repair.

        The question a splice was honoured is asked of the statement it names and not of the
        resulting list, and only the first is the same question: a replacement that already stands
        in the list is carried over by an edit that ignored its splice, so reading the result back
        reports it installed by an edit that installed nothing.
        """
        if not allowed:
            return False, []
        held = {id(item) for item in getattr(self.parent, self.attr, None) or []}
        if not self._edit(allowed).apply():
            return False, []
        return True, [
            statement
            for proposal in allowed
            if id(proposal.statement) in held
            for statement in proposal.replacement
        ]

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
    """

    def __init__(
        self,
        faults: Ps1FaultReach,
        world: Ps1WorldReach | None = None,
        error_state: Ps1ErrorStateReach | None = None,
    ):
        self.faults = faults
        self.world = world
        self.error_state = error_state
        #: Every plan this opens may remove, so unlike `Ps1RemovalPlan` there is no
        #: substitution-only spelling of this class: a caller holding one is a pass that deletes.
        self._plans: dict[tuple[int, str], Ps1RemovalPlan] = {}
        self._rewrites: dict[int, _Proposal] = {}
        #: The filed statement is kept beside its plan, and not only its `id`, for the reason
        #: `refinery.lib.scripts.BodyEdit` keeps a spliced node beside its own: a statement that is
        #: collected while its entry stands would let the next object at that address be withdrawn
        #: from a plan that never held it.
        self._filed: dict[int, tuple[Statement, Ps1RemovalPlan]] = {}

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
        will silently drop and `accepted` will still report; see `Ps1RemovalPlan.accepted` for what
        rests on it. Filing the same statement a second time drops the first proposal rather than
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
                faults=self.faults,
                world=self.world,
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
        owner = owning_list(statement)
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

    def withdraw(self, statement: Statement) -> None:
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
            filed[1].withdraw(statement)

    def abandon(self) -> None:
        """
        Drop every proposal in every plan. Same contract as `Ps1RemovalPlan.abandon`.
        """
        for plan in self._plans.values():
            plan.abandon()
        self._rewrites.clear()
        self._filed.clear()

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
        direct-field rewrites it would install. Same contract, and the same two limits, as
        `Ps1RemovalPlan.accepted`.

        A pass that scatters one logical removal across several lists needs this rather than the
        per-plan answer: `refinery.lib.scripts.ps1.deobfuscation.unused.Ps1JunkStatementRemoval`
        drops an inert definition and the bare calls to it, and those routinely land in different
        plans, so a veto on either half is only visible here.
        """
        accepted = [statement for plan in self._plans.values() for statement in plan.accepted]
        accepted.extend(proposal.statement for proposal, _ in self._installable())
        return accepted

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
        verdicts = [(plan, plan._allowed()) for plan in self._plans.values()]
        rewrites = self._installable()
        landed: list[Node] = []
        moved = False
        for plan, allowed in verdicts:
            was_moved, installed = plan._apply(allowed)
            moved = moved or was_moved
            landed.extend(installed)
        for proposal, replacement in rewrites:
            if not _replace_in_parent(proposal.statement, replacement):
                continue
            landed.append(replacement)
            moved = True
        _restore(landed)
        return moved
