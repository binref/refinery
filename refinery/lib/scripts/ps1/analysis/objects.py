"""
Which object a PowerShell name holds, who else keeps it, and what may change it.

`refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow` answers which write a read observes.
That is a question about names, and it is not the whole of what a read may observe: a read hands
over the object and not a copy, and `refinery.lib.scripts.ps1.analysis.handoff.object_handoff`
says whether the place it hands it to keeps it — a second name, a container, a callee, a caller
collecting the output of a body. Once one does, a store through that place changes what the name
holds. `Ps1ObjectFlow.unseen_change` answers whether such a store may run between a write and a
read, and `Ps1ObjectFlow.change_may_follow` whether one may run after a read. Both are facts about
the *object*, so whether they matter is the caller's question: a String is never changed in place,
and only the caller holds the value — `may_be_changed_in_place` is that question.

**A store counts only against an object it may change.** `$buf[0] = 7` changes the array `$buf`
holds, and which array that is follows from the writes of `$buf` that may reach the store:
`Ps1ObjectFlow.allocations_at` names the expressions whose evaluation may have made it, and
`Ps1ObjectFlow.changes_of` the ones a change may reach. A change whose objects are known and made
somewhere other than every object a read may hold cannot reach that read's object. Anything this
cannot name — a store two steps into an object, through `$_`, into a value no name holds — may reach
every object.

**Code this analysis cannot read is a change of any object.** It may store through any place it can
name, in any scope: `& ([scriptblock]::Create($c))` runs in a scope of its own and still reaches the
table a script-scope variable holds. So every node that runs such code counts beside the stores the
semantic model reads off the tree, its
`refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel.object_change_sites`. Which code that is,
is `refinery.lib.scripts.ps1.analysis.opaque.runs_unreadable_code` and
`refinery.lib.scripts.ps1.analysis.world.runs_code_it_cannot_read`, read whatever the options say:
trusting code supplied as data is a claim about the type system and the command table, not about the
objects a script holds.

**A change is ordered against a read in the first graph on the read's way out that places both.** A
read inside a body that runs where it is written — the `,$x` of `$y = & { ,$x }` — is projected onto
the statement that runs the body, and a change in the graph around it is ordered there. A change no
such graph places may run at any time and may follow anything: one in a function body, or in a
stored block.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, Projection
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.arguments import RECEIVER
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.handoff import (
    Ps1CallTrust,
    Ps1Handoff,
    assignment_handoff,
    object_handoff,
)
from refinery.lib.scripts.ps1.analysis.identity import object_sources
from refinery.lib.scripts.ps1.analysis.model import (
    Binding,
    Occurrence,
    changes_the_object_it_names,
    written_slots_of,
)
from refinery.lib.scripts.ps1.analysis.opaque import runs_unreadable_code
from refinery.lib.scripts.ps1.analysis.values import read, type_of, unwrap_to_array_literal
from refinery.lib.scripts.ps1.analysis.world import runs_code_it_cannot_read
from refinery.lib.scripts.ps1.ast import (
    assignment_of,
    is_builtin_variable,
    is_reference_cast,
    stored_value,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.model import (
    Ps1InvokeMember,
    Ps1TypeExpression,
    Ps1Variable,
)


def may_be_changed_in_place(value: Expression) -> bool:
    """
    Whether a store can reach the object *value* names, so that a copy of it and a second name for
    it are two different things.

    A String, a number, a Char and a Boolean are what 5.1 hands over by value or never changes at
    all — `$s[0] = 'x'` on a String raises rather than writing — so a copy of one is the object.
    An array is not, and neither is a value the domain declines to name: the list of objects a store
    can reach is not one this can finish, so anything it cannot read is answered `True`. A type
    literal is the `System.Type` it spells, which holds nothing a store can reach.
    """
    if isinstance(unwrap_parens(value), Ps1TypeExpression):
        return False
    named = type_of(read(value))
    return named is None or bool(named.ranks)


def may_change_at(value: Expression, handoff: Ps1Handoff) -> bool:
    """
    Whether a store can change what a hand-off keeps of *value*: the object itself, or only the
    objects inside it where the hand-off keeps `PARTS` of it. The elements of `1, 2, 3` are numbers,
    so taking them apart hands on nothing a store can reach.
    """
    if handoff is not Ps1Handoff.PARTS:
        return may_be_changed_in_place(value)
    array = unwrap_to_array_literal(value)
    if array is None:
        return may_be_changed_in_place(value)
    return any(may_be_changed_in_place(element) for element in array.elements)


class Ps1ObjectFlow:
    """
    Which object each name of one script holds, who else keeps it, and what may change it, over
    that script's `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow`. Build it through
    `build_object_flow`.
    """

    def __init__(self, variables: Ps1VariableFlow, trust: Ps1CallTrust):
        self.variables = variables
        self.semantic = variables.semantic
        self._trust = trust
        self._between = ReachabilityQuery(variables.dominators, Projection.MAY)
        self._handoffs: dict[int, Ps1Handoff] = {}
        self._exposures: dict[int, tuple[tuple[Node, Ps1Handoff], ...]] = {}
        self._placements: dict[int, tuple[CfgNode | None, ...]] = {}
        self._allocations: dict[int, frozenset[Node] | None] = {}
        self._changed: dict[int, frozenset[Node] | None] = {}
        self._unreadable: tuple[Node, ...] | None = None
        self._every: tuple[Node, ...] | None = None

    def a_copy_may_stand_for(self, read: Ps1Variable, value: Expression) -> bool:
        """
        Whether a copy of *value* may be installed where *read* stands, which leaves every other
        name for the object the read hands on observing what it observed.

        A bare read hands over the object the name holds rather than a copy of it, so `$y = $x`
        gives one array two names, and writing the array's value where `$x` stands gives `$y` an
        array of its own: a store through `$y` below then reaches one and not the other. Measured,
        without this `$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x[0]` emits `1` where 5.1
        prints `9`. So a copy may stand only where nothing keeps the object, where what is kept is
        never changed in place, or where no change that may reach the object may follow the read.
        """
        if not may_be_changed_in_place(value):
            return True
        handoff = self.handoff(read)
        if handoff is Ps1Handoff.NOWHERE or not may_change_at(value, handoff):
            return True
        return not self.change_may_follow(read)

    def still_holds(self, write: Node, read: Ps1Variable, value: Expression) -> bool:
        """
        Whether *value*, which *write* stored, is still what *read* observes: the object it made
        cannot have been changed in between through a place no occurrence of the name spells.
        Measured, `$x = 1, 2, 3; function f { ,$x }; $y = f; $y[0] = 9; $x[0]` is `9`.
        """
        if not may_be_changed_in_place(value):
            return True
        changed = self.unseen_change(write, read)
        return changed is Ps1Handoff.NOWHERE or not may_change_at(value, changed)

    def handoff(self, var: Ps1Variable) -> Ps1Handoff:
        """
        What keeps the object the read *var* produces — see
        `refinery.lib.scripts.ps1.analysis.handoff.object_handoff`.
        """
        found = self._handoffs.get(id(var))
        if found is None:
            found = self._handoffs[id(var)] = object_handoff(var, self._trust)
        return found

    def unseen_change(self, write: Node, read: Ps1Variable) -> Ps1Handoff:
        """
        How much of the object the binding of *read* holds may be changed, between *write* and
        *read*, through a place no occurrence of that binding spells: `NOWHERE` of
        `refinery.lib.scripts.ps1.analysis.handoff.Ps1Handoff` where nothing can be, and otherwise
        the widest hand-off of the object that may already have run when *read* is evaluated — a
        hand-off only *read* itself makes, or one that runs after it, leaves nothing the read
        observes.

        Every change in place that may reach the object is asked. One this cannot order against the
        two — a store in a function body or in a stored block — may run in between. One standing in
        the statement of *read* runs before it unless the language orders it after, which
        `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.runs_after` decides. The change
        *write* itself makes — the `[Array]::Reverse($y)` a reversal of `$x` is read off — is the
        value the caller holds and not a change it has not seen.
        """
        binding = self.semantic.binding_of(read)
        if binding is None:
            return Ps1Handoff.OBJECT
        variables = self.variables
        placed = variables.flow.locate(write)
        target = None if placed is None else variables.position_of(read, placed[0])
        if placed is None or target is None:
            return self._widest_exposure(binding)
        graph, source = placed
        exposure = self._exposure_before(binding, read, graph, target)
        if exposure is Ps1Handoff.NOWHERE:
            return exposure
        held = self.allocations_at(read)
        kills: set[int] = set()
        for change, here in zip(self._every_change(), self._placements_in(graph)):
            if change is write or write.is_descendant_of(change):
                continue
            if not self._may_reach(change, held):
                continue
            if here is None:
                return exposure
            if here is target and variables.runs_after(graph, target, read, change):
                continue
            kills.add(id(here))
        if self._between.any_between(graph, source, target, kills):
            return exposure
        return Ps1Handoff.NOWHERE

    def change_may_follow(self, read: Ps1Variable) -> bool:
        """
        Whether a change in place that may reach the object *read* holds may run once *read* has
        been evaluated.

        Each change is ordered in the first graph on the read's way out that places it: the read's
        own, and then, while the read stands in a body that runs where it is written, the graph
        around the statement that runs it. There a change at that very statement may run before
        the body or after it, since the body and the rest of the statement interleave, so it
        follows. A statement control can return to counts its own changes as following it, and a
        change no graph on the way places may follow anything.
        """
        levels = [
            (here, self._between.reachable(here, forward=True), self._placements_in(graph))
            for graph, here in self.variables.positions_on_the_way_out(read)
        ]
        if not levels:
            return True
        held = self.allocations_at(read)
        for index, change in enumerate(self._every_change()):
            if not self._may_reach(change, held):
                continue
            for here, after, placements in levels:
                placed = placements[index]
                if placed is None:
                    continue
                if id(placed) in after:
                    return True
                break
            else:
                return True
        return False

    def allocations_at(self, read: Ps1Variable) -> frozenset[Node] | None:
        """
        The expressions whose evaluation may have made the object *read* holds, or `None` where
        that cannot be said.

        They are read off the writes that may reach the read — the plain assignments among them,
        each followed through the expressions that give back the object they were handed, as
        `refinery.lib.scripts.ps1.analysis.identity.object_sources` names them, and through the
        variables it reads in turn. Any other write, a value this cannot name, and a read the flow
        answers nothing for, leave the object unknown.
        """
        key = id(read)
        if key not in self._allocations:
            self._allocations[key] = self._allocations_of_read(read, frozenset())
        return self._allocations[key]

    def changes_of(self, site: Node) -> frozenset[Node] | None:
        """
        The expressions whose evaluation may have made an object the change in place at *site* may
        change, or `None` where that cannot be said.

        A store one step into what a name holds — `$b[0] = 7`, `$b.P = 7`, `$b[0]++`, and a call
        writing through a slot `$b` fills whole — changes the object `$b` holds, which is
        `allocations_at` of that occurrence. A call writing through its slots changes what each of
        them holds. Everything else may change any object: a store two steps in, one into a value no
        name holds, and code this analysis cannot read.
        """
        key = id(site)
        if key not in self._changed:
            self._changed[key] = self._find_changes_of(site)
        return self._changed[key]

    @property
    def unreadable_code(self) -> tuple[Node, ...]:
        """
        Every node of the script that runs code this analysis cannot read, in whatever scope it runs
        that code.
        """
        if self._unreadable is None:
            self._unreadable = tuple(
                node for node in self.semantic.root.walk()
                if runs_unreadable_code(node) or runs_code_it_cannot_read(node)
            )
        return self._unreadable

    def _find_changes_of(self, site: Node) -> frozenset[Node] | None:
        if runs_unreadable_code(site) or runs_code_it_cannot_read(site):
            return None
        if isinstance(site, Ps1Variable):
            if not changes_the_object_it_names(site):
                return None
            return self.allocations_at(site)
        if isinstance(site, Ps1InvokeMember):
            member = site.member
            if not isinstance(member, str):
                return None
            found: set[Node] = set()
            for slot in written_slots_of(site, member).slots:
                if slot == RECEIVER:
                    written = site.object
                elif 0 <= slot < len(site.arguments):
                    written = site.arguments[slot]
                else:
                    return None
                if written is None:
                    return None
                made = self._allocations_of_value(written, frozenset())
                if made is None:
                    return None
                found.update(made)
            return frozenset(found)
        return None

    def _may_reach(self, change: Node, held: frozenset[Node] | None) -> bool:
        """
        Whether *change* may change an object made where one of *held* was evaluated.
        """
        if held is None:
            return True
        changed = self.changes_of(change)
        return changed is None or not changed.isdisjoint(held)

    def _allocations_of_read(
        self, read: Ps1Variable, chased: frozenset[int],
    ) -> frozenset[Node] | None:
        """
        `allocations_at` for *read*, where the reads in *chased* are already being answered: a read
        met again on the way contributes nothing, since what it holds is what the writes already
        being followed made.
        """
        if id(read) in chased:
            return frozenset()
        writes = self.variables.writes_reaching(read)
        if writes is None:
            return None
        chased = chased | {id(read)}
        found: set[Node] = set()
        for write in writes:
            if not isinstance(write, Ps1Variable):
                return None
            stored = stored_value(write)
            if stored is None or stored.value is None:
                return None
            made = self._allocations_of_value(stored.value, chased)
            if made is None:
                return None
            found.update(made)
            if stored.constraint is not None:
                found.add(write)
        return frozenset(found)

    def _allocations_of_value(
        self, value: Node, chased: frozenset[int],
    ) -> frozenset[Node] | None:
        """
        The expressions whose evaluation may have made the object *value* evaluates to, or `None`
        where that cannot be said. `$null`, `$true` and `$false` are no object a store can reach.
        """
        found: set[Node] = set()
        cursor: Node | None = value
        while cursor is not None:
            if isinstance(cursor, Ps1Variable):
                if is_builtin_variable(cursor):
                    break
                made = self._allocations_of_read(cursor, chased)
                if made is None:
                    return None
                found.update(made)
                break
            sources = object_sources(cursor, self._trust.trusts)
            if sources.unknown:
                return None
            if sources.made_here:
                found.add(cursor)
            cursor = sources.operand
        return frozenset(found)

    def _widest_exposure(self, binding: Binding) -> Ps1Handoff:
        found = Ps1Handoff.NOWHERE
        for _, handoff in self._hand_offs_of(binding):
            found = found.widest(handoff)
        return found

    def _hand_offs_of(self, binding: Binding) -> tuple[tuple[Node, Ps1Handoff], ...]:
        """
        Every occurrence of a name for the object *binding* holds that hands the object to a place
        no occurrence of the binding spells, each with how much of the object it hands on. A second
        name `$y = $x` gives the object is such a place and holds all of it. Computed once for the
        whole alias class, since each of its names holds the same object.
        """
        found = self._exposures.get(id(binding))
        if found is None:
            hand_offs: list[tuple[Node, Ps1Handoff]] = []
            members = self.semantic.names_for_one_object(binding)
            for member in members:
                for occurrence in member.reads:
                    handoff = self._read_exposure(occurrence.node)
                    if handoff is not Ps1Handoff.NOWHERE:
                        hand_offs.append((occurrence.node, handoff))
                for write in member.writes:
                    handoff = self._write_exposure(write)
                    if handoff is not Ps1Handoff.NOWHERE:
                        hand_offs.append((write.node, handoff))
            found = tuple(hand_offs)
            for member in members:
                self._exposures[id(member)] = found
        return found

    def _read_exposure(self, node: Node) -> Ps1Handoff:
        """
        What the read *node* exposes of the object: its hand-off, where a hand-off to one name
        exposes all of it, and a string-addressed read hands all of it to a command.
        """
        if not isinstance(node, Ps1Variable):
            return Ps1Handoff.OBJECT
        handoff = self.handoff(node)
        return Ps1Handoff.OBJECT if handoff is Ps1Handoff.A_NAME else handoff

    def _write_exposure(self, write: Occurrence) -> Ps1Handoff:
        """
        What the write *write* exposes of the object it leaves under its name: all of it for a
        `[ref]`, whose callee holds the variable itself, and for an assignment used as a value
        whatever keeps that value — see
        `refinery.lib.scripts.ps1.analysis.handoff.assignment_handoff`.
        """
        if write.may_define:
            return Ps1Handoff.NOWHERE
        node = write.node
        if is_reference_cast(node.parent):
            return Ps1Handoff.OBJECT
        if not isinstance(node, Ps1Variable) or write.role.through:
            return Ps1Handoff.NOWHERE
        assignment = assignment_of(node)
        if assignment is None:
            return Ps1Handoff.NOWHERE
        handoff = assignment_handoff(assignment, self._trust)
        return Ps1Handoff.OBJECT if handoff is Ps1Handoff.A_NAME else handoff

    def _exposure_before(
        self,
        binding: Binding,
        read: Ps1Variable,
        graph: ControlFlowGraph,
        target: CfgNode,
    ) -> Ps1Handoff:
        """
        The widest hand-off of the object *binding* holds that may have run by the time *read* is
        evaluated at *target* of *graph*. A hand-off this cannot place may have run at any time, and
        *read* hands its own value on only after it has been read, unless its statement repeats.
        """
        earlier = self._between.reachable(target, forward=False)
        found = Ps1Handoff.NOWHERE
        for node, handoff in self._hand_offs_of(binding):
            if node is read and self._evaluated_once_at(graph, target, read):
                continue
            here = self.variables.position_of(node, graph)
            if here is not None and id(here) not in earlier:
                continue
            found = found.widest(handoff)
        return found

    def _evaluated_once_at(self, graph: ControlFlowGraph, use: CfgNode, read: Node) -> bool:
        """
        Whether *read* is written in the statement *use* stands for rather than projected onto it
        out of a body, and that statement is not one control can return to.
        """
        if use.element is None or self.variables.cycles.repeats(use.element):
            return False
        placed = self.variables.flow.locate(read)
        return placed is not None and placed[0] is graph and placed[1] is use

    def _every_change(self) -> tuple[Node, ...]:
        """
        Every node that may change an object in place: the stores the semantic model reads off the
        tree, and the code this analysis cannot read.
        """
        if self._every is None:
            self._every = (*self.semantic.object_change_sites, *self.unreadable_code)
        return self._every

    def _placements_in(self, graph: ControlFlowGraph) -> tuple[CfgNode | None, ...]:
        """
        Where *graph* evaluates each of `_every_change`, in that order, `None` for one it does not
        place.
        """
        found = self._placements.get(id(graph))
        if found is None:
            found = self._placements[id(graph)] = tuple(
                self.variables.position_of(change, graph) for change in self._every_change())
        return found


def build_object_flow(variables: Ps1VariableFlow, trust: Ps1CallTrust) -> Ps1ObjectFlow:
    """
    Build the `Ps1ObjectFlow` of one script over its `Ps1VariableFlow`. *trust* says what a command
    or a call handed an object may be believed to keep.
    """
    return Ps1ObjectFlow(variables, trust)
