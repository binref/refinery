"""
Which object a PowerShell name holds, who else keeps it, and what may change it.

`refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow` answers which write a read observes.
That is a question about names, and it is not the whole of what a read may observe: a read hands
over the object and not a copy, and `refinery.lib.scripts.ps1.analysis.handoff.object_handoff`
says whether the place it hands it to keeps it — a container, a callee, a caller collecting the
output of a body. Once one does, a store through that place changes what the name holds, and it is
spelled on no name the semantic model can link to this one. `Ps1ObjectFlow.unseen_change` answers
whether such a store may run between a write and a read, and `Ps1ObjectFlow.change_may_follow`
whether one may run after a node at all. Both are facts about the *object*, so whether they matter
is the caller's question: a String is never changed in place, and only the caller holds the value.

**Code this analysis cannot read is a change.** It may store through any place it can name, in any
scope: `& ([scriptblock]::Create($c))` runs in a scope of its own and still reaches the table a
script-scope variable holds. So every node that runs such code counts beside the stores the
semantic model reads off the tree, its
`refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel.object_change_sites`. Which code that is,
is `refinery.lib.scripts.ps1.analysis.opaque.runs_unreadable_code` and
`refinery.lib.scripts.ps1.analysis.world.runs_code_it_cannot_read`, read whatever the options say:
trusting code supplied as data is a claim about the type system and the command table, not about the
objects a script holds.

**A change is ordered against a node in the first graph on the node's way out that places both.** A
node inside a body that runs where it is written — the `,$x` of `$y = & { ,$x }` — is projected onto
the statement that runs the body, and a change in the graph around it is ordered there. A change no
such graph places may run at any time and may follow anything: one in a function body, or in a
stored block.
"""
from __future__ import annotations

import enum
import typing

from typing import Callable

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, Projection
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.handoff import (
    Ps1Handoff,
    assignment_handoff,
    object_handoff,
)
from refinery.lib.scripts.ps1.analysis.model import Binding, Occurrence
from refinery.lib.scripts.ps1.analysis.opaque import runs_unreadable_code
from refinery.lib.scripts.ps1.analysis.world import runs_code_it_cannot_read
from refinery.lib.scripts.ps1.ast import (
    assignment_of,
    is_reference_cast,
    unwrap_assignment_target,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1ScriptBlock,
    Ps1Variable,
)


class Ps1ObjectFlow:
    """
    Which object each name of one script holds, who else keeps it, and what may change it, over
    that script's `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow`. Build it through
    `build_object_flow`.
    """

    def __init__(self, variables: Ps1VariableFlow, trusts: Callable[[str], bool]):
        self.variables = variables
        self.semantic = variables.semantic
        self._trusts = trusts
        self._between = ReachabilityQuery(variables.dominators, Projection.MAY)
        self._handoffs: dict[int, Ps1Handoff] = {}
        self._exposures: dict[int, tuple[_HandOff, ...]] = {}
        self._placements: dict[int, tuple[CfgNode | None, ...]] = {}
        self._unreadable: tuple[Node, ...] | None = None
        self._every: tuple[Node, ...] | None = None

    def handoff(self, var: Ps1Variable) -> Ps1Handoff:
        """
        What keeps the object the read *var* produces — see
        `refinery.lib.scripts.ps1.analysis.handoff.object_handoff`.
        """
        found = self._handoffs.get(id(var))
        if found is None:
            found = self._handoffs[id(var)] = object_handoff(var, self._trusts)
        return found

    def exposure(self, binding: Binding) -> Ps1Handoff:
        """
        How much of the object *binding* holds a place no occurrence of it spells may keep: the
        widest hand-off of any read of it, or of a name `$y = $x` gave the same object, as a
        `refinery.lib.scripts.ps1.analysis.handoff.Ps1Handoff` other than `A_NAME`.

        A read that hands the whole value to one name by a plain `=` is the link the semantic model
        files stores across, and is not an exposure unless no link came of it because the target
        has no binding to hold it by. A string-addressed read hands the value to a command, and a
        `[ref]` hands the variable itself to a callee; each keeps all of it. So does an assignment
        of the name that is used as a value, which hands on the very object it stored.
        """
        return self._widest_exposure(binding, _Changer.SPELLED)

    def files_stores_across(self, binding: Binding, other: Binding) -> bool:
        """
        Whether a store through *other* is filed against *binding*, so that handing the object one
        holds to the other by a plain `=` needs nothing further. Both must be names for one object
        in the semantic model, and *other* must end with its own body: a block that runs in its
        caller's scope, as a `ForEach-Object` body does, stores into the caller's name rather than
        into the one the model gives it.
        """
        if other not in self.semantic.names_for_one_object(binding):
            return False
        node = other.scope.node
        return not isinstance(node, Ps1ScriptBlock) or not (
            self.variables.blocks.may_write_caller_scope(node))

    def unseen_change(self, write: Node, read: Ps1Variable) -> Ps1Handoff:
        """
        How much of the object the binding of *read* holds may be changed, between *write* and
        *read*, through a place no occurrence of that binding spells: `NOWHERE` of
        `refinery.lib.scripts.ps1.analysis.handoff.Ps1Handoff` where nothing can be, and otherwise
        the widest hand-off of the object that may already have run when *read* is evaluated — a
        hand-off only *read* itself makes, or one that runs after it, leaves nothing the read
        observes.

        Every place anything in the script may change an object in place is asked, since which
        object a store through a container reaches is not something the source says. A place this
        cannot order against the two — a store in a function body or in a stored block — may run in
        between. One standing in the statement of *read* runs before it unless the language orders
        it after, which `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.runs_after`
        decides.

        A second name `$y = $x` gave the object is no exposure to a store spelled through it, which
        the semantic model files against both names, and all of one to code this cannot read, which
        may store through it with no occurrence of it anywhere.
        """
        binding = self.semantic.binding_of(read)
        if binding is None:
            return Ps1Handoff.OBJECT
        variables = self.variables
        placed = variables.flow.locate(write)
        target = None if placed is None else variables.position_of(read, placed[0])
        if placed is None or target is None:
            found = self._widest_exposure(binding, _Changer.SPELLED)
            if self.unreadable_code:
                found = found.widest(self._widest_exposure(binding, _Changer.UNREADABLE))
            return found
        graph, source = placed
        found = Ps1Handoff.NOWHERE
        for changer in _Changer:
            exposure = self._exposure_before(binding, read, graph, target, changer)
            if exposure is Ps1Handoff.NOWHERE or exposure is found:
                continue
            if self._may_change_between(graph, source, target, read, changer):
                found = found.widest(exposure)
        return found

    def change_may_follow(self, node: Node, apart_from: Node | None = None) -> bool:
        """
        Whether anything may change an object in place once *node* has been evaluated. *apart_from*
        is a store standing in the statement of *node* that the caller knows to change nothing it
        cares about. A statement control can return to counts its own stores as following it.
        """
        return self._may_follow(node, apart_from, None)

    def unreadable_code_may_follow(self, node: Node) -> bool:
        """
        Whether code this analysis cannot read may run once *node* has been evaluated. Such code may
        store through any name it likes, so it is the one change in place that no store-through of a
        name the semantic model files can stand for.
        """
        return self._may_follow(node, None, frozenset(id(code) for code in self.unreadable_code))

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

    def _may_follow(
        self, node: Node, apart_from: Node | None, only: frozenset[int] | None,
    ) -> bool:
        """
        Whether a change may run once *node* has been evaluated — any change, or only those whose
        identities are *only* — the stores of the statement of *node* that are all *apart_from*
        excepted.

        Each change is ordered in the first graph on *node*'s way out that places it: *node*'s own,
        and then, while *node* stands in a body that runs where it is written, the graph around the
        statement that runs it. There a change at that very statement may run before the body or
        after it, since the body and the rest of the statement interleave, so it follows. A change
        no graph on the way places may follow anything.
        """
        levels = [
            (here, self._between.reachable(here, forward=True), self._placements_in(graph))
            for graph, here in self.variables.positions_on_the_way_out(node)
        ]
        if not levels:
            return True
        for index, change in enumerate(self._every_change()):
            if only is not None and id(change) not in only:
                continue
            for level, (here, after, placements) in enumerate(levels):
                placed = placements[index]
                if placed is None:
                    continue
                if id(placed) not in after:
                    break
                if placed is not here or level > 0 or change is not apart_from:
                    return True
                break
            else:
                return True
        return False

    def _widest_exposure(self, binding: Binding, changer: _Changer) -> Ps1Handoff:
        found = Ps1Handoff.NOWHERE
        for hand_off in self._hand_offs_of(binding):
            found = found.widest(hand_off.to(changer))
        return found

    def _hand_offs_of(self, binding: Binding) -> tuple[_HandOff, ...]:
        """
        Every occurrence of a name for the object *binding* holds that hands the object to a place
        no occurrence of those names spells, each with how much of the object it hands on. Computed
        once for the whole alias class, since each of its names holds the same object.
        """
        found = self._exposures.get(id(binding))
        if found is None:
            hand_offs: list[_HandOff] = []
            members = self.semantic.names_for_one_object(binding)
            for member in members:
                for read in member.reads:
                    hand_off = self._read_exposure(member, read.node)
                    if hand_off.unreadable is not Ps1Handoff.NOWHERE:
                        hand_offs.append(hand_off)
                for write in member.writes:
                    handoff = self._write_exposure(write)
                    if handoff is not Ps1Handoff.NOWHERE:
                        hand_offs.append(_HandOff(write.node, handoff, handoff))
            found = tuple(hand_offs)
            for member in members:
                self._exposures[id(member)] = found
        return found

    def _read_exposure(self, binding: Binding, node: Node) -> _HandOff:
        """
        What the read *node* of *binding* exposes of the object: its hand-off, where a hand-off to
        one name is an exposure to a spelled store only where the semantic model files the stores
        of that name against *binding* — see `files_stores_across`.
        """
        if not isinstance(node, Ps1Variable):
            return _HandOff(node, Ps1Handoff.OBJECT, Ps1Handoff.OBJECT)
        handoff = self.handoff(node)
        if handoff is not Ps1Handoff.A_NAME:
            return _HandOff(node, handoff, handoff)
        target = _assigned_variable(node)
        stored_into = None if target is None else self.semantic.binding_of(target)
        if stored_into is None or not self.files_stores_across(binding, stored_into):
            return _HandOff(node, Ps1Handoff.OBJECT, Ps1Handoff.OBJECT)
        return _HandOff(node, Ps1Handoff.NOWHERE, Ps1Handoff.OBJECT)

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
        return assignment_handoff(assignment, self._trusts)

    def _exposure_before(
        self,
        binding: Binding,
        read: Ps1Variable,
        graph: ControlFlowGraph,
        target: CfgNode,
        changer: _Changer,
    ) -> Ps1Handoff:
        """
        The widest hand-off of the object *binding* holds, to a change made by *changer*, that may
        have run by the time *read* is evaluated at *target* of *graph*. A hand-off this cannot
        place may have run at any time, and *read* hands its own value on only after it has been
        read, unless its statement repeats.
        """
        earlier = self._between.reachable(target, forward=False)
        found = Ps1Handoff.NOWHERE
        for hand_off in self._hand_offs_of(binding):
            node = hand_off.node
            if node is read and self._evaluated_once_at(graph, target, read):
                continue
            here = self.variables.position_of(node, graph)
            if here is not None and id(here) not in earlier:
                continue
            found = found.widest(hand_off.to(changer))
        return found

    def _may_change_between(
        self,
        graph: ControlFlowGraph,
        source: CfgNode,
        target: CfgNode,
        read: Ps1Variable,
        changer: _Changer,
    ) -> bool:
        """
        Whether a change made by *changer* may run on a path from *source* to *target* of *graph*
        before *read* is evaluated there. One *graph* does not place may run at any time.
        """
        unreadable = frozenset(id(code) for code in self.unreadable_code)
        kills: set[int] = set()
        for change, here in zip(self._every_change(), self._placements_in(graph)):
            if (id(change) in unreadable) is not (changer is _Changer.UNREADABLE):
                continue
            if here is None:
                return True
            if here is target and self.variables.runs_after(graph, target, read, change):
                continue
            kills.add(id(here))
        return self._between.any_between(graph, source, target, kills)

    def _evaluated_once_at(self, graph: ControlFlowGraph, use: CfgNode, read: Node) -> bool:
        """
        Whether *read* is written in the statement *use* stands for rather than projected onto it
        out of a body, and that statement is not one control can return to.
        """
        if use.element is None or self.variables.cycles.repeats(use.element):
            return False
        placed = self.variables.flow.locate(read)
        return placed is not None and placed[0] is graph and placed[1] is use



class _Changer(enum.Enum):
    """
    Who makes a change in place: a store the source spells, or code this analysis cannot read.
    """
    SPELLED = enum.auto()
    UNREADABLE = enum.auto()


class _HandOff(typing.NamedTuple):
    """
    One occurrence that hands the object on, and how much of it that exposes to a spelled store
    and to code this analysis cannot read.
    """
    node: Node
    spelled: Ps1Handoff
    unreadable: Ps1Handoff

    def to(self, changer: _Changer) -> Ps1Handoff:
        return self.spelled if changer is _Changer.SPELLED else self.unreadable


def _assigned_variable(read: Ps1Variable) -> Ps1Variable | None:
    """
    The variable a plain `=` stores *read* into, climbing the parentheses and conversions a hand-off
    to one name passes through, or `None` where the read is not such a value.
    """
    cursor: Node = read
    while (parent := cursor.parent) is not None and not isinstance(parent, Ps1AssignmentExpression):
        cursor = parent
    if parent is None or parent.value is not cursor:
        return None
    target = unwrap_assignment_target(parent.target)
    return target if isinstance(target, Ps1Variable) else None


def build_object_flow(
    variables: Ps1VariableFlow,
    trusts: Callable[[str], bool] = lambda name: False,
) -> Ps1ObjectFlow:
    """
    Build the `Ps1ObjectFlow` of one script over its `Ps1VariableFlow`. *trusts* says whether a
    command name still runs the command it names there; the default trusts none, which reads every
    command as one that may keep what it is handed.
    """
    return Ps1ObjectFlow(variables, trusts)
