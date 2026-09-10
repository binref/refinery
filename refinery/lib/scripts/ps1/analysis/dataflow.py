"""
Which write a PowerShell variable read observes.

This is the join of three layers that already exist and have never been asked one question together:
`refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel` says which occurrences name the same
binding, `refinery.lib.scripts.analysis.cfg.ControlFlowModel` says what runs before what, and
`refinery.lib.scripts.ps1.analysis.blocks.Ps1BlockModel` says whose variables a script block writes.
The join is possible because the graphs and the scopes now partition the script the same way — one
graph and one scope per `refinery.lib.scripts.ps1.model.Ps1ScriptBlock`, plus one of each for the
root — so a binding's writes and a read of it land in comparable places.

**A write is a write.** Whether its value happens to be a constant is the *caller's* question and is
asked after this one, never before it. The pass this replaces sorted writes into two tables by that
test and only one table killed, so `if ($c) { $x = 'b' }` silently kept the value from before the
branch while `if ($c) { $x = $y }` correctly refused — same position, same graph, opposite answers.
Nothing here may reintroduce that split.

**One refusal this layer owes its callers that is not graph-theoretic: a store that did not finish.**
Dominance says a statement ran, not that its store completed —
`refinery.lib.scripts.analysis.liveness` states the same asymmetry as the reason its transfer function
is not the textbook one — so `try { [int]$x = 'abc' } catch { Write-Host $x }` must not publish
`'abc'`, because the run that enters the handler is exactly the run in which the cast raised and the
store never happened. Dominance cannot see this: the handler *is* dominated by the statement that
failed to store it. `Ps1VariableFlow._observes_completed_store` is the rule, and it decides on the
first edge only — once control has left the statement normally, the store is done. It is asked of
both walks, because a handler rejoins: the statement after a whole `try` and the one a
`trap { continue }` resumes into are reached by completing *and* by throwing, and a use the throwing
path reaches at all is a use that may observe no store.

**A read inside a body is evaluated where that body runs, and that is a position this layer holds
whenever `Ps1BlockModel` knows the site.** `$v = 'a'; 1..3 | %{ $v }` reads `$v` at the pipeline,
which `$v = 'a'` dominates, and refusing it because the read and the write sit in different graphs
throws away most of what obfuscated PowerShell is made of. So the read is *projected* to its body's
site and asked there, climbing out through each enclosing body in turn.

What may not be projected is a body that does not run when its site does — a function body, a stored
block, a block handed to something that may or may not invoke it. `$b = { Write-Host $x }` is a
value, and ordering the read inside it against the script around it reads the script as if the block
ran where it was written. The climb stops at the first such body and the read goes unanswered.

That is a fact about *the read*, never about the binding: `$x = 'a'; function f { Write-Host $x }`
still tells the read beside the write exactly what it observes. Widening it to the binding refuses
every name a function body mentions, which is most of them, and — because it then answers nothing —
leaves the question of whether a write may be *deleted* resting on nothing at all.

**One statement is one point to the graphs, and PowerShell orders what is inside it.** A read and a
write of the same name can share a control-flow node — `$x = [char]($x)`, `Write-Host $x ($x = 'new')`
— and the graph cannot say which came first, so on its own it must refuse both. What it *can* be told
is `refinery.lib.scripts.ps1.ast.in_evaluation_order`, which is the language's answer: a write later
in it than the read has not happened when the read is evaluated, so it is not a definition for that
read and is left out rather than counted against it. The exception is a statement control returns to,
where the previous visit's store is exactly what the read observes — `while ($c) { $x = $x[0] }` — so
the exclusion is asked of `refinery.lib.scripts.analysis.cycles.CycleModel` first.

**A write nobody can attribute to a name is still a write at a known point.** `Set-Variable $n 'v'`
may land on any binding of the scope it runs in, and no reading of the source narrows that — but when
it runs is not in doubt at all, so `Write-Host $x; Set-Variable $n 'v'` observes the value it always
would have. Holding the fact on the `Scope` instead refuses that read too, and refuses it for as long
as the tree stands: `$x = 'a'; . { Set-Variable $n 'v' }; Write-Host $x` then folded to `'a'` at the
same time, because the flag sat on the block's scope while the write landed in the caller's.
`unattributable_writes` is the kill, and `Ps1BlockModel.unattributable_writes_reaching_caller` is what
carries it out of a body that runs in its caller's scope. What stays on the scope is only what has no
point to stand at: a write aimed at the script scope from anywhere, one aimed at a scope the lexical
chain cannot name, and one run by a block whose own run time this layer cannot place.

A write inside a `trap` is a case this layer gets right for the wrong reason, and the distinction
matters if either half is touched. 5.1 runs a trap body in a child scope, so the write cannot reach
a read outside the trap at all; `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel` does not
model that and binds it to the enclosing scope. What refuses the answer is the kill rule — the
trap's write is another write of the same binding, and the exceptional edge into the handler with
the resume edge back out puts it on a path between any earlier write and that read.
"""
from __future__ import annotations

import enum

from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    Projection,
    distinct,
)
from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockModel, Ps1BlockReach
from refinery.lib.scripts.ps1.analysis.model import (
    Binding,
    Occurrence,
    Ps1SemanticModel,
    Scope,
    scope_local_nodes,
)
from refinery.lib.scripts.ps1.analysis.opaque import writes_nobody_can_attribute
from refinery.lib.scripts.ps1.ast import in_evaluation_order
from refinery.lib.scripts.ps1.model import (
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1Variable,
)


class Ps1FlowUnknown(enum.Flag):
    """
    Why a binding's values cannot be tracked. A flag rather than a boolean because the reasons are
    not the same kind of fact and a caller may be able to live with one and not another — and because
    one predicate folding several unrelated refusals is the shape this package has already had to
    take apart once.
    """
    NONE = 0
    #: A write occurrence the control-flow graphs do not place. Its point of evaluation is not a
    #: point these graphs hold, so nothing can be ordered against it.
    UNPLACED_WRITE = enum.auto()
    #: The binding's writes are spread over more than one body. Whether one body runs before another
    #: is a question about calls, which this layer does not answer, so no read of it can be. A write
    #: in one body and a *read* in another is not this: only that read is out of reach, and
    #: `reaching_definition` refuses it where it stands.
    WRITES_IN_SEVERAL_BODIES = enum.auto()
    #: The binding is reachable through a scope qualifier or a dynamic scope, so an occurrence that
    #: does not appear in `reads` or `writes` at all may still touch it.
    REACHED_BY_QUALIFIER = enum.auto()
    #: A body that may write this binding runs at a time this layer cannot place — a stored block, a
    #: block handed to a command that may or may not invoke it.
    WRITTEN_BY_DEFERRED_BODY = enum.auto()
    #: A write whose name cannot be read off the source — `Set-Variable $n 'v'` — may land on this
    #: binding at a moment nothing here can place: aimed at the script scope out of any body, at a
    #: scope the lexical chain cannot name, or run by a block whose own run time is unplaceable.
    #: The placeable ones are not this; they are nodes in `unattributable_writes`. Kept apart from
    #: `REACHED_BY_QUALIFIER`, which says a *known* name is reachable another way: these are
    #: different reasons and a caller may be able to live with one.
    WRITTEN_BY_UNREADABLE_NAME = enum.auto()
    #: The binding holds writes through two scopes a read resolves in order — see
    #: `_shadows_a_wider_scope`. One name here is two names in the language, and every write of the
    #: wider one is a write a bare read never observes.
    SHADOWS_A_WIDER_SCOPE = enum.auto()


class Ps1ObservedWrite(enum.Enum):
    """
    What `Ps1VariableFlow.write_observed_at` answers where it names no write occurrence. Two answers
    rather than one, because a caller acts on them differently: nothing having been written is a
    fact about the name, and it is the caller's own business what a name nobody wrote is worth.
    """
    #: No write of the name has run by the time the point is reached, so what stands there is
    #: whatever stood before the script did.
    NOTHING = enum.auto()
    #: No single write can be named — several reach, one may have run in between, or something the
    #: script does puts the name out of reach altogether.
    UNKNOWN = enum.auto()


class Ps1VariableFlow:
    """
    Which write each variable read of one script observes, over that script's semantic, control-flow
    and block models. Build it through `build_variable_flow`.
    """

    def __init__(
        self,
        semantic: Ps1SemanticModel,
        flow: ControlFlowModel,
        dominators: DominatorModel,
        blocks: Ps1BlockModel,
        cycles: CycleModel,
    ):
        self.semantic = semantic
        self.flow = flow
        self.dominators = dominators
        self.blocks = blocks
        self.cycles = cycles
        self._between = ReachabilityQuery(dominators, Projection.MAY)
        self._unknowns: dict[int, Ps1FlowUnknown] = {}
        self._exits: dict[tuple[int, int], tuple[frozenset[int], frozenset[int]]] = {}
        self._kills: dict[tuple[int, str], frozenset[int]] = {}
        self._unattributable: dict[int, tuple[tuple[CfgNode, Node], ...]] = {}
        self._unattributable_ids_by_graph: dict[int, frozenset[int]] = {}
        self._deferred_unattributable: bool | None = None
        self._any_unattributable: bool | None = None
        self._any_placed: bool | None = None
        self._blocks_by_owner: dict[int, list[Ps1ScriptBlock]] = {}
        self._deferred_writes: dict[tuple[str, int], bool] = {}
        self._alias_holds: dict[tuple[int, int], bool] = {}

    def reaching_definition(self, read: Ps1Variable) -> Ps1Variable | None:
        """
        The write occurrence whose value *read* observes, or `None` when no single write does.

        `None` is the answer to every kind of doubt — the binding is unknown, two writes reach, a
        write between them may have changed the value — so a caller may treat a returned occurrence
        as the one and only value the read can see, and must treat `None` as knowing nothing.

        A write the binding only *may* receive is one of those doubts, and `_alias_holds_at` is what
        settles it. `Occurrence.shared_through` marks a store filed against this name because
        another name for the same object carries it; it always kills, and it names a value only
        where the definitions that made the two names one are still standing at the store.
        Answering with one that is not is how `$x = 1, 2, 3; $y = $x; $y = 9, 9, 9;
        [Array]::Reverse($x); $y` came to print the reversal of an array `$y` had already stopped
        holding.

        A read in another body is asked at the point that body runs, or not at all — see
        `_position_of`.
        """
        binding = self.semantic.binding_of(read)
        if binding is None or not binding.writes:
            return None
        if self.unknowns(binding) is not Ps1FlowUnknown.NONE:
            return None
        placed = {id(write.node): self.flow.locate(write.node) for write in binding.writes}
        graph = placed[id(binding.writes[0].node)][0]
        use = self._position_of(read, graph)
        if use is None:
            return None
        definitions = [
            (write.node, placed[id(write.node)][1]) for write in binding.writes
            if not self._stores_after(use, read, write.node)
        ]
        found = self._between.reaching_definition(
            graph,
            use,
            definitions,
            self._block_kills(graph, binding.name) | self._unattributable_kills(graph, read, use),
        )
        if found is None:
            return None
        if not self._observes_completed_store(graph, placed[id(found)][1], use):
            return None
        if not self._shared_write_names_a_value(binding, found, graph):
            return None
        return found

    def _shared_write_names_a_value(
        self,
        binding: Binding,
        found: Node,
        graph: ControlFlowGraph,
    ) -> bool:
        """
        Whether a value may be read out of the write standing at *found*: either it is spelled on
        *binding*'s own name, or it was shared in and every definition it came through still holds.

        The two orderings this stands between — a read of an occurrence and a read of a point —
        ask the same question, so it is asked once here rather than spelled twice.
        """
        return all(
            self._alias_holds_at(write, graph)
            for write in binding.writes
            if write.may_define and write.node is found
        )

    def _alias_holds_at(self, shared: Occurrence, graph: ControlFlowGraph) -> bool:
        """
        Whether every definition *shared* reaches its binding through is still standing where the
        store runs, so that the name really does hold the object the store changed.

        One link holds when it certainly handed the object over, its definition runs first on every
        path to the store, and neither of the two names it joins is *rebound* between the two. A
        store through either name does not end the link: `$y = $x; $x[0] = 9; [Array]::Reverse($x)`
        leaves both names on the one array
        throughout. A replacing write does end it, on either side: `$y = 9, 9, 9` gives `$y` an
        array of its own, and `$x = 9, 9, 9` gives one to `$x` and leaves `$y` on what it had.

        A link the model marked uncertain never holds here. `$y = [array]$x` shares where the cast
        converts nothing and copies where it converts, so the store has to keep killing — a read
        below it must not be answered from above — while naming no value for either name.

        Nothing is ordered across bodies here, and nothing is ordered within a statement: a rebind
        the graphs place at the store's own node is refused rather than guessed at, which is the
        same rule `reaching_definition` follows for a definition sharing its use's statement.

        **A rebind no occurrence spells ends the link too.** A dot-sourced block writes the caller's
        scope, so `$y = $x; . { $y = 9, 9, 9 }; [Array]::Reverse($x)` leaves `$y` on an array of its
        own — measured, 5.1 writes `9 9 9` — and the write is one statement to this graph with no
        occurrence of `$y` in the tree around it. `_block_kills` is where the block model already
        answers that, and it is asked of both names; `unknowns` is asked of both bindings for the
        same reason, since a name a qualifier, a deferred body or an unreadable spelling can reach
        is one this cannot say is unrebound.
        """
        key = (id(shared), id(graph))
        found = self._alias_holds.get(key)
        if found is None:
            found = self._alias_holds[key] = self._compute_alias_holds_at(shared, graph)
        return found

    def _compute_alias_holds_at(self, shared: Occurrence, graph: ControlFlowGraph) -> bool:
        store = self.flow.locate(shared.node)
        if store is None or store[0] is not graph:
            return False
        for link in shared.shared_through:
            if not link.certain:
                return False
            placed = self.flow.locate(link.definition)
            if placed is None or placed[0] is not graph or placed[1] is store[1]:
                return False
            if not self.dominators.dominates_node(graph, placed[1], store[1], Projection.MAY):
                return False
            rebinds: set[int] = set()
            for side in (link.first, link.second):
                if self.unknowns(side) is not Ps1FlowUnknown.NONE:
                    return False
                rebinds.update(self._block_kills(graph, side.name))
                for write in side.writes:
                    if write.role.through or write.node is link.definition:
                        continue
                    where = self.flow.locate(write.node)
                    if where is None or where[0] is not graph:
                        return False
                    if where[1] is store[1]:
                        return False
                    rebinds.add(id(where[1]))
            if self._between.any_between(graph, placed[1], store[1], rebinds):
                return False
        return True

    def write_observed_at(self, key: str, site: Node) -> Node | Ps1ObservedWrite:
        """
        The write of the script's own binding of *key* whose value stands where *site* is evaluated,
        or why none can be named.

        The sibling of `reaching_definition` for a read nothing spells. A name the *engine* consults
        where a value is used — `$OFS`, which a collection is joined with — is read at a point
        holding no occurrence to key a binding by and no position to order against, so the name and
        the point are given here instead. What the two share is the whole of the ordering: the same
        definitions, the same block and unattributable kills, the same completed-store rule.

        **Only a site the script's own scope evaluates is answered.** A body has a scope of its own
        and a bare write inside one binds there, so a site within a body may be reading a name this
        binding is not — `& { $OFS = '-'; [string]@(1, 2) }` separates on the block's own write, of
        which the script's binding says nothing at all. Projecting the site out of the body
        the way a read is projected would answer for the wrong binding, so it is refused instead.

        `Ps1ObservedWrite.NOTHING` is the answer no read of an occurrence has and this one needs: a
        name the script has not written by the time the point is reached still has a value, and only
        the caller knows what. It is a claim that no write and no kill lies between the script's
        entry and the point, which is stronger than `reaching_definition` naming none — a write on
        a branch, or one a back edge carries around, names no single definition and is not nothing.
        """
        graph = self.flow.graph_of(self.semantic.root)
        if graph is None or self._doubt_without_a_point():
            return Ps1ObservedWrite.UNKNOWN
        if self._deferred_body_writes(key, self.semantic.root):
            return Ps1ObservedWrite.UNKNOWN
        located = self.flow.locate(site)
        if located is None or located[0] is not graph:
            return Ps1ObservedWrite.UNKNOWN
        use = located[1]
        placed: dict[int, CfgNode] = {}
        definitions: list[tuple[Node, CfgNode]] = []
        binding = self.semantic.root_scope.bindings.get(key)
        if binding is not None:
            if self.unknowns(binding) & (
                Ps1FlowUnknown.REACHED_BY_QUALIFIER
                | Ps1FlowUnknown.SHADOWS_A_WIDER_SCOPE
            ):
                return Ps1ObservedWrite.UNKNOWN
            for write in binding.writes:
                where = self.flow.locate(write.node)
                if where is None or where[0] is not graph:
                    return Ps1ObservedWrite.UNKNOWN
                placed[id(write.node)] = where[1]
                if not self._stores_after(use, site, write.node):
                    definitions.append((write.node, where[1]))
        kills = self._block_kills(graph, key) | self._unattributable_kills(graph, site, use)
        found = self._between.reaching_definition(graph, use, definitions, kills)
        if found is not None:
            if not self._observes_completed_store(graph, placed[id(found)], use):
                return Ps1ObservedWrite.UNKNOWN
            if binding is not None and not self._shared_write_names_a_value(binding, found, graph):
                return Ps1ObservedWrite.UNKNOWN
            return found
        blocking = kills | frozenset(id(node) for _, node in definitions)
        if self._between.any_between(graph, graph.entry, use, blocking):
            return Ps1ObservedWrite.UNKNOWN
        return Ps1ObservedWrite.NOTHING

    def written_before(self, read: Ps1Variable) -> bool:
        """
        Whether a write of the binding *read* names has certainly run by the time *read* is
        evaluated.

        Weaker than `reaching_definition`, which names *which* write reaches. This says only that
        the name has been given a value at all, and it is what a caller reasoning about every write
        of a binding at once has to establish before its reasoning means anything: a binding whose
        writes all agree about something says nothing about a read that precedes all of them. What
        stands there is whatever stood before the script ran, and `$q = New-Object X` written
        *after* `$q | Get-Member` does not make the name a WebClient at the pipeline.

        Two ways for a write to have run, and a caller needs both. A write whose statement dominates
        the read's ran on every path that arrives, and stored what it ran to store —
        `_observes_completed_store` is asked here for the reason this module's own documentation
        gives it: `try { $q = New-Object X } catch { $q.Foo }` reaches the handler on exactly the
        run where the store did not happen, and dominance cannot see that. A write inside the *same*
        statement is ordered by the language where the graphs cannot order it at all, which is what
        a script that builds a name and reads it inside one `$( ... )` depends on.

        The read is asked at the position `_position_of` gives it, so a read inside a body that runs
        exactly where it is written is ordered against the writes around that body. Locating the
        read where it is *spelled* instead refuses `$q = New-Object …; & { $q.Foo }` outright, which
        is the shape this whole question was kept for. The graph a write is asked in is the write's
        own, so a binding whose writes are spread over several bodies is answered by whichever of
        them the read can be projected into, rather than by whichever one happens to be written
        first.
        """
        binding = self.semantic.binding_of(read)
        if binding is None or not binding.writes:
            return False
        positions: dict[int, CfgNode | None] = {}
        for write in binding.writes:
            where = self.flow.locate(write.node)
            if where is None:
                continue
            graph, at = where
            if id(graph) not in positions:
                positions[id(graph)] = self._position_of(read, graph)
            use = positions[id(graph)]
            if use is None:
                continue
            if at is not use:
                if (
                    self.dominators.dominates_node(graph, at, use, Projection.MAY)
                    and self._observes_completed_store(graph, at, use)
                ):
                    return True
            elif self._runs_before(graph, use, read, write.node):
                return True
        return False

    def _runs_before(
        self, graph: ControlFlowGraph, use: CfgNode, read: Node, write: Node,
    ) -> bool:
        """
        Whether *write* is evaluated before *read*, both of them parts of the one statement *use*
        stands for.

        The positive counterpart of `_runs_after`, and it has to be its own question rather than
        that one negated: `_runs_after` answers `False` wherever it cannot tell, which is the safe
        answer for a caller keeping a kill and the unsafe one for a caller claiming an order. A
        statement control can return to is refused for the reason stated there — the previous visit
        ordered the two the other way round — and so is a read projected here out of a body, which
        may be evaluated on visits this walk does not describe.

        **One occurrence is not before itself**, and the walk below would say it is: `$x += 1` and
        `$x++` are one node filed under both `reads` and `writes`, so the first test would match it
        as the write and claim a value had been stored at the point of its own store. The two
        questions phrased the other way round order the read first and fail safe where this one
        fails open, which is why the refusal has to be spelled here.
        """
        if read is write:
            return False
        if use.element is None or self.cycles.repeats(use.element):
            return False
        placed = self.flow.locate(read)
        if placed is None or placed[0] is not graph or placed[1] is not use:
            return False
        for node in in_evaluation_order(use.element):
            if node is write:
                return True
            if node is read:
                return False
        return False

    def foreign_write_before(self, read: Ps1Variable) -> bool:
        """
        Whether a write the binding *read* names does not hold may already have run when *read* is
        evaluated.

        The kills `reaching_definition` folds into its selection, asked on their own. A caller whose
        other half is not an ordering still has to know them, because its whole claim is that the
        writes it can see are all the writes there are: `Invoke-Expression $code` stores a value of
        any type under any name, and `. { $q = New-Object X }` stores into the caller's scope from a
        binding of its own — neither appears in `Binding.writes`, and a name every visible write
        agrees about is still whatever one of these left behind. `True` is the answer to every
        doubt, a read the graphs do not place included.

        The unattributable half is `ambient_value_survives` read the other way round, and it is
        spelled as that rather than assembled again: asking the read's *own* graph would let an
        `Invoke-Expression` in the script around it go unseen, since the graph of a block holds none
        of the statements that surround the block. `written_before` projects the read with
        `_position_of` and this has to be answered at the same position or the two say nothing
        together.
        """
        if not self.ambient_value_survives(read):
            return True
        binding = self.semantic.binding_of(read)
        if binding is None:
            return True
        positions: dict[int, CfgNode | None] = {}
        for write in binding.writes:
            placed = self.flow.locate(write.node)
            if placed is None:
                return True
            graph = placed[0]
            if id(graph) not in positions:
                positions[id(graph)] = self._position_of(read, graph)
            use = positions[id(graph)]
            if use is None:
                return True
            kills = self._block_kills(graph, binding.name)
            if self._between.any_between(graph, graph.entry, use, kills):
                return True
        return False

    def unknowns(self, binding: Binding) -> Ps1FlowUnknown:
        """
        Every reason *binding*'s values cannot be tracked, or `Ps1FlowUnknown.NONE` when there is
        none. Fixed for as long as the tree is, so it is computed once per binding.
        """
        found = self._unknowns.get(id(binding))
        if found is None:
            found = self._unknowns[id(binding)] = self._compute_unknowns(binding)
        return found

    def _compute_unknowns(self, binding: Binding) -> Ps1FlowUnknown:
        found = Ps1FlowUnknown.NONE
        if binding.dynamic_or_qualified:
            found |= Ps1FlowUnknown.REACHED_BY_QUALIFIER
        if _shadows_a_wider_scope(binding):
            found |= Ps1FlowUnknown.SHADOWS_A_WIDER_SCOPE
        graphs: set[int] = set()
        for write in binding.writes:
            placed = self.flow.locate(write.node)
            if placed is None:
                found |= Ps1FlowUnknown.UNPLACED_WRITE
                continue
            graphs.add(id(placed[0]))
        if len(graphs) > 1:
            found |= Ps1FlowUnknown.WRITES_IN_SEVERAL_BODIES
        if self._deferred_body_writes(binding.name, binding.scope.node):
            found |= Ps1FlowUnknown.WRITTEN_BY_DEFERRED_BODY
        if binding.scope.writes_unreadable_names or self.deferred_unattributable_writes:
            found |= Ps1FlowUnknown.WRITTEN_BY_UNREADABLE_NAME
        return found

    def _position_of(self, read: Ps1Variable, graph: ControlFlowGraph) -> CfgNode | None:
        """
        The node of *graph* at which *read* is evaluated, or `None` when *graph* never evaluates it.

        A read inside a body happens wherever that body runs, so a read one graph in is projected
        onto the statement that runs its body, and again for each body around that one. It is the
        step that lets `$v = 'a'; 1..3 | %{ $v }` be answered at all: the read sits in the block's
        graph and every write of `$v` in the script's, and the pipeline is a point both can be
        ordered against.

        Only a body that runs exactly when its site does may be projected — `Ps1BlockReach.IMMEDIATE`
        and nothing else. A function body runs at its call sites, a stored block whenever its value
        is invoked, and a block handed to an unrecognized command perhaps never; giving any of them
        the position of the statement they are *written* in is the false claim the per-body split
        exists to avoid, so the climb stops there and the read goes unanswered.
        """
        located = self.flow.locate(read)
        while located is not None:
            found, node = located
            if found is graph:
                return node
            owner = found.owner
            if not isinstance(owner, Ps1ScriptBlock):
                return None
            facts = self.blocks.facts(owner)
            if facts.reach is not Ps1BlockReach.IMMEDIATE or facts.site is None:
                return None
            located = self.flow.locate(facts.site)
        return None

    def _stores_after(self, use: CfgNode, read: Node, write: Node) -> bool:
        """
        Whether *write* stores its value only once *read* has already been evaluated, both of them
        parts of the one statement *use* stands for.

        Such a write is not a definition for that read and is left out of the selection entirely
        rather than counted against it — the distinction `refinery.lib.scripts.analysis.reaching`
        asks the caller to make, since a write left in kills whether or not it wins. What decides it
        is `refinery.lib.scripts.ps1.ast.in_evaluation_order`, not source position: `$x = [char]($x)`
        writes a target written to the *left* of the read and stores after it.

        A statement control can return to is excluded from the exclusion: there the store of the
        previous visit is what the read observes, so `while ($c) { $x = $x[0] }` knows nothing.
        """
        placed = self.flow.locate(write)
        if use.element is None or placed is None or placed[1] is not use:
            return False
        if self.cycles.repeats(use.element):
            return False
        for node in in_evaluation_order(use.element):
            if node is read:
                return True
            if node is write:
                return False
        return False

    def _deferred_body_writes(self, key: str, own: Node) -> bool:
        """
        Whether a block whose run time this layer cannot place may write the binding *key* names.
        Asked once per binding by `unknowns` and once per site by `write_observed_at`, so the walk
        over every block of the script is kept rather than repeated.

        *own* is required rather than defaulted so that a caller states which body the binding lives
        in. A default of `None` happens to answer the same for a binding of the root scope, because
        a `Ps1Script` is not a `Ps1ScriptBlock` and so is never among the blocks walked — an
        accident that would go on being right until the day the walk or the caller changed.
        """
        cached = (key, id(own))
        found = self._deferred_writes.get(cached)
        if found is None:
            found = self._deferred_writes[cached] = self._find_deferred_body_writes(key, own)
        return found

    def _find_deferred_body_writes(self, key: str, own: Node) -> bool:
        """
        Whether a block whose run time this layer cannot place may write the binding *key* names. A
        stored block is a value: it may be invoked before or after any statement here, so a write
        inside it defeats every ordering the graphs could establish.

        The body a binding lives in is not one of those blocks, and *own* is what names it. A stored
        block's statements are perfectly ordered against *each other* however late the block runs,
        and counting it against itself makes every binding local to a stored block unanswerable —
        which reads as caution and is simply a wrong reading of the question.

        Every other block of the script is one, wherever it is written. A stored block is a value
        and its bare writes land in the scope of whoever runs it, so `$b = { $x = 'b' }` written at
        the root reaches the `$x` of `. { $x = 'a'; . $b; … }` just as surely as one written inside
        that body — searching only the binding's own subtree answers for the second and misses the
        first.
        """
        for block in self._blocks_of(self.semantic.root):
            if block is own:
                continue
            facts = self.blocks.facts(block)
            if facts.reach not in (Ps1BlockReach.STORED, Ps1BlockReach.UNKNOWN):
                continue
            for write in self.blocks.writes_reaching_caller(block):
                if write.key == key:
                    return True
        return False

    def _blocks_of(self, owner: Node) -> list[Ps1ScriptBlock]:
        """
        Every script block written inside *owner*. Read off the tree once per owner: a caller asks
        this per read, and the walk is the whole subtree.
        """
        found = self._blocks_by_owner.get(id(owner))
        if found is None:
            found = self._blocks_by_owner[id(owner)] = [
                node for node in owner.walk() if isinstance(node, Ps1ScriptBlock)
            ]
        return found

    def _block_kills(self, graph: ControlFlowGraph, name: str) -> frozenset[int]:
        """
        The nodes of *graph* that run a script block writing the binding *name* names into the scope
        that invokes it. A `. { $x = 'b' }` is one statement to the graph and its store is invisible
        in the tree around it, so without this the caller's `$x` reads as never having been touched.

        The answer turns on the graph and the name alone, both fixed for as long as this model
        lives, so it is computed once per pair rather than per read.
        """
        key = (id(graph), name)
        found = self._kills.get(key)
        if found is not None:
            return found
        kills: set[int] = set()
        for block in self._blocks_of(graph.owner):
            if not any(
                write.key == name
                for write in self.blocks.writes_reaching_caller(block)
            ):
                continue
            placed = self.flow.locate(block)
            if placed is not None and placed[0] is graph:
                kills.add(id(placed[1]))
        found = self._kills[key] = frozenset(kills)
        return found

    def unattributable_writes(self, graph: ControlFlowGraph) -> tuple[CfgNode, ...]:
        """
        The nodes of *graph* at which a write nobody can attribute to a name lands in the scope that
        node runs in — `Set-Variable $n 'v'`, and a `. { }` running one in its caller's scope.

        Such a write is a fact about a *point*. Which binding it hit is unknown and stays unknown,
        but when it happened is not, so a read reaching its definition without passing this node
        observes the value it would have observed had the write not been there. Recording it against
        the whole scope instead — which is what `Scope.writes_unreadable_names` still does for the
        writes that cannot be placed — refuses those reads as well, and refuses them for as long as
        the tree stands.
        """
        return tuple(distinct(node for node, _ in self._unattributable_pairs(graph)))

    def _unattributable_pairs(
        self, graph: ControlFlowGraph,
    ) -> tuple[tuple[CfgNode, Node], ...]:
        """
        Each unattributable write of *graph* paired with the node that performs it. One graph node
        may hold several, and the element is what orders one of them against a read sharing it.
        """
        found = self._unattributable.get(id(graph))
        if found is None:
            found = self._unattributable[id(graph)] = tuple(self._find_unattributable(graph))
        return found

    def _find_unattributable(self, graph: ControlFlowGraph) -> Iterator[tuple[CfgNode, Node]]:
        for node in scope_local_nodes(graph.owner):
            if isinstance(node, Ps1ScriptBlock):
                if not self.blocks.unattributable_writes_reaching_caller(node):
                    continue
            elif not writes_nobody_can_attribute(node):
                continue
            placed = self.flow.locate(node)
            if placed is not None and placed[0] is graph:
                yield placed[1], node

    def _unattributable_kills(
        self, graph: ControlFlowGraph, read: Node, use: CfgNode,
    ) -> frozenset[int]:
        """
        The unattributable writes of *graph* that may already have run when *read* is evaluated.

        All of them but one: the statement holding the read may hold the write as well, and there
        the language orders them where the graph cannot. `Invoke-Expression $x` is the shape that
        matters, and getting it wrong does not merely lose a fold — the read is the payload the call
        expands, so a kill that blocks it stops the call ever becoming literal, which stops it
        expanding, which leaves the kill in place. The loader comes back out as the obfuscator
        wrote it.

        A read *projected* onto this statement out of a body gets no such exclusion, even though the
        walk would order it: the body may run many times against the one visit the walk describes.
        `1..2 | %{ Write-Host $x } | %{ iex $s }` streams, so the second object reaches the first
        body only after the first object has reached the second, and `CycleModel.repeats` does not
        say so — what repeats is the body, not the pipeline the read was projected onto. So the
        exclusion is refused wherever the ordering is not the read's own statement's.
        """
        kills = self._unattributable_ids(graph)
        if id(use) not in kills:
            return kills
        if any(
            not self._runs_after(graph, use, read, effect)
            for node, effect in self._unattributable_pairs(graph) if node is use
        ):
            return kills
        return kills - {id(use)}

    def _unattributable_ids(self, graph: ControlFlowGraph) -> frozenset[int]:
        found = self._unattributable_ids_by_graph.get(id(graph))
        if found is None:
            found = self._unattributable_ids_by_graph[id(graph)] = frozenset(
                id(node) for node, _ in self._unattributable_pairs(graph)
            )
        return found

    def _runs_after(
        self, graph: ControlFlowGraph, use: CfgNode, read: Node, effect: Node,
    ) -> bool:
        """
        Whether *effect* runs its unreadable code only once *read* has been evaluated, both of them
        parts of the one statement *use* stands for.

        **A read the call is given is evaluated to produce its argument**, so it always happens
        first, however deeply it sits, which `Node.is_descendant_of` is the question for —
        `Invoke-Expression ($a | %{ [char]($_ -bxor $k) })` reads `$k` inside a body, and the whole
        argument is built, iterations and all, before the call runs. That is the shape an obfuscated
        loader is made of, and refusing it does more than lose a fold: the read is the payload, so a
        kill that blocks it stops the call ever becoming literal, which stops it expanding, which
        leaves the kill in place.

        **A read inside the body the effect stands for is a different thing entirely.** When the
        effect is a block projected onto this statement, a read within it is not an argument the
        block consumes but a statement beside the one that does the writing, and which runs first is
        the *block's* graph to answer, not this one's. `. { iex $c; Write-Host $x }` would read as
        safe under the same test, so the test is not applied there and the fold inside a projected
        body is given up.

        **Anything else is ordered only if this statement is where the read is written.**
        `refinery.lib.scripts.ps1.ast.in_evaluation_order` describes one visit, and a read projected
        here out of a body may be evaluated on many: `1..2 | %{ Write-Host $x } | %{ iex $s }`
        streams, so the second object reaches the first body only after the first object reached the
        second. `CycleModel.repeats` does not catch that — what repeats is the body, not the
        pipeline it was projected onto.

        A statement control can return to is refused outright, exactly as in `_stores_after`: the
        previous visit's effect ran before this visit's read whatever the order within one visit.
        """
        if use.element is None or self.cycles.repeats(use.element):
            return False
        if not isinstance(effect, Ps1ScriptBlock) and read.is_descendant_of(effect):
            return True
        placed = self.flow.locate(read)
        if placed is None or placed[0] is not graph:
            return False
        for node in in_evaluation_order(use.element):
            if node is read:
                return True
            if node is effect:
                return False
        return False

    def ambient_value_survives(self, read: Ps1Variable) -> bool:
        """
        Whether a value the engine established *before* the script ran is still what *read*
        observes.

        An ambient default has no write occurrence to order a read against, which reads as having
        no position at all — but it does have one: it is a definition at the entry of the script.
        So the question is the ordinary one, asked from there, and a write nobody can attribute
        answers it exactly as it answers any other read. `iex $c; Write-Host $env:ComSpec` must not
        publish the default, and `Write-Host $env:ComSpec; iex $c` must still publish it.

        Refused outright where nothing places the doubt: a scope held in doubt as a whole, and an
        unattributable write in a body whose run time is unknown.

        A read this cannot project into the script's own graph — one inside a function body or a
        stored block — has no position to order against either, so it is answered by whether the
        script holds any such write *at all*. Refusing it outright instead costs the `$PSHome` and
        `$env:` unpacking of every loader whose first stage sits inside a body, in scripts where
        nothing could have displaced the default in the first place.
        """
        if self._doubt_without_a_point():
            return False
        graph = self.flow.graph_of(self.semantic.root)
        if graph is None:
            return False
        use = self._position_of(read, graph)
        if use is None:
            return not self._any_placed_unattributable_write()
        kills = self._unattributable_kills(graph, read, use)
        return not self._between.any_between(graph, graph.entry, use, kills)

    def _any_placed_unattributable_write(self) -> bool:
        """
        Whether any graph of the script holds a write nobody can attribute. The question a read
        this cannot place has to fall back on: nothing orders it, so what is left is whether there
        is anything to order it against.
        """
        if self._any_placed is None:
            self._any_placed = any(
                self._unattributable_pairs(graph) for graph in self.flow.graphs.values()
            )
        return self._any_placed

    def _doubt_without_a_point(self) -> bool:
        """
        Whether the script holds an unattributable write that no node of any graph stands for.
        """
        if self._any_unattributable is None:
            self._any_unattributable = self.deferred_unattributable_writes or any(
                scope.writes_unreadable_names for scope in _scopes_of(self.semantic.root_scope)
            )
        return self._any_unattributable

    @property
    def deferred_unattributable_writes(self) -> bool:
        """
        Whether a block whose run time this layer cannot place runs a write nobody can attribute.
        Its point is the point the block runs at, and that is exactly what a stored block does not
        have, so the kill above has nowhere to land and the doubt belongs to the whole scope again.

        A fact about the script rather than about any binding, unlike `_deferred_body_writes`, which
        asks after one name: the name here is the part nobody can read.
        """
        if self._deferred_unattributable is None:
            self._deferred_unattributable = any(
                self.blocks.facts(block).reach in (Ps1BlockReach.STORED, Ps1BlockReach.UNKNOWN)
                and self.blocks.unattributable_writes_reaching_caller(block)
                for block in self._blocks_of(self.semantic.root)
            )
        return self._deferred_unattributable

    def _observes_completed_store(
        self,
        graph: ControlFlowGraph,
        definition: CfgNode,
        use: CfgNode,
    ) -> bool:
        """
        Whether *use* is reached from *definition* only on runs where the statement holding the
        definition ran to completion — that is, whether every path joining them leaves *definition*
        by an edge no throw is needed to take
        (`refinery.lib.scripts.analysis.cfg.ControlFlowGraph.raise_taken`).

        `try { [int]$x = 'abc' } catch { … }` enters the handler because the cast failed, which is
        exactly the run in which the store never happened, and dominance cannot see it: the handler
        is dominated by the statement that failed to store. Reaching the use *after* completing is
        therefore not enough on its own, because a handler rejoins — the statement after the whole
        `try` is reached both ways, and so is every statement a `trap { continue }` resumes into. A
        use the throwing path also reaches has to be refused however it is spelled. Once control has
        left the statement normally the store is done, so only the first edge out of *definition*
        decides which walk a node belongs to.
        """
        completed, thrown = self._exit_reach(graph, definition)
        return id(use) in completed and id(use) not in thrown

    def _exit_reach(
        self,
        graph: ControlFlowGraph,
        definition: CfgNode,
    ) -> tuple[frozenset[int], frozenset[int]]:
        """
        The ids of the nodes reached from *definition* by first leaving it normally, and the ids of
        those reached by first leaving it on a run where it threw.
        """
        key = (id(graph), id(definition))
        found = self._exits.get(key)
        if found is None:
            found = self._exits[key] = (
                self._reached_from(graph, definition, raising=False),
                self._reached_from(graph, definition, raising=True),
            )
        return found

    @staticmethod
    def _reached_from(
        graph: ControlFlowGraph,
        definition: CfgNode,
        *,
        raising: bool,
    ) -> frozenset[int]:
        seen: set[int] = set()
        stack: list[CfgNode] = []
        for successor in definition.successors:
            if graph.raise_taken(definition, successor) != raising:
                continue
            if id(successor) not in seen:
                seen.add(id(successor))
                stack.append(successor)
        while stack:
            node = stack.pop()
            for successor in node.successors:
                if id(successor) not in seen:
                    seen.add(id(successor))
                    stack.append(successor)
        return frozenset(seen)


#: The qualifiers that name a scope wider than the one a script's own statements write. A bare write
#: at the top level of a script lands in the script's scope, and `$global:` names the scope around
#: it, so the two are different names that a read resolves in order — but `Ps1SemanticModel` binds
#: both at the root and cannot tell them apart. `$script:` and `$local:` are not among them: at the
#: top level they name the scope a bare write already lands in.
_WIDER_SCOPES = frozenset({
    Ps1ScopeModifier.GLOBAL,
    Ps1ScopeModifier.USING,
})


def _shadows_a_wider_scope(binding: Binding) -> bool:
    """
    Whether *binding* holds writes through two scopes a read would resolve in order. The model files
    a `$global:` write at the root beside the script's own, so `$x = 'a'; $global:x = 'b'` reads as
    one name written twice where the language has two, and the second is the one a bare read never
    sees. A single write through a wider scope is not this: with nothing shadowing it, a bare read
    resolves to it and the two readings agree.

    Published as `Ps1FlowUnknown.SHADOWS_A_WIDER_SCOPE` rather than asked by whoever remembers to:
    it is a fact about the binding and every consumer reading `binding.writes` needs it, so a
    consumer that asked for itself is one more consumer that could forget. `reaching_definition`
    refuses on any unknown at all and inherits it that way.

    Only writes this name is *spelled* on count, in the ratio as well as in the tally. A store
    shared in from another name for the same object carries that other name's qualifier and has
    nothing to say about which scope a read of this one resolves to, and counting it would make
    a binding with a single `$global:` write read as one written through two scopes.

    A command that writes a name in a wider scope — `Set-Variable x 'v' -Scope Global` — is not
    caught, because the occurrence records no qualifier to read. That is a recorded hole rather than
    a claim; it lands on `Scope.writes_unreadable_names` instead, which is a refusal of its own.
    """
    spelled = [write for write in binding.writes if not write.may_define]
    qualified = sum(
        isinstance(write.node, Ps1Variable) and write.node.scope in _WIDER_SCOPES
        for write in spelled
    )
    return 0 < qualified < len(spelled)


def _scopes_of(scope: Scope) -> Iterator[Scope]:
    """
    *scope* and every scope nested inside it.
    """
    yield scope
    for child in scope.children:
        yield from _scopes_of(child)


def build_variable_flow(
    semantic: Ps1SemanticModel,
    flow: ControlFlowModel,
    dominators: DominatorModel,
    blocks: Ps1BlockModel,
    cycles: CycleModel,
) -> Ps1VariableFlow:
    return Ps1VariableFlow(semantic, flow, dominators, blocks, cycles)
