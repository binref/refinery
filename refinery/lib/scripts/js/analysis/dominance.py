"""
Dominance over the per-function control-flow graphs of the
`refinery.lib.scripts.js.analysis.model.SemanticModel`. One node *dominates* another when every path
from the function's entry to the second passes through the first — so the first is guaranteed to have
executed by the time the second runs. This is the flow-sensitive replacement for the constant
inliner's statement-position heuristics: because an inlining candidate is single-assignment, "does the
constant hold its value at this use?" is exactly "does the definition dominate the use?".

This is a fourth layer of the analysis substrate, built on the control-flow graphs in
`refinery.lib.scripts.js.analysis.cfg` and keyed to AST node identity. Like those graphs it is
per-function — a nested function is a separate graph — and conservative by construction: the
exceptional edges the graph adds (a throw reaching a handler) are kept in the dominator computation, so
a definition is reported as dominating a use only when it runs before that use on *every* path,
including the ones that leave a `try` by throwing. A use a definition does not dominate, or one in a
different function's graph, is answered conservatively as not-dominated.

The public surface — `DominanceModel.dominates`, `DominanceModel.strictly_dominates`,
`DominanceModel.cfg_node_of`, `DominanceModel.runs_before_function`, `build_dominance` — is keyed to AST
nodes: an arbitrary node is located to the control-flow node of the statement (or loop head) that
evaluates it, the granularity at which the graph reasons. `strictly_dominates` is the non-reflexive
`dominates`, refusing a same-statement pair a caller must order. `runs_before_function` lifts dominance
across calls: it answers whether a definition runs before every invocation of a function, which a single
graph cannot, by ordering the definition against the points the function is referenced and recursing up
the call graph. `runs_before` and `runs_before_all` expose that same ordering against a single reference,
or every reference in a set — the query a transform needs to confirm a value is established before every
use that could observe it.
"""
from __future__ import annotations

from typing import Iterable

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cfg import (
    FUNCTION_NODES,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_control_flow_model,
)
from refinery.lib.scripts.js.analysis.model import SemanticModel, enclosing_function


class DominanceModel:
    """
    Dominator relations for the per-function control-flow graphs of one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Ask whether one AST node is guaranteed to
    execute before another with `dominates`. Build through `build_dominance`.
    """

    def __init__(self, model: SemanticModel, control_flow: ControlFlowModel | None = None):
        self.model = model
        self._flow = control_flow if control_flow is not None else build_control_flow_model(model.root)
        self._dominators: dict[int, frozenset[int]] = {}
        self._reference_points_cache: dict[int, list[Node] | None] = {}
        for graph in self._flow.graphs.values():
            self._compute_dominators(graph)

    def _locate_pair(self, a: Node, b: Node) -> tuple[CfgNode, CfgNode] | None:
        """
        The control-flow nodes that evaluate *a* and *b* when both lie in the same function's graph, or
        `None` when either is unlocatable or the two lie in different functions' graphs, where
        intraprocedural dominance does not apply.
        """
        located_a = self._flow.locate(a)
        located_b = self._flow.locate(b)
        if located_a is None or located_b is None:
            return None
        graph_a, node_a = located_a
        graph_b, node_b = located_b
        if graph_a is not graph_b:
            return None
        return node_a, node_b

    def dominates(self, a: Node, b: Node) -> bool:
        """
        Whether the statement evaluating *a* is guaranteed to have executed by the time the statement
        evaluating *b* runs: every path from the enclosing function's entry to *b* passes through *a*.
        Reflexive — a node dominates itself, since *a* and *b* in the same statement share one
        control-flow node. `False` when either node lies outside the control-flow graphs (an expression
        the graph does not represent on its own resolves to its enclosing statement; one with no
        enclosing statement node is unlocatable) or when the two lie in different functions' graphs,
        where intraprocedural dominance does not apply.
        """
        pair = self._locate_pair(a, b)
        return pair is not None and self.dominates_node(*pair)

    def strictly_dominates(self, a: Node, b: Node) -> bool:
        """
        Like `dominates`, but not reflexive: whether the statement evaluating *a* is guaranteed to have
        executed by the time *b* runs *and* is not *b*'s own statement — `False` when *a* and *b* share
        one control-flow node, where statement-granularity dominance cannot order two occurrences within
        it. A caller that must reject a same-statement occurrence needs this: a reference in the same
        statement as a definition may be evaluated before it (an earlier declarator, an earlier sequence
        operand), which the reflexive `dominates` would wrongly accept. `False` too when either node is
        unlocatable or the two lie in different functions' graphs, exactly as `dominates`.
        """
        pair = self._locate_pair(a, b)
        if pair is None or pair[0] is pair[1]:
            return False
        return self.dominates_node(*pair)

    def cfg_node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node of the statement (or loop head) that evaluates *element*, climbing out of
        any expression *element* is nested in, or `None` when *element* has no enclosing graph node.
        """
        located = self._flow.locate(element)
        return located[1] if located is not None else None

    def locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The control-flow graph and node that evaluate *element* — climbing out of any expression it is
        nested in — or `None` when it has no enclosing graph node. The graph identifies the function
        whose invocation runs *element*, which a caller needs to keep a query within one graph.
        """
        return self._flow.locate(element)

    @staticmethod
    def _reachable(start: CfgNode, *, forward: bool) -> set[int]:
        """
        The ids of the control-flow nodes reachable from *start* — over successor edges when *forward*,
        over predecessor edges otherwise — including *start* itself. Exceptional edges are followed like
        any other edge, since they are part of the same successor and predecessor lists.
        """
        seen: set[int] = {id(start)}
        stack = [start]
        while stack:
            node = stack.pop()
            for neighbour in (node.successors if forward else node.predecessors):
                if id(neighbour) not in seen:
                    seen.add(id(neighbour))
                    stack.append(neighbour)
        return seen

    def dominates_node(self, a: CfgNode, b: CfgNode) -> bool:
        """
        Whether control-flow node *a* dominates *b*: every path from the graph's entry to *b* passes
        through *a*. Reflexive — a node dominates itself. Node-level counterpart of `dominates`, for a
        caller that has already located the two nodes.
        """
        return id(a) in self._dominators.get(id(b), frozenset())

    def reachable(self, start: CfgNode, *, forward: bool) -> set[int]:
        """
        The ids of the control-flow nodes reachable from *start* — over successor edges when *forward*,
        over predecessor edges otherwise — including *start*. Exceptional edges are followed like any
        other. A flow-sensitive query intersects a forward set from one point with a backward set from
        another to find the nodes that lie on some path between them (a kill that can execute in
        between); keeping the two directions separate lets the caller memoize and short-circuit them.
        """
        return self._reachable(start, forward=forward)

    def runs_before_function(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before any invocation of *function* — so a
        value established at *definition* holds throughout every call of *function*, and may be inlined
        into its body. The reasoning rests on one fact: a function cannot be invoked before a reference
        to it has been evaluated. Its reference points are its own creation, for an anonymous function
        expression, or the uses of its name, for a named binding; no invocation can precede the earliest
        of them. So *definition* runs before every invocation exactly when it runs before every reference
        point — and that, per point, is strict dominance when the point lies in *definition*'s own
        function, or the same question applied to the function the point lies in, recursing up the call
        graph. The ordering is *strict*: a reference sharing the definition's statement — an earlier
        declarator or sequence operand evaluated before it — is not accepted, since statement-granularity
        dominance is reflexive and cannot order within one statement. A reference's function is its
        nearest enclosing function (its `_activation_of`), so a use in a function's parameter defaults is
        attributed to that function's invocation, not to the statement that declares it. This is the
        interprocedural counterpart of `dominates`, and the sound replacement for ordering a
        cross-function inline by statement position.

        Conservatively `False` when a reference point cannot be ordered or enumerated: the named binding
        is reassigned or redeclared (its references no longer pin one function), a reference lies in a
        function that itself runs too late or escapes, or the walk meets a call cycle it cannot bottom
        out. A function neither referenced nor within reflection's reach is vacuously safe.
        """
        definition_owner = self._activation_of(definition)
        return self._runs_before_function(definition, definition_owner, function, set(), {})

    def runs_before(self, definition: Node, reference: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before *reference* is evaluated — the
        single-reference form of the ordering `runs_before_function` applies per reference point. When
        *reference* shares *definition*'s activation this is intraprocedural *strict* dominance (a
        reference sharing *definition*'s statement is not accepted, since statement-granularity
        dominance is reflexive and cannot order within one statement); when *reference* lies inside a
        function that cannot be invoked until after *definition*, it is the interprocedural
        runs-before-function query, recursing up the call graph. Conservatively `False` whenever the
        ordering cannot be established — a reference in an activation that may run before *definition*,
        or a reference point that cannot be enumerated — so a caller may treat `True` as a guarantee.
        """
        definition_owner = self._activation_of(definition)
        return self._runs_after(definition, definition_owner, reference, set(), {})

    def runs_before_all(self, definition: Node, references: Iterable[Node]) -> bool:
        """
        Whether *definition* is guaranteed to run before every reference in *references* — `runs_before`
        for each, vacuously `True` for an empty iterable. The definition's activation is resolved once
        and shared across the references.
        """
        definition_owner = self._activation_of(definition)
        return all(
            self._runs_after(definition, definition_owner, reference, set(), {})
            for reference in references
        )

    def _runs_before_function(
        self,
        definition: Node,
        definition_owner: Node,
        function: Node,
        visiting: set[int],
        memo: dict[int, bool],
    ) -> bool:
        function_id = id(function)
        if function_id in visiting:
            return False
        cached = memo.get(function_id)
        if cached is not None:
            return cached
        points = self._reference_points(function)
        if points is None:
            memo[function_id] = False
            return False
        visiting = visiting | {function_id}
        result = all(
            self._runs_after(definition, definition_owner, point, visiting, memo)
            for point in points
        )
        memo[function_id] = result
        return result

    def _reference_points(self, function: Node) -> list[Node] | None:
        """
        The points no invocation of *function* can precede, or `None` when they cannot be enumerated.
        For a function pinned to a name (`SemanticModel.invocation_binding`) these are the value-reads of
        that name — a read must be evaluated before the value it denotes can be called — together with the
        opaque reflective surface sites that could invoke it by name
        (`SemanticModel.reflection_surface_sites`): a direct `eval`, `Function`, a string timer, or a
        dynamic global access cannot invoke the function before the surface that grants the capability has
        run, so each surface is itself a point no invocation precedes, ranked exactly like a read. The
        enumeration is `None` when the name is redeclared, reassigned to another value so a read no longer
        pins this one function (`SemanticModel.binding_pinned_to`), or resolved inside a dynamic scope a
        `with` body governs, whose `dynamic_refs` entry is unorderable; this mirrors the escape verdict
        `EffectModel.function_escapes` draws from the same fact. A surface lexically inside *function* is
        dropped: it cannot trigger the function's first invocation, only a re-entrant one, so it never
        bounds the ordering. For a function bound to no name the single point is the function expression
        itself: the closure cannot be invoked before it is created.

        Memoized by function identity: the enumeration is a pure function of *function* and the model,
        both fixed for the model's lifetime — the whole DominanceModel is rebuilt when the tree version
        advances — so every `runs_before*` caller shares one result per function instead of recomputing
        it per reference and per query.
        """
        key = id(function)
        cache = self._reference_points_cache
        if key not in cache:
            cache[key] = self._compute_reference_points(function)
        return cache[key]

    def _compute_reference_points(self, function: Node) -> list[Node] | None:
        binding = self.model.invocation_binding(function)
        if binding is None:
            return [function]
        if (
            binding.dynamic_refs
            or len(binding.declarations) != 1
            or not self.model.binding_pinned_to(binding, function)
        ):
            return None
        points: list[Node] = [*binding.reads]
        points.extend(
            site
            for site in self.model.reflection_surface_sites(binding)
            if not site.is_descendant_of(function)
        )
        return points

    def _runs_after(
        self,
        definition: Node,
        definition_owner: Node,
        point: Node,
        visiting: set[int],
        memo: dict[int, bool],
    ) -> bool:
        owner = self._activation_of(point)
        if owner is definition_owner:
            return self.strictly_dominates(definition, point)
        if isinstance(owner, FUNCTION_NODES):
            return self._runs_before_function(definition, definition_owner, owner, visiting, memo)
        return False

    def _activation_of(self, element: Node) -> Node:
        """
        The function or script whose invocation evaluates *element*: the nearest function that lexically
        encloses it, or the script root when none does. This is the unit `runs_before_function` reasons
        about — a reference in a function's body *or its parameter defaults* runs when that function is
        invoked, so both must attribute to the function, never to the statement that merely declares it in
        the enclosing graph.
        """
        function = enclosing_function(element)
        return function if function is not None else self.model.root

    def _compute_dominators(self, graph: ControlFlowGraph):
        nodes = graph.nodes
        all_ids = {id(node) for node in nodes}
        dom: dict[int, set[int]] = {
            id(node): {id(node)} if node is graph.entry else set(all_ids) for node in nodes
        }
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node is graph.entry:
                    continue
                incoming = node.predecessors
                if incoming:
                    new = set(all_ids)
                    for predecessor in incoming:
                        new &= dom[id(predecessor)]
                else:
                    new = set()
                new.add(id(node))
                if new != dom[id(node)]:
                    dom[id(node)] = new
                    changed = True
        for node in nodes:
            self._dominators[id(node)] = frozenset(dom[id(node)])


def build_dominance(
    model: SemanticModel, control_flow: ControlFlowModel | None = None,
) -> DominanceModel:
    """
    Build the `DominanceModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`,
    reusing *control_flow* when the caller has one to share, or building a fresh one when it is `None`.
    """
    return DominanceModel(model, control_flow)
