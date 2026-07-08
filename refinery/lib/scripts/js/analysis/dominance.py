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

The public surface — `DominanceModel.dominates`, `DominanceModel.cfg_node_of`,
`DominanceModel.runs_before_function`, `build_dominance` — is keyed to AST nodes: an arbitrary node is
located to the control-flow node of the statement (or loop head) that evaluates it, the granularity at
which the graph reasons. `runs_before_function` lifts dominance across calls: it answers whether a
definition runs before every invocation of a function, which a single graph cannot, by ordering the
definition against the points the function is referenced and recursing up the call graph. `runs_before`
and `runs_before_all` expose that same ordering against a single reference, or every reference in a set —
the query a transform needs to confirm a value is established before every use that could observe it.
"""
from __future__ import annotations

from typing import Iterable

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cfg import (
    FUNCTION_NODES,
    CfgNode,
    ControlFlowGraph,
    ElementLocator,
    build_control_flow,
)
from refinery.lib.scripts.js.analysis.model import SemanticModel, enclosing_function


class DominanceModel:
    """
    Dominator relations for the per-function control-flow graphs of one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Ask whether one AST node is guaranteed to
    execute before another with `dominates`. Build through `build_dominance`.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self._graphs = build_control_flow(model.root)
        self._locator = ElementLocator(self._graphs)
        self._dominators: dict[int, frozenset[int]] = {}
        for graph in self._graphs.values():
            self._compute_dominators(graph)

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
        located_a = self._locator.locate(a)
        located_b = self._locator.locate(b)
        if located_a is None or located_b is None:
            return False
        graph_a, node_a = located_a
        graph_b, node_b = located_b
        if graph_a is not graph_b:
            return False
        return id(node_a) in self._dominators.get(id(node_b), frozenset())

    def cfg_node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node of the statement (or loop head) that evaluates *element*, climbing out of
        any expression *element* is nested in, or `None` when *element* has no enclosing graph node.
        """
        located = self._locator.locate(element)
        return located[1] if located is not None else None

    def locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        """
        The control-flow graph and node that evaluate *element* — climbing out of any expression it is
        nested in — or `None` when it has no enclosing graph node. The graph identifies the function
        whose invocation runs *element*, which a caller needs to keep a query within one graph.
        """
        return self._locator.locate(element)

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
        out. A function never referenced is vacuously safe.
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
        For a named function these are the references to its binding — a use of the name must be
        evaluated before the value it denotes can be called — unless the binding is reassigned or
        redeclared, in which case a reference no longer pins this one function and the points are
        unknowable. A reference inside a dynamic scope — a name a `with` body resolves at runtime — is
        equally unorderable: the invocation it may perform has no static reference the dominator walk can
        rank, so the points cannot be enumerated and the answer is `None`, mirroring the escape verdict
        `EffectModel.function_escapes` draws from the same fact. For an anonymous function the single
        point is the function expression itself: the closure cannot be invoked before it is created.
        """
        binding = self.model.naming_binding(function)
        if binding is not None:
            if binding.writes or binding.dynamic_refs or len(binding.declarations) != 1:
                return None
            return list(self.model.references(binding))
        return [function]

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
            return self._strictly_dominates(definition, point)
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

    def _strictly_dominates(self, a: Node, b: Node) -> bool:
        """
        Like `dominates`, except a node does not strictly dominate itself: `False` when *a* and *b* share
        one control-flow node (the same statement), where statement-granularity dominance is reflexive
        and cannot order them. `runs_before_function` needs this — a reference in the same statement as a
        definition may be evaluated before it (an earlier declarator, an earlier sequence operand), which
        plain `dominates` would wrongly accept.
        """
        located_a = self._locator.locate(a)
        located_b = self._locator.locate(b)
        if located_a is None or located_b is None:
            return False
        graph_a, node_a = located_a
        graph_b, node_b = located_b
        if graph_a is not graph_b or node_a is node_b:
            return False
        return id(node_a) in self._dominators.get(id(node_b), frozenset())

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


def build_dominance(model: SemanticModel) -> DominanceModel:
    """
    Build the `DominanceModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`.
    """
    return DominanceModel(model)
