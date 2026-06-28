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
definition against the points the function is referenced and recursing up the call graph.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cfg import (
    FUNCTION_NODES,
    CfgNode,
    ControlFlowGraph,
    build_control_flow,
)
from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel
from refinery.lib.scripts.js.model import (
    JsFunctionDeclaration,
    JsIdentifier,
    JsVariableDeclarator,
)


class DominanceModel:
    """
    Dominator relations for the per-function control-flow graphs of one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Ask whether one AST node is guaranteed to
    execute before another with `dominates`. Build through `build_dominance`.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self._graphs = build_control_flow(model.root)
        self._element_graph: dict[int, ControlFlowGraph] = {}
        self._dominators: dict[int, frozenset[int]] = {}
        self._index_elements()
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
        located_a = self._locate(a)
        located_b = self._locate(b)
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
        located = self._locate(element)
        return located[1] if located is not None else None

    def runs_before_function(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before any invocation of *function* — so a
        value established at *definition* holds throughout every call of *function*, and may be inlined
        into its body. The reasoning rests on one fact: a function cannot be invoked before a reference
        to it has been evaluated. Its reference points are its own creation, for an anonymous function
        expression, or the uses of its name, for a named binding; no invocation can precede the earliest
        of them. So *definition* runs before every invocation exactly when it runs before every reference
        point — and that, per point, is `dominates` when the point lies in *definition*'s own function,
        or the same question applied to the function the point lies in, recursing up the call graph. This
        is the interprocedural counterpart of `dominates`, and the sound replacement for ordering a
        cross-function inline by statement position.

        Conservatively `False` when a reference point cannot be ordered or enumerated: the named binding
        is reassigned or redeclared (its references no longer pin one function), a reference lies in a
        function that itself runs too late or escapes, or the walk meets a call cycle it cannot bottom
        out. A function never referenced is vacuously safe.
        """
        return self._runs_before_function(definition, function, set())

    def _runs_before_function(self, definition: Node, function: Node, visiting: set[int]) -> bool:
        if id(function) in visiting:
            return False
        points = self._reference_points(function)
        if points is None:
            return False
        visiting = visiting | {id(function)}
        return all(self._runs_after(definition, point, visiting) for point in points)

    def _reference_points(self, function: Node) -> list[Node] | None:
        """
        The points no invocation of *function* can precede, or `None` when they cannot be enumerated.
        For a named function these are the references to its binding — a use of the name must be
        evaluated before the value it denotes can be called — unless the binding is reassigned or
        redeclared, in which case a reference no longer pins this one function and the points are
        unknowable. For an anonymous function the single point is the function expression itself: the
        closure cannot be invoked before it is created.
        """
        binding = self._naming_binding(function)
        if binding is not None:
            if binding.writes or len(binding.declarations) != 1:
                return None
            return list(self.model.references(binding))
        return [function]

    def _runs_after(self, definition: Node, point: Node, visiting: set[int]) -> bool:
        owner = self._owner_of(point)
        definition_owner = self._owner_of(definition)
        if owner is None or definition_owner is None:
            return False
        if owner is definition_owner:
            return self.dominates(definition, point)
        if isinstance(owner, FUNCTION_NODES):
            return self._runs_before_function(definition, owner, visiting)
        return False

    def _owner_of(self, element: Node) -> Node | None:
        located = self._locate(element)
        return located[0].owner if located is not None else None

    def _naming_binding(self, function: Node) -> Binding | None:
        if isinstance(function, JsFunctionDeclaration) and function.id is not None:
            return self.model.binding_of(function.id)
        parent = function.parent
        if (
            isinstance(parent, JsVariableDeclarator)
            and parent.init is function
            and isinstance(parent.id, JsIdentifier)
        ):
            return self.model.binding_of(parent.id)
        return None

    def _index_elements(self):
        for graph in self._graphs.values():
            for node in graph.nodes:
                if node.element is not None:
                    self._element_graph[id(node.element)] = graph

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

    def _locate(self, element: Node) -> tuple[ControlFlowGraph, CfgNode] | None:
        cursor: Node | None = element
        while cursor is not None:
            graph = self._element_graph.get(id(cursor))
            if graph is not None:
                node = graph.node_of(cursor)
                if node is not None:
                    return graph, node
            cursor = cursor.parent
        return None


def build_dominance(model: SemanticModel) -> DominanceModel:
    """
    Build the `DominanceModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`.
    """
    return DominanceModel(model)
