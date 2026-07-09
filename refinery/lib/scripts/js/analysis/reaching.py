"""
Reaching-value queries for JavaScript inlining, over the per-function control-flow graphs of the
`refinery.lib.scripts.js.analysis.model.SemanticModel`. One question: does the value a binding holds
where a definition is evaluated still hold when a later use runs? A definition *reaches* a use
unchanged when it runs first on every path to the use and nothing rewrites the binding in between —
the precondition for replacing the use with the definition's value.

This is the query the constant inliner needs, stated once for the binding it inlines and once for each
free variable of the expression it inlines: an expression may be relocated to a use only when the
inlined binding *and* every variable the expression reads all still hold, at the use, the value they
held at the definition. The layer sits above two others. Dominance
(`refinery.lib.scripts.js.analysis.dominance.DominanceModel`) orders the definition strictly before
the use and supplies the reachability primitive `path_between`; the effect model
(`refinery.lib.scripts.js.analysis.effects.EffectModel`) says where a binding may change — a
reassignment recorded on the binding, or a call to a function that may write it. Kills the model
cannot pin to a site — a mutating function that escapes, a write through a global-object alias or a
dynamic scope — make the answer conservatively negative, and so does a definition and use that share a
single statement, which statement granularity cannot order.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cfg import CfgNode, ControlFlowGraph
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import Binding
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsIdentifier,
    JsVariableDeclarator,
    strip_parens,
)


class ReachingModel:
    """
    Reaching-value verdicts for one script, built over a
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel` and a
    `refinery.lib.scripts.js.analysis.effects.EffectModel`. Ask whether the value a binding holds at a
    definition is the value observed at a use with `value_preserved`. Build through `build_reaching`.
    """

    def __init__(self, dominance: DominanceModel, effects: EffectModel):
        self.dominance = dominance
        self.effects = effects
        self.model = effects.model
        self._kill_cache: dict[tuple[int, int, int], frozenset[int] | None] = {}
        self._call_cache: dict[int, list[tuple[JsCallExpression, CfgNode]]] = {}
        self._reach_cache: dict[tuple[int, bool], set[int]] = {}

    def value_preserved(self, binding: Binding, definition: Node, use: Node) -> bool:
        """
        Whether the value *binding* holds where *definition* is evaluated is the value observed at *use*:
        *definition*'s control-flow node strictly dominates *use*'s — it runs first on every path that
        reaches *use*, and the two do not merely share one statement, which statement granularity cannot
        order — and no kill of *binding* lies on any control-flow path between them. `False` when either
        node lies outside the graphs or in a different function, when *definition* does not strictly
        dominate *use*, or when *binding*'s kills cannot be enumerated. *definition* is the value
        expression whose binding is tracked; a free variable of that expression is checked by passing the
        same *definition* and *use* with the variable's own binding.
        """
        located_d = self.dominance.locate(definition)
        located_u = self.dominance.locate(use)
        if located_d is None or located_u is None:
            return False
        graph_d, node_d = located_d
        graph_u, node_u = located_u
        if graph_d is not graph_u:
            return False
        if node_d is node_u:
            return False
        if not self.dominance.dominates_node(node_d, node_u):
            return False
        kills = self._kill_nodes(binding, graph_d, definition)
        if kills is None:
            return False
        if not kills:
            return True
        downstream = self._reachable(node_d, forward=True) & kills
        if not downstream:
            return True
        return not (downstream & self._reachable(node_u, forward=False))

    def _reachable(self, node: CfgNode, *, forward: bool) -> set[int]:
        """
        The control-flow nodes reachable from *node* in the given direction, memoized: the graphs do not
        change over the model's lifetime, and one definition is queried against many uses, so a forward
        set from the definition is reused across them.
        """
        key = (id(node), forward)
        cached = self._reach_cache.get(key)
        if cached is None:
            cached = self.dominance.reachable(node, forward=forward)
            self._reach_cache[key] = cached
        return cached

    def _kill_nodes(
        self, binding: Binding, graph: ControlFlowGraph, definition: Node,
    ) -> frozenset[int] | None:
        """
        The ids of the control-flow nodes in *graph* at which *binding* may change value — a reassignment
        located in this graph, or a call whose statically known callee may write *binding* — excluding
        the write that establishes *definition* itself. `None` when a change cannot be pinned to a site:
        *binding* is written by a function that escapes, through a global-object alias, or through a name
        a dynamic scope resolves at runtime, so its value must be treated as volatile everywhere. The
        answer is fixed for the model's lifetime, so it is memoized per definition.
        """
        def_write = self._definition_write(definition)
        key = (id(binding), id(graph), id(def_write) if def_write is not None else 0)
        if key not in self._kill_cache:
            self._kill_cache[key] = self._compute_kill_nodes(binding, graph, def_write)
        return self._kill_cache[key]

    def _compute_kill_nodes(
        self, binding: Binding, graph: ControlFlowGraph, def_write: Node | None,
    ) -> frozenset[int] | None:
        if (
            self.effects.mutators_escape(binding)
            or binding.has_global_member_write
            or self.model.reflection_can_reach(binding)
        ):
            return None
        kills: set[int] = set()
        for definition in self._value_definitions(binding):
            if definition is def_write:
                continue
            located = self.dominance.locate(definition)
            if located is None:
                return None
            def_graph, def_node = located
            if def_graph is graph:
                kills.add(id(def_node))
        for call, node in self._graph_calls(graph):
            target = self.effects.static_callee(call)
            if target is not None and self.effects.function_can_mutate(target, binding):
                kills.add(id(node))
        return frozenset(kills)

    def _graph_calls(self, graph: ControlFlowGraph) -> list[tuple[JsCallExpression, CfgNode]]:
        """
        The call expressions whose control-flow node lies in *graph*, each paired with that node. A call
        inside a nested function locates into that function's own graph and is left out. Memoized per
        graph.
        """
        cached = self._call_cache.get(id(graph))
        if cached is None:
            cached = []
            for node in graph.owner.walk():
                if not isinstance(node, JsCallExpression):
                    continue
                located = self.dominance.locate(node)
                if located is not None and located[0] is graph:
                    cached.append((node, located[1]))
            self._call_cache[id(graph)] = cached
        return cached

    @staticmethod
    def _value_definitions(binding: Binding) -> Iterator[Node]:
        """
        Every site that establishes *binding*'s value: an assignment or update recorded in `writes`, and
        a declaration whose declarator carries an initializer. A later definition kills an earlier one,
        so the reaching query counts them all bar the one it tracks from. A bare `var x;` with no
        initializer establishes nothing and is left out.
        """
        yield from binding.writes
        for declaration in binding.declarations:
            parent = declaration.parent
            if isinstance(parent, JsVariableDeclarator) and parent.init is not None:
                yield declaration

    @staticmethod
    def _definition_write(definition: Node) -> Node | None:
        """
        The identifier a value expression is assigned to — the declarator or `=` target *definition* is
        the initializer of — so the reaching query can exclude that write from the binding's kills. `None`
        when *definition* is not the value of a single-identifier declarator or assignment.
        """
        cursor: Node | None = definition
        while cursor is not None:
            parent = cursor.parent
            if isinstance(parent, JsVariableDeclarator) and parent.init is cursor:
                return parent.id if isinstance(parent.id, JsIdentifier) else None
            if isinstance(parent, JsAssignmentExpression) and parent.right is cursor:
                left = strip_parens(parent.left)
                return left if isinstance(left, JsIdentifier) else None
            cursor = parent
        return None


def build_reaching(dominance: DominanceModel, effects: EffectModel) -> ReachingModel:
    """
    Build the `ReachingModel` from a script's dominance and effect models.
    """
    return ReachingModel(dominance, effects)
