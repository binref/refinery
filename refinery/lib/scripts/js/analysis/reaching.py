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
the use and supplies the reachability primitive
`refinery.lib.scripts.js.analysis.dominance.DominanceModel.reachable`, from which the path-between
question is asked as a forward walk from the definition intersected with a backward walk from the
use; the effect model
(`refinery.lib.scripts.js.analysis.effects.EffectModel`) says where a binding may change — a
reassignment recorded on the binding, or a call to a function that may write it. Kills the model
cannot pin to a site — a mutating function that escapes, a write through a global-object alias or a
dynamic scope — make the answer conservatively negative, and so does a definition and use that share a
single statement, which statement granularity cannot order.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import Projection
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.js.analysis.cfg import CfgNode, ControlFlowGraph
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import Binding, annex_b_copies_into
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsFunctionDeclaration,
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
        self._between = ReachabilityQuery(dominance, Projection.MAY)

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
        if not self.dominance.dominates_node(graph_d, node_d, node_u, Projection.MAY):
            return False
        kills = self._kill_nodes(binding, graph_d, definition)
        if kills is None:
            return False
        return not self._between.any_between(graph_d, node_d, node_u, kills)

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
        """
        The nodes of *graph* at which *binding*'s definition stops holding, or `None` where they
        cannot be listed and the caller must treat the value as reaching nowhere.

        A call this file binds the name of but whose function the model will not state kills the
        binding, wherever some function of this file writes it. Not knowing which function runs is
        not knowing that it does not write, and the one that runs may be exactly the one that does:
        a body `var` repeating a parameter's name is such a callee, since the call writes the name
        before any statement runs and the model declines to say what it holds after that, while the
        name is still one every invocation of the function goes through, so `mutators_escape` reads
        it as pinned down. A callee no name here binds is a different answer and is left alone,
        which is the condition every reader of this was already written under.
        """
        if (
            binding.has_indefinite_write
            or binding.has_global_member_write
            or self.effects.mutators_escape(binding)
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
            if target is None:
                if not self.effects.a_name_this_file_binds_holds_the_callee(call):
                    continue
                if not self.effects.some_function_can_mutate(binding):
                    continue
            elif not self.effects.function_can_mutate(target, binding):
                continue
            if node is None:
                return None
            kills.add(id(node))
        return frozenset(kills)

    def _graph_calls(
        self, graph: ControlFlowGraph,
    ) -> list[tuple[JsCallExpression, CfgNode | None]]:
        """
        The call expressions of *graph*'s body that are not inside a nested function, each paired
        with the control-flow node that evaluates it, or with `None` when the graphs place it
        nowhere. Memoized per graph.

        A call inside a nested function locates into that function's own graph and is left out. A
        call the graphs do not place at all is a different answer and is kept: it is evaluated when
        the body around it is invoked, which is a point no node of this graph stands for — a
        parameter default of a function *expression* is one — so it can neither be ordered here nor
        dismissed, and the caller has to refuse rather than drop the kill.
        """
        cached = self._call_cache.get(id(graph))
        if cached is None:
            cached = []
            for node in graph.owner.walk():
                if not isinstance(node, JsCallExpression):
                    continue
                located = self.dominance.locate(node)
                if located is None:
                    cached.append((node, None))
                elif located[0] is graph:
                    cached.append((node, located[1]))
            self._call_cache[id(graph)] = cached
        return cached

    @staticmethod
    def _value_definitions(binding: Binding) -> Iterator[Node]:
        """
        Every site that establishes *binding*'s value: a write in `writes`, and a declaration that
        ends the binding's temporal dead zone. A `let`, `const`, or `class` declaration ends that
        zone even without an initializer, so a read cannot move across it and it is a kill; a `var`
        has no dead zone, so a bare `var x;` establishes nothing and only an initialized declarator
        counts. A later definition kills an earlier one, so the query counts them all bar the
        one it tracks from.

        A function declaration Annex B copies into the scope around its block is one too, and for
        the same reason a lexical declaration is: the value arrives where the declaration runs, so a
        read of the name before it answers something else and may not move across it. A function
        declared in the scope it names is not, its value being there before any statement runs.

        The flow-aware sibling of `SemanticModel.binding_values`: that query lists the values a
        binding's readable channels store and whether the list is complete, while this one enumerates
        the sites whose execution changes which value a read observes — every write, whatever it
        stores, is a kill here even where it is no readable channel there.
        """
        yield from binding.writes
        lexical = binding.is_lexical
        copied = annex_b_copies_into(binding)
        for declaration in binding.declarations:
            if lexical:
                yield declaration
                continue
            parent = declaration.parent
            if isinstance(parent, JsVariableDeclarator) and parent.init is not None:
                yield declaration
            elif isinstance(parent, JsFunctionDeclaration) and copied:
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
    return ReachingModel(dominance, effects)
