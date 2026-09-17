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
reassignment recorded on the binding, or a call to a function that may write it. A store on the
global object under a key only the runtime resolves may replace a script-scope binding's name, and
that kill is located: it holds at the site spelling the store, exempt for a use evaluated inside
the operands the store is computed from (§13.15.5). A direct `eval`, an unread source span, or a
`with`-governed reference in a local's own function can change the value the same located way, at
the node of the site spelling it. Kills the model cannot pin to a site — a mutating function that
escapes, a write through a global-object alias or a dynamic scope, a surface standing outside the
use's own graph — make the answer conservatively negative, and so does a definition and use that
share a single statement, which statement granularity cannot order.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

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
    JsMemberExpression,
    JsVariableDeclarator,
    strip_parens,
)


class _Kills(NamedTuple):
    """
    The sites at which a binding may change value, for one definition tracked from: the kills that
    hold for every use — reassignments, mutating calls, and the located reflective hazards of a
    local's own scope — as control-flow node ids, and the opaque global writes that may replace
    the binding's name, kept as site-and-node pairs because a use can be exempt from such a store:
    the store is the last step of the assignment spelling it, so a use inside its operands runs
    before it and is not killed by it.
    """
    nodes: frozenset[int]
    opaque: tuple[tuple[JsMemberExpression, CfgNode], ...]


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
        self._kill_cache: dict[tuple[int, int, int], _Kills | None] = {}
        self._call_cache: dict[int, list[tuple[JsCallExpression, CfgNode]]] = {}
        self._cycle_cache: dict[int, bool] = {}
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
        kill_nodes = kills.nodes | {
            id(node)
            for site, node in kills.opaque
            if self._store_kills_the_use(site, node, use)
        }
        return not self._between.any_between(graph_d, node_d, node_u, kill_nodes)

    def _kill_nodes(
        self, binding: Binding, graph: ControlFlowGraph, definition: Node,
    ) -> _Kills | None:
        """
        The sites in *graph* at which *binding* may change value — a reassignment located in this
        graph, or a call whose statically known callee may write *binding* — excluding the write that
        establishes *definition* itself. `None` when a change cannot be pinned to a site: *binding* is
        written by a function that escapes, through a global-object alias, or through a name a dynamic
        scope resolves at runtime, so its value must be treated as volatile everywhere. The answer is
        fixed for the model's lifetime and holds for every use alike, so it is memoized per definition
        and the per-use exemption an opaque write can earn is applied by the caller.
        """
        def_write = self._definition_write(definition)
        key = (id(binding), id(graph), id(def_write) if def_write is not None else 0)
        if key not in self._kill_cache:
            self._kill_cache[key] = self._compute_kill_nodes(binding, graph, def_write)
        return self._kill_cache[key]

    def _compute_kill_nodes(
        self, binding: Binding, graph: ControlFlowGraph, def_write: Node | None,
    ) -> _Kills | None:
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

        A reflective surface that could change the value is a kill like these, and a located one:
        the model enumerates its sites (`SemanticModel.binding_reflection_kill_sites`) — an opaque
        global write, a direct `eval` or unread span in a local's own function, a reference a
        `with` body resolves at runtime — and every one that lies in this graph is a kill at its
        own node, while any that lies elsewhere, or that no graph places at all, makes the value
        volatile: a surface running in another function's graph runs at that function's invocation,
        a point no node here stands for.
        """
        if (
            binding.has_indefinite_write
            or binding.has_global_member_write
            or self.effects.mutators_escape(binding)
        ):
            return None
        hazards = self.model.binding_reflection_kill_sites(binding)
        if hazards is None:
            return None
        located = self._located_hazards(hazards, graph)
        if located is None:
            return None
        kills, opaque = located
        for definition in self._value_definitions(binding):
            if definition is def_write:
                continue
            located_def = self.dominance.locate(definition)
            if located_def is None:
                return None
            def_graph, def_node = located_def
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
        return _Kills(frozenset(kills), tuple(opaque))

    def _located_hazards(
        self, sites: list[Node], graph: ControlFlowGraph,
    ) -> tuple[set[int], list[tuple[JsMemberExpression, CfgNode]]] | None:
        """
        Every reflective hazard site of *sites* located into *graph* — the plain ones as
        control-flow node ids, and the opaque global writes among them as the site-and-node pairs
        whose per-use exemption the caller applies — or `None` when any of them lies outside it:
        another function's graph, whose hazards run at its invocation, or a point no graph places
        at all.
        """
        kills: set[int] = set()
        opaque: list[tuple[JsMemberExpression, CfgNode]] = []
        for site in sites:
            pair = self.dominance.locate(site)
            if pair is None or pair[0] is not graph:
                return None
            if isinstance(site, JsMemberExpression):
                opaque.append((site, pair[1]))
            else:
                kills.add(id(pair[1]))
        return kills, opaque

    def _store_kills_the_use(
        self, site: JsMemberExpression, node: CfgNode, use: Node,
    ) -> bool:
        """
        Whether the opaque write at *site*, evaluated at *node*, may change the binding's value
        before *use* runs. It may not when *use* is part of what that store is computed from — the
        member object, the computed key, or the assigned value, which §13.15.5 evaluates before the
        store, the last step of every assignment form — and the store's node is not on a cycle, where
        a later iteration's store precedes the next evaluation of the same operands.
        """
        if not _precedes_the_store(site, use):
            return True
        return self._on_a_cycle(node)

    def _on_a_cycle(self, node: CfgNode) -> bool:
        cached = self._cycle_cache.get(id(node))
        if cached is None:
            cached = any(
                id(node) in self._between.reachable(successor, forward=True)
                for successor in node.successors
            )
            self._cycle_cache[id(node)] = cached
        return cached

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


def _precedes_the_store(site: JsMemberExpression, use: Node) -> bool:
    """
    Whether *use* is evaluated as part of computing the store *site* spells — it lies inside the
    member object, the computed key, or the assigned value of the assignment holding it.
    """
    regions: list[Node] = [site.object, site.property]
    assigned = _assigned_value(site)
    if assigned is not None:
        regions.append(assigned)
    cursor: Node | None = use
    while cursor is not None:
        if any(cursor is region for region in regions):
            return True
        cursor = cursor.parent
    return False


def _assigned_value(site: JsMemberExpression) -> Node | None:
    """
    The value expression of the assignment storing through *site*, or `None` when the store is
    spelled by no assignment — a `delete`, an update, or a loop head — whose operands are the member
    alone. The innermost assignment whose target holds the site is the one; a store written as the
    value of another assignment (`x = g[k] = v`) is its own.
    """
    cursor: Node = site
    while True:
        parent = cursor.parent
        if parent is None:
            return None
        if isinstance(parent, JsAssignmentExpression):
            return None if _is_within(parent.right, cursor) else parent.right
        cursor = parent


def _is_within(ancestor: Node, node: Node) -> bool:
    cursor: Node | None = node
    while cursor is not None:
        if cursor is ancestor:
            return True
        cursor = cursor.parent
    return False
