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
(`refinery.lib.scripts.js.analysis.dominance.DominanceModel`) orders the definition's statement as
completed before the use and supplies the reachability primitive
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
share a single control-flow node, whose parts the graph does not order: the operands of an
expression share one, while each declarator of a declaration but the last is a node of its own. A
point where the body suspends, an `await` or a `yield`, is a kill of a binding code outside the
body writes, and of one every run of the body shares and the body writes, since that code, or
another run of the body, may run before the body resumes.

The same kills answer a second question: at which points of a body may code other than the body's
own statements change a binding? These are the kills less the stores the body spells — a mutating
call, a suspension, a located reflective hazard — and `ReachingModel.foreign_kills` lists them for
`refinery.lib.scripts.js.analysis.localization`, which asks whether a script-scope `var` is live at
any of them.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import Projection
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.js.analysis.cfg import CfgNode, ControlFlowGraph
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import Binding
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsCallExpression,
    JsForOfStatement,
    JsIdentifier,
    JsMemberExpression,
    JsReturnStatement,
    JsScript,
    JsVariableDeclarator,
    JsYieldExpression,
    is_async_function,
    is_generator_function,
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


class _BodyEvents(NamedTuple):
    """
    The points of one graph's body at which code other than the body's statements may run, each
    with the control-flow node that evaluates it, or with `None` where the graphs place it nowhere.
    One inside a nested function locates into that function's own graph and is left out.

    The *calls* are its call expressions. A call the graphs do not place at all is kept: it is
    evaluated when the body around it is invoked, which is a point no node of this graph stands for
    — a parameter default of a function *expression* is one — so it can neither be ordered here
    nor dismissed, and the caller has to refuse rather than drop the kill. The *suspensions* are
    the points at which its run may stop and resume later, with other code run in between: an
    `await`, a `yield`, the head of a `for await` loop, which awaits each value, and the `return`
    of a value in an async generator, which awaits that value before any `finally` around it runs.
    """
    calls: list[tuple[JsCallExpression, CfgNode | None]]
    suspensions: list[tuple[Node, CfgNode | None]]


class _CallWriters(NamedTuple):
    """
    The calls of one graph's body grouped by the function they run, each with the control-flow node
    that evaluates it, or with `None` where the graphs place it nowhere (`_BodyEvents`): *stated*
    maps each function the model states a call runs to the calls that run it, and *unstated* holds
    the calls whose callee a name this file binds holds while the model will not state which
    function that is. A call of anything else is in neither.
    """
    stated: dict[Node, list[tuple[JsCallExpression, CfgNode | None]]]
    unstated: list[tuple[JsCallExpression, CfgNode | None]]


class _Changes(NamedTuple):
    """
    The sites in one graph at which a binding may change value, each with the control-flow node
    that evaluates it: the *stores* the body's own statements spell, and the *foreign* kills, at
    which code other than those statements may write it — a mutating call, a point where the body
    suspends, a located reflective hazard. The opaque global writes among the hazards are kept
    apart as *opaque*, because a use can be exempt from such a store (`_Kills`).
    """
    stores: tuple[tuple[Node, CfgNode], ...]
    foreign: tuple[tuple[Node, CfgNode], ...]
    opaque: tuple[tuple[JsMemberExpression, CfgNode], ...]


class ReachingModel:
    """
    Reaching-value verdicts for one script, built over a
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel` and a
    `refinery.lib.scripts.js.analysis.effects.EffectModel`. Ask whether the value a binding holds at
    a definition is the value observed at a use with `ReachingModel.value_preserved`, and where code
    other than a body's own statements may change a binding with `ReachingModel.foreign_kills`.
    Build through `build_reaching`.
    """

    def __init__(self, dominance: DominanceModel, effects: EffectModel):
        self.dominance = dominance
        self.effects = effects
        self.model = effects.model
        self._kill_cache: dict[tuple[int, int, int], _Kills | None] = {}
        self._change_cache: dict[tuple[int, int], _Changes | None] = {}
        self._event_cache: dict[int, _BodyEvents] = {}
        self._writer_cache: dict[int, _CallWriters] = {}
        self._cycle_cache: dict[int, bool] = {}
        self._between = ReachabilityQuery(dominance, Projection.MAY)

    def value_preserved(self, binding: Binding, definition: Node, use: Node) -> bool:
        """
        Whether the value *binding* holds where *definition* is evaluated is the value observed at *use*:
        *definition* has run on every path that reaches *use*
        (`refinery.lib.scripts.js.analysis.dominance.DominanceModel.completes_before`), the two do
        not merely share one control-flow node, whose parts the graph does not order, and no kill of
        *binding* lies on any control-flow path between them. `False` when either node lies outside
        the graphs or in a different function, when *definition* has not run before *use*, or when
        *binding*'s kills cannot be enumerated. *definition* is the value expression whose binding
        is tracked; a free variable of that expression is checked by passing the same *definition*
        and *use* with the variable's own binding.
        """
        located_d = self.dominance.locate(definition)
        located_u = self.dominance.locate(use)
        if located_d is None or located_u is None:
            return False
        graph_d, node_d = located_d
        graph_u, node_u = located_u
        if graph_d is not graph_u:
            return False
        if not self.dominance.completes_before(definition, use):
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

    def foreign_kills(self, binding: Binding, owner: Node) -> list[Node] | None:
        """
        The sites in the body of *owner*, a function or the script, at which *binding* may change
        value other than through a store the body spells: a call that may write it, a point where
        the body suspends while other code or another run of the body may write it, and a located
        reflective hazard. `None` where these cannot be listed, under the refusals
        `ReachingModel.value_preserved` answers `False` for, and where *owner* has no graph.
        """
        graph = self.dominance.graph_of(owner)
        if graph is None:
            return None
        changes = self._changes(binding, graph)
        if changes is None:
            return None
        return [site for site, _ in (*changes.foreign, *changes.opaque)]

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
        cannot be listed and the caller must treat the value as reaching nowhere: every site
        `_changes` lists but the write the definition is tracked from.
        """
        changes = self._changes(binding, graph)
        if changes is None:
            return None
        kills = {id(node) for _, node in changes.foreign}
        kills.update(id(node) for site, node in changes.stores if site is not def_write)
        return _Kills(frozenset(kills), changes.opaque)

    def _changes(self, binding: Binding, graph: ControlFlowGraph) -> _Changes | None:
        """
        The sites of *graph* at which *binding* may change value, memoized per graph.
        """
        key = (id(binding), id(graph))
        if key not in self._change_cache:
            self._change_cache[key] = self._compute_changes(binding, graph)
        return self._change_cache[key]

    def _compute_changes(self, binding: Binding, graph: ControlFlowGraph) -> _Changes | None:
        """
        The sites of *graph* at which *binding* may change value, or `None` where they cannot be
        listed.

        Every site that stores into the binding
        (`refinery.lib.scripts.js.analysis.model.Binding.store_sites`) is one, whatever it stores:
        `var {k: x} = o`, the head of `for (var x of xs)` and a `let x;` alike.

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

        A point where the body stops and other code runs before it resumes — an `await`, a `yield`,
        the head of a `for await` loop, the `return` of a value in an async generator
        (`_BodyEvents.suspensions`) — is a kill of a binding some store outside this graph writes:
        that code may be the code that writes it. It is a kill as well of a binding a store in this
        graph writes, where every run of the body shares the binding (`_shared_by_every_run`):
        another run of the same body may write it while this one waits. In

            var x; async function f(v) { x = v; var r = x; await 0; return r; }

        the calls `f(1)` and `f(2)` leave `x` holding `2` when the first one resumes.
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
        foreign, opaque = located
        stores: list[tuple[Node, CfgNode]] = []
        written_elsewhere = False
        for site in binding.store_sites:
            located_site = self.dominance.locate(site)
            if located_site is None:
                return None
            site_graph, site_node = located_site
            if site_graph is graph:
                stores.append((site, site_node))
            else:
                written_elsewhere = True
        events = self._body_events(graph)
        if written_elsewhere or (stores and self._shared_by_every_run(binding, graph)):
            for suspension, node in events.suspensions:
                if node is None:
                    return None
                foreign.append((suspension, node))
        writers = self._call_writers(graph)
        mutating = [
            calls for target, calls in writers.stated.items()
            if self.effects.function_can_mutate(target, binding)
        ]
        if writers.unstated and self.effects.some_function_can_mutate(binding):
            mutating.append(writers.unstated)
        for calls in mutating:
            for call, node in calls:
                if node is None:
                    return None
                foreign.append((call, node))
        return _Changes(tuple(stores), tuple(foreign), tuple(opaque))

    def _located_hazards(
        self, sites: list[Node], graph: ControlFlowGraph,
    ) -> tuple[list[tuple[Node, CfgNode]], list[tuple[JsMemberExpression, CfgNode]]] | None:
        """
        Every reflective hazard site of *sites* located into *graph*, each with its node — the
        plain ones, and apart from them the opaque global writes whose per-use exemption the caller
        applies — or `None` when any of them lies outside it: another function's graph, whose
        hazards run at its invocation, or a point no graph places at all.
        """
        plain: list[tuple[Node, CfgNode]] = []
        opaque: list[tuple[JsMemberExpression, CfgNode]] = []
        for site in sites:
            pair = self.dominance.locate(site)
            if pair is None or pair[0] is not graph:
                return None
            if isinstance(site, JsMemberExpression):
                opaque.append((site, pair[1]))
            else:
                plain.append((site, pair[1]))
        return plain, opaque

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

    def _body_events(self, graph: ControlFlowGraph) -> _BodyEvents:
        """
        The calls and suspensions of *graph*'s body, found in one walk of it and memoized per graph.
        """
        cached = self._event_cache.get(id(graph))
        if cached is None:
            cached = _BodyEvents([], [])
            owner = graph.owner
            awaits_what_it_returns = (
                isinstance(owner, FUNCTION_NODES)
                and is_async_function(owner)
                and is_generator_function(owner)
            )
            for node in owner.walk():
                if isinstance(node, JsCallExpression):
                    located = self.dominance.locate(node)
                    if located is None:
                        cached.calls.append((node, None))
                    elif located[0] is graph:
                        cached.calls.append((node, located[1]))
                elif (
                    isinstance(node, (JsAwaitExpression, JsYieldExpression))
                    or (isinstance(node, JsForOfStatement) and node.is_await)
                    or (
                        awaits_what_it_returns
                        and isinstance(node, JsReturnStatement)
                        and node.argument is not None
                    )
                ):
                    located = self.dominance.locate(node)
                    if located is None:
                        cached.suspensions.append((node, None))
                    elif located[0] is graph:
                        cached.suspensions.append((node, located[1]))
            self._event_cache[id(graph)] = cached
        return cached

    def _call_writers(self, graph: ControlFlowGraph) -> _CallWriters:
        """
        The calls of *graph*'s body grouped by the function they run, memoized per graph: each
        callee is resolved once, so a binding is asked about once per function the body calls and
        not once per call.
        """
        cached = self._writer_cache.get(id(graph))
        if cached is None:
            cached = _CallWriters({}, [])
            for call, node in self._body_events(graph).calls:
                target = self.effects.static_callee(call)
                if target is not None:
                    cached.stated.setdefault(target, []).append((call, node))
                elif self.effects.a_name_this_file_binds_holds_the_callee(call):
                    cached.unstated.append((call, node))
            self._writer_cache[id(graph)] = cached
        return cached

    def _shared_by_every_run(self, binding: Binding, graph: ControlFlowGraph) -> bool:
        """
        Whether every run of the body *graph* stands for shares *binding*: the body is a function's,
        and the binding belongs to no one call of it
        (`refinery.lib.scripts.js.analysis.model.Scope.closure_home`). The script runs once.
        """
        if isinstance(graph.owner, JsScript):
            return False
        return binding.scope.closure_home is not self.model.function_scope(graph.owner)

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
