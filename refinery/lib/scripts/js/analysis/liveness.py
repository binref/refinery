"""
Flow-sensitive live-variable analysis for JavaScript, computed over the per-function control-flow
graphs and the resolved bindings of the `refinery.lib.scripts.js.analysis.model.SemanticModel`. For
each program point it answers which local bindings are *live* — may still be read before being
overwritten — and from that derives a *dead-store* query: a write whose value no execution can
observe.

This is the flow-sensitive layer of the analysis substrate. It sharpens the model's flow-insensitive
`refinery.lib.scripts.js.analysis.model.Binding.is_dead` (a binding never read anywhere) into
`is_dead_store` (this particular write is never read on any path). Where the model must keep a
binding that is written, then read, then written again, the liveness solution sees that the first
write is dead even though the binding is read elsewhere.

Soundness is the governing concern, because a later pass removes the stores this layer reports: the
analysis over-approximates liveness, so the reported dead stores are a *subset* of the truly dead ones.
Two rules secure that direction. Intra-statement evaluation order is not modelled, so every read is
treated as observing the value of any earlier write in the same statement, keeping such a write live. And
a write counts as killing a binding only when it is unconditional and the statement completes normally;
a conditional write, or one on a path that may throw before it runs (an exceptional edge out of a `try`),
does not mask an earlier live store. Only a function's own, uncaptured `var`/`let` bindings are analysed
— anything a closure or another scope might read is conservatively kept.

Beyond the locals, the dataflow tracks a script-scope `var` every read and store of which lies in
the body of one function inside that function's graph (`LivenessModel.pseudo_local_owner`), so that
`refinery.lib.scripts.js.analysis.localization` can ask where it is live there. The tracking is kept
separate from `LivenessModel.is_dead_store`, which retains its strict function-local candidacy, so
widening the dataflow never widens what counts as a removable dead store.

The public surface — `LivenessModel.live_in`, `LivenessModel.live_out`,
`LivenessModel.live_around`, `LivenessModel.node_of`, `LivenessModel.is_dead_store`,
`LivenessModel.dead_stores`, `LivenessModel.is_dead_on_entry`, `LivenessModel.pseudo_local_owner`,
`build_liveness` — is keyed to AST node identity, matching the contract of the model and effect
layers.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.liveness import solve_liveness
from refinery.lib.scripts.js.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_control_flow_model,
)
from refinery.lib.scripts.js.analysis.evaluation import evaluated_whenever_completed
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Binding,
    BindingKind,
    Role,
    Scope,
    ScopeKind,
    SemanticModel,
    _governing_target,
    enclosing_function,
    is_use_position,
    reference_role,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsIdentifier,
    JsVariableDeclarator,
)

_CANDIDATE_KINDS = (BindingKind.VAR, BindingKind.LET)


class LivenessModel:
    """
    Flow-sensitive live-variable sets and dead-store verdicts for one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Query a control-flow node's live sets
    with `live_in` and `live_out`, find the node standing for an AST element with `node_of`, and ask
    whether a write is dead with `is_dead_store`. Build through `build_liveness`.
    """

    def __init__(self, model: SemanticModel, control_flow: ControlFlowModel | None = None):
        self.model = model
        self._flow = control_flow if control_flow is not None else build_control_flow_model(model.root)
        self._live_in: dict[int, frozenset[Binding]] = {}
        self._live_out: dict[int, frozenset[Binding]] = {}
        self._pseudo_local_owners: dict[Binding, Node] = {}
        self._index_pseudo_locals()
        for graph in self._flow.graphs.values():
            self._compute_graph(graph)

    def live_in(self, node: CfgNode) -> frozenset[Binding]:
        """
        The bindings live on entry to *node* — those that may be read before being overwritten on some
        path that begins at *node*.
        """
        return self._live_in.get(id(node), frozenset())

    def live_out(self, node: CfgNode) -> frozenset[Binding]:
        """
        The bindings live on exit from *node* — those that may be read on some path that leaves it,
        including the path taken if *node* throws.
        """
        return self._live_out.get(id(node), frozenset())

    def live_around(self, element: Node) -> frozenset[Binding] | None:
        """
        The bindings live on entry to or on exit from the control-flow node that evaluates
        *element*, climbing out of any expression it is nested in, or `None` when no graph places
        it. The graph does not order the parts of one node, so a binding live here may be read
        after *element* is evaluated.
        """
        located = self._flow.locate(element)
        if located is None:
            return None
        node = located[1]
        return self.live_in(node) | self.live_out(node)

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node standing for *element* in whichever function graph owns it, or `None` if
        *element* is not a node the graphs represent.
        """
        return self._flow.node_of(element)

    def is_dead_store(self, write: JsIdentifier) -> bool:
        """
        Whether the value written to a binding at *write* is never read on any execution. Only an
        unconditional store to an uncaptured function-local `var`/`let` qualifies; a read, a compound or
        conditional write, a captured or outer binding, or a store whose value may still be read all
        return `False`, the conservative verdict. The verdict concerns the stored *value* alone: a
        caller removing the store must still preserve any side effect of the expression producing it.

        No store is reported while a `with` or direct `eval` lexically inside the owning function could
        read the local by name without a reference the model sees. A reflective surface elsewhere in the
        program runs in the global scope and cannot reach a local, so it does not suppress the report.
        """
        located = self._flow.locate(write)
        if located is None:
            return False
        graph, node = located
        owner_scope = self.model.function_scope(graph.owner)
        binding, construct = self._store_target(write)
        if binding is None or construct is None:
            return False
        if not self._trackable(binding, owner_scope):
            return False
        if self.model.reflection_can_reach(binding):
            return False
        if binding in self.live_out(node):
            return False
        return self._unobserved_within(graph, node, write, binding, construct)

    def dead_stores(self) -> list[JsIdentifier]:
        """
        Every write identifier in the script whose stored value is dead, in source order.
        """
        result: list[JsIdentifier] = []
        for node in self.model.root.walk_in_order():
            if isinstance(node, JsIdentifier) and self._is_candidate_write(node):
                if self.is_dead_store(node):
                    result.append(node)
        return result

    def is_dead_on_entry(self, binding: Binding, function: Node) -> bool:
        """
        Whether *function* writes *binding* before reading it on every path, so no value carried into the
        call — from a previous invocation or from load — is ever observed. Answered from the liveness at
        the function's control-flow entry; a binding not tracked in *function* returns `False`.
        """
        graph = self._flow.graph_of(function)
        if graph is None:
            return False
        if not self._analysable(graph, binding, self.model.function_scope(graph.owner)):
            return False
        return binding not in self.live_in(graph.entry)

    def pseudo_local_owner(self, binding: Binding) -> Node | None:
        """
        The function whose graph tracks *binding*, a script-scope `var`, as one of its locals: the
        one function whose body holds every read of it and every site that stores into it
        (`refinery.lib.scripts.js.analysis.model.Binding.store_sites`), none at script scope, in the
        parameter list or in a function nested below it. `None` for every other binding.
        """
        return self._pseudo_local_owners.get(binding)

    def _index_pseudo_locals(self):
        """
        Record, for each script-scope `var` binding that behaves as a single function's local, that
        function, so the dataflow can track it inside it: the owner `_sole_owning_function` finds.
        """
        for binding in self.model.root_scope.bindings.values():
            if binding.kind is not BindingKind.VAR:
                continue
            function = self._sole_owning_function(binding)
            if function is not None:
                self._pseudo_local_owners[binding] = function

    def _compute_graph(self, graph: ControlFlowGraph):
        owner_scope = self.model.function_scope(graph.owner)

        def node_sets(_graph: ControlFlowGraph, node: CfgNode) -> tuple[set[Binding], set[Binding]]:
            return self._node_sets(_graph, node, owner_scope)

        live_in, live_out = solve_liveness(graph, node_sets)
        self._live_in.update(live_in)
        self._live_out.update(live_out)

    def _node_sets(
        self, graph: ControlFlowGraph, node: CfgNode, owner_scope: Scope | None,
    ) -> tuple[set[Binding], set[Binding]]:
        use: set[Binding] = set()
        kill: set[Binding] = set()
        if node.element is None:
            return use, kill
        for ident in self._shallow_idents(graph, node.element):
            declared = self.model.binding_of(ident)
            if declared is not None:
                if self._trackable(declared, owner_scope) and self._declarator_has_init(ident):
                    kill.add(declared)
                continue
            if not is_use_position(ident):
                continue
            binding = self.model.resolve(ident)
            if binding is None or not self._analysable(graph, binding, owner_scope):
                continue
            role = reference_role(ident)
            if role is not Role.WRITE:
                use.add(binding)
            elif self._is_assignment_kill(ident, node.element):
                kill.add(binding)
        return use, kill

    def _unobserved_within(
        self,
        graph: ControlFlowGraph,
        node: CfgNode,
        write: JsIdentifier,
        binding: Binding,
        construct: Node,
    ) -> bool:
        """
        Whether no reference to *binding* other than *write* within *node* can observe *write*'s value.
        A read nested in *construct* (the assignment or declarator performing the write) consumes the
        prior value, so it is ignored; any other reference — a later read or a second write in the same
        node — is treated conservatively as observing the store, since the graph does not order
        the parts of one node.
        """
        assert node.element is not None
        for ident in self._shallow_idents(graph, node.element):
            if ident is write:
                continue
            if self._reference_binding(ident) is not binding:
                continue
            if self._is_read(ident) and ident.is_descendant_of(construct):
                continue
            return False
        return True

    def _shallow_idents(self, graph: ControlFlowGraph, element: Node) -> Iterator[JsIdentifier]:
        """
        Yield the identifiers belonging to *element*'s own control-flow node: *element* itself and
        those in its subtree that are not inside a nested function or a descendant that is itself a
        separate control-flow node (whose identifiers are accounted there). This keeps a loop or
        branch head from double-counting the body that follows it.
        """
        stack: list[Node] = [element]
        while stack:
            current = stack.pop()
            if current is not element:
                if isinstance(current, FUNCTION_NODES):
                    continue
                if graph.node_of(current) is not None:
                    continue
            if isinstance(current, JsIdentifier):
                yield current
            stack.extend(current.children())

    def _store_target(self, write: JsIdentifier) -> tuple[Binding | None, Node | None]:
        """
        The binding *write* stores into and the construct whose completion performs the store, or
        `(None, None)` if *write* is not an unconditional value store: a `var`/`let`/`const` declarator
        with an initializer, or the target of a plain `=` assignment.
        """
        declared = self.model.binding_of(write)
        if declared is not None:
            if not self._declarator_has_init(write):
                return None, None
            return declared, self._enclosing_declarator(write)
        if not is_use_position(write):
            return None, None
        binding = self.model.resolve(write)
        if binding is None or reference_role(write) is not Role.WRITE:
            return None, None
        governor = self._governor(write)
        if not isinstance(governor, JsAssignmentExpression) or governor.operator != '=':
            return None, None
        return binding, governor

    def _is_candidate_write(self, ident: JsIdentifier) -> bool:
        if self.model.binding_of(ident) is not None:
            return self._declarator_has_init(ident)
        if not is_use_position(ident):
            return False
        return reference_role(ident) is Role.WRITE

    def _is_assignment_kill(self, ident: JsIdentifier, element: Node) -> bool:
        governor = self._governor(ident)
        if not isinstance(governor, JsAssignmentExpression) or governor.operator != '=':
            return False
        return evaluated_whenever_completed(ident, element)

    def _is_read(self, ident: JsIdentifier) -> bool:
        if not self.model.is_reference(ident):
            return False
        return reference_role(ident) is not Role.WRITE

    def _reference_binding(self, ident: JsIdentifier) -> Binding | None:
        declared = self.model.binding_of(ident)
        if declared is not None:
            return declared
        if not is_use_position(ident):
            return None
        return self.model.resolve(ident)

    def _declarator_has_init(self, ident: JsIdentifier) -> bool:
        declarator = self._enclosing_declarator(ident)
        return declarator is not None and declarator.init is not None

    def _enclosing_declarator(self, ident: JsIdentifier) -> JsVariableDeclarator | None:
        governor, target = _governing_target(ident)
        if isinstance(governor, JsVariableDeclarator) and governor.id is target:
            return governor
        return None

    def _governor(self, ident: JsIdentifier) -> Node | None:
        """
        The construct that governs the binding target *ident* sits in — the assignment, declarator, or
        loop head reached by climbing out through any destructuring containers and parentheses around
        it, or `None` past the top of the tree.
        """
        governor, _ = _governing_target(ident)
        return governor

    def _trackable(self, binding: Binding, owner_scope: Scope | None) -> bool:
        """
        Whether *binding* is a local of the function *owner_scope* is the body scope of, so that the
        graph built for that function sees every store to it.

        The parameters of a function whose parameter list holds an expression are bound in a scope
        of their own standing outside the body's, so their variable scope is that one rather than
        the body's; `Scope.closure_home` says the two belong to one call, and is what this asks.
        """
        return (
            binding.kind in _CANDIDATE_KINDS
            and not binding.captured
            and owner_scope is not None
            and owner_scope.kind is ScopeKind.FUNCTION
            and binding.scope.closure_home is owner_scope
        )

    def _analysable(
        self, graph: ControlFlowGraph, binding: Binding, owner_scope: Scope | None,
    ) -> bool:
        """
        Whether *binding* is tracked in *graph*: either an uncaptured function-local of the graph's
        own function (the strict store candidate) or a script-scope `var` that function owns
        (`LivenessModel.pseudo_local_owner`). The second case feeds only the live sets; it never
        reaches `LivenessModel.is_dead_store`, which keeps the strict candidacy.
        """
        if self._trackable(binding, owner_scope):
            return True
        return self._pseudo_local_owners.get(binding) is graph.owner

    def _sole_owning_function(self, binding: Binding) -> Node | None:
        """
        The one function whose body lexically contains every read of *binding* and every site that
        stores into it, or `None` when they span more than one function, include one at script
        scope, or do not exist. A declaration that stores where it runs is such a site, so a
        declarator with an initializer or a loop head at script scope rejects the binding. A site
        inside a function nested below the candidate counts as a separate owner, so a binding
        captured by such a nested closure is rejected, and so is one the candidate's parameter list
        reads or writes: parameter expressions run in a scope of their own, which a `var` the body
        declares does not reach.
        """
        owner: Node | None = None
        body: Node | None = None
        for site in (*binding.reads, *binding.store_sites):
            function = enclosing_function(site)
            if function is None:
                return None
            if owner is None:
                owner = function
                body = getattr(function, 'body', None)
            elif function is not owner:
                return None
            if body is None or not site.is_descendant_of(body):
                return None
        return owner


def build_liveness(
    model: SemanticModel, control_flow: ControlFlowModel | None = None,
) -> LivenessModel:
    """
    Build the `LivenessModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`,
    reusing *control_flow* when the caller has one to share, or building a fresh one when it is `None`.
    """
    return LivenessModel(model, control_flow)
