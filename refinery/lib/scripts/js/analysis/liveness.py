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

Beyond the dead-store query, the same liveness answers a scope-tightening question. A script-scope
`var` whose every reference is owned by one function, and which that function overwrites before reading,
behaves as a local of it: no value carried into the call from a previous invocation or from load is ever
observed, so the declaration can be relocated into the function. `localization_target` reports that
function. The tracking this needs is kept separate from `is_dead_store`, which retains its strict
function-local candidacy, so widening the dataflow never widens what counts as a removable dead store.

The public surface — `LivenessModel.live_in`, `live_out`, `node_of`, `is_dead_store`, `dead_stores`,
`is_dead_on_entry`, `localization_target`, `localizable_bindings`, `build_liveness` — is keyed to AST
node identity, matching the contract of the model and effect layers.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cfg import CfgNode, ControlFlowGraph, build_control_flow
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    FUNCTION_NODES,
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
    JsAssignmentPattern,
    JsConditionalExpression,
    JsIdentifier,
    JsLogicalExpression,
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

    def __init__(self, model: SemanticModel):
        self.model = model
        self._graphs = build_control_flow(model.root)
        self._element_graph: dict[int, ControlFlowGraph] = {}
        self._live_in: dict[int, frozenset[Binding]] = {}
        self._live_out: dict[int, frozenset[Binding]] = {}
        self._pseudo_locals: dict[int, frozenset[Binding]] = {}
        self._index_elements()
        self._index_pseudo_locals()
        for graph in self._graphs.values():
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

    def node_of(self, element: Node) -> CfgNode | None:
        """
        The control-flow node standing for *element* in whichever function graph owns it, or `None` if
        *element* is not a node the graphs represent.
        """
        graph = self._element_graph.get(id(element))
        if graph is None:
            return None
        return graph.node_of(element)

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
        located = self._locate(write)
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
        graph = self._graphs.get(id(function))
        if graph is None:
            return False
        return binding not in self.live_in(graph.entry)

    def localization_target(self, binding: Binding) -> Node | None:
        """
        The function into which *binding*, a script-scope `var`, can be soundly relocated, or `None`. A
        binding qualifies when every reference is owned by one function, that function writes it before
        any read (so a value carried across calls or from load is never observed), it has no initializer
        whose load-time effect the move would strand, and the program keeps no reflection surface that
        could read it by name. Relocating it tightens a pseudo-global into the local it behaves as.
        """
        if self.model.has_reflection_surface():
            return None
        if binding.kind is not BindingKind.VAR or binding.scope is not self.model.root_scope:
            return None
        if self._has_initializer(binding):
            return None
        function = self._sole_owning_function(binding)
        if function is None:
            return None
        if not self.is_dead_on_entry(binding, function):
            return None
        return function

    def localizable_bindings(self) -> list[tuple[Binding, Node]]:
        """
        Every script-scope `var` binding that can be relocated into a function, each paired with that
        function, in the order the script declares them.
        """
        result: list[tuple[Binding, Node]] = []
        for binding in self.model.root_scope.bindings.values():
            function = self.localization_target(binding)
            if function is not None:
                result.append((binding, function))
        return result

    def _index_elements(self):
        for graph in self._graphs.values():
            for node in graph.nodes:
                if node.element is not None:
                    self._element_graph[id(node.element)] = graph

    def _index_pseudo_locals(self):
        """
        Group the script-scope `var` bindings that each behave as a single function's locals, keyed by
        that function, so the dataflow can track them inside it. A binding qualifies when every reference
        lies in one function and none at script scope or in a function nested below it.
        """
        grouped: dict[int, set[Binding]] = {}
        for binding in self.model.root_scope.bindings.values():
            if binding.kind is not BindingKind.VAR:
                continue
            function = self._sole_owning_function(binding)
            if function is not None:
                grouped.setdefault(id(function), set()).add(binding)
        self._pseudo_locals = {owner: frozenset(bindings) for owner, bindings in grouped.items()}

    def _compute_graph(self, graph: ControlFlowGraph):
        owner_scope = self.model.function_scope(graph.owner)
        use: dict[int, set[Binding]] = {}
        kill: dict[int, set[Binding]] = {}
        for node in graph.nodes:
            use[id(node)], kill[id(node)] = self._node_sets(graph, node, owner_scope)
        live_in: dict[int, set[Binding]] = {id(n): set() for n in graph.nodes}
        live_out: dict[int, set[Binding]] = {id(n): set() for n in graph.nodes}
        changed = True
        while changed:
            changed = False
            for node in reversed(graph.nodes):
                normal: set[Binding] = set()
                exceptional: set[Binding] = set()
                for successor in node.successors:
                    if graph.is_exceptional(node, successor):
                        exceptional |= live_in[id(successor)]
                    else:
                        normal |= live_in[id(successor)]
                out = normal | exceptional
                inn = use[id(node)] | (normal - kill[id(node)]) | exceptional
                if out != live_out[id(node)] or inn != live_in[id(node)]:
                    live_out[id(node)] = out
                    live_in[id(node)] = inn
                    changed = True
        for node in graph.nodes:
            self._live_in[id(node)] = frozenset(live_in[id(node)])
            self._live_out[id(node)] = frozenset(live_out[id(node)])

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
        statement — is treated conservatively as observing the store, since intra-statement order is not
        modelled.
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
        Yield the identifiers belonging to *element*'s own control-flow node: those in its subtree that
        are not inside a nested function or a descendant that is itself a separate control-flow node
        (whose identifiers are accounted there). This keeps a loop or branch head from double-counting
        the body that follows it.
        """
        stack: list[Node] = list(element.children())
        while stack:
            current = stack.pop()
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
        return self._is_unconditional(ident, element)

    def _is_read(self, ident: JsIdentifier) -> bool:
        if self.model.binding_of(ident) is not None:
            return False
        if not is_use_position(ident):
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

    @staticmethod
    def _is_unconditional(ident: JsIdentifier, element: Node) -> bool:
        """
        Whether *ident* is written every time its control-flow node *element* runs, i.e. its position is
        not guarded by a short-circuit operand, a conditional branch, or a destructuring default.
        """
        cursor: Node = ident
        while cursor is not element:
            parent = cursor.parent
            if parent is None:
                return True
            if isinstance(parent, JsLogicalExpression) and parent.right is cursor:
                return False
            if isinstance(parent, JsConditionalExpression) and cursor in (
                parent.consequent, parent.alternate,
            ):
                return False
            if isinstance(parent, JsAssignmentPattern) and parent.right is cursor:
                return False
            cursor = parent
        return True

    def _trackable(self, binding: Binding, owner_scope: Scope | None) -> bool:
        return (
            binding.kind in _CANDIDATE_KINDS
            and not binding.captured
            and owner_scope is not None
            and owner_scope.kind is ScopeKind.FUNCTION
            and binding.scope.var_scope is owner_scope
        )

    def _analysable(
        self, graph: ControlFlowGraph, binding: Binding, owner_scope: Scope | None,
    ) -> bool:
        """
        Whether *binding* is tracked in *graph*: either an uncaptured function-local of the graph's own
        function (the strict store candidate) or a script-scope `var` whose every reference is owned by
        that function and so behaves as one of its locals. The second case feeds only the entry-liveness
        `localization_target` reads; it never reaches `is_dead_store`, which keeps the strict candidacy.
        """
        if self._trackable(binding, owner_scope):
            return True
        return binding in self._pseudo_locals.get(id(graph.owner), frozenset())

    def _sole_owning_function(self, binding: Binding) -> Node | None:
        """
        The one function whose body lexically contains every reference to *binding*, or `None` when the
        references span more than one function, include one at script scope, or do not exist. A reference
        inside a function nested below the candidate counts as a separate owner, so a binding captured by
        such a nested closure is rejected.
        """
        owner: Node | None = None
        for ref in (*binding.reads, *binding.writes):
            function = enclosing_function(ref)
            if function is None:
                return None
            if owner is None:
                owner = function
            elif function is not owner:
                return None
        return owner

    def _has_initializer(self, binding: Binding) -> bool:
        for declaration in binding.declarations:
            declarator = self._enclosing_declarator(declaration)
            if declarator is not None and declarator.init is not None:
                return True
        return False

    def _locate(self, write: JsIdentifier) -> tuple[ControlFlowGraph, CfgNode] | None:
        cursor: Node | None = write
        while cursor is not None:
            graph = self._element_graph.get(id(cursor))
            if graph is not None:
                node = graph.node_of(cursor)
                if node is not None:
                    return graph, node
            cursor = cursor.parent
        return None


def build_liveness(model: SemanticModel) -> LivenessModel:
    """
    Build the `LivenessModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`.
    """
    return LivenessModel(model)
