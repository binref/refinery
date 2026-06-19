"""
Flow-sensitive live-variable analysis for JavaScript, computed over the per-function control-flow graphs
and the resolved bindings of the `SemanticModel`. For each program point it answers which local bindings
are *live* — may still be read before being overwritten — and from that derives a *dead-store* query: a
write whose value no execution can observe.

This is the flow-sensitive layer of the analysis substrate. It sharpens the model's flow-insensitive
`Binding.is_dead` (a binding never read anywhere) into `is_dead_store` (this particular write is never
read on any path). Where the model must keep a binding that is written, then read, then written again,
the liveness solution sees that the first write is dead even though the binding is read elsewhere.

Soundness is the governing concern, because a later pass removes the stores this layer reports: the
analysis over-approximates liveness, so the reported dead stores are a *subset* of the truly dead ones.
Two rules secure that direction. Intra-statement evaluation order is not modelled, so every read is
treated as observing the value of any earlier write in the same statement, keeping such a write live. And
a write counts as killing a binding only when it is unconditional and the statement completes normally;
a conditional write, or one on a path that may throw before it runs (an exceptional edge out of a `try`),
does not mask an earlier live store. Only a function's own, uncaptured `var`/`let` bindings are analysed
— anything a closure or another scope might read is conservatively kept.

The public surface — `LivenessModel.live_in`, `live_out`, `node_of`, `is_dead_store`, `dead_stores`,
`build_liveness` — is keyed to AST node identity, matching the contract of the model and effect layers.
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
    is_use_position,
    reference_role,
)
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsConditionalExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsObjectPattern,
    JsProperty,
    JsRestElement,
    JsScript,
    JsVariableDeclarator,
)

_PATTERN_CONTAINERS = (
    JsArrayPattern,
    JsObjectPattern,
    JsRestElement,
)

_CANDIDATE_KINDS = (BindingKind.VAR, BindingKind.LET)


class LivenessModel:
    """
    Flow-sensitive live-variable sets and dead-store verdicts for one script, built over a
    `SemanticModel`. Query a control-flow node's live sets with `live_in` and `live_out`, find the node
    standing for an AST element with `node_of`, and ask whether a write is dead with `is_dead_store`.
    Build through `build_liveness`.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self._graphs = build_control_flow(model.root)
        self._element_graph: dict[int, ControlFlowGraph] = {}
        self._live_in: dict[int, frozenset[Binding]] = {}
        self._live_out: dict[int, frozenset[Binding]] = {}
        self._index_elements()
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

        While the program retains a reflection surface (`eval`, `with`, ...) no store is reported,
        because such a construct can read a local by name without a reference the model can see.
        """
        if self.model.has_reflection_surface():
            return False
        located = self._locate(write)
        if located is None:
            return False
        graph, node = located
        owner_scope = self._function_scope(graph.owner)
        binding, construct = self._store_target(write)
        if binding is None or construct is None:
            return False
        if not self._trackable(binding, owner_scope):
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

    def _index_elements(self):
        for graph in self._graphs.values():
            for node in graph.nodes:
                if node.element is not None:
                    self._element_graph[id(node.element)] = graph

    def _compute_graph(self, graph: ControlFlowGraph):
        owner_scope = self._function_scope(graph.owner)
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
            if binding is None or not self._trackable(binding, owner_scope):
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
        cursor: Node = ident
        parent = cursor.parent
        while parent is not None:
            if isinstance(parent, JsVariableDeclarator):
                return parent
            if not self._climbs_binding_target(parent, cursor):
                return None
            cursor = parent
            parent = cursor.parent
        return None

    def _governor(self, ident: JsIdentifier) -> Node | None:
        """
        The nearest ancestor of *ident* that is not a destructuring container, i.e. the assignment,
        declarator, or loop head that governs the binding target *ident* sits in.
        """
        cursor: Node = ident
        parent = cursor.parent
        while parent is not None:
            if not self._climbs_binding_target(parent, cursor):
                return parent
            cursor = parent
            parent = cursor.parent
        return None

    @staticmethod
    def _climbs_binding_target(parent: Node, cursor: Node) -> bool:
        if isinstance(parent, _PATTERN_CONTAINERS):
            return True
        if isinstance(parent, JsAssignmentPattern):
            return parent.left is cursor
        if isinstance(parent, JsProperty):
            return parent.value is cursor
        return False

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
            and self._owning_var_scope(binding.scope) is owner_scope
        )

    @staticmethod
    def _owning_var_scope(scope: Scope | None) -> Scope | None:
        while scope is not None and not scope.is_var_scope:
            scope = scope.parent
        return scope

    def _function_scope(self, owner: Node) -> Scope | None:
        if isinstance(owner, JsScript):
            return self.model.root_scope
        body = getattr(owner, 'body', None)
        if body is None:
            return None
        return self.model.scope_of(body)

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
    Build the `LivenessModel` for a script's `SemanticModel`.
    """
    return LivenessModel(model)
