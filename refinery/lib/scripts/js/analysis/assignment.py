"""
Definite assignment for implicit globals: a forward must-analysis over the per-function control-flow
graphs answering whether a write to a name the program never declares has certainly completed before
a given reference runs. The consumers are the removal sweep and the alias collapse, both of which may
treat a read of such a name as unable to throw only where this model vouches for it.

The transfer function reasons about normal completion alone: a statement's gen set holds the bindings
whose write is performed on *every* evaluation of the statement that completes normally, computed by
an evaluation-order walk of the statement's own expressions, so a write guarded by a short-circuit, a
ternary arm, an optional chain, a logical assignment's right-hand side, or a loop target contributes
nothing. A write whose statement throws first is discarded structurally — the throw leaves along the
raising edge, which carries no gens, and the meet at the join forgets the fact — except where the
statement provably cannot throw at all, whose raising edge is never taken and may carry them
vacuously. No throw analysis decides what the normal edge means.

A bare write in sloppy script code creates the property; in strict code, or anywhere under the module
reading, it throws instead, so it gens nothing there. A member write through this realm's global
object creates the property in either mode; `top` and `frames` name another document's global and
never qualify.

Facts are monotone: a name is tracked only while nothing the analysis cannot see can unbind it. A
binding a reflection surface can reach is not tracked; neither is one carried into a body this file
does not read, which is what handing the global object to a call does
(`refinery.lib.scripts.js.analysis.model.Binding.reachable_through_a_handed_object`), because such a
body may `delete` the property or freeze the object it hangs on and the file spells neither; and
neither is one any `delete` in the program addresses — through its bare name, through a member of
that name on any base, or possibly through a computed key on a global-object spelling no scan can
read, which untracks everything. What remains can only ever gain its property, so there
are no kill sets, and a fact held at a call site still holds whenever a body invoked there runs —
including a getter, an iterator, or an async continuation the text spells no call for.

Interprocedurally, a call completing normally has run its callee to normal exit, so a call whose
callee is one known non-async, non-generator function — resolved through its name, or spelled inline
as the callee — adds that function's exit summary to the gen set; and a function whose every
invocation site is a direct call of its one pinned name, or an immediately-invoked function
expression, takes the meet of the facts at those sites as its entry fact. Both start empty and grow
to a least fixpoint, so no fact ever rests on itself.
"""
from __future__ import annotations

from typing import Callable

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_control_flow_model,
)
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    GLOBAL_OBJECT_ALIASES,
    SAME_REALM_GLOBAL_OBJECT_ALIASES,
    Binding,
    BindingKind,
    SemanticModel,
    enclosing_operator,
    is_invocation_target,
    member_property_name,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsConditionalExpression,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsRestElement,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsTemplateLiteral,
    JsThrowStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    is_generator_function,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.strict import strict_mode_at

_OTHER_REALM_ALIASES = GLOBAL_OBJECT_ALIASES - SAME_REALM_GLOBAL_OBJECT_ALIASES

_LOGICAL_ASSIGNMENT = frozenset({
    '&&=',
    '||=',
    '??=',
})

#: The statements whose control-flow node evaluates a head of its own rather than its children: a
#: declaration evaluates its initializers and a `for-in`/`for-of` head its subject, while the target
#: each writes is written once per iteration and by no evaluation of the head.
_OWN_HEAD_NODES = (
    JsVariableDeclaration,
    JsForInStatement,
    JsForOfStatement,
)


class DefiniteAssignmentModel:
    """
    Build over a `refinery.lib.scripts.js.analysis.model.SemanticModel` and its
    `refinery.lib.scripts.analysis.cfg.ControlFlowModel`; query with `definitely_assigned_at`.
    *module_scope* is the run's execution model: under the module reading every region is strict and
    a top-level `this` does not denote the global object, so no bare write and no `this` member
    write establishes anything.
    *host_entrypoint* names the top-level functions the analyst declared a host invokes by name;
    such a function has a call site outside the file, so the meet over its spelled call sites does
    not bound its entry facts and it gets none.
    """

    def __init__(
        self,
        model: SemanticModel,
        control_flow: ControlFlowModel | None = None,
        *,
        module_scope: bool = False,
        host_entrypoint: Callable[[str], bool] | None = None,
    ):
        self.model = model
        self._flow = control_flow if control_flow is not None else build_control_flow_model(model.root)
        self._module = module_scope
        self._host_entrypoint = host_entrypoint
        self._tracked: dict[int, Binding] = {}
        self._by_name: dict[str, Binding] = {}
        for binding in model.root_scope.bindings.values():
            if binding.kind is not BindingKind.IMPLICIT_GLOBAL:
                continue
            if not binding.writes:
                continue
            if binding.reachable_through_a_handed_object:
                continue
            if model.reflection_can_reach(binding):
                continue
            self._tracked[id(binding)] = binding
            self._by_name[binding.name] = binding
        self._in_facts: dict[int, frozenset[Binding]] = {}
        self._parts: dict[int, list[Node]] = {}
        self._effects: dict[int, tuple[frozenset[Binding], bool]] = {}
        self._summaries: dict[int, frozenset[Binding]] = {}
        if self._tracked:
            self._untrack_deleted()
        if self._tracked:
            self._solve()

    def definitely_assigned_at(self, binding: Binding | None, reference: Node) -> bool:
        """
        Whether a write to *binding* has certainly completed before *reference* is evaluated. Facts
        hold at statement entry, so a write in *reference*'s own statement never vouches for it.
        """
        if binding is None or id(binding) not in self._tracked:
            return False
        located = self._flow.locate(reference)
        if located is None:
            return False
        _, node = located
        return binding in self._in_facts.get(id(node), frozenset())

    def read_established(self, node: JsIdentifier) -> bool:
        """
        Whether a write creating the name *node* spells has certainly completed before the read is
        evaluated, so it cannot be the read that raises a `ReferenceError`.

        The one composition every consumer of this model shares, and it lives here because the
        binding a reference resolves to must come from the same semantic model the facts were built
        over: a caller resolving against a model built after a rewrite would hand over a binding
        this one has never seen, and every answer would silently be `False`.
        """
        return self.definitely_assigned_at(self.model.resolve(node), node)

    def _untrack_deleted(self):
        """
        Remove from tracking every binding a `delete` in the program could unbind, wherever that
        delete stands — a called function, a getter a member read fires, an iterator a spread drives.
        Untracking is what makes the remaining facts monotone without enumerating who runs the code.

        A member delete is keyed on the property name it spells rather than on whether the base is a
        spelling of the global object, because the base need not be one to *be* one: `globalThis
        .window.X` and any name a call was handed the object under both delete the global the file
        reads bare. Untracking a name because some object's property of that name is deleted only
        forgets a fact; trusting a base the scan cannot read is what deletes a read. The one base
        that does not untrack is one that provably cannot be the global object — a literal, an
        allocation, or a name pinned to one — and a computed key on any other base untracks
        everything, since the key it deletes is one no scan can read.
        """
        deleted: set[int] = set()
        for node in self.model.root.walk():
            if not isinstance(node, JsUnaryExpression) or node.operator != 'delete':
                continue
            target = strip_parens(node.operand) if node.operand is not None else None
            if isinstance(target, JsIdentifier):
                resolved = self.model.resolve(target)
                if resolved is not None:
                    deleted.add(id(resolved))
                    continue
                self._tracked = {}
                return
            if isinstance(target, JsMemberExpression):
                if self._cannot_be_the_global_object(target.object):
                    continue
                name = self.model.global_alias_member_name(target, module_scope=self._module)
                if name is None:
                    name = member_property_name(target)
                if name is not None:
                    named = self._by_name.get(name)
                    if named is not None:
                        deleted.add(id(named))
                    continue
                self._tracked = {}
                return
            self._tracked = {}
            return
        if deleted:
            self._tracked = {
                key: binding for key, binding in self._tracked.items() if key not in deleted
            }
            self._by_name = {binding.name: binding for binding in self._tracked.values()}

    def _cannot_be_the_global_object(self, base: Node | None) -> bool:
        """
        Whether the base of a member delete provably does not denote the global object, so the
        delete cannot unbind a name the file reads bare: a literal, an allocation, a function, or a
        name pinned to one of those. Everything else — an unresolved name, a multi-valued binding,
        any expression the scan cannot evaluate — may be the object under another spelling and
        answers `False`.
        """
        value = strip_parens(base) if base is not None else None
        if isinstance(value, JsIdentifier):
            binding = self.model.resolve(value)
            if binding is None or binding.dynamic_refs:
                return False
            pinned = self.model.singular_value(binding)
            value = strip_parens(pinned) if pinned is not None else None
        if isinstance(value, FUNCTION_NODES):
            return True
        return isinstance(value, (
            JsArrayExpression,
            JsObjectExpression,
            JsStringLiteral,
            JsNumericLiteral,
            JsBooleanLiteral,
            JsNullLiteral,
            JsTemplateLiteral,
        ))

    def _solve(self):
        """
        Grow the call summaries and entry facts to a least fixpoint, re-solving every graph under
        the previous round's answers until neither moves.

        Only the summary a call contributes changes between rounds, so the parts each node
        evaluates and whether it can throw are settled once, before the first round: both are read
        off the tree alone, and the tree does not move while a model is being built.
        """
        graphs = list(self._flow.graphs.values())
        elements = [
            (graph, node) for graph in graphs for node in graph.nodes if node.element is not None
        ]
        for graph, node in elements:
            assert node.element is not None
            self._parts[id(node)] = self._evaluated_parts(graph, node.element)
        cannot_throw = {
            id(node): self._parts_cannot_throw(node.element, self._parts[id(node)])
            for graph, node in elements
        }
        summaries: dict[int, frozenset[Binding]] = {}
        entries: dict[int, frozenset[Binding]] = {}
        while True:
            self._summaries = summaries
            self._effects = {
                id(node): (self._parts_gen(self._parts[id(node)]), cannot_throw[id(node)])
                for _, node in elements
            }
            facts: dict[int, frozenset[Binding]] = {}
            for graph in graphs:
                self._solve_graph(graph, entries.get(id(graph.owner), frozenset()), facts)
            new_summaries = {id(graph.owner): self._exit_summary(graph, facts) for graph in graphs}
            new_entries = {id(graph.owner): self._entry_fact(graph, facts) for graph in graphs}
            if new_summaries == summaries and new_entries == entries:
                self._in_facts = facts
                return
            summaries = new_summaries
            entries = new_entries

    def _edge_out(
        self,
        graph: ControlFlowGraph,
        pred: CfgNode,
        target: CfgNode,
        state: dict[int, frozenset[Binding]],
    ) -> frozenset[Binding]:
        gen, cannot_throw = self._effects.get(id(pred), (frozenset(), False))
        out = state[id(pred)]
        if cannot_throw or not graph.raise_taken(pred, target):
            out = out | gen
        return out

    def _solve_graph(
        self, graph: ControlFlowGraph, entry: frozenset[Binding], facts: dict[int, frozenset[Binding]],
    ):
        top = frozenset(self._tracked.values())
        state: dict[int, frozenset[Binding]] = {id(node): top for node in graph.nodes}
        state[id(graph.entry)] = entry
        reachable: set[int] = set()
        frontier = [graph.entry]
        while frontier:
            node = frontier.pop()
            if id(node) in reachable:
                continue
            reachable.add(id(node))
            frontier.extend(node.successors)
        changed = True
        while changed:
            changed = False
            for node in graph.nodes:
                if node is graph.entry:
                    continue
                met: frozenset[Binding] | None = None
                for pred in node.predecessors:
                    out = self._edge_out(graph, pred, node, state)
                    met = out if met is None else met & out
                if met is None:
                    met = frozenset()
                if met != state[id(node)]:
                    state[id(node)] = met
                    changed = True
        for node in graph.nodes:
            facts[id(node)] = state[id(node)] if id(node) in reachable else frozenset()

    def _exit_summary(
        self, graph: ControlFlowGraph, facts: dict[int, frozenset[Binding]],
    ) -> frozenset[Binding]:
        """
        What a call of this body's owner adds to the facts of a caller whose call completed
        normally: the meet over every predecessor of the exit a normal completion may leave through,
        minus the entry fact the caller already held.

        A predecessor is dropped from the meet only where no normal completion reaches the exit from
        it, which is a statement that never completes at all rather than an edge kind. An edge kind
        is recorded per *pair* of nodes and two edges between one pair collapse to a single entry
        (`refinery.lib.scripts.analysis.cfg.CfgBuilder.kind_edge`), so an empty `finally` — whose
        entry both falls through to whatever follows the statement and carries the unwinding edge
        outward — reads as raise-taken while the normal path runs through it. Dropping it took the
        meet over the other predecessors alone and claimed a write the normal path never performed.
        """
        met: frozenset[Binding] | None = None
        for pred in graph.exit.predecessors:
            if not self._completes_normally(pred) and graph.raise_taken(pred, graph.exit):
                continue
            out = self._edge_out(graph, pred, graph.exit, facts)
            met = out if met is None else met & out
        entry = facts.get(id(graph.entry), frozenset())
        return frozenset() if met is None else frozenset(met - entry)

    @staticmethod
    def _completes_normally(node: CfgNode) -> bool:
        """
        Whether the statement *node* stands for may complete normally at all. A `throw` never does,
        so the edge it draws to the exit stands for the one run it has and carries no fact about a
        normal return; every other node reaches the exit on some run that completed.
        """
        return not isinstance(node.element, JsThrowStatement)

    def _entry_fact(
        self, graph: ControlFlowGraph, facts: dict[int, frozenset[Binding]],
    ) -> frozenset[Binding]:
        owner = graph.owner
        if not isinstance(owner, FUNCTION_NODES):
            return frozenset()
        if is_generator_function(owner):
            return frozenset()
        binding = self.model.invocation_binding(owner)
        if binding is None:
            immediate = self._immediate_call_of(owner)
            if immediate is None:
                return frozenset()
            return self._fact_at(immediate, facts)
        if binding.dynamic_refs or not self.model.binding_pinned_to(binding, owner):
            return frozenset()
        if self._host_entrypoint is not None and self._host_entrypoint(binding.name):
            return frozenset()
        met: frozenset[Binding] | None = None
        for read in binding.reads:
            if not is_invocation_target(read):
                return frozenset()
            met_here = self._fact_at(read, facts)
            met = met_here if met is None else met & met_here
        return met or frozenset()

    def _fact_at(self, site: Node, facts: dict[int, frozenset[Binding]]) -> frozenset[Binding]:
        located = self._flow.locate(site)
        if located is None:
            return frozenset()
        return facts.get(id(located[1]), frozenset())

    @staticmethod
    def _immediate_call_of(function: Node) -> JsCallExpression | None:
        """
        The call that invokes *function* where it is written as that call's own callee, so its
        every invocation is the one site — an immediately-invoked function expression. `None` for
        any other position, a tagged template among them, whose call node the fact is not read off.
        """
        governor = enclosing_operator(function)
        if isinstance(governor, JsCallExpression) and is_invocation_target(function):
            return governor
        return None

    def _evaluated_parts(self, graph: ControlFlowGraph, element: Node) -> list[Node]:
        """
        The expressions the control-flow node for *element* evaluates itself: the element where it is
        an expression handed its own node (a loop header's init, test, or update), a declaration's
        initializers, a `for-in`/`for-of` head's subject, and otherwise every child that is neither a
        function body nor a statement owned by another node.
        """
        if (
            not isinstance(element, _OWN_HEAD_NODES)
            and not self._is_statement(element)
        ):
            return [element]
        if isinstance(element, JsVariableDeclaration):
            inits: list[Node] = []
            for declarator in element.declarations:
                init = getattr(declarator, 'init', None)
                if init is not None:
                    inits.append(init)
            return inits
        if isinstance(element, (JsForInStatement, JsForOfStatement)):
            subject = getattr(element, 'right', None)
            return [subject] if subject is not None else []
        parts: list[Node] = []
        for child in element.children():
            if isinstance(child, FUNCTION_NODES):
                continue
            if graph.node_of(child) is not None:
                continue
            parts.append(child)
        return parts

    @staticmethod
    def _is_statement(element: Node) -> bool:
        return isinstance(element, Statement)

    def _parts_gen(self, parts: list[Node]) -> frozenset[Binding]:
        gens: set[Binding] = set()
        for part in parts:
            gens |= self._gens(part)
        return frozenset(gens)

    def _parts_cannot_throw(self, element: Node | None, parts: list[Node]) -> bool:
        """
        Whether the statement *element* provably throws on no run at all, so that its raising edge
        is never taken and may carry its gens vacuously.

        A declaration is more than the initializers `_evaluated_parts` reports: each declarator
        binds its target once its initializer is evaluated, and binding a pattern destructures,
        which is what `var {a} = null, b = (X = 1);` throws at — after `null` was read and before
        the second declarator ran. So a declarator naming anything but a plain identifier answers
        `False` here, while the gen it contributes on the *normal* edge stays what it was.
        """
        if isinstance(element, JsVariableDeclaration):
            if not all(
                isinstance(declarator.id, JsIdentifier) for declarator in element.declarations
            ):
                return False
        elif not isinstance(element, JsExpressionStatement):
            return False
        return all(self._cannot_throw(part) for part in parts)

    def _cannot_throw(self, node: Node | None) -> bool:
        """
        Whether evaluating *node* is guaranteed not to throw, so its statement's raising edge is never
        taken and may vacuously carry its gens. Deliberately minimal: literals, function values, a
        sloppy bare store of such a value to a tracked name, and a member store of one through this
        realm's global object — the shapes a `try`-wrapped establishment scaffold is written in.
        """
        if node is None:
            return False
        if isinstance(node, (
            JsStringLiteral,
            JsNumericLiteral,
            JsBooleanLiteral,
            JsNullLiteral,
        )):
            return True
        if isinstance(node, FUNCTION_NODES):
            return True
        if isinstance(node, JsParenthesizedExpression):
            return node.expression is not None and self._cannot_throw(node.expression)
        if isinstance(node, JsSequenceExpression):
            return all(self._cannot_throw(part) for part in node.expressions)
        if isinstance(node, JsAssignmentExpression):
            if node.operator != '=':
                return False
            if not isinstance(strip_parens(node.left), JsIdentifier):
                return False
            if not self._target_gen(node):
                return False
            return self._cannot_throw(node.right)
        return False

    def _gens(self, node: Node | None) -> frozenset[Binding]:
        if node is None:
            return frozenset()
        if isinstance(node, JsParenthesizedExpression):
            return self._gens(node.expression)
        if isinstance(node, JsAssignmentExpression):
            if node.operator in _LOGICAL_ASSIGNMENT:
                return self._target_gen(node)
            return self._gens(node.right) | self._target_gen(node)
        if isinstance(node, JsUpdateExpression):
            return self._gens(node.argument) | self._update_gen(node)
        if isinstance(node, JsLogicalExpression):
            return self._gens(node.left)
        if isinstance(node, JsConditionalExpression):
            return self._gens(node.test) | (
                self._gens(node.consequent) & self._gens(node.alternate))
        if isinstance(node, JsBinaryExpression):
            return self._gens(node.left) | self._gens(node.right)
        if isinstance(node, JsSequenceExpression):
            result: frozenset[Binding] = frozenset()
            for expression in node.expressions:
                result = result | self._gens(expression)
            return result
        if isinstance(node, JsUnaryExpression):
            if node.operator == 'delete':
                return frozenset()
            return self._gens(node.operand)
        if isinstance(node, JsMemberExpression):
            result = self._gens(node.object)
            if node.optional or self._chain_short_circuits(node.object):
                return result
            if node.computed:
                result = result | self._gens(node.property)
            return result
        if isinstance(node, (JsCallExpression, JsNewExpression)):
            result = self._gens(node.callee)
            if getattr(node, 'optional', False) or self._chain_short_circuits(node.callee):
                return result
            for argument in node.arguments:
                result = result | self._gens(argument)
            if isinstance(node, JsCallExpression):
                result = result | self._callee_summary(node)
            return result
        if isinstance(node, JsSpreadElement):
            return self._gens(node.argument)
        if isinstance(node, JsArrayExpression):
            result = frozenset()
            for element in node.elements:
                if element is not None:
                    result = result | self._gens(element)
            return result
        if isinstance(node, JsObjectExpression):
            result = frozenset()
            for prop in node.properties:
                if isinstance(prop, JsProperty):
                    if prop.computed and prop.key is not None:
                        result = result | self._gens(prop.key)
                    if prop.value is not None and not isinstance(prop.value, FUNCTION_NODES):
                        result = result | self._gens(prop.value)
                elif isinstance(prop, JsSpreadElement):
                    result = result | self._gens(prop.argument)
            return result
        if isinstance(node, JsTemplateLiteral):
            result = frozenset()
            for expression in node.expressions:
                result = result | self._gens(expression)
            return result
        if isinstance(node, JsTaggedTemplateExpression):
            return self._gens(node.tag) | self._gens(node.quasi)
        return frozenset()

    def _update_gen(self, update: JsUpdateExpression) -> frozenset[Binding]:
        """
        The binding an increment or decrement leaves written when the expression completes normally.

        Neither spelling is mode-dependent the way a bare store is. `X++` reads `X` before it writes
        it, so a run that got past the read had the name already, in strict code as much as in
        sloppy; and a member update through this realm's global object reads `undefined` off a
        missing property and stores the result, which creates it.
        """
        target = strip_parens(update.argument)
        if isinstance(target, JsIdentifier):
            binding = self.model.resolve(target)
            if binding is None or id(binding) not in self._tracked:
                return frozenset()
            return frozenset({binding})
        if isinstance(target, JsMemberExpression):
            return self._member_target_gen(target)
        return frozenset()

    def _target_gen(self, assignment: JsAssignmentExpression) -> frozenset[Binding]:
        target = strip_parens(assignment.left)
        if isinstance(target, JsIdentifier):
            binding = self.model.resolve(target)
            if binding is None or id(binding) not in self._tracked:
                return frozenset()
            if assignment.operator != '=':
                return frozenset({binding})
            return self._bare_target_gen(target, binding)
        if isinstance(target, JsMemberExpression):
            if assignment.operator in _LOGICAL_ASSIGNMENT:
                return frozenset()
            return self._member_target_gen(target)
        if isinstance(target, (JsArrayPattern, JsObjectPattern)):
            return self._pattern_target_gen(target)
        return frozenset()

    def _bare_target_gen(self, target: JsIdentifier, binding: Binding) -> frozenset[Binding]:
        if self._module or strict_mode_at(target):
            return frozenset()
        return frozenset({binding})

    def _pattern_target_gen(self, pattern: Node | None) -> frozenset[Binding]:
        """
        The tracked bindings a destructuring assignment writes when it completes normally, which is
        every target the pattern holds however deep: an iteration or a property read that throws
        does so before the statement completes, and a default only replaces the value assigned, so a
        normal completion has assigned them all. A default's own expression runs conditionally and
        contributes nothing here; it is not a target. A nested pattern is read in both the pattern
        and the expression spelling, because the parser converts only the positions the grammar
        forces and leaves a pattern in an object property's value written as the expression it
        lexed.
        """
        target = strip_parens(pattern) if pattern is not None else None
        if isinstance(target, JsIdentifier):
            binding = self.model.resolve(target)
            if binding is None or id(binding) not in self._tracked:
                return frozenset()
            return self._bare_target_gen(target, binding)
        if isinstance(target, JsMemberExpression):
            return self._member_target_gen(target)
        if isinstance(target, JsAssignmentPattern):
            return self._pattern_target_gen(target.left)
        if isinstance(target, (JsRestElement, JsSpreadElement)):
            return self._pattern_target_gen(target.argument)
        if isinstance(target, (JsArrayPattern, JsArrayExpression)):
            result: frozenset[Binding] = frozenset()
            for element in target.elements:
                if element is not None:
                    result = result | self._pattern_target_gen(element)
            return result
        if isinstance(target, (JsObjectPattern, JsObjectExpression)):
            result = frozenset()
            for prop in target.properties:
                if isinstance(prop, JsProperty):
                    result = result | self._pattern_target_gen(prop.value)
                elif isinstance(prop, (JsRestElement, JsSpreadElement)):
                    result = result | self._pattern_target_gen(prop.argument)
            return result
        return frozenset()

    def _member_target_gen(self, target: JsMemberExpression) -> frozenset[Binding]:
        """
        The tracked binding a member write to *target* creates the property of, which is one only
        where the base names *this* realm's global object: `top` and `frames` name another
        document's and create nothing a bare name in this file reads.
        """
        base = strip_parens(target.object) if target.object is not None else None
        if isinstance(base, JsIdentifier) and base.name in _OTHER_REALM_ALIASES:
            return frozenset()
        name = self.model.global_alias_member_name(target, module_scope=self._module)
        if name is None:
            return frozenset()
        binding = self._by_name.get(name)
        if binding is None:
            return frozenset()
        return frozenset({binding})

    @staticmethod
    def _chain_short_circuits(callee: Node | None) -> bool:
        cursor = callee
        while cursor is not None:
            if isinstance(cursor, JsParenthesizedExpression):
                cursor = cursor.expression
                continue
            if isinstance(cursor, (JsMemberExpression, JsCallExpression)):
                if getattr(cursor, 'optional', False):
                    return True
                cursor = cursor.object if isinstance(cursor, JsMemberExpression) else cursor.callee
                continue
            return False
        return False

    def _callee_summary(self, call: JsCallExpression) -> frozenset[Binding]:
        callee = strip_parens(call.callee) if call.callee is not None else None
        function: Node | None = None
        if isinstance(callee, FUNCTION_NODES):
            function = callee
        elif isinstance(callee, JsIdentifier):
            binding = self.model.resolve(callee)
            if binding is None or binding.dynamic_refs:
                return frozenset()
            function = self.model.singular_value(binding)
        if function is None or not isinstance(function, FUNCTION_NODES):
            return frozenset()
        if wraps_return(function):
            return frozenset()
        return self._summaries.get(id(function), frozenset())


def build_definite_assignment(
    model: SemanticModel,
    control_flow: ControlFlowModel | None = None,
    *,
    module_scope: bool = False,
    host_entrypoint: Callable[[str], bool] | None = None,
) -> DefiniteAssignmentModel:
    return DefiniteAssignmentModel(
        model,
        control_flow,
        module_scope=module_scope,
        host_entrypoint=host_entrypoint,
    )
