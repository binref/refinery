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

The public surface — `DominanceModel.dominates`, `DominanceModel.strictly_dominates`,
`DominanceModel.cfg_node_of`, `DominanceModel.runs_before_function`, `build_dominance` — is keyed to AST
nodes: an arbitrary node is located to the control-flow node of the statement (or loop head) that
evaluates it, the granularity at which the graph reasons. `strictly_dominates` is the non-reflexive
`dominates`, refusing a same-statement pair a caller must order. `completes_before` is the
ordering the queries below are built from: dominance orders *entering* a statement, and a run
reaching a handler because the statement threw has entered it without completing it, so a point
such a run reaches is ordered after the statement only when the statement cannot throw at all.
`runs_before_function` lifts that ordering across calls: it answers whether a definition runs
before every invocation of a function, which a single graph cannot, by ordering the definition
against the points the function is referenced and recursing up the call graph. `runs_before` and
`runs_before_all` expose that same ordering against a single reference, or every reference in a
set — the query a transform needs to confirm a value is established before every use that could
observe it.
"""
from __future__ import annotations

from typing import Callable, Iterable, Iterator, NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import Projection
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.js.analysis.cfg import (
    FUNCTION_NODES,
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_control_flow_model,
)
from refinery.lib.scripts.js.analysis.intrinsics import IntrinsicWrites, build_intrinsic_writes
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    enclosing_function,
    is_invocation_target,
    is_simple_assignment_target,
    member_property_name,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsExportDefaultDeclaration,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsParenthesizedExpression,
    object_member_access_runs_accessor,
    strip_parens,
)


class _InvocationOrder(NamedTuple):
    """
    How every invocation of one function stands to one definition: *ordered* when each of them
    follows the definition, and *entered* when one of them is reachable from the definition's own
    activation rather than only from code nothing in the file runs.
    """
    ordered: bool
    entered: bool


class _Gathered:
    """
    What the walk of `DominanceModel._solve_invocation_orders` has gathered for one function whose
    component is still open: whether every point seen so far is ordered, and whether one of them
    enters the function.
    """
    __slots__ = 'ordered', 'entered'

    def __init__(self, ordered: bool):
        self.ordered = ordered
        self.entered = False

    def absorb(self, order: _InvocationOrder):
        self.ordered = self.ordered and order.ordered
        self.entered = self.entered or order.entered


class DominanceModel(DominatorModel):
    """
    Dominator relations for the per-function control-flow graphs of one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Ask whether one AST node is guaranteed to
    execute before another with `dominates`. Build through `build_dominance`.

    The ordering across calls reads three facts about what lies outside the text: *intrinsic_writes*
    says whether the program writes the prototype chain a plain object reads through, *module_scope*
    is the run's execution model, and *host_entrypoint* names the top-level functions the analyst
    declared a host invokes by name.
    """

    def __init__(
        self,
        model: SemanticModel,
        control_flow: ControlFlowModel | None = None,
        *,
        intrinsic_writes: IntrinsicWrites | None = None,
        module_scope: bool = False,
        host_entrypoint: Callable[[str], bool] | None = None,
    ):
        flow = control_flow if control_flow is not None else build_control_flow_model(model.root)
        super().__init__(flow)
        self.model = model
        if intrinsic_writes is None:
            intrinsic_writes = build_intrinsic_writes(model)
        self.intrinsic_writes = intrinsic_writes
        self._module_scope = module_scope
        self._host_entrypoint = host_entrypoint
        self._reference_points_cache: dict[int, list[Node] | None] = {}
        self._invocation_orders: dict[int, dict[int, _InvocationOrder]] = {}

    def completes_before(self, definition: Node, point: Node) -> bool:
        """
        Whether the statement evaluating *definition* has completed on every run that reaches the
        statement evaluating *point*, both in one graph. Dominance alone orders entering the first
        statement: in `try { r = window; } catch (e) {} use(r);` the statement `r = window`
        dominates `use(r)`, yet the handler runs exactly when reading `window` threw and `r` was
        never written. So a point
        `refinery.lib.scripts.analysis.cfg.ControlFlowGraph.reached_after_a_throw` places after a
        throw out of the statement is ordered after it only when
        `refinery.lib.scripts.js.analysis.model.SemanticModel.statement_cannot_throw` holds for the
        statement. Not reflexive: a point sharing the statement is refused, since statement
        granularity cannot order within one statement.
        """
        located = self.locate_pair(definition, point)
        return located is not None and self.completes_before_node(*located)

    def completes_before_node(self, graph: ControlFlowGraph, a: CfgNode, b: CfgNode) -> bool:
        """
        The node-level counterpart of `completes_before`, for a caller that has already located the
        two statements in *graph*.
        """
        if a is b or not self.dominates_node(graph, a, b, Projection.MAY):
            return False
        thrown = graph.reached_after_a_throw(a)
        return id(b) not in thrown or self.model.statement_cannot_throw(a.element)

    def runs_before_function(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before any invocation of *function* — so a
        value established at *definition* holds throughout every call of *function*, and may be inlined
        into its body. The reasoning rests on one fact: a function cannot be invoked before a reference
        to it has been evaluated. Its reference points are its own creation, for an anonymous function
        expression, or the uses of its name, for a named binding; no invocation can precede the earliest
        of them. So *definition* runs before every invocation exactly when it runs before every reference
        point — and that, per point, is `completes_before` when the point lies in *definition*'s own
        function, or the same question applied to the function the point lies in, recursing up the call
        graph. The ordering is *strict*: a reference sharing the definition's statement — an earlier
        declarator or sequence operand evaluated before it — is not accepted, since statement-granularity
        dominance is reflexive and cannot order within one statement. A reference's function is its
        nearest enclosing function (its `_activation_of`), so a use in a function's parameter defaults is
        attributed to that function's invocation, not to the statement that declares it. Functions that
        reach each other's invocations — a recursive function, mutually recursive ones — are answered
        together (`_solve_invocation_orders`). This is the interprocedural counterpart of `dominates`,
        and the sound replacement for ordering a cross-function inline by statement position.

        Conservatively `False` when a reference point cannot be ordered or enumerated: the named binding
        is reassigned or redeclared (its references no longer pin one function), code outside the file
        can call the function, or a reference lies in a function that itself runs too late or escapes.
        A function neither referenced nor within reflection's reach is vacuously safe.
        """
        return self._invocation_order(definition, function).ordered

    def runs_before_every_invocation(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* is guaranteed to run before every invocation of *function*, and
        *function* is entered from the activation that runs *definition* — `runs_before_function`
        with the vacuity refused. A reader nothing in the file invokes, or one only code nothing
        invokes calls, answers the ordering question over no invocation at all and passes
        vacuously; a value established against no invocation is established for no read, so such a
        reader does not qualify. An anonymous function expression created in that activation is
        entered by its own creation, the one point no invocation can precede.
        """
        order = self._invocation_order(definition, function)
        return order.ordered and order.entered

    def runs_before(self, definition: Node, reference: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before *reference* is evaluated — the
        single-reference form of the ordering `runs_before_function` applies per reference point. When
        *reference* shares *definition*'s activation this is `completes_before` (a reference sharing
        *definition*'s statement is not accepted, since statement-granularity dominance is reflexive
        and cannot order within one statement); when *reference* lies inside a
        function that cannot be invoked until after *definition*, it is the interprocedural
        runs-before-function query, recursing up the call graph. Conservatively `False` whenever the
        ordering cannot be established — a reference in an activation that may run before *definition*,
        or a reference point that cannot be enumerated — so a caller may treat `True` as a guarantee.
        """
        definition_owner = self._activation_of(definition)
        return self._runs_after(definition, definition_owner, reference)

    def runs_before_all(self, definition: Node, references: Iterable[Node]) -> bool:
        """
        Whether *definition* is guaranteed to run before every reference in *references* — `runs_before`
        for each, vacuously `True` for an empty iterable. The definition's activation is resolved once
        and shared across the references.
        """
        definition_owner = self._activation_of(definition)
        return all(
            self._runs_after(definition, definition_owner, reference)
            for reference in references
        )

    def established_before(self, function: Node, reference: Node) -> bool:
        """
        Whether *function*'s callable value is in place before *reference* runs. The
        function-invocation view of `binding_established_before`: `False` when *function* is not invoked
        through a single orderable name, so its presence cannot be ordered — the query a consumer needs
        before folding or dropping a call whose callee would otherwise read a temporal dead zone or a
        hoisted `undefined`.
        """
        return self.binding_established_before(self.model.invocation_binding(function), reference)

    def binding_established_before(self, binding: Binding | None, reference: Node) -> bool:
        """
        Whether *binding*'s `singular_value` is in place before *reference* runs: every node in its
        `SemanticModel.binding_establishment_sites` executes first. A hoisted function declaration has no
        sites and qualifies unconditionally; a `var`/`let`/`const` initializer, a class declaration, or a
        lone assignment (`f = function(){}`, the form namespace flattening leaves) qualifies only where
        each establishing node runs before *reference*. `False` when the binding holds no single orderable
        value, so its presence cannot be ordered — the query a consumer needs before trusting a value that
        would otherwise be read out of its temporal dead zone or before its establishing write.
        """
        sites = self.model.binding_establishment_sites(binding)
        if sites is None:
            return False
        return all(self.runs_before(site, reference) for site in sites)

    def past_dead_zone(self, binding: Binding, reference: Node) -> bool:
        """
        Whether *reference* is guaranteed to run past *binding*'s temporal dead zone: every
        declaration of this `let`/`const`/`class` binding executes first, so a read at *reference*
        cannot raise a `ReferenceError`. Distinct from `binding_established_before`, which orders
        the singular value's establishing write: a dead zone ends at the DECLARATION, not at the
        first value assignment, so a `let` declared before *reference* but reassigned afterward is
        past its dead zone here while `binding_established_before` — reasoning about the value —
        answers `False`. `False` when the binding carries no declaration to order, so the dead
        zone's end cannot be proven.
        """
        return bool(binding.declarations) and all(
            self.runs_before(site, reference) for site in binding.declarations
        )

    def _invocation_order(self, definition: Node, function: Node) -> _InvocationOrder:
        """
        How every invocation of *function* stands to *definition*. Answers are kept per definition
        and every one kept is final, so each query of the same definition shares the functions an
        earlier one solved.
        """
        orders = self._invocation_orders.setdefault(id(definition), {})
        order = orders.get(id(function))
        if order is None:
            self._solve_invocation_orders(definition, function, orders)
            order = orders[id(function)]
        return order

    def _solve_invocation_orders(
        self,
        definition: Node,
        function: Node,
        orders: dict[int, _InvocationOrder],
    ):
        """
        Solve `_invocation_order` for *function* and for every function a reference point of it
        lies in, one strongly connected component of that graph at a time: Tarjan's algorithm, kept
        on an explicit stack so a long chain of calls cannot exhaust the interpreter's. The
        functions of one component reach each other's invocations and get one answer. They are
        ordered when every point outside the component is: one in the definition's activation by
        `completes_before`, one in another function by that function's answer. They are entered
        when one of those points lies in the definition's activation or in an entered function.

        This is sound because the earliest invocation of any function in a component follows a
        reference to it that nothing in the component can have evaluated yet, so that reference is
        one of the points outside it. A component is stored only once every component it reaches
        is, which is what makes each stored answer final.
        """
        owner = self._activation_of(definition)
        index: dict[int, int] = {}
        lowlink: dict[int, int] = {}
        gathered: dict[int, _Gathered] = {}
        stack: list[Node] = []
        frames: list[tuple[Node, Iterator[Node]]] = []

        def open_frame(opened: Node):
            key = id(opened)
            index[key] = lowlink[key] = len(index)
            stack.append(opened)
            points = self._reference_points(opened)
            gathered[key] = _Gathered(points is not None)
            frames.append((opened, iter(points or ())))

        open_frame(function)
        while frames:
            current, points = frames[-1]
            key = id(current)
            state = gathered[key]
            for point in points:
                activation = self._activation_of(point)
                if activation is owner:
                    state.entered = True
                    if not self.completes_before(definition, point):
                        state.ordered = False
                elif not isinstance(activation, FUNCTION_NODES):
                    state.ordered = False
                elif (order := orders.get(id(activation))) is not None:
                    state.absorb(order)
                elif id(activation) not in index:
                    open_frame(activation)
                    break
                else:
                    lowlink[key] = min(lowlink[key], index[id(activation)])
            else:
                frames.pop()
                if lowlink[key] == index[key]:
                    members: list[Node] = []
                    while not members or members[-1] is not current:
                        members.append(stack.pop())
                    order = _InvocationOrder(
                        all(gathered[id(member)].ordered for member in members),
                        any(gathered[id(member)].entered for member in members),
                    )
                    for member in members:
                        orders[id(member)] = order
                if frames:
                    parent = id(frames[-1][0])
                    if key in orders:
                        gathered[parent].absorb(orders[key])
                    else:
                        lowlink[parent] = min(lowlink[parent], lowlink[key])

    def _reference_points(self, function: Node) -> list[Node] | None:
        """
        The points no invocation of *function* can precede, or `None` when they cannot be enumerated.
        For a function pinned to a name (`SemanticModel.invocation_binding`) these are the value-reads of
        that name — a read must be evaluated before the value it denotes can be called — together with the
        opaque reflective surface sites that could invoke it by name
        (`SemanticModel.reflection_surface_sites`): a direct `eval`, `Function`, a string timer, or a
        dynamic global access cannot invoke the function before the surface that grants the capability has
        run, so each surface is itself a point no invocation precedes, ranked exactly like a read. The
        enumeration is `None` when the name is redeclared, reassigned to another value so a read no longer
        pins this one function (`SemanticModel.binding_pinned_to`), or resolved inside a dynamic scope a
        `with` body governs, whose `dynamic_refs` entry is unorderable; this mirrors the escape verdict
        `EffectModel.function_escapes` draws from the same fact. A surface lexically inside *function* is
        dropped: it cannot trigger the function's first invocation, only a re-entrant one, so it never
        bounds the ordering. A function pinned to no name but installed as a property of a non-escaping
        local object (`_member_reference_points`) is enumerated instead by the accesses of that object
        through which its callable can be obtained; this is consulted first, so a namespace method
        ordered by its call sites is not mistaken for an anonymous closure ordered by its creation. For
        a function bound to no name and matching neither pattern, the single point is the function
        expression itself: the closure cannot be invoked before it is created. A function code outside
        the file can call (`_callable_from_outside_the_file`) has no enumeration at all.

        Memoized by function identity: the enumeration is a pure function of *function* and the model,
        both fixed for the model's lifetime — the whole DominanceModel is rebuilt when the tree version
        advances — so every `runs_before*` caller shares one result per function instead of recomputing
        it per reference and per query.
        """
        key = id(function)
        cache = self._reference_points_cache
        if key not in cache:
            cache[key] = self._compute_reference_points(function)
        return cache[key]

    def _compute_reference_points(self, function: Node) -> list[Node] | None:
        if self._callable_from_outside_the_file(function):
            return None
        member_points = self._member_reference_points(function)
        if member_points is not None:
            return member_points
        binding = self.model.invocation_binding(function)
        if binding is None:
            return [function]
        if (
            binding.dynamic_refs
            or len(binding.declarations) != 1
            or not self.model.binding_pinned_to(binding, function)
        ):
            return None
        points: list[Node] = [*binding.reads]
        points.extend(
            site
            for site in self.model.reflection_surface_sites(binding)
            if not site.is_descendant_of(function)
        )
        return points

    def _callable_from_outside_the_file(self, function: Node) -> bool:
        """
        Whether code outside the file can call *function* at a point the file's text does not order.
        A host calls a declared entry point (*host_entrypoint*) by name once it is a property of the
        global object, which `SemanticModel.reaches_global_object` answers under *module_scope*. An
        importer calls an exported function — one exported by name, or an anonymous `export default
        function` — and it can do so before this module's body has finished exactly where
        `SemanticModel.module_may_be_reentered` holds; elsewhere every importer calls in after the
        last statement, so an export keeps the ordering the file gives it.
        """
        binding = self.model.invocation_binding(function)
        if self._importer_may_run_first(binding):
            return True
        if (
            isinstance(function.parent, JsExportDefaultDeclaration)
            and self.model.module_may_be_reentered()
        ):
            return True
        return (
            binding is not None
            and self._host_entrypoint is not None
            and self._host_entrypoint(binding.name)
            and self.model.reaches_global_object(binding, module_scope=self._module_scope)
        )

    def _importer_may_run_first(self, binding: Binding | None) -> bool:
        """
        Whether *binding* is exported from a module an importer can run in before its body has
        finished, so the importer can read it at a point the file's text does not order.
        """
        return binding is not None and binding.exported and self.model.module_may_be_reentered()

    def _member_reference_points(self, function: Node) -> list[Node] | None:
        """
        The points no invocation of *function* can precede when it is installed as a property of a
        non-escaping local object, or `None` where that pattern does not hold. *function* is the value
        of a `BASE.key = function` assignment whose `BASE` resolves to a local binding holding one
        object literal (`SemanticModel.singular_value`) that never escapes as a bare value: every
        reference to it is the object of a member access. The callable can then be obtained in two
        ways only, by reading `BASE.key`, or by code that runs with the object in hand and reads the
        key there, and the points are every access through which either can happen.

        An access may read the property when it reads `key` or a key that is not statically known.
        An access hands the object to code when it is a method call in any form, whose callee
        receives the object as `this`; when it accesses `__proto__` or a key that is not statically
        known, which may give the object a prototype carrying accessors; and in every case, the
        establishing write included, when the literal declares an accessor or a prototype
        (`refinery.lib.scripts.js.model.object_member_access_runs_accessor`) or the program writes
        the prototype chain of a plain object
        (`refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.chain_roots_unwritten`), since
        any access may then run an accessor with the object as `this`. Nothing can call the function
        through the object before the access that hands the object over has run, so such an access
        is a point rather than a reason to refuse, for the reason a reflective surface is one. An
        access of a different key that runs no code, and a write of `key`, never obtain the value and
        are not points.

        The opaque reflective surfaces that could name the binding are added as points exactly as
        the name-based enumeration adds them. A `with` that could rename the base (a `dynamic_refs`
        entry), and an exported base an importer can reach before the body has finished, make the
        ordering unknowable and yield `None`, as does any shape the recognition does not match, so
        the caller falls through to its name-based ordering.
        """
        parent = function.parent
        if not (
            isinstance(parent, JsAssignmentExpression)
            and parent.operator == '='
            and parent.right is function
        ):
            return None
        target = strip_parens(parent.left)
        if not isinstance(target, JsMemberExpression) or not isinstance(target.object, JsIdentifier):
            return None
        key = member_property_name(target)
        if key is None:
            return None
        binding = self.model.resolve(target.object)
        if binding is None:
            return None
        literal = self.model.singular_value(binding)
        if not isinstance(literal, JsObjectExpression):
            return None
        if binding.dynamic_refs or self._importer_may_run_first(binding):
            return None
        every_access_runs_code = (
            object_member_access_runs_accessor(literal)
            or not self.intrinsic_writes.chain_roots_unwritten(dict)
        )
        points: list[Node] = [target] if every_access_runs_code else []
        for read in binding.reads:
            node = read
            access = node.parent
            while isinstance(access, JsParenthesizedExpression):
                node, access = access, access.parent
            if not isinstance(access, JsMemberExpression) or access.object is not node:
                return None
            if access is target:
                continue
            name = member_property_name(access)
            if (
                every_access_runs_code
                or name is None
                or name == '__proto__'
                or is_invocation_target(access)
            ):
                points.append(access)
            elif name == key and not is_simple_assignment_target(access):
                points.append(access)
        points.extend(
            site
            for site in self.model.reflection_surface_sites(binding)
            if not site.is_descendant_of(function)
        )
        return points

    def _runs_after(self, definition: Node, definition_owner: Node, point: Node) -> bool:
        owner = self._activation_of(point)
        if owner is definition_owner:
            return self.completes_before(definition, point)
        if isinstance(owner, FUNCTION_NODES):
            return self._invocation_order(definition, owner).ordered
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


def build_dominance(
    model: SemanticModel,
    control_flow: ControlFlowModel | None = None,
    *,
    intrinsic_writes: IntrinsicWrites | None = None,
    module_scope: bool = False,
    host_entrypoint: Callable[[str], bool] | None = None,
) -> DominanceModel:
    """
    Build the `DominanceModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`,
    reusing *control_flow* and *intrinsic_writes* when the caller has them to share, or building
    fresh ones when they are `None`. *module_scope* and *host_entrypoint* are the run's execution
    model and declared host entry points; the defaults describe a script no host calls into.
    """
    return DominanceModel(
        model,
        control_flow,
        intrinsic_writes=intrinsic_writes,
        module_scope=module_scope,
        host_entrypoint=host_entrypoint,
    )
