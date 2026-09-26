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

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Sequence

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
from refinery.lib.scripts.js.analysis.intrinsics import (
    SPECIES_KEYS,
    IntrinsicWrites,
    build_intrinsic_writes,
)
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    enclosing_function,
    is_invocation_target,
    is_member_write_target,
    is_simple_assignment_target,
    member_property_name,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsExportDefaultDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsParenthesizedExpression,
    object_member_access_runs_accessor,
    strip_parens,
    value_is_discarded,
)


@dataclass(eq=False)
class _HandOver:
    """
    The moment one local object reaches code that can call a function installed on it without
    reading the key the function is stored at. A method call on the object runs its callee with
    the object as `this`; where an accessor may run on the object's prototype chain, any access
    runs one with the object as `this`. The functions installed on the object share this node of
    the ordering graph, whose *points* are those accesses, so the accesses are listed and ordered
    once for all of them (`DominanceModel._member_reference_points`). The other points of such a
    function name it and belong to it alone: the *reads* of its key, the reads at a key that is
    not statically known (*unnamed*), the reflective *surfaces* that can name the object, and the
    end of the script where an importer reaches the object (*exported*).
    """
    points: list[Node]
    reads: dict[str, list[Node]]
    unnamed: list[Node]
    surfaces: list[Node]
    exported: bool


def _may_name_the_prototype(access: JsMemberExpression) -> bool:
    """
    Whether *access* may read or write the prototype of the object it accesses, or the constructor
    whose `prototype` that is: its key is one of
    `refinery.lib.scripts.js.analysis.intrinsics.SPECIES_KEYS`, or not statically known.
    """
    name = member_property_name(access)
    return name is None or name in SPECIES_KEYS


def _may_hand_out_the_prototype(access: JsMemberExpression) -> bool:
    """
    Whether *access* may hand out the prototype of the object it reads for code to install an
    accessor on (`_may_name_the_prototype`). A write into the key only swaps the prototype of this
    one object, and a call only runs what the key holds, so neither hands the prototype out; any
    other use of the value, a member access or install through it included, may.
    """
    return (
        _may_name_the_prototype(access)
        and not is_invocation_target(access)
        and not is_member_write_target(access)
    )


class DominanceModel(DominatorModel):
    """
    Dominator relations for the per-function control-flow graphs of one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Ask whether one AST node is guaranteed to
    execute before another with `dominates`. Build through `build_dominance`.

    The ordering across calls reads three facts about what lies outside the text: *intrinsic_writes*
    says whether the program writes the prototype chain a plain object reads through, *module_scope*
    is the run's execution model, and *host_entrypoint* names the top-level bindings the analyst
    declared a host reaches by name: a function it invokes, or an object whose methods it calls.
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
        self._reference_points_cache: dict[Node, list[Node | _HandOver] | None] = {}
        self._invocation_orders: dict[Node, dict[Node | _HandOver, bool]] = {}
        self._entered_from: dict[Node, dict[Node, bool]] = {}
        self._hand_overs: dict[Binding, _HandOver | None] = {}

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
        granularity cannot order within one statement. The script root as *point* stands for the
        end of the script (`_completes_before_the_end`).
        """
        if point is self.model.root:
            return self._completes_before_the_end(definition)
        located = self.locate_pair(definition, point)
        return located is not None and self.completes_before_node(*located)

    def _completes_before_the_end(self, definition: Node) -> bool:
        """
        Whether the statement evaluating *definition* has completed on every run that finishes the
        script, the point where an importer outside every import cycle calls what a module
        exports: every edge that enters the exit of the script's graph without a throw leaves that
        statement, or one it `completes_before_node`. A run that ends in a throw finishes nothing,
        since no importer runs after a module whose body threw.
        """
        graph = self._flow.graph_of(self.model.root)
        located = self.locate(definition)
        if graph is None or located is None or located[0] is not graph:
            return False
        node = located[1]
        return all(
            source is node or self.completes_before_node(graph, node, source)
            for source in graph.exit.predecessors
            if not graph.raise_taken(source, graph.exit)
        )

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
        Whether *definition* is guaranteed to have executed before any invocation of *function* — so
        a value established at *definition* holds throughout every call of *function*, and may be
        inlined into its body. The reasoning rests on one fact: a function cannot be invoked before
        a reference to it has been evaluated. Its reference points are its own creation, for an
        anonymous function expression, or the uses of its name, for a named binding; no invocation
        can precede the earliest of them. So *definition* runs before every invocation exactly when
        it runs before every reference point — and that, per point, is `completes_before` when the
        point lies in *definition*'s own function, or the same question applied to the function the
        point lies in, recursing up the call graph. The ordering is *strict*: a reference sharing
        the definition's statement — an earlier declarator or sequence operand evaluated before it —
        is not accepted, since statement-granularity dominance is reflexive and cannot order within
        one statement. A reference's function is its nearest enclosing function (its
        `_activation_of`), so a use in a function's parameter defaults is attributed to that
        function's invocation, not to the statement that declares it. Functions that reach each
        other's invocations — a recursive function, mutually recursive ones — are answered together
        (`_solve_invocation_orders`). This is the interprocedural counterpart of `dominates`, and
        the sound replacement for ordering a cross-function inline by statement position.

        Conservatively `False` when a reference point cannot be ordered or enumerated: the named
        binding is reassigned or redeclared (its references no longer pin one function), code
        outside the file can call the function, or a reference lies in a function that itself runs
        too late or escapes. A function neither referenced nor within reflection's reach is
        vacuously safe.
        """
        return self._ordered(definition, function)

    def runs_before_every_invocation(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* is guaranteed to run before every invocation of *function*, and
        *function* is entered from the activation that runs *definition* (`_entered`) —
        `runs_before_function` with the vacuity refused. A reader nothing in the file obtains, or
        one only code nothing obtains calls, answers the ordering question over no invocation at
        all and passes vacuously; a value established against no invocation is established for no
        read, so such a reader does not qualify. An object handed to code does not enter the
        methods stored on it. An anonymous function expression created in that activation is
        entered by its own creation, the one point no invocation can precede.
        """
        return (
            self._ordered(definition, function)
            and self._entered(self._activation_of(definition), function)
        )

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

    def _ordered(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* runs before every invocation of *function*. Answers are kept per
        definition and every one kept is final, so each query of the same definition shares the
        functions an earlier one solved.
        """
        orders = self._invocation_orders.setdefault(definition, {})
        ordered = orders.get(function)
        if ordered is None:
            self._solve_invocation_orders(definition, function, orders)
            ordered = orders[function]
        return ordered

    def _solve_invocation_orders(
        self,
        definition: Node,
        function: Node,
        orders: dict[Node | _HandOver, bool],
    ):
        """
        Solve `_ordered` for *function* and for every function a reference point of it lies in,
        one strongly connected component of that graph at a time: Tarjan's algorithm, kept on an
        explicit stack so a long chain of calls cannot exhaust the interpreter's. A point that is a
        `_HandOver` is a node of the graph in its own right, shared by every function installed on
        one object. The members of one component reach each other's invocations and get one
        answer: they are ordered when every point outside the component is, one in the
        definition's activation by `completes_before`, one in another function or hand-over by that
        node's answer. A function expression the definition's activation creates only after the
        definition has completed is ordered without its points (`_created_after`).

        This is sound because the earliest invocation of any function in a component follows a
        reference to it that nothing in the component can have evaluated yet, so that reference is
        one of the points outside it. A node stops at the first point it cannot order: that point
        lies outside every component the node belongs to, so it leaves each of them unordered
        however the other points stand. Every other component is stored only once every component
        it reaches is, which is what makes each stored answer final.
        """
        owner = self._activation_of(definition)
        index: dict[Node | _HandOver, int] = {}
        lowlink: dict[Node | _HandOver, int] = {}
        ordered: dict[Node | _HandOver, bool] = {}
        stack: list[Node | _HandOver] = []
        frames: list[tuple[Node | _HandOver, Iterator[Node | _HandOver]]] = []

        def open_frame(opened: Node | _HandOver):
            index[opened] = lowlink[opened] = len(index)
            stack.append(opened)
            if self._created_after(definition, owner, opened):
                points = ()
            else:
                points = self._reference_points(opened)
            ordered[opened] = points is not None
            frames.append((opened, iter(points or ())))

        open_frame(function)
        while frames:
            current, points = frames[-1]
            for point in points:
                if not ordered[current]:
                    break
                if isinstance(point, _HandOver):
                    activation: Node | _HandOver = point
                else:
                    activation = self._activation_of(point)
                    if activation is owner:
                        if not self.completes_before(definition, point):
                            ordered[current] = False
                        continue
                    if not isinstance(activation, FUNCTION_NODES):
                        ordered[current] = False
                        continue
                if (known := orders.get(activation)) is not None:
                    if not known:
                        ordered[current] = False
                elif activation not in index:
                    open_frame(activation)
                    break
                else:
                    lowlink[current] = min(lowlink[current], index[activation])
            if frames[-1][0] is not current:
                continue
            frames.pop()
            if lowlink[current] == index[current]:
                members: list[Node | _HandOver] = []
                while not members or members[-1] is not current:
                    members.append(stack.pop())
                answer = all(ordered[member] for member in members)
                for member in members:
                    orders[member] = answer
            if frames:
                parent = frames[-1][0]
                if current in orders:
                    ordered[parent] = ordered[parent] and orders[current]
                else:
                    lowlink[parent] = min(lowlink[parent], lowlink[current])

    def _created_after(self, definition: Node, owner: Node, activation: Node | _HandOver) -> bool:
        """
        Whether *activation* is a function expression that *owner*, the activation running
        *definition*, creates only once *definition* has completed. No copy of the function exists
        before that, so none is invoked before it, whatever its reference points are: a method call
        that hands its object over before the method is stored there cannot call the method yet. A
        function declaration exists from the start of its activation and never qualifies.
        """
        return (
            isinstance(activation, (JsFunctionExpression, JsArrowFunctionExpression))
            and self._activation_of(activation) is owner
            and self.completes_before(definition, activation)
        )

    def _entered(self, owner: Node, function: Node) -> bool:
        """
        Whether a reference point of *function* that names it lies in *owner*, or in a function
        entered from *owner* the same way: a read of its name or of the key it is stored at, a
        reflective surface that can name it, the end of the script where an importer calls it, or
        its own creation for a function bound to nothing. The accesses of a `_HandOver` hand an
        object on and never enter a function, so a method no code in the file obtains stays
        unentered however often its object is handed over. Answers are kept per activation, since
        the question does not depend on the definition.
        """
        known = self._entered_from.setdefault(owner, {})
        answer = known.get(function)
        if answer is not None:
            return answer
        seen: set[Node] = {function}
        pending: list[Node] = [function]
        while pending:
            current = pending.pop()
            for point in self._reference_points(current) or ():
                if isinstance(point, _HandOver):
                    continue
                activation = self._activation_of(point)
                if activation is owner or known.get(activation) is True:
                    known[function] = True
                    return True
                if (
                    isinstance(activation, FUNCTION_NODES)
                    and activation not in seen
                    and known.get(activation) is None
                ):
                    seen.add(activation)
                    pending.append(activation)
        for node in seen:
            known[node] = False
        return False

    def _reference_points(self, activation: Node | _HandOver) -> Sequence[Node | _HandOver] | None:
        """
        The points no invocation of *activation* can precede, or `None` when they cannot be
        enumerated. A `_HandOver` holds its own points. For a function pinned to a name
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.invocation_binding`) these are the
        value-reads of that name — a read must be evaluated before the value it denotes can be
        called — together with the opaque reflective surface sites that could invoke it by name
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.reflection_surface_sites`): a direct
        `eval`, `Function`, a string timer, or a dynamic global access cannot invoke the function
        before the surface that grants the capability has run, so each surface is itself a point no
        invocation precedes, ranked exactly like a read. The enumeration is `None` when the name is
        redeclared, reassigned to another value so a read no longer pins this one function
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.binding_pinned_to`), or resolved
        inside a dynamic scope a `with` body governs, whose
        `refinery.lib.scripts.js.analysis.model.Binding.dynamic_refs` entry is unorderable; this
        mirrors the escape verdict
        `refinery.lib.scripts.js.analysis.effects.EffectModel.function_escapes` draws from the same
        fact. A surface lexically inside the function is dropped: it cannot trigger the function's
        first invocation, only a re-entrant one, so it never bounds the ordering. A function
        installed as a property of a non-escaping local object (`_member_reference_points`) is
        enumerated instead by the points that name it and the object's `_HandOver`; this is
        consulted first, so a namespace method ordered by its call sites is not mistaken for an
        anonymous closure ordered by its creation.

        A function is ordered by its creation alone, the one point no invocation can precede, when
        it is bound to no name and matches neither pattern, and when the value of the assignment
        installing it flows on (`_installed_value_escapes`). A function code outside the file can
        call while the file runs (`_callable_before_the_end`) has no enumeration at all. One an
        importer outside every import cycle can call has the end of the script as one more point,
        the script root standing for it (`completes_before`), since such an importer calls in only
        once the module has finished.

        Memoized by identity: the enumeration is a pure function of *activation* and the model,
        both fixed for the model's lifetime — the whole DominanceModel is rebuilt when the tree
        version advances — so every `runs_before*` caller shares one result per function instead of
        recomputing it per reference and per query.
        """
        if isinstance(activation, _HandOver):
            return activation.points
        cache = self._reference_points_cache
        if activation not in cache:
            cache[activation] = self._compute_reference_points(activation)
        return cache[activation]

    def _compute_reference_points(self, function: Node) -> list[Node | _HandOver] | None:
        binding = self.model.invocation_binding(function)
        if self._callable_before_the_end(function, binding):
            return None
        if self._installed_value_escapes(function):
            return [function]
        if binding is None and isinstance(function.parent, JsExportDefaultDeclaration):
            return [self.model.root]
        member_points = self._member_reference_points(function)
        if member_points is not None:
            return member_points
        if binding is None:
            return [function]
        if (
            binding.dynamic_refs
            or len(binding.declarations) != 1
            or not self.model.binding_pinned_to(binding, function)
        ):
            return None
        points: list[Node | _HandOver] = [*binding.reads]
        points.extend(
            site
            for site in self.model.reflection_surface_sites(binding)
            if not site.is_descendant_of(function)
        )
        if binding.exported:
            points.append(self.model.root)
        return points

    def _callable_before_the_end(self, function: Node, binding: Binding | None) -> bool:
        """
        Whether code outside the file can call *function* while the file's own text still runs, at
        a point that text does not order. A host calls a declared entry point whenever the script
        hands it control (`_host_may_reach`). An importer in an import cycle calls an export — one
        exported by name, or an anonymous `export default function` — before the module's body has
        finished, exactly where
        `refinery.lib.scripts.js.analysis.model.SemanticModel.module_may_be_reentered` holds
        (`_importer_may_run_first`). An importer outside every cycle calls in only after the module
        has finished, which `_compute_reference_points` orders as the end of the script instead.
        """
        if binding is not None and (
            self._importer_may_run_first(binding)
            or self._host_may_reach(binding)
        ):
            return True
        return (
            isinstance(function.parent, JsExportDefaultDeclaration)
            and self.model.module_may_be_reentered()
        )

    def _importer_may_run_first(self, binding: Binding) -> bool:
        """
        Whether *binding* is exported from a module an importer can run in before its body has
        finished, so the importer can read it at a point the file's text does not order.
        """
        return binding.exported and self.model.module_may_be_reentered()

    def _host_may_reach(self, binding: Binding) -> bool:
        """
        Whether a host may reach *binding* by name: the analyst declared it an entry point
        (*host_entrypoint*), and it is a property of the global object under the run's execution
        model (`refinery.lib.scripts.js.analysis.model.SemanticModel.reaches_global_object`). A
        declared object is reached as much as a declared function, and the host may call a method
        installed on it whenever the script hands it control.
        """
        return (
            self._host_entrypoint is not None
            and self._host_entrypoint(binding.name)
            and self.model.reaches_global_object(binding, module_scope=self._module_scope)
        )

    @staticmethod
    def _installed_value_escapes(function: Node) -> bool:
        """
        Whether *function* is the right side of an assignment whose own value the program goes on
        to use: chained into another name or key (`h = NS.g = function(){}`), called on the spot,
        or passed on as an argument. That value reaches code through no read of the name or of the
        key the assignment installs into, so neither enumeration lists it.
        """
        parent = function.parent
        return (
            isinstance(parent, JsAssignmentExpression)
            and parent.right is function
            and not value_is_discarded(parent)
        )

    def _member_reference_points(self, function: Node) -> list[Node | _HandOver] | None:
        """
        The points no invocation of *function* can precede when it is installed as a property of a
        non-escaping local object, or `None` where that pattern does not hold. *function* is the
        value of a `BASE.key = function` statement whose `BASE` resolves to a binding with a
        `_HandOver`, one holding a single object literal that never escapes as a bare value
        (`_hand_over`). The callable can then be obtained in two ways only: by reading `BASE.key`,
        or by code the object is handed to, which reads the key itself. The points are the
        hand-over, the reads of `key` and of keys that are not statically known, the reflective
        surfaces that could name the binding, and the end of the script for an object an importer
        reaches. A write of `key` never obtains the value and is not a point. An install at the key
        `__proto__` makes *function* the object's prototype rather than a property of it, so every
        inherited read reaches it, and the pattern does not hold.
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
        if key is None or key == '__proto__':
            return None
        binding = self.model.resolve(target.object)
        if binding is None:
            return None
        hand_over = self._hand_over(binding)
        if hand_over is None:
            return None
        points: list[Node | _HandOver] = [hand_over]
        points.extend(hand_over.reads.get(key, ()))
        points.extend(hand_over.unnamed)
        points.extend(site for site in hand_over.surfaces if not site.is_descendant_of(function))
        if hand_over.exported:
            points.append(self.model.root)
        return points

    def _hand_over(self, binding: Binding) -> _HandOver | None:
        """
        The `_HandOver` of the object *binding* holds, computed once per binding, or `None` where
        its accesses cannot all be enumerated: the binding holds no single object literal
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.singular_value`), one of its reads is
        not the object of a member access, a `with` could rename it (a
        `refinery.lib.scripts.js.analysis.model.Binding.dynamic_refs` entry), an importer can reach
        it before the module has finished (`_importer_may_run_first`), or a host can reach it by
        name (`_host_may_reach`).

        An access hands the object to code when it is a method call in any form, whose callee
        receives the object as `this`, and when it reads or writes the object's prototype
        (`_may_name_the_prototype`), after which the object may inherit accessors from another
        prototype. Every access does, the establishing writes included, when an accessor may run on
        the object's prototype chain and receive the object as `this`, or at its own key the very
        function being stored there. That is so when the literal declares an accessor or a prototype
        (`refinery.lib.scripts.js.model.object_member_access_runs_accessor`); when the program
        writes the prototype chain of a plain object
        (`refinery.lib.scripts.js.analysis.intrinsics.IntrinsicWrites.chain_roots_unwritten`); when
        it holds code this analysis cannot read, which may install one anywhere
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.has_reflection_surface`), the term
        `refinery.lib.scripts.js.analysis.effects.EffectModel.read_chain_intact` asks of a plain
        read as well; and when an access of the object may hand out its prototype
        (`_may_hand_out_the_prototype`). An accessor installed through what that access yields lands
        on a prototype every later object of the same kind inherits, the objects later runs of the
        same code create included, so a point at the access alone would not order those.

        An accessor can receive the object at no other moment, since the object never escapes as
        a bare value. Nothing can call a function through the object before the access that hands
        the object over has run, so such an access is a point rather than a reason to refuse, for
        the reason a reflective surface is one.
        """
        if binding in self._hand_overs:
            return self._hand_overs[binding]
        hand_over = self._compute_hand_over(binding)
        self._hand_overs[binding] = hand_over
        return hand_over

    def _compute_hand_over(self, binding: Binding) -> _HandOver | None:
        literal = self.model.singular_value(binding)
        if not isinstance(literal, JsObjectExpression):
            return None
        if (
            binding.dynamic_refs
            or self._importer_may_run_first(binding)
            or self._host_may_reach(binding)
        ):
            return None
        accesses: list[JsMemberExpression] = []
        for read in binding.reads:
            node = read
            access = node.parent
            while isinstance(access, JsParenthesizedExpression):
                node, access = access, access.parent
            if not isinstance(access, JsMemberExpression) or access.object is not node:
                return None
            accesses.append(access)
        every_access_runs_code = (
            object_member_access_runs_accessor(literal)
            or not self.intrinsic_writes.chain_roots_unwritten(dict)
            or self.model.has_reflection_surface()
            or any(_may_hand_out_the_prototype(access) for access in accesses)
        )
        points: list[Node] = []
        reads: dict[str, list[Node]] = {}
        unnamed: list[Node] = []
        for access in accesses:
            if (
                every_access_runs_code
                or is_invocation_target(access)
                or _may_name_the_prototype(access)
            ):
                points.append(access)
            if is_simple_assignment_target(access):
                continue
            if (key := member_property_name(access)) is None:
                unnamed.append(access)
            else:
                reads.setdefault(key, []).append(access)
        return _HandOver(
            points,
            reads,
            unnamed,
            self.model.reflection_surface_sites(binding),
            binding.exported,
        )

    def _runs_after(self, definition: Node, definition_owner: Node, point: Node) -> bool:
        owner = self._activation_of(point)
        if owner is definition_owner:
            return self.completes_before(definition, point)
        if isinstance(owner, FUNCTION_NODES):
            return self._ordered(definition, owner)
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
