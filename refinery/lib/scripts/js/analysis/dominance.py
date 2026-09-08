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
`dominates`, refusing a same-statement pair a caller must order. `runs_before_function` lifts dominance
across calls: it answers whether a definition runs before every invocation of a function, which a single
graph cannot, by ordering the definition against the points the function is referenced and recursing up
the call graph. `runs_before` and `runs_before_all` expose that same ordering against a single reference,
or every reference in a set — the query a transform needs to confirm a value is established before every
use that could observe it.
"""
from __future__ import annotations

from typing import Iterable

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.js.analysis.cfg import (
    FUNCTION_NODES,
    ControlFlowModel,
    build_control_flow_model,
)
from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel, enclosing_function


class DominanceModel(DominatorModel):
    """
    Dominator relations for the per-function control-flow graphs of one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Ask whether one AST node is guaranteed to
    execute before another with `dominates`. Build through `build_dominance`.
    """

    def __init__(self, model: SemanticModel, control_flow: ControlFlowModel | None = None):
        flow = control_flow if control_flow is not None else build_control_flow_model(model.root)
        super().__init__(flow)
        self.model = model
        self._reference_points_cache: dict[int, list[Node] | None] = {}

    def runs_before_function(self, definition: Node, function: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before any invocation of *function* — so a
        value established at *definition* holds throughout every call of *function*, and may be inlined
        into its body. The reasoning rests on one fact: a function cannot be invoked before a reference
        to it has been evaluated. Its reference points are its own creation, for an anonymous function
        expression, or the uses of its name, for a named binding; no invocation can precede the earliest
        of them. So *definition* runs before every invocation exactly when it runs before every reference
        point — and that, per point, is strict dominance when the point lies in *definition*'s own
        function, or the same question applied to the function the point lies in, recursing up the call
        graph. The ordering is *strict*: a reference sharing the definition's statement — an earlier
        declarator or sequence operand evaluated before it — is not accepted, since statement-granularity
        dominance is reflexive and cannot order within one statement. A reference's function is its
        nearest enclosing function (its `_activation_of`), so a use in a function's parameter defaults is
        attributed to that function's invocation, not to the statement that declares it. This is the
        interprocedural counterpart of `dominates`, and the sound replacement for ordering a
        cross-function inline by statement position.

        Conservatively `False` when a reference point cannot be ordered or enumerated: the named binding
        is reassigned or redeclared (its references no longer pin one function), a reference lies in a
        function that itself runs too late or escapes, or the walk meets a call cycle it cannot bottom
        out. A function neither referenced nor within reflection's reach is vacuously safe.
        """
        definition_owner = self._activation_of(definition)
        return self._runs_before_function(definition, definition_owner, function, set(), {})

    def runs_before(self, definition: Node, reference: Node) -> bool:
        """
        Whether *definition* is guaranteed to have executed before *reference* is evaluated — the
        single-reference form of the ordering `runs_before_function` applies per reference point. When
        *reference* shares *definition*'s activation this is intraprocedural *strict* dominance (a
        reference sharing *definition*'s statement is not accepted, since statement-granularity
        dominance is reflexive and cannot order within one statement); when *reference* lies inside a
        function that cannot be invoked until after *definition*, it is the interprocedural
        runs-before-function query, recursing up the call graph. Conservatively `False` whenever the
        ordering cannot be established — a reference in an activation that may run before *definition*,
        or a reference point that cannot be enumerated — so a caller may treat `True` as a guarantee.
        """
        definition_owner = self._activation_of(definition)
        return self._runs_after(definition, definition_owner, reference, set(), {})

    def runs_before_all(self, definition: Node, references: Iterable[Node]) -> bool:
        """
        Whether *definition* is guaranteed to run before every reference in *references* — `runs_before`
        for each, vacuously `True` for an empty iterable. The definition's activation is resolved once
        and shared across the references.
        """
        definition_owner = self._activation_of(definition)
        return all(
            self._runs_after(definition, definition_owner, reference, set(), {})
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
        Whether *reference* is guaranteed to run past *binding*'s temporal dead zone: every declaration of
        this `let`/`const`/`class` binding executes first, so a read at *reference* cannot raise a
        `ReferenceError`. Distinct from `binding_established_before`, which orders the singular value's
        establishing write: a dead zone ends at the DECLARATION, not at the first value assignment, so a
        `let` declared before *reference* but reassigned afterward is past its dead zone here while
        `binding_established_before` — reasoning about the value — answers `False`. `False` when the binding
        carries no declaration to order, so the dead zone's end cannot be proven.
        """
        return bool(binding.declarations) and all(
            self.runs_before(site, reference) for site in binding.declarations
        )

    def _runs_before_function(
        self,
        definition: Node,
        definition_owner: Node,
        function: Node,
        visiting: set[int],
        memo: dict[int, bool],
    ) -> bool:
        function_id = id(function)
        if function_id in visiting:
            return False
        cached = memo.get(function_id)
        if cached is not None:
            return cached
        points = self._reference_points(function)
        if points is None:
            memo[function_id] = False
            return False
        visiting = visiting | {function_id}
        result = all(
            self._runs_after(definition, definition_owner, point, visiting, memo)
            for point in points
        )
        memo[function_id] = result
        return result

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
        local object (`SemanticModel.object_property_reference_points`) is enumerated instead by the read
        sites of that property, the only way its callable can be obtained; this is consulted first, so a
        namespace method ordered by its call sites is not mistaken for an anonymous closure ordered by its
        creation. For a function bound to no name and matching neither pattern, the single point is the
        function expression itself: the closure cannot be invoked before it is created.

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
        member_points = self.model.object_property_reference_points(function)
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

    def _runs_after(
        self,
        definition: Node,
        definition_owner: Node,
        point: Node,
        visiting: set[int],
        memo: dict[int, bool],
    ) -> bool:
        owner = self._activation_of(point)
        if owner is definition_owner:
            return self.strictly_dominates(definition, point)
        if isinstance(owner, FUNCTION_NODES):
            return self._runs_before_function(definition, definition_owner, owner, visiting, memo)
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
    model: SemanticModel, control_flow: ControlFlowModel | None = None,
) -> DominanceModel:
    """
    Build the `DominanceModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`,
    reusing *control_flow* when the caller has one to share, or building a fresh one when it is `None`.
    """
    return DominanceModel(model, control_flow)
