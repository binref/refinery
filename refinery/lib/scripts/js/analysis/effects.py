"""
Per-function effect summaries for JavaScript, computed over the
`refinery.lib.scripts.js.analysis.model.SemanticModel`'s resolved bindings and call graph. A summary
records, conservatively, what observable effects *one call* of a function may have — writing a
global, mutating a binding captured from an enclosing scope, throwing, or invoking code the analysis
cannot account for — from which a single `is_pure` verdict follows.

This is the second layer of the analysis substrate. Like the model it sits on, it is *flow-insensitive*
and conservative by construction: every effect is an over-approximation (when in doubt, an effect is
reported), so a function judged pure is pure on every path, and callers may treat a pure call whose
result is unused as removable. The summary deliberately does not model termination; purity here means
freedom from observable effects, not a guarantee that the call returns.

Purity of a call to a built-in (for example `String.fromCharCode`) is asserted only under a verified
*pristine-intrinsics precondition*: the whole program must not reassign or monkeypatch any intrinsic the
registry trusts, nor contain a reflection surface through which one could be replaced at runtime. When
that precondition fails the registry is disregarded and such calls are treated as unknown. A read of a
trusted intrinsic-named property off the global object (for example `globalThis.Uint8Array`) is treated
likewise, under a parallel *pristine-global precondition*: no reflective surface and no accessor installed
on the global object, so the read cannot run a user getter.

Symmetrically, an assignment is not counted as a write when nothing can observe it: the assigned binding
is read nowhere, or every reference to it is confined to the assigning function so it never escapes. Both
rest on the same pristine-global precondition, since a reflective surface or an installed setter could
otherwise observe the assignment. This is what lets a function whose only effect is an obfuscator's
scratch temporary — a write-only global, or an accumulator local to one function — be judged pure.

The public surface — `EffectSummary`, `EffectModel.summary_of`, `EffectModel.is_pure_call`,
`build_effects` — is representation-agnostic and keyed to AST node identity, matching the model's
contract so a later control-flow layer can sharpen the same answers without changing callers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    ContainerRole,
    FUNCTION_NODES,
    GLOBAL_OBJECT_ALIASES,
    Role,
    Scope,
    SemanticModel,
    container_reference_role,
    enclosing_function,
    is_member_write_target,
    reference_role,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsConditionalExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsImportExpression,
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsThrowStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclarator,
    strip_parens,
)

_PURE_INTRINSIC_METHODS = frozenset({
    'String.fromCharCode',
    'Array.isArray',
    'Math.abs',
    'Math.ceil',
    'Math.floor',
    'Math.round',
    'Math.trunc',
    'Math.sign',
    'Math.max',
    'Math.min',
    'Math.pow',
    'Math.sqrt',
    'Math.cbrt',
    'Math.log',
    'Math.log2',
    'Math.log10',
    'Math.exp',
    'Number.isNaN',
    'Number.isFinite',
    'Number.isInteger',
    'Number.isSafeInteger',
})

_PURE_GLOBAL_FUNCTIONS = frozenset({
    'parseInt',
    'parseFloat',
    'isNaN',
    'isFinite',
})

_PURE_INTRINSIC_ROOTS = (
    frozenset(name.split('.', 1)[0] for name in _PURE_INTRINSIC_METHODS) | _PURE_GLOBAL_FUNCTIONS
)

_SPEC_GLOBAL_INTRINSICS = frozenset({
    'Object',
    'Boolean',
    'Symbol',
    'BigInt',
    'Number',
    'Math',
    'Date',
    'String',
    'RegExp',
    'Array',
    'JSON',
    'Promise',
    'Reflect',
    'Proxy',
    'Map',
    'Set',
    'WeakMap',
    'WeakSet',
    'ArrayBuffer',
    'SharedArrayBuffer',
    'DataView',
    'Int8Array',
    'Uint8Array',
    'Uint8ClampedArray',
    'Int16Array',
    'Uint16Array',
    'Int32Array',
    'Uint32Array',
    'Float32Array',
    'Float64Array',
    'BigInt64Array',
    'BigUint64Array',
    'Error',
    'EvalError',
    'RangeError',
    'ReferenceError',
    'SyntaxError',
    'TypeError',
    'URIError',
})
"""
Global properties the ECMAScript specification mandates as writable, configurable *data* properties of
the global object. A read of one runs no user getter and so carries no observable effect, soundly and
without any host assumption.
"""

_HOST_GLOBAL_INTRINSICS = frozenset({
    'TextDecoder',
    'TextEncoder',
    'Buffer',
})
"""
Global intrinsics a standard, non-adversarial host (Node, browsers) exposes as data properties. Trusted
like `_SPEC_GLOBAL_INTRINSICS`, but resting on that host assumption rather than the language standard.
"""

_GLOBAL_DATA_PROPERTIES = _SPEC_GLOBAL_INTRINSICS | _HOST_GLOBAL_INTRINSICS

_ACCESSOR_INSTALL_METHODS = frozenset({
    'defineProperty',
    'defineProperties',
    '__defineGetter__',
    '__defineSetter__',
})


class _PureCall:
    """
    Sentinel marking a callee resolved to a known-pure intrinsic, distinct from an unresolved callee.
    """


_PURE = _PureCall()


@dataclass
class EffectSummary:
    """
    The observable effects one call of a function may have, each field a conservative over-estimate.
    `writes_global` covers assignment to a global or to a property of an object reached through one;
    `writes_captured` covers assignment to a binding owned by an enclosing function (a closure mutation
    visible after the call returns); `throws` covers a `throw` or an operation that may throw on a
    value the analysis cannot prove safe; `calls_unknown` covers invoking a callee that cannot be
    resolved and summarized. A summary with none of these set is `is_pure`. `wraps_return` is separate:
    it does not bear on purity but records that a call to the function yields a wrapper (a promise from
    an `async` function, an iterator from a generator) rather than the value of its return expression,
    so the call cannot be replaced by that expression. `written_bindings` names, by identity, the outer
    bindings — captured locals and globals — a call may write where the write resolves to one, so a
    caller can ask which binding a call mutates rather than only whether it mutates some. It is decided
    independently of purity: a write the purity analysis deems unobservable because the binding never
    escapes the function is still recorded here, since a consumer reasoning about a read *inside* that
    function must still see the mutation. A binding written but never read anywhere adds nothing, as no
    read can observe the change; likewise a coarse write with no resolvable binding (a dynamic-scope or
    `globalThis.x =` member write) sets `writes_global` but adds nothing here.
    """
    writes_global: bool = False
    writes_captured: bool = False
    throws: bool = False
    calls_unknown: bool = False
    wraps_return: bool = False
    written_bindings: set[Binding] = field(default_factory=set)

    @property
    def is_pure(self) -> bool:
        """
        Whether a call to the summarized function produces no observable effect, so a call whose result
        is unused carries no consequence the program can detect (termination aside).
        """
        return not (self.writes_global or self.writes_captured or self.throws or self.calls_unknown)

    @property
    def is_value_replaceable(self) -> bool:
        """
        Whether replacing a call to the summarized function with its computed return value drops no
        observable effect. This holds when the call writes no state visible after it returns — neither a
        global nor a captured binding — and the call returns its value directly rather than wrapped: an
        `async` function's call is a promise and a generator's is an iterator, neither equal to the
        return expression, so `wraps_return` disqualifies it. Unlike `is_pure`, a call that may throw or
        read unknown state still qualifies: an evaluator that actually executes the call to a value
        reproduces those, and only a *write* would be silently lost. `is_pure`, which additionally
        forbids throwing and unknown reads, is the right test for removing a call outright rather than
        replacing it.
        """
        return not (self.writes_global or self.writes_captured or self.wraps_return)

    def absorb(self, other: EffectSummary):
        """
        Union *other*'s effects into this summary, used to fold a callee's effects into its caller.
        """
        self.writes_global = self.writes_global or other.writes_global
        self.writes_captured = self.writes_captured or other.writes_captured
        self.throws = self.throws or other.throws
        self.calls_unknown = self.calls_unknown or other.calls_unknown
        self.written_bindings |= other.written_bindings


def _is_safe_property_base(node: Node, defunct: set[str] | None = None) -> bool:
    """
    Whether a property access on *node* cannot run a custom getter, so the read carries no hidden
    effect: the object is a value with no own accessors — a literal, a fresh object/array/function
    expression, or an identifier in *defunct* (being removed, so its getters are irrelevant to live
    code). A member chain is safe when its root base is safe.
    """
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, (JsObjectExpression, JsArrayExpression, JsFunctionExpression)):
        return True
    if isinstance(node, JsIdentifier):
        return bool(defunct) and node.name in defunct
    if isinstance(node, JsMemberExpression) and node.object is not None:
        return _is_safe_property_base(node.object, defunct)
    return False


def side_effect_free(
    node: Node,
    defunct: set[str] | None = None,
    call_pure: Callable[[JsCallExpression | JsNewExpression], bool] | None = None,
    read_effect: Callable[[Node], bool] | None = None,
) -> bool:
    """
    Conservative check for whether evaluating an expression can be dropped or reordered with no
    observable side effect. Compositional: an expression is free when every sub-expression is. Two leaves
    can bear an effect. The call — free only when its callee is a *defunct* identifier or an inline
    function expression, or, when *call_pure* is supplied, when *call_pure* certifies the call (or
    `new`) pure and its arguments are free. The identifier read — free unless *read_effect* rejects it,
    which `EffectModel.is_side_effect_free` supplies as `SemanticModel.read_has_dynamic_effect` to reject
    a bare name that resolves through a `with` body's dynamic scope (reading it may fire the `with`
    object's getter or throw). A function expression is free without descending into its body — defining
    it runs nothing — so a dynamic-scope read inside an un-called function does not make the value
    effectful. A parenthesized expression is transparent, bearing exactly the effects of the expression
    it groups. `EffectModel.is_side_effect_free` passes `EffectModel.is_pure_call` and
    `read_has_dynamic_effect`; a caller without a model gets the conservative behaviour. When *defunct*
    is given its identifiers name bindings being removed, so calls to them and property reads through
    them are treated as free.
    """
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, JsIdentifier):
        return read_effect is None or not read_effect(node)
    if isinstance(node, (JsFunctionExpression, JsArrowFunctionExpression)):
        return True
    if isinstance(node, JsParenthesizedExpression):
        return node.expression is not None and side_effect_free(
            node.expression, defunct, call_pure, read_effect)
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'delete':
            return False
        return node.operand is not None and side_effect_free(node.operand, defunct, call_pure, read_effect)
    if isinstance(node, JsMemberExpression):
        if node.object is None:
            return False
        if not side_effect_free(node.object, defunct, call_pure, read_effect):
            return False
        if node.property is not None and not side_effect_free(node.property, defunct, call_pure, read_effect):
            return False
        return _is_safe_property_base(node.object, defunct)
    if isinstance(node, (JsBinaryExpression, JsLogicalExpression)):
        return (
            node.left is not None
            and side_effect_free(node.left, defunct, call_pure, read_effect)
            and node.right is not None
            and side_effect_free(node.right, defunct, call_pure, read_effect)
        )
    if isinstance(node, JsConditionalExpression):
        return (
            node.test is not None
            and side_effect_free(node.test, defunct, call_pure, read_effect)
            and node.consequent is not None
            and side_effect_free(node.consequent, defunct, call_pure, read_effect)
            and node.alternate is not None
            and side_effect_free(node.alternate, defunct, call_pure, read_effect)
        )
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                return False
            if prop.computed and (
                prop.key is None or not side_effect_free(prop.key, defunct, call_pure, read_effect)
            ):
                return False
            if prop.value is not None and not side_effect_free(prop.value, defunct, call_pure, read_effect):
                return False
        return True
    if isinstance(node, JsArrayExpression):
        return all(
            elem is None or side_effect_free(elem, defunct, call_pure, read_effect)
            for elem in node.elements
        )
    if isinstance(node, JsSequenceExpression):
        return all(side_effect_free(e, defunct, call_pure, read_effect) for e in node.expressions)
    if isinstance(node, JsCallExpression):
        if defunct and isinstance(node.callee, JsIdentifier) and node.callee.name in defunct:
            return all(side_effect_free(arg, defunct, call_pure, read_effect) for arg in node.arguments)
        if isinstance(node.callee, JsFunctionExpression):
            return all(side_effect_free(arg, defunct, call_pure, read_effect) for arg in node.arguments)
    if call_pure is not None and isinstance(node, (JsCallExpression, JsNewExpression)) and call_pure(node):
        return all(side_effect_free(arg, defunct, call_pure, read_effect) for arg in node.arguments)
    return False


class EffectModel:
    """
    Per-function effect summaries for one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Query a function's summary with
    `summary_of` and a call expression's purity with `is_pure_call`. Build through `build_effects`.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self.intrinsics_pristine = _intrinsics_pristine(model)
        self.global_pristine = _global_pristine(model)
        self._summaries: dict[int, EffectSummary] = {}
        self._confine_cache: dict[int, Node | None] = {}
        self._immutable_cache: dict[tuple[int, bool], bool] = {}
        self._member_write_cache: dict[int, bool] = {}
        self._uses_arguments_cache: dict[int, bool] = {}
        self._mutators_escape_cache: dict[int, bool] = {}
        self._functions: list[Node] = self._collect_functions()
        self._compute()

    def summary_of(self, func: Node) -> EffectSummary:
        """
        The effect summary of a function node (or the script). An unknown node is reported as impure.
        """
        return self._summaries.get(id(func), EffectSummary(calls_unknown=True))

    def mutated_bindings(self, func: Node) -> frozenset[Binding]:
        """
        The outer bindings (captured locals and globals) a call to *func* may write, directly or through
        any function it transitively calls, each identified by its `Binding` rather than its name so a
        caller can ask whether one specific binding is mutated. Empty for a function with no such writes
        and for an unknown node alike — use `summary_of(func).calls_unknown` to tell those apart.
        """
        return frozenset(self.summary_of(func).written_bindings)

    def function_can_mutate(self, func: Node, binding: Binding) -> bool:
        """
        Whether a call to *func* may write *binding*, itself or through a transitive callee.
        """
        return binding in self.summary_of(func).written_bindings

    def function_escapes(self, func: Node) -> bool:
        """
        Whether *func* may be invoked at a point the surrounding scope cannot enumerate as a resolvable
        `name(...)` call site: an anonymous function (an IIFE, a callback, stored and called later), or a
        named function whose binding is reassigned, redeclared, or referenced anywhere other than as the
        callee of a direct call (aliased, passed as an argument, `f.call(...)`). A reference inside a
        dynamic scope — a name a `with` body resolves at runtime — counts too: the model cannot order or
        resolve it, so the function may be invoked or aliased there with no static call site. A call to
        such a function can land at a point no call site pins down; a function only ever called directly
        by name has all its invocations enumerated by those call sites.
        """
        binding = self.model.naming_binding(func)
        if binding is None:
            return True
        if binding.writes or binding.dynamic_refs or len(binding.declarations) != 1:
            return True
        for ref in self.model.references(binding):
            parent = ref.parent
            if isinstance(parent, JsCallExpression) and parent.callee is ref:
                continue
            return True
        return False

    def mutators_escape(self, binding: Binding) -> bool:
        """
        Whether some function that may write *binding* — itself or through a transitive callee — escapes
        (`function_escapes`), so a write to *binding* may occur at a point no call site enumerates. When
        true, the places *binding* changes cannot be pinned down, and a caller reasoning about where its
        value survives must treat it as volatile everywhere. Memoized per binding.
        """
        cached = self._mutators_escape_cache.get(id(binding))
        if cached is None:
            cached = any(
                func is not self.model.root
                and binding in self.summary_of(func).written_bindings
                and self.function_escapes(func)
                for func in self._functions
            )
            self._mutators_escape_cache[id(binding)] = cached
        return cached

    def is_pure_call(self, call: JsCallExpression | JsNewExpression) -> bool:
        """
        Whether evaluating *call* has no observable effect: it invokes a trusted pure intrinsic (under
        the pristine-intrinsics precondition) or a local function whose summary is pure.
        """
        callee = self._resolve_callee(call)
        if callee is _PURE:
            return True
        if isinstance(callee, Node):
            return self.summary_of(callee).is_pure
        return False

    def is_side_effect_free(self, node: Node, defunct: set[str] | None = None) -> bool:
        """
        Whether evaluating *node* can be dropped or reordered without an observable side effect, with
        the call leaf resolved through this model's `is_pure_call`: a call to a proven-pure function or
        trusted intrinsic is free, recursing into its arguments. *defunct* names bindings being removed,
        whose calls and property reads are treated as free. This is the model-aware form of the
        model-free `side_effect_free` in this module, which clears only calls to a defunct name or an
        inline function; unlike it, an identifier read that resolves through a `with` body's dynamic
        scope is rejected here — reading the bare name may fire the `with` object's getter or throw (see
        `refinery.lib.scripts.js.analysis.model.SemanticModel.read_has_dynamic_effect`) — while a
        function value whose body performs such a read stays free, since defining it runs nothing.
        """
        return side_effect_free(node, defunct, self.is_pure_call, self.model.read_has_dynamic_effect)

    def binding_is_immutable_container(
        self, binding: Binding, *, member_calls_mutate: bool = True, exclude: Node | None = None,
    ) -> bool:
        """
        Whether *binding* holds a container — an object or array — whose element and property values are
        stable after construction, so that an access into it may be soundly inlined at its read sites.
        Every reference must read through the container (`obj.k`, `obj[i]`) or plainly rebind the name
        (`obj = ...`, whose value the caller resolves by domination); a write through the container
        (`obj.k = v`, `obj[i]++`, `delete obj[i]`, a `for-of` or destructuring target) makes it mutable.
        A method invoked on the container (`obj.m(...)`) may mutate it — an array's `sort`/`push`/`splice`
        and so on — so by default it too counts as mutable; a caller that knows the container's methods
        cannot mutate it (an object literal with no `this`-bound property) may pass *member_calls_mutate*
        false to permit such calls. A reference that escapes is safe in two cases: it aliases another
        binding that is itself an immutable container (alias-following the textual predicates this
        replaces could not do, and the reason a reassigned-and-aliased lookup array stays inlinable), or
        it is passed to a statically known function as an argument whose parameter is itself an immutable
        container (so the callee neither mutates nor further-escapes it). Any other escape — returned,
        stored as a property, passed to a call that cannot be resolved — is treated conservatively as
        mutable. A mutation through a dynamic scope is modelled: a `with` body that names the container —
        a member write, method call, reassignment, or escape — is attributed to it as a dynamic reference
        and judged by the same role logic, so a `with` that never names it keeps it foldable, and a direct
        `eval` in a local container's own function makes it mutable. The one residual is a script-scope
        container reached by an opaque global surface — a direct `eval`, `Function`, timer, or dynamic
        global write whose code cannot be read — which cannot be frozen without also freezing the lookup
        arrays real samples fold, so it is left to the caller's reflection reasoning, the trust an
        unresolved external call already receives.

        The query is over a *resolved binding*, so it is shadowing-correct, and it descends through
        alias chains, callee parameters, and nested functions, so a capturing closure that mutates the
        container is caught. The answer is fixed for the model's lifetime — a binding's reference set does
        not change — so it is memoized per `(binding, member_calls_mutate)`. A caller may pass *exclude*
        to disregard references within that subtree — asking whether the container is stable across the
        rest of the program, ignoring a read site about to be relocated into it; such a query is not
        memoized, since the answer depends on the excluded region.
        """
        if exclude is not None:
            return self._immutable_container(binding, set(), member_calls_mutate, exclude)
        key = (id(binding), member_calls_mutate)
        cached = self._immutable_cache.get(key)
        if cached is None:
            cached = self._immutable_container(binding, set(), member_calls_mutate)
            self._immutable_cache[key] = cached
        return cached

    def _immutable_container(
        self, binding: Binding, visiting: set[int], member_calls_mutate: bool, exclude: Node | None = None,
    ) -> bool:
        key = id(binding)
        if key in visiting:
            return True
        visiting = visiting | {key}
        if self._dynamic_scope_mutates(binding, member_calls_mutate, exclude):
            return False
        for ref in self.model.references(binding, exclude=exclude):
            role = container_reference_role(ref)
            if role is ContainerRole.MEMBER_WRITE:
                return False
            if role is ContainerRole.MEMBER_CALL and member_calls_mutate:
                return False
            if role is ContainerRole.ESCAPE:
                if not isinstance(ref, JsIdentifier) or not self._escape_keeps_container(
                    ref, visiting, member_calls_mutate,
                ):
                    return False
        return True

    def _dynamic_scope_mutates(
        self, binding: Binding, member_calls_mutate: bool, exclude: Node | None,
    ) -> bool:
        """
        Whether a dynamic scope may change the container *binding* holds. A direct `eval` in a local
        container's own function can rewrite it opaquely — a global is left to the caller's reflection
        reasoning, since freezing every global on any surface over-blocks. A `with` body's accesses are
        attributed by name: a member write, a reassignment, or an escape mutates it or may alias it out,
        and a method call may mutate it unless the caller vouches that its methods cannot; only a plain
        member read leaves it intact, so a `with` that never names the container is no threat. A dynamic
        escape or reassignment cannot be alias-followed or ordered the way a resolved one can, so either
        is treated as mutating.
        """
        if self.model.local_reachable_by_direct_eval(binding):
            return True
        for ref in self.model.dynamic_references(binding, exclude=exclude):
            role = container_reference_role(ref)
            if role is ContainerRole.MEMBER_READ:
                continue
            if role is ContainerRole.MEMBER_CALL and not member_calls_mutate:
                continue
            return True
        return False

    def _escape_keeps_container(self, ref: JsIdentifier, visiting: set[int], member_calls_mutate: bool) -> bool:
        """
        Whether an escaping reference leaves the container unmutated. Two escapes are precise: an alias
        (`var x = ref` or `x = ref`) keeps it when the aliased binding is itself an immutable container,
        and an argument passed to a statically known function (`f(ref)`) keeps it when the parameter it
        binds is itself an immutable container — interprocedural Case B, the parameter's own references
        decide whether the callee mutates or further-escapes it. Every other escape is conservatively
        unsafe.
        """
        alias = self._alias_target(ref)
        if alias is not None:
            return self._immutable_container(alias, visiting, member_calls_mutate)
        return self._argument_keeps_container(ref, visiting)

    def _argument_keeps_container(self, ref: JsIdentifier, visiting: set[int]) -> bool:
        """
        Case B: whether an argument *ref* passed to a statically known function leaves the container it
        holds unmutated — true when the parameter it binds is itself an immutable container, judged
        recursively from that parameter's own references, so the callee neither member-writes the
        argument nor lets it escape mutably. The parameter is judged under the conservative
        `member_calls_mutate=True`: a relaxed `member_calls_mutate=False` is the *caller*'s promise that
        the container's own methods cannot mutate it at the original site, and does not carry to a method
        the callee invokes on the argument or on one of its nested containers (`x.a.push(...)`), which
        may mutate it. False, conservatively, when the call cannot be analysed: the callee is not a
        single known function, it can reach the argument through its own `arguments` object, the argument
        is spread, a spread precedes it (so its runtime position shifts past the textual index and the
        parameter it binds cannot be pinned down), the slot it lands in is a rest or destructuring
        parameter, or the parameter is reachable through a `with` or direct `eval` in the callee that
        resolves a name at runtime (an unrecorded write the parameter's reference set cannot rule out).
        An argument with no parameter to bind — passed beyond the declared parameters of a function with
        no rest collector and no `arguments` reach, textual or reflective — is safe, since the callee
        cannot name it.
        """
        parent = ref.parent
        if not isinstance(parent, JsCallExpression) or ref not in parent.arguments:
            return False
        func = self.static_callee(parent)
        if func is None:
            return False
        if self._callee_uses_arguments(func):
            return False
        params = func.params
        if any(isinstance(param, JsRestElement) for param in params):
            return False
        index = parent.arguments.index(ref)
        if any(isinstance(arg, JsSpreadElement) for arg in parent.arguments[:index]):
            return False
        if index >= len(params):
            return True
        param = params[index]
        if not isinstance(param, JsIdentifier):
            return False
        binding = self.model.binding_of(param)
        if binding is None:
            return False
        if self.model.reflection_can_reach(binding):
            return False
        return self._immutable_container(binding, visiting, True)

    def _callee_uses_arguments(self, func: Node) -> bool:
        """
        Whether a non-arrow callee can reach its call's arguments through its own `arguments` object,
        which aliases the positional arguments — including any passed beyond the declared parameters — so
        that `arguments[i][...] = v` mutates a container the by-position parameter reasoning in
        `_argument_keeps_container` would otherwise miss. It is reached either by naming `arguments`
        directly, or reflectively: a `with` or a direct `eval` in the callee — or in a closure nested
        inside it, which inherits the callee's `arguments` — can read that object with no textual
        reference, so a reflectively reachable `arguments` counts too. An arrow has no `arguments` of its
        own (a reference inside it binds the enclosing function's, unrelated to the arrow's parameters),
        so it is exempt. When the callee can reach `arguments`, the escape is treated as mutable. The
        answer is a structural property of the callee, so it is memoized per function.
        """
        cached = self._uses_arguments_cache.get(id(func))
        if cached is None:
            cached = self._compute_callee_uses_arguments(func)
            self._uses_arguments_cache[id(func)] = cached
        return cached

    def _compute_callee_uses_arguments(self, func: Node) -> bool:
        if isinstance(func, JsArrowFunctionExpression):
            return False
        func_scope = self.model.function_scope(func)
        if func_scope is None:
            return False
        binding = func_scope.bindings.get('arguments')
        if binding is None:
            return False
        if self.model.references(binding):
            return True
        return self.model.reflection_can_reach(binding)

    def static_callee(
        self, call: JsCallExpression
    ) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
        """
        The function a call invokes when it is statically a single, never-reassigned function: a direct
        function or arrow expression callee, or an identifier bound once to a function declaration or a
        function/arrow initializer. `None` for anything else — a method call, a parameter, a reassigned
        binding (including one a dynamic scope could rebind through a `with` body or direct `eval`), or an
        unresolved name — whose target cannot be pinned down.
        """
        callee = call.callee
        if isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
            return callee
        if not isinstance(callee, JsIdentifier):
            return None
        return self.function_of(self.model.resolve(callee))

    def _alias_target(self, ref: JsIdentifier) -> Binding | None:
        parent = ref.parent
        if isinstance(parent, JsVariableDeclarator) and parent.init is ref:
            if isinstance(parent.id, JsIdentifier):
                return self.model.binding_of(parent.id)
            return None
        if (
            isinstance(parent, JsAssignmentExpression)
            and parent.right is ref
            and parent.operator == '='
            and isinstance(parent.left, JsIdentifier)
        ):
            return self.model.resolve(parent.left)
        return None

    def _collect_functions(self) -> list[Node]:
        functions: list[Node] = [self.model.root]
        for node in self.model.root.walk():
            if isinstance(node, FUNCTION_NODES):
                functions.append(node)
        return functions

    def _compute(self):
        for func in self._functions:
            self._summaries[id(func)] = EffectSummary()
        changed = True
        while changed:
            changed = False
            for func in self._functions:
                summary = self._scan(func)
                if summary != self._summaries[id(func)]:
                    self._summaries[id(func)] = summary
                    changed = True

    def _scan(self, func: Node) -> EffectSummary:
        summary = EffectSummary()
        if getattr(func, 'is_async', False) or getattr(func, 'generator', False):
            summary.wraps_return = True
        func_scope = self.model.function_scope(func)
        for node in _body_nodes(func):
            if isinstance(node, JsThrowStatement):
                summary.throws = True
            elif isinstance(node, JsIdentifier):
                if reference_role(node) is not Role.READ:
                    self._account_write(summary, node, func_scope, func)
            elif isinstance(node, JsMemberExpression):
                base = node.object
                if base is not None and not self._base_is_safe(base):
                    summary.throws = True
                if is_member_write_target(node):
                    if not self._member_write_unobservable(node, func):
                        summary.writes_global = True
                elif (
                    base is not None
                    and not self._base_getter_safe(base)
                    and not self._is_trusted_global_read(node)
                ):
                    summary.calls_unknown = True
            elif isinstance(node, (JsCallExpression, JsNewExpression)):
                self._account_call(summary, node)
            elif isinstance(node, JsImportExpression):
                summary.calls_unknown = True
        return summary

    def _account_write(
        self, summary: EffectSummary, target: JsIdentifier, func_scope: Scope | None, func: Node
    ):
        binding = self.model.resolve(target)
        if binding is None:
            summary.writes_global = True
            return
        is_global = binding.kind is BindingKind.IMPLICIT_GLOBAL or binding.scope is self.model.root_scope
        if not is_global and func_scope is not None and func_scope.contains(binding.scope):
            return
        if binding.is_read:
            summary.written_bindings.add(binding)
        if self._write_unobservable(binding, func):
            return
        if is_global:
            summary.writes_global = True
        else:
            summary.writes_captured = True

    def _write_unobservable(self, binding: Binding, func: Node) -> bool:
        """
        Whether assigning *binding* within *func* has no observable consumer, so a function whose only
        effect is the assignment is pure. The program must be `global_pristine`: it exposes no reflection
        surface through which the name could be read and installs no accessor that an assignment to a
        global property could trigger as a setter. Then the write is unobservable when either the value
        is read nowhere (`Binding.is_read` is false), or every reference to it is `_confined_to` *func* so
        no outside code can see it. This ports the evaluator's sound permissiveness for an obfuscator's
        scratch binding — whether a write-only global or an accumulator local to a single function.
        """
        if not self.global_pristine:
            return False
        return not binding.is_read or self._confined_to(binding, func)

    def _confined_to(self, binding: Binding, func: Node) -> bool:
        """
        Whether every reference to *binding* lies within *func*, which must be a function rather than the
        script, so the binding does not escape: no code outside *func* can read it, and a write to it is
        unobservable past the single call.
        """
        if not isinstance(func, FUNCTION_NODES):
            return False
        return self._confining_function(binding) is func

    def _member_write_unobservable(self, member: JsMemberExpression, func: Node) -> bool:
        """
        Whether the container written by *member* (`base.k = v`, `base[i]++`, `delete base[i]`) is a
        value built inside *func* that never escapes it, so no caller can observe the write and a
        function whose only effect is the mutation is pure. The base must be a fresh value — written
        directly on an object/array/function literal, or resolving to a binding local to *func* whose
        value is always freshly built: a rest parameter, which the language guarantees is a new array,
        or a local initialized only to an object/array/function literal. An object literal with an own
        setter — or one that installs a custom prototype through `__proto__:`, which may carry an
        inherited setter — does NOT qualify, since the write then runs an accessor, an effect a caller
        can observe. A plain parameter does NOT qualify either — it aliases the caller's object, so
        `function modify(a){ a[0] = 9; }` mutates the argument observably — which is the soundness
        boundary this rests on. Every reference to the binding must keep the container contained: only
        member reads and writes, never an escape that could alias it out (returned, passed to a call,
        stored as a property, aliased to another name) or a method call that might leak or
        mutate-and-return it, and never a capture by a nested function that could outlive the call.

        A write hidden behind a dynamic scope — through a name a `with` body or direct `eval` resolves
        at runtime — is not modelled here: the base resolves to no binding, so the write is
        conservatively kept, which is sound. The residual is the opaque-surface one
        `binding_is_immutable_container` documents: a reflective surface whose code cannot be read could
        install a prototype accessor that observes a write this deems unobservable, and freezing on it
        would refuse the obfuscator idioms this is meant to see through, so it is left to that boundary.

        The judgment is structural — fixed by the binding's declarations and reference set — so it is
        invariant across the fixpoint passes that recompute the summaries, and is memoized per member.
        """
        cached = self._member_write_cache.get(id(member))
        if cached is None:
            cached = self._fresh_local_member_write(member, func)
            self._member_write_cache[id(member)] = cached
        return cached

    def _fresh_local_member_write(self, member: JsMemberExpression, func: Node) -> bool:
        base = member.object
        if isinstance(base, (JsArrayExpression, JsFunctionExpression)):
            return True
        if isinstance(base, JsObjectExpression):
            return not object_member_access_runs_accessor(base)
        if not isinstance(base, JsIdentifier):
            return False
        binding = self.model.resolve(base)
        if binding is None or binding.captured:
            return False
        if not self._confined_to(binding, func):
            return False
        if not self._fresh_container_origin(binding):
            return False
        return self._container_non_escaping(binding)

    def _fresh_container_origin(self, binding: Binding) -> bool:
        """
        Whether *binding* only ever holds a freshly built container: a rest parameter (always a new
        array) or a `var`/`let`/`const` whose every declaration initializes it to an object, array, or
        function literal. A plain parameter, a catch binding, or a local initialized from anything that
        could alias an external object fails, since a write through it could then be observed elsewhere.
        An object literal that declares its own getter or setter — or installs a custom prototype
        through `__proto__:`, which may carry an inherited one — also fails: a member write to such a
        container can run an accessor, an effect a caller can observe, so the write is not unobservable.
        """
        if self._is_rest_param(binding):
            return True
        if binding.kind not in (BindingKind.VAR, BindingKind.LET, BindingKind.CONST):
            return False
        if not binding.declarations:
            return False
        for decl in binding.declarations:
            declarator = decl.parent
            if not isinstance(declarator, JsVariableDeclarator):
                return False
            init = declarator.init
            if not isinstance(init, (
                JsArrayExpression, JsObjectExpression, JsFunctionExpression, JsArrowFunctionExpression,
            )):
                return False
            if isinstance(init, JsObjectExpression) and object_member_access_runs_accessor(init):
                return False
        return True

    @staticmethod
    def _is_rest_param(binding: Binding) -> bool:
        """
        Whether *binding* is a function's rest parameter (`function f(...xs)`), whose value the language
        guarantees is a fresh array on every call.
        """
        return binding.kind is BindingKind.PARAM and any(
            isinstance(decl.parent, JsRestElement) for decl in binding.declarations
        )

    def _container_non_escaping(self, binding: Binding) -> bool:
        """
        Whether every reference to *binding* keeps its container contained: each is a member read or
        write (`obj.k`, `obj[i] = v`), never an escape, rebinding, or method call through which the
        container could be aliased out, mutated by other code, or replaced. The tightest form of the
        escape check, since a mutation only stays unobservable while no other code can reach the object.
        """
        for ref in self.model.references(binding):
            if container_reference_role(ref) not in (
                ContainerRole.MEMBER_READ, ContainerRole.MEMBER_WRITE,
            ):
                return False
        return True

    def _confining_function(self, binding: Binding) -> Node | None:
        """
        The single function that lexically encloses every reference to *binding*, or `None` when the
        references do not share one — they span sibling functions or reach the top level. Cached per
        binding, since the binding's reference set is fixed for the lifetime of the model.
        """
        key = id(binding)
        if key not in self._confine_cache:
            self._confine_cache[key] = self._scan_confining_function(binding)
        return self._confine_cache[key]

    def _scan_confining_function(self, binding: Binding) -> Node | None:
        refs = self.model.references(binding)
        if not refs:
            return None
        enclosing = enclosing_function(refs[0])
        if enclosing is None:
            return None
        for ref in refs[1:]:
            if enclosing_function(ref) is not enclosing:
                return None
        return enclosing

    def _account_call(self, summary: EffectSummary, call: JsCallExpression | JsNewExpression):
        callee = self._resolve_callee(call)
        if callee is _PURE:
            return
        if isinstance(callee, Node):
            summary.absorb(self.summary_of(callee))
        else:
            summary.calls_unknown = True

    def _resolve_callee(self, call: JsCallExpression | JsNewExpression) -> Node | _PureCall | None:
        callee = call.callee
        if isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
            return callee
        if isinstance(callee, JsMemberExpression) and not callee.computed:
            base, prop = callee.object, callee.property
            if isinstance(base, JsIdentifier) and isinstance(prop, JsIdentifier):
                if F'{base.name}.{prop.name}' in _PURE_INTRINSIC_METHODS and self._is_global_intrinsic(base):
                    return _PURE
            return None
        if isinstance(callee, JsIdentifier):
            if callee.name in _PURE_GLOBAL_FUNCTIONS and self._is_global_intrinsic(callee):
                return _PURE
            return self.function_of(self.model.resolve(callee))
        return None

    def function_of(
        self, binding: Binding | None
    ) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None:
        """
        The single function a *binding* stably resolves to — a sole declaration's function declaration or
        function/arrow initializer, or a name assigned a function exactly once (`f = function(){}`, the
        form namespace flattening leaves) — or `None` when the binding is absent, redeclared, reassigned
        to more than one value, dynamically rebindable, or not bound to a function. A lone assignment
        counts because the name denotes that one function wherever it is not in the value's temporal dead
        zone; a caller that also needs the value established before a use orders it separately. The
        binding-level twin of `static_callee`.
        """
        if binding is None or len(binding.declarations) != 1:
            return None
        if self.model.binding_maybe_reassigned_dynamically(binding):
            return None
        decl = binding.declarations[0]
        parent = decl.parent
        if not binding.writes:
            if isinstance(parent, JsFunctionDeclaration) and parent.id is decl:
                return parent
            if (
                isinstance(parent, JsVariableDeclarator)
                and parent.id is decl
                and isinstance(parent.init, FUNCTION_NODES)
            ):
                return parent.init
            return None
        if len(binding.writes) == 1:
            assignment = binding.writes[0].parent
            if (
                isinstance(assignment, JsAssignmentExpression)
                and assignment.operator == '='
                and strip_parens(assignment.left) is binding.writes[0]
            ):
                value = strip_parens(assignment.right)
                if isinstance(value, FUNCTION_NODES):
                    return value
        return None

    def _is_global_intrinsic(self, name: JsIdentifier) -> bool:
        """
        Whether *name* denotes a trusted intrinsic root that the program leaves pristine and does not
        shadow with a local binding at this use site.
        """
        if not self.intrinsics_pristine:
            return False
        return self.model.lookup(name.name, self.model.scope_of(name)) is None

    def _is_trusted_global_read(self, member: JsMemberExpression) -> bool:
        """
        Whether reading *member* off the global object runs no user getter, so the read carries no
        observable effect: a non-computed access of a trusted intrinsic-named data property on the global
        object, sound only under the `global_pristine` precondition. This mirrors the intrinsic-call trust
        of `_resolve_callee`, lifted from methods to global data-property reads.
        """
        if not self.global_pristine or member.computed:
            return False
        prop = member.property
        if not isinstance(prop, JsIdentifier) or prop.name not in _GLOBAL_DATA_PROPERTIES:
            return False
        return member.object is not None and self._base_is_global_object(member.object)

    def _base_is_global_object(self, node: Node) -> bool:
        """
        Whether *node* denotes the global object itself. The syntactic base case is an unshadowed
        global-object alias identifier; a later value-provenance layer may prove more expressions global.
        """
        if isinstance(node, JsIdentifier) and node.name in GLOBAL_OBJECT_ALIASES:
            return self.model.lookup(node.name, self.model.scope_of(node)) is None
        return False

    def _base_is_safe(self, node: Node) -> bool:
        """
        Whether a property access on *node* cannot throw because *node* is known not to be nullish: a
        freshly built value, the global object, a pristine intrinsic root, or a member chain on one.
        """
        if isinstance(node, (
            JsArrayExpression,
            JsObjectExpression,
            JsFunctionExpression,
            JsStringLiteral,
            JsNumericLiteral,
            JsBooleanLiteral,
        )):
            return True
        if isinstance(node, JsIdentifier):
            if node.name in GLOBAL_OBJECT_ALIASES:
                return True
            return node.name in _PURE_INTRINSIC_ROOTS and self._is_global_intrinsic(node)
        if isinstance(node, JsMemberExpression):
            return node.object is not None and self._base_is_safe(node.object)
        return False

    def _base_getter_safe(self, node: Node) -> bool:
        """
        Whether reading a property of *node* cannot run a user-defined getter, so the read carries no
        hidden effect: a freshly built value with no accessor of its own and no installed prototype, a
        primitive, or a pristine intrinsic root. Unlike `_base_is_safe`, the global object does not
        qualify — a global property such as `location` may be an accessor — so a read through it is
        treated as an unknown call.
        """
        if isinstance(node, (
            JsArrayExpression,
            JsFunctionExpression,
            JsStringLiteral,
            JsNumericLiteral,
            JsBooleanLiteral,
        )):
            return True
        if isinstance(node, JsObjectExpression):
            return not object_member_access_runs_accessor(node)
        if isinstance(node, JsIdentifier):
            return node.name in _PURE_INTRINSIC_ROOTS and self._is_global_intrinsic(node)
        if isinstance(node, JsMemberExpression):
            return node.object is not None and self._base_getter_safe(node.object)
        return False


def _object_has_own_accessor(obj: JsObjectExpression) -> bool:
    """
    Whether the object literal *obj* declares an own getter or setter (`{ get k(){...} }`,
    `{ set k(v){...} }`). A read of such a property runs the getter and a write to it runs the setter,
    so a member access on an otherwise fresh literal that has one carries a hidden effect rather than a
    plain field read or store.
    """
    return any(
        isinstance(prop, JsProperty) and prop.kind in (JsPropertyKind.GET, JsPropertyKind.SET)
        for prop in obj.properties
    )


def object_sets_prototype(obj: JsObjectExpression) -> bool:
    """
    Whether the object literal *obj* installs a custom prototype through the special `__proto__:`
    property form (`{ __proto__: p }`, `{ '__proto__': p }`) — a plain, non-computed data property
    whose key is `__proto__`. Such an object no longer inherits from `Object.prototype` alone, so a
    plain-looking member read or write on it may run a getter or setter the installed prototype
    carries rather than touch a data slot. A computed key (`{ ['__proto__']: p }`), a shorthand
    (`{ __proto__ }`), a method, or an own `__proto__` accessor define an ordinary own property and do
    not set the prototype.
    """
    for prop in obj.properties:
        if not isinstance(prop, JsProperty):
            continue
        if prop.kind is not JsPropertyKind.INIT or prop.computed or prop.shorthand or prop.method:
            continue
        key = prop.key
        if isinstance(key, JsIdentifier) and key.name == '__proto__':
            return True
        if isinstance(key, JsStringLiteral) and key.value == '__proto__':
            return True
    return False


def object_member_access_runs_accessor(obj: JsObjectExpression) -> bool:
    """
    Whether a plain member read or write on the object literal *obj* may run a user-defined accessor
    instead of touching a data slot: it declares its own getter or setter, or it installs a custom
    prototype through the `__proto__:` literal form that may carry an inherited one. A fresh literal
    with neither behaves as a plain field container, so an access on it is observable only as the field
    it names.
    """
    return _object_has_own_accessor(obj) or object_sets_prototype(obj)


def _body_nodes(func: Node) -> Iterator[Node]:
    """
    Yield the nodes a single execution of *func* evaluates — the statements of its body and their
    descendants — without descending into nested function bodies, whose effects belong to *their* calls.
    Nested function nodes are still yielded so a call to one can be recognized.
    """
    if isinstance(func, JsScript):
        roots: list[Node] = list(func.body)
    else:
        body = getattr(func, 'body', None)
        roots = [body] if body is not None else []
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FUNCTION_NODES):
            continue
        stack.extend(reversed(node.children()))


def _intrinsics_pristine(model: SemanticModel) -> bool:
    """
    Whether the program leaves every trusted intrinsic untouched: it neither reassigns an intrinsic
    root nor writes a property on one, nor shadows one with a binding of its own, nor contains a
    reflection surface through which an intrinsic could be replaced at runtime. Only then may a call to
    a registry intrinsic be trusted to behave as specified.
    """
    if model.has_reflection_surface():
        return False
    if any(name in model.root_scope.bindings for name in _PURE_INTRINSIC_ROOTS):
        return False
    for node in model.root.walk():
        if isinstance(node, JsIdentifier) and node.name in _PURE_INTRINSIC_ROOTS:
            if reference_role(node) is not Role.READ:
                return False
        elif isinstance(node, JsAssignmentExpression):
            left = node.left
            if (
                isinstance(left, JsMemberExpression)
                and isinstance(left.object, JsIdentifier)
                and left.object.name in _PURE_INTRINSIC_ROOTS
            ):
                return False
        elif isinstance(node, JsUpdateExpression):
            target = node.argument
            if (
                isinstance(target, JsMemberExpression)
                and isinstance(target.object, JsIdentifier)
                and target.object.name in _PURE_INTRINSIC_ROOTS
            ):
                return False
    return True


def _global_pristine(model: SemanticModel) -> bool:
    """
    Whether a property read on the global object is free of user getters: the program exposes no
    reflective surface through which an accessor could be installed at runtime, and installs none
    statically through `Object.defineProperty`, `defineProperties`, or the legacy `__define[GS]etter__`.
    Only under this precondition may a read of a trusted global data property be treated as effect-free.
    """
    if model.has_reflection_surface():
        return False
    for node in model.root.walk():
        if isinstance(node, JsMemberExpression) and not node.computed:
            prop = node.property
            if isinstance(prop, JsIdentifier) and prop.name in _ACCESSOR_INSTALL_METHODS:
                return False
    return True


def build_effects(model: SemanticModel) -> EffectModel:
    """
    Build the `EffectModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`.
    """
    return EffectModel(model)
