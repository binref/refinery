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

from dataclasses import dataclass
from typing import Callable, Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    FUNCTION_NODES,
    GLOBAL_OBJECT_ALIASES,
    Role,
    Scope,
    SemanticModel,
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
    JsLogicalExpression,
    JsMemberExpression,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsThrowStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclarator,
)

_FunctionNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression

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
    resolved and summarized. A summary with none of these set is `is_pure`.
    """
    writes_global: bool = False
    writes_captured: bool = False
    throws: bool = False
    calls_unknown: bool = False

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
        global nor a captured binding. Unlike `is_pure`, a call that may throw or read unknown state
        still qualifies: an evaluator that actually executes the call to a value reproduces those, and
        only a *write* would be silently lost. `is_pure`, which additionally forbids throwing and
        unknown reads, is the right test for removing a call outright rather than replacing it.
        """
        return not (self.writes_global or self.writes_captured)

    def absorb(self, other: EffectSummary):
        """
        Union *other*'s effects into this summary, used to fold a callee's effects into its caller.
        """
        self.writes_global = self.writes_global or other.writes_global
        self.writes_captured = self.writes_captured or other.writes_captured
        self.throws = self.throws or other.throws
        self.calls_unknown = self.calls_unknown or other.calls_unknown


def _scope_contains(outer: Scope, inner: Scope) -> bool:
    """
    Whether *inner* is *outer* itself or a scope nested below it.
    """
    cursor: Scope | None = inner
    while cursor is not None:
        if cursor is outer:
            return True
        cursor = cursor.parent
    return False


def _enclosing_function(node: Node) -> Node | None:
    """
    The nearest function node (declaration, expression, or arrow) that lexically encloses *node*, or
    `None` when *node* sits at the top level below no function.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, FUNCTION_NODES):
            return cursor
        cursor = cursor.parent
    return None


def _is_member_write(member: JsMemberExpression) -> bool:
    """
    Whether *member* is the target of a mutation — the left of an assignment, the operand of `++`/`--`,
    or the operand of `delete` — so the property it names is being written rather than read.
    """
    parent = member.parent
    if isinstance(parent, JsAssignmentExpression):
        return parent.left is member
    if isinstance(parent, JsUpdateExpression):
        return parent.argument is member
    if isinstance(parent, JsUnaryExpression):
        return parent.operator == 'delete' and parent.operand is member
    return False


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
) -> bool:
    """
    Conservative check for whether evaluating an expression can be dropped or reordered with no
    observable side effect. Compositional: an expression is free when every sub-expression is. The
    effect-bearing leaf is the call — free only when its callee is a *defunct* identifier or an inline
    function expression, or, when *call_pure* is supplied, when *call_pure* certifies the call (or
    `new`) pure and its arguments are free. `EffectModel.is_side_effect_free` passes
    `EffectModel.is_pure_call` as *call_pure*; a caller without a model gets the conservative behaviour.
    When *defunct* is given its identifiers name bindings being removed, so calls to them and property
    reads through them are treated as free.
    """
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, JsIdentifier):
        return True
    if isinstance(node, JsFunctionExpression):
        return True
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'delete':
            return False
        return node.operand is not None and side_effect_free(node.operand, defunct, call_pure)
    if isinstance(node, JsMemberExpression):
        if node.object is None:
            return False
        if not side_effect_free(node.object, defunct, call_pure):
            return False
        if node.property is not None and not side_effect_free(node.property, defunct, call_pure):
            return False
        return _is_safe_property_base(node.object, defunct)
    if isinstance(node, (JsBinaryExpression, JsLogicalExpression)):
        return (
            node.left is not None
            and side_effect_free(node.left, defunct, call_pure)
            and node.right is not None
            and side_effect_free(node.right, defunct, call_pure)
        )
    if isinstance(node, JsConditionalExpression):
        return (
            node.test is not None
            and side_effect_free(node.test, defunct, call_pure)
            and node.consequent is not None
            and side_effect_free(node.consequent, defunct, call_pure)
            and node.alternate is not None
            and side_effect_free(node.alternate, defunct, call_pure)
        )
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                return False
            if prop.computed and (prop.key is None or not side_effect_free(prop.key, defunct, call_pure)):
                return False
            if prop.value is not None and not side_effect_free(prop.value, defunct, call_pure):
                return False
        return True
    if isinstance(node, JsArrayExpression):
        return all(
            elem is None or side_effect_free(elem, defunct, call_pure) for elem in node.elements
        )
    if isinstance(node, JsSequenceExpression):
        return all(side_effect_free(e, defunct, call_pure) for e in node.expressions)
    if isinstance(node, JsCallExpression):
        if defunct and isinstance(node.callee, JsIdentifier) and node.callee.name in defunct:
            return all(side_effect_free(arg, defunct, call_pure) for arg in node.arguments)
        if isinstance(node.callee, JsFunctionExpression):
            return all(side_effect_free(arg, defunct, call_pure) for arg in node.arguments)
    if call_pure is not None and isinstance(node, (JsCallExpression, JsNewExpression)) and call_pure(node):
        return all(side_effect_free(arg, defunct, call_pure) for arg in node.arguments)
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
        self._functions: list[Node] = self._collect_functions()
        self._compute()

    def summary_of(self, func: Node) -> EffectSummary:
        """
        The effect summary of a function node (or the script). An unknown node is reported as impure.
        """
        return self._summaries.get(id(func), EffectSummary(calls_unknown=True))

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
        standalone `refinery.lib.scripts.js.deobfuscation.helpers.is_side_effect_free`, which clears
        only calls to a defunct name or an inline function.
        """
        return side_effect_free(node, defunct, self.is_pure_call)

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
        func_scope = self._function_scope(func)
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
                if _is_member_write(node):
                    summary.writes_global = True
                elif (
                    base is not None
                    and not self._base_getter_safe(base)
                    and not self._is_trusted_global_read(node)
                ):
                    summary.calls_unknown = True
            elif isinstance(node, (JsCallExpression, JsNewExpression)):
                self._account_call(summary, node)
        return summary

    def _account_write(
        self, summary: EffectSummary, target: JsIdentifier, func_scope: Scope | None, func: Node
    ):
        binding = self.model.resolve(target)
        if binding is None:
            summary.writes_global = True
            return
        if self._write_unobservable(binding, func):
            return
        if binding.kind is BindingKind.IMPLICIT_GLOBAL or binding.scope is self.model.root_scope:
            summary.writes_global = True
        elif func_scope is not None and _scope_contains(func_scope, binding.scope):
            pass
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
        enclosing = _enclosing_function(refs[0])
        if enclosing is None:
            return None
        for ref in refs[1:]:
            if _enclosing_function(ref) is not enclosing:
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
            return self._function_of(self.model.resolve(callee))
        return None

    def _function_of(self, binding) -> Node | None:
        if binding is None:
            return None
        for decl in binding.declarations:
            parent = decl.parent
            if isinstance(parent, JsFunctionDeclaration) and parent.id is decl:
                return parent
            if isinstance(parent, JsVariableDeclarator) and isinstance(parent.init, FUNCTION_NODES):
                return parent.init
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
        hidden effect: a freshly built value with no accessor of its own, a primitive, or a pristine
        intrinsic root. Unlike `_base_is_safe`, the global object does not qualify — a global property
        such as `location` may be an accessor — so a read through it is treated as an unknown call.
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
            return not any(
                isinstance(prop, JsProperty) and prop.kind in (JsPropertyKind.GET, JsPropertyKind.SET)
                for prop in node.properties
            )
        if isinstance(node, JsIdentifier):
            return node.name in _PURE_INTRINSIC_ROOTS and self._is_global_intrinsic(node)
        if isinstance(node, JsMemberExpression):
            return node.object is not None and self._base_getter_safe(node.object)
        return False

    def _function_scope(self, func: Node) -> Scope | None:
        if isinstance(func, JsScript):
            return self.model.root_scope
        body = getattr(func, 'body', None)
        if body is None:
            return None
        return self.model.scope_of(body)


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
