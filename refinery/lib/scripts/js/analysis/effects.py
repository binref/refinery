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
that precondition fails the registry is disregarded and such calls are treated as unknown.

The public surface — `EffectSummary`, `EffectModel.summary_of`, `EffectModel.is_pure_call`,
`build_effects` — is representation-agnostic and keyed to AST node identity, matching the model's
contract so a later control-flow layer can sharpen the same answers without changing callers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.model import (
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
    JsBooleanLiteral,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
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


class EffectModel:
    """
    Per-function effect summaries for one script, built over a
    `refinery.lib.scripts.js.analysis.model.SemanticModel`. Query a function's summary with
    `summary_of` and a call expression's purity with `is_pure_call`. Build through `build_effects`.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self.intrinsics_pristine = _intrinsics_pristine(model)
        self._summaries: dict[int, EffectSummary] = {}
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
                    self._account_write(summary, node, func_scope)
            elif isinstance(node, JsMemberExpression):
                base = node.object
                if base is not None and not self._base_is_safe(base):
                    summary.throws = True
                if _is_member_write(node):
                    summary.writes_global = True
                elif base is not None and not self._base_getter_safe(base):
                    summary.calls_unknown = True
            elif isinstance(node, (JsCallExpression, JsNewExpression)):
                self._account_call(summary, node)
        return summary

    def _account_write(self, summary: EffectSummary, target: JsIdentifier, func_scope: Scope | None):
        binding = self.model.resolve(target)
        if binding is None or binding.kind is BindingKind.IMPLICIT_GLOBAL:
            summary.writes_global = True
        elif binding.scope is self.model.root_scope:
            summary.writes_global = True
        elif func_scope is not None and _scope_contains(func_scope, binding.scope):
            pass
        else:
            summary.writes_captured = True

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
            if isinstance(parent, JsFunctionDeclaration):
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


def build_effects(model: SemanticModel) -> EffectModel:
    """
    Build the `EffectModel` for a script's `refinery.lib.scripts.js.analysis.model.SemanticModel`.
    """
    return EffectModel(model)
