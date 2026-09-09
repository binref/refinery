"""
Resolve global-object-finder functions to `globalThis`.

A *global-object finder* is the common obfuscation idiom of a function that locates the host's global
object by probing a sequence of candidates — `globalThis`, `global`, `window`, `self`, `this`, or
closures returning them — validating each and returning the first that works. Because `globalThis` is
the global object in every standard host, a call to such a finder evaluates to the same value as the
identifier `globalThis`; rewriting the call as `globalThis` lets the surrounding reflection collapse and
leaves the finder unreferenced for
`refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` to drop.

This recognition is a *trusted* judgment rather than a static proof: a finder's success depends on which
globals the host defines, and its fallback path is not statically decidable, so "returns the global
object" holds only under the standard-host assumption the obfuscator itself relies on. The trust is the
same one `refinery.lib.scripts.js.deobfuscation.reflection.JsReflectionInlining` already applies when it
rewrites the `Function('return this')()` idiom to `globalThis`. It is confined by strict gates: every
return is global-object-valued, the function performs no observable write, every call it makes is rooted
at one of its own locals (never `console.log` or any other external), and it actually references a
global-object alias — so only a function that does nothing but compute the global object qualifies.
"""
from __future__ import annotations

from typing import Iterator, Sequence

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    GLOBAL_OBJECT_ALIASES,
    Binding,
    SemanticModel,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    rewrite_receiver_this_to_global,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDoWhileStatement,
    JsEmptyStatement,
    JsExpressionStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsLabeledStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsThisExpression,
    JsTryStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
    strip_parens,
    wraps_return,
)

_CLOSURE_NODES = (JsFunctionExpression, JsArrowFunctionExpression)


class JsGlobalFinderInlining(ScriptLevelTransformer):
    """
    Replace each call to a recognized global-object-finder function with the identifier `globalThis`.
    See the module documentation for the recognition criteria and the trust they rest on.
    """

    self_converging = True

    def _process_script(self, node: JsScript) -> None:
        cache = model_cache(self, node)
        model = cache.model
        finders = _collect_finders(node, model, cache.effects)
        if not finders:
            return
        if self._materialize_finder_receivers(model, finders):
            self.mark_changed()
            return
        finder_ids = {id(f) for f in finders}
        for call in list(node.walk()):
            if not isinstance(call, JsCallExpression) or call.arguments:
                continue
            callee = strip_parens(call.callee)
            if not isinstance(callee, JsIdentifier):
                continue
            target = cache.effects.function_of(model.resolve(callee))
            if target is None or id(target) not in finder_ids or _within(call, target):
                continue
            if not cache.dominance.established_before(target, call):
                continue
            scope = model.scope_of(call)
            if scope is not None and model.lookup('globalThis', scope) is not None:
                continue
            _replace_in_parent(call, JsIdentifier(name='globalThis'))
            self.mark_changed()

    @staticmethod
    def _materialize_finder_receivers(model: SemanticModel, finders: list[Node]) -> bool:
        """
        Rewrite the receiver `this` of each recognized finder that is stored as a namespace method
        (`NS.f = function(){ … return r || this; }`) to `globalThis`, returning whether any finder was
        changed. A finder invoked as `NS.f()` binds its object as `this`, so its `… || this` fallback
        cannot be folded through the identifier-callee path and the namespace flattening declines to
        detach the method while it observes a receiver. Materializing the belief the recognition already
        rests on — that the finder yields the global object — makes the method `this`-free, so flattening
        detaches it to a bare `f()` the fold path then resolves to `globalThis`. Only a non-arrow,
        member-assigned finder is touched, and only where `globalThis` is not shadowed in its scope: a
        name-bound finder is left to the fold path untouched (its body needs no rewrite), and an arrow
        inherits `this` lexically rather than from the call, so neither is a receiver to materialize.
        """
        changed = False
        for finder in finders:
            if isinstance(finder, JsArrowFunctionExpression):
                continue
            parent = finder.parent
            if not (
                isinstance(parent, JsAssignmentExpression)
                and parent.operator == '='
                and parent.right is finder
                and isinstance(parent.left, JsMemberExpression)
            ):
                continue
            scope = model.function_scope(finder)
            if scope is None or model.lookup('globalThis', scope) is not None:
                continue
            if rewrite_receiver_this_to_global(finder):
                changed = True
        return changed


def _collect_finders(
    root: JsScript,
    model: SemanticModel,
    effects: EffectModel,
) -> list[Node]:
    finders: list[Node] = []
    for node in root.walk():
        if not isinstance(node, FUNCTION_NODES):
            continue
        parent = node.parent
        named = (
            (isinstance(node, JsFunctionDeclaration) and node.id is not None)
            or (isinstance(parent, JsVariableDeclarator) and parent.init is node)
            or (
                isinstance(parent, JsAssignmentExpression)
                and parent.operator == '='
                and parent.right is node
            )
        )
        if named and _is_finder(node, model, effects):
            finders.append(node)
    return finders


def _is_finder(func: Node, model: SemanticModel, effects: EffectModel) -> bool:
    summary = effects.summary_of(func)
    if not summary.is_expression_replaceable:
        return False
    if not any(_is_global_alias(node, model) for node in func.walk()):
        return False
    for node in func.walk():
        if isinstance(node, JsCallExpression) and not _root_is_local(node.callee, func, model):
            return False
    returns = [node for node in _own_nodes(func) if isinstance(node, JsReturnStatement)]
    if not returns:
        return False
    if not _finder_cannot_throw(func, model, effects):
        return False
    taint = _global_taint(func, model)
    return all(
        ret.argument is not None and _is_global_valued(ret.argument, func, model, taint, set())
        for ret in returns
    )


def _is_global_valued(
    expr: Node | None, func: Node, model: SemanticModel, taint: set[int], visiting: set[int]
) -> bool:
    expr = strip_parens(expr)
    if isinstance(expr, JsThisExpression):
        return True
    if isinstance(expr, JsIdentifier):
        if _is_global_alias(expr, model):
            return True
        binding = model.resolve(expr)
        return binding is not None and id(binding) in taint
    if isinstance(expr, JsLogicalExpression):
        return (
            _is_global_valued(expr.left, func, model, taint, visiting)
            or _is_global_valued(expr.right, func, model, taint, visiting)
        )
    if isinstance(expr, JsConditionalExpression):
        return (
            _is_global_valued(expr.consequent, func, model, taint, visiting)
            or _is_global_valued(expr.alternate, func, model, taint, visiting)
        )
    if isinstance(expr, JsCallExpression):
        closures = _callee_closures(expr.callee, func, model)
        return bool(closures) and all(
            _closure_returns_global(closure, model, visiting) for closure in closures
        )
    return False


def _global_taint(func: Node, model: SemanticModel) -> set[int]:
    defs: list[tuple[Binding | None, Node | None]] = []
    for node in _own_nodes(func):
        if (
            isinstance(node, JsVariableDeclarator)
            and node.init is not None
            and isinstance(node.id, JsIdentifier)
        ):
            defs.append((model.binding_of(node.id), node.init))
        elif (
            isinstance(node, JsAssignmentExpression)
            and node.operator == '='
            and isinstance(node.left, JsIdentifier)
        ):
            defs.append((model.resolve(node.left), node.right))
    taint: set[int] = set()
    changed = True
    while changed:
        changed = False
        for binding, value in defs:
            if binding is None or id(binding) in taint or not _binding_within(binding, func, model):
                continue
            if _is_global_valued(value, func, model, taint, set()):
                taint.add(id(binding))
                changed = True
    return taint


def _callee_closures(callee: Node | None, func: Node, model: SemanticModel) -> list[Node]:
    callee = strip_parens(callee)
    if isinstance(callee, _CLOSURE_NODES):
        return [callee]
    if isinstance(callee, JsIdentifier):
        return _function_declarations(model.resolve(callee))
    if isinstance(callee, JsMemberExpression):
        base = strip_parens(callee.object)
        if isinstance(base, JsIdentifier):
            return _array_closures(model.resolve(base), func, model)
    return []


def _array_closures(binding: Binding | None, func: Node, model: SemanticModel) -> list[Node]:
    value = strip_parens(_sole_value(binding, func, model))
    if not isinstance(value, JsArrayExpression):
        return []
    closures: list[Node] = []
    for element in value.elements:
        element = strip_parens(element)
        if not isinstance(element, _CLOSURE_NODES):
            return []
        closures.append(element)
    return closures


def _closure_returns_global(closure: Node, model: SemanticModel, visiting: set[int]) -> bool:
    """
    Whether calling *closure* answers the global object. What the body returns decides that only
    where the call answers what the body returned: an `async` closure answers a promise and a
    generator answers a generator object, neither of which is the global object however the body
    ends. `_is_finder` asks `is_expression_replaceable` of the finder itself, which cannot cover
    this — `refinery.lib.scripts.js.analysis.effects.EffectSummary.absorb` deliberately leaves
    `wraps_return` out, so a callee's wrapping never reaches its caller's summary.
    """
    if isinstance(closure, FUNCTION_NODES) and wraps_return(closure):
        return False
    if id(closure) in visiting:
        return False
    visiting = visiting | {id(closure)}
    body = getattr(closure, 'body', None)
    taint = _global_taint(closure, model)
    if isinstance(closure, JsArrowFunctionExpression) and not isinstance(body, JsBlockStatement):
        return _is_global_valued(body, closure, model, taint, visiting)
    returns = [node for node in _own_nodes(closure) if isinstance(node, JsReturnStatement)]
    return bool(returns) and all(
        ret.argument is not None and _is_global_valued(ret.argument, closure, model, taint, visiting)
        for ret in returns
    )


def _sole_value(binding: Binding | None, func: Node, model: SemanticModel) -> Node | None:
    if binding is None:
        return None
    values: list[Node] = []
    for decl in binding.declarations:
        parent = decl.parent
        if isinstance(parent, JsVariableDeclarator) and parent.init is not None:
            values.append(parent.init)
    for node in _own_nodes(func):
        if (
            isinstance(node, JsAssignmentExpression)
            and node.operator == '='
            and isinstance(node.left, JsIdentifier)
            and node.right is not None
            and model.resolve(node.left) is binding
        ):
            values.append(node.right)
    return values[0] if len(values) == 1 else None


def _root_is_local(expr: Node | None, func: Node, model: SemanticModel) -> bool:
    expr = strip_parens(expr)
    if isinstance(expr, _CLOSURE_NODES):
        return True
    if isinstance(expr, JsIdentifier):
        return _binding_within(model.resolve(expr), func, model)
    if isinstance(expr, JsMemberExpression):
        return _root_is_local(expr.object, func, model)
    if isinstance(expr, JsCallExpression):
        return _root_is_local(expr.callee, func, model)
    return False


def _binding_within(binding: Binding | None, func: Node, model: SemanticModel) -> bool:
    if binding is None:
        return False
    func_scope = model.function_scope(func)
    return func_scope is not None and func_scope.contains(binding.scope)


def _finder_cannot_throw(func: Node, model: SemanticModel, effects: EffectModel) -> bool:
    """
    Whether calling *func* cannot raise a `ReferenceError` in any host, so replacing the call with
    `globalThis` drops no throw. The fold lifts the finder's return value and discards its body,
    unlike an expression replacement (`EffectSummary.is_expression_replaceable`), which reproduces a
    throw where the call stood; a finder that reads a host-conditional alias (`window`, `self`,
    `top`, `frames`, `global`) on a path some host runs would have that throw silently dropped.

    A read of such an alias is safe only where a host lacking it never evaluates the read: inside a
    `try` that catches, past a `globalThis` short-circuit that leaves it unevaluated, or as a
    `typeof`/`delete` operand, which `SemanticModel.read_may_throw` already answers cannot throw.
    `globalThis` and any bound local read the same way. The host-existence fact is not re-encoded
    here: each read defers to `read_may_throw` and each called closure to its
    `EffectSummary.throws`, so this judgment is only the control flow deciding which of those reads
    a lacking host reaches. A construct not modelled here is refused, keeping the fold sound at the
    cost of at most a fold a host pin would recover.
    """
    body = getattr(func, 'body', None)
    if isinstance(func, JsArrowFunctionExpression) and not isinstance(body, JsBlockStatement):
        return _throwless_expr(body, func, model, effects)
    return isinstance(body, JsBlockStatement) and _throwless_stmts(body.body, func, model, effects)


def _throwless_stmts(
    stmts: Sequence[Node], func: Node, model: SemanticModel, effects: EffectModel
) -> bool:
    return all(_throwless_stmt(stmt, func, model, effects) for stmt in stmts)


def _throwless_stmt(
    stmt: Node | None, func: Node, model: SemanticModel, effects: EffectModel
) -> bool:
    if stmt is None or isinstance(stmt, (
        JsEmptyStatement, JsBreakStatement, JsContinueStatement, JsFunctionDeclaration,
    )):
        return True
    if isinstance(stmt, JsReturnStatement):
        return _throwless_expr(stmt.argument, func, model, effects)
    if isinstance(stmt, JsExpressionStatement):
        return _throwless_expr(stmt.expression, func, model, effects)
    if isinstance(stmt, JsVariableDeclaration):
        return all(_throwless_expr(d.init, func, model, effects) for d in stmt.declarations)
    if isinstance(stmt, JsBlockStatement):
        return _throwless_stmts(stmt.body, func, model, effects)
    if isinstance(stmt, JsLabeledStatement):
        return _throwless_stmt(stmt.body, func, model, effects)
    if isinstance(stmt, JsIfStatement):
        return (
            _throwless_expr(stmt.test, func, model, effects)
            and _throwless_stmt(stmt.consequent, func, model, effects)
            and _throwless_stmt(stmt.alternate, func, model, effects)
        )
    if isinstance(stmt, JsTryStatement):
        handler = stmt.handler
        trapped = handler is not None and _throwless_stmt(handler.body, func, model, effects)
        block_ok = trapped or _throwless_stmt(stmt.block, func, model, effects)
        return block_ok and _throwless_stmt(stmt.finalizer, func, model, effects)
    if isinstance(stmt, JsForStatement):
        init = stmt.init
        init_ok = (
            _throwless_stmt(init, func, model, effects)
            if isinstance(init, JsVariableDeclaration)
            else _throwless_expr(init, func, model, effects)
        )
        return (
            init_ok
            and _throwless_expr(stmt.test, func, model, effects)
            and _throwless_expr(stmt.update, func, model, effects)
            and _throwless_stmt(stmt.body, func, model, effects)
        )
    if isinstance(stmt, (JsWhileStatement, JsDoWhileStatement)):
        return (
            _throwless_expr(stmt.test, func, model, effects)
            and _throwless_stmt(stmt.body, func, model, effects)
        )
    return False


def _throwless_expr(
    expr: Node | None, func: Node, model: SemanticModel, effects: EffectModel
) -> bool:
    if expr is None:
        return True
    expr = strip_parens(expr)
    if isinstance(expr, JsIdentifier):
        return not model.read_may_throw(expr)
    if isinstance(expr, (
        JsThisExpression,
        JsNumericLiteral,
        JsStringLiteral,
        JsBooleanLiteral,
        JsNullLiteral,
        JsFunctionExpression,
        JsArrowFunctionExpression,
    )):
        return True
    if isinstance(expr, JsArrayExpression):
        return all(_throwless_expr(element, func, model, effects) for element in expr.elements)
    if isinstance(expr, (JsUnaryExpression, JsUpdateExpression)):
        operand = expr.operand if isinstance(expr, JsUnaryExpression) else expr.argument
        return _throwless_expr(operand, func, model, effects)
    if isinstance(expr, JsBinaryExpression):
        return (
            _throwless_expr(expr.left, func, model, effects)
            and _throwless_expr(expr.right, func, model, effects)
        )
    if isinstance(expr, JsLogicalExpression):
        if expr.operator in ('||', '??') and _guaranteed_truthy(expr.left, model):
            return _throwless_expr(expr.left, func, model, effects)
        return (
            _throwless_expr(expr.left, func, model, effects)
            and _throwless_expr(expr.right, func, model, effects)
        )
    if isinstance(expr, JsConditionalExpression):
        return (
            _throwless_expr(expr.test, func, model, effects)
            and _throwless_expr(expr.consequent, func, model, effects)
            and _throwless_expr(expr.alternate, func, model, effects)
        )
    if isinstance(expr, JsSequenceExpression):
        return all(_throwless_expr(part, func, model, effects) for part in expr.expressions)
    if isinstance(expr, JsAssignmentExpression):
        return (
            _throwless_expr(expr.left, func, model, effects)
            and _throwless_expr(expr.right, func, model, effects)
        )
    if isinstance(expr, JsMemberExpression):
        base_ok = _throwless_expr(expr.object, func, model, effects)
        key_ok = not expr.computed or _throwless_expr(expr.property, func, model, effects)
        return base_ok and key_ok
    if isinstance(expr, JsCallExpression):
        if not _throwless_expr(expr.callee, func, model, effects):
            return False
        if not all(_throwless_expr(arg, func, model, effects) for arg in expr.arguments):
            return False
        closures = _callee_closures(expr.callee, func, model)
        return bool(closures) and all(not effects.summary_of(c).throws for c in closures)
    return False


def _guaranteed_truthy(expr: Node | None, model: SemanticModel) -> bool:
    """
    Whether *expr* evaluates to a truthy value in every host, so a `||`/`??` whose left it is
    never evaluates the right. Only `globalThis` qualifies as a leaf — the one global-object alias
    the language mandates everywhere, always a truthy object — and a `||`/`??` chain is truthy where
    its own left is.
    """
    expr = strip_parens(expr)
    if isinstance(expr, JsIdentifier):
        return expr.name == 'globalThis' and _is_global_alias(expr, model)
    if isinstance(expr, JsLogicalExpression) and expr.operator in ('||', '??'):
        return _guaranteed_truthy(expr.left, model)
    return False


def _is_global_alias(node: Node, model: SemanticModel) -> bool:
    if not isinstance(node, JsIdentifier) or node.name not in GLOBAL_OBJECT_ALIASES:
        return False
    scope = model.scope_of(node)
    return scope is not None and model.lookup(node.name, scope) is None


def _function_declarations(binding: Binding | None) -> list[Node]:
    if binding is None:
        return []
    return [decl.parent for decl in binding.declarations if isinstance(decl.parent, FUNCTION_NODES)]


def _own_nodes(func: Node) -> Iterator[Node]:
    body = getattr(func, 'body', None)
    if not isinstance(body, JsBlockStatement):
        return
    stack: list[Node] = list(body.body)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, FUNCTION_NODES):
            stack.extend(node.children())


def _within(node: Node, ancestor: Node) -> bool:
    current = node.parent
    while current is not None:
        if current is ancestor:
            return True
        current = current.parent
    return False
