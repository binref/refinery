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

from typing import Iterator

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    FUNCTION_NODES,
    GLOBAL_OBJECT_ALIASES,
    SemanticModel,
)
from refinery.lib.scripts.js.deobfuscation.helpers import ScriptLevelTransformer
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsConditionalExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsReturnStatement,
    JsScript,
    JsThisExpression,
    JsVariableDeclarator,
    strip_parens,
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
            sites = model.establishment_sites(target)
            if sites is None or not all(cache.dominance.runs_before(site, call) for site in sites):
                continue
            scope = model.scope_of(call)
            if scope is not None and model.lookup('globalThis', scope) is not None:
                continue
            _replace_in_parent(call, JsIdentifier(name='globalThis'))
            self.mark_changed()


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
    if summary.writes_global or summary.writes_captured:
        return False
    if not any(_is_global_alias(node, model) for node in func.walk()):
        return False
    for node in func.walk():
        if isinstance(node, JsCallExpression) and not _root_is_local(node.callee, func, model):
            return False
    returns = [node for node in _own_nodes(func) if isinstance(node, JsReturnStatement)]
    if not returns:
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
