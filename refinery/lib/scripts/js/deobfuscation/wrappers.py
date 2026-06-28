"""
Inline trivial function call wrappers.

A call wrapper is a small function whose only purpose is to forward a call to another function
after rearranging or arithmetically transforming its arguments. This is a common obfuscation
technique that adds a layer of indirection around every call site. The transformer detects these
wrappers and substitutes each call site with the inlined return expression.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import (
    Node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    _param_written,
    extract_identifier_params,
    is_closed_expression,
    substitute_params,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsFunctionDeclaration,
    JsIdentifier,
    JsReturnStatement,
    JsScript,
)


class _WrapperInfo(NamedTuple):
    """
    Describes a detected call wrapper function.
    """
    node: JsFunctionDeclaration
    name: str
    param_names: list[str]
    return_expression: Node


def _detect_wrapper(node: JsFunctionDeclaration) -> _WrapperInfo | None:
    """
    Test whether a function declaration is a trivial wrapper. Two forms are recognized:

    1. **Call wrappers** (one or more parameters): the body is a single return of a call expression
       whose arguments are closed over the wrapper's parameters and literal constants.
    2. **Constant functions** (zero parameters): the body is a single return of an expression that
       is closed (no free variables — only literal constants).
    """
    if node.id is None or node.body is None:
        return None
    param_names = extract_identifier_params(node.params)
    if param_names is None:
        return None
    body = node.body.body
    if len(body) != 1:
        return None
    stmt = body[0]
    if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
        return None
    expr = stmt.argument
    if param_names:
        if not isinstance(expr, JsCallExpression):
            return None
        if not isinstance(expr.callee, JsIdentifier):
            return None
        param_set = set(param_names)
        allowed_names = param_set | {expr.callee.name}
        for arg in expr.arguments:
            if not is_closed_expression(arg, allowed_names):
                return None
        if _param_written(expr, param_set):
            return None
    else:
        if not is_closed_expression(expr, set()):
            return None
    return _WrapperInfo(node, node.id.name, param_names, expr)


def _collect_wrappers(root: Node) -> dict[str, _WrapperInfo]:
    """
    Walk the entire AST and collect all function declarations that qualify as call wrappers.
    """
    wrappers: dict[str, _WrapperInfo] = {}
    for node in root.walk():
        if isinstance(node, JsFunctionDeclaration):
            info = _detect_wrapper(node)
            if info is not None:
                wrappers[info.name] = info
    return wrappers


class JsCallWrapperInliner(ScriptLevelTransformer):
    """
    Detect trivial call wrapper functions and inline them at every call site.
    """

    def _process_script(self, node: JsScript):
        wrappers = _collect_wrappers(node)
        if not wrappers:
            return
        effects = model_cache(self, node).effects
        by_node = {id(info.node): info for info in wrappers.values()}
        for dead in self._self_forwarding_wrappers(wrappers, by_node, effects):
            del by_node[dead]
        inlined = False
        for ast_node in list(node.walk()):
            if not isinstance(ast_node, JsCallExpression):
                continue
            target = effects.static_callee(ast_node)
            if target is None:
                continue
            info = by_node.get(id(target))
            if info is None:
                continue
            if len(ast_node.arguments) != len(info.param_names):
                continue
            if not all(effects.is_side_effect_free(a) for a in ast_node.arguments):
                continue
            replacement = substitute_params(
                info.return_expression,
                info.node.params,
                ast_node.arguments,
                transformer=self,
            )
            _replace_in_parent(ast_node, replacement)
            inlined = True
        if not inlined:
            return
        kept = self._wrappers_to_keep(node, wrappers)
        for name, info in wrappers.items():
            if name not in kept:
                _remove_from_parent(info.node)
        self.mark_changed()

    @staticmethod
    def _self_forwarding_wrappers(
        wrappers: dict[str, _WrapperInfo],
        by_node: dict[int, _WrapperInfo],
        effects: EffectModel,
    ) -> set[int]:
        """
        The wrapper declaration nodes that lie on a cycle of wrapper-to-wrapper forwarding, where
        inlining would never bottom out: a wrapper whose body forwards to itself, directly or through
        a chain of other wrappers (`W -> V -> W`). Each call wrapper forwards to at most one statically
        resolvable callee, so the forwarding graph is functional and a node lies on a cycle exactly
        when following its single edge returns to it. Such a wrapper is left un-inlined; inlining it
        would regenerate an equivalent call on every pass and the fold loop would never terminate.
        """
        edge: dict[int, int | None] = {}
        for info in wrappers.values():
            expr = info.return_expression
            target = effects.static_callee(expr) if isinstance(expr, JsCallExpression) else None
            edge[id(info.node)] = id(target) if target is not None and id(target) in by_node else None
        on_cycle: set[int] = set()
        visited: set[int] = set()
        for start in edge:
            if start in visited:
                continue
            path: list[int] = []
            index: dict[int, int] = {}
            cursor: int | None = start
            while cursor is not None and cursor not in visited:
                visited.add(cursor)
                index[cursor] = len(path)
                path.append(cursor)
                cursor = edge.get(cursor)
            if cursor is not None and cursor in index:
                on_cycle.update(path[index[cursor]:])
        return on_cycle

    @staticmethod
    def _wrappers_to_keep(
        node: JsScript, wrappers: dict[str, _WrapperInfo]
    ) -> set[str]:
        """
        The wrapper names still referenced after inlining, so the rest may be removed. A wrapper is
        kept when its name is referenced from live code: code outside every wrapper body, or the body
        of a wrapper that is itself kept. The keep-set is grown to a fixpoint so that a wrapper reached
        only from another surviving (un-inlined, e.g. arity-mismatched) wrapper is retained rather than
        deleted into a dangling call. A reference inside a body that will itself be removed does not
        count, since that body goes away with it.
        """
        kept: set[str] = set()
        changed = True
        while changed:
            changed = False
            dead_body_ids: set[int] = set()
            for name, info in wrappers.items():
                if name not in kept:
                    for n in info.node.walk():
                        dead_body_ids.add(id(n))
            for n in node.walk():
                if id(n) in dead_body_ids:
                    continue
                if isinstance(n, JsIdentifier) and n.name in wrappers and n.name not in kept:
                    kept.add(n.name)
                    changed = True
        return kept
