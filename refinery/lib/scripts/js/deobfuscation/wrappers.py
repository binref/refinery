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
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    extract_identifier_params,
    is_closed_expression,
    is_side_effect_free,
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
        allowed_names = set(param_names)
        allowed_names.add(expr.callee.name)
        for arg in expr.arguments:
            if not is_closed_expression(arg, allowed_names):
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
        inlined = False
        for ast_node in list(node.walk()):
            if not isinstance(ast_node, JsCallExpression):
                continue
            if not isinstance(ast_node.callee, JsIdentifier):
                continue
            info = wrappers.get(ast_node.callee.name)
            if info is None:
                continue
            if len(ast_node.arguments) != len(info.param_names):
                continue
            if not all(is_side_effect_free(a) for a in ast_node.arguments):
                continue
            replacement = substitute_params(
                info.return_expression,
                info.param_names,
                ast_node.arguments,
            )
            _replace_in_parent(ast_node, replacement)
            inlined = True
        if not inlined:
            return
        exclude_ids: set[int] = set()
        for info in wrappers.values():
            for n in info.node.walk():
                exclude_ids.add(id(n))
        referenced: set[str] = set()
        for n in node.walk():
            if id(n) in exclude_ids:
                continue
            if isinstance(n, JsIdentifier) and n.name in wrappers:
                referenced.add(n.name)
        for name, info in wrappers.items():
            if name not in referenced:
                _remove_from_parent(info.node)
        self.mark_changed()
