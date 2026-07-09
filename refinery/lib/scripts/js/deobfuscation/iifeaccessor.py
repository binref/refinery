"""
Promote IIFE-bound function accessors to plain function declarations.

Recognizes the pattern

    var X = function () {
        var c1 = <literal>;
        var c2 = <literal-array>;
        return function (p) { ... uses c1, c2 ... };
    }();

and rewrites it as

    function X(p) {
        var c1 = <literal>;
        var c2 = <literal-array>;
        ... uses c1, c2 ...
    }

This is a common obfuscator pattern where a string-decoding accessor is built once and bound to a
variable through the result of an IIFE that closes over a constant lookup table and a few scalar
parameters. `refinery.lib.scripts.js.deobfuscation.evaluator.JsFunctionEvaluator` only registers
`refinery.lib.scripts.js.model.JsFunctionDeclaration` nodes in its scope tree, so call sites like
`X(0x3a2)` are otherwise never folded. The rewrite is only applied when the captured closure
variables are read-only inside the returned function; under that condition the hoisting is
semantically equivalent because the closure values are re-initialised to identical literals on every
call. After the rewrite, the function evaluator folds each call site to its computed string literal.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import (
    Node,
    _clone_node,
    _replace_in_parent,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    FUNCTION_NODE_TYPES,
    ScriptLevelTransformer,
    extract_identifier_params,
    is_literal,
    references_receiver_this,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsObjectExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    strip_parens,
)


def _is_literal_initializer(node: Node | None) -> bool:
    if node is None:
        return False
    if is_literal(node):
        return True
    if isinstance(node, JsArrayExpression):
        return all(el is not None and _is_literal_initializer(el) for el in node.elements)
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                return False
            if prop.value is None or not _is_literal_initializer(prop.value):
                return False
        return True
    return False


class _Pattern(NamedTuple):
    declaration: JsVariableDeclaration
    name: str
    closure_decls: list[JsVariableDeclaration]
    inner_func: JsFunctionExpression | JsArrowFunctionExpression


def _detect(declarator: JsVariableDeclarator) -> _Pattern | None:
    if not isinstance(declarator.id, JsIdentifier):
        return None
    declaration = declarator.parent
    if not isinstance(declaration, JsVariableDeclaration):
        return None
    if len(declaration.declarations) != 1:
        return None
    init = strip_parens(declarator.init)
    if not isinstance(init, JsCallExpression):
        return None
    if init.arguments:
        return None
    callee = strip_parens(init.callee)
    if not isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
        return None
    if callee.params:
        return None
    body = callee.body
    if not isinstance(body, JsBlockStatement) or not body.body:
        return None
    closure_decls: list[JsVariableDeclaration] = []
    inner_func: JsFunctionExpression | JsArrowFunctionExpression | None = None
    for stmt in body.body:
        if inner_func is not None:
            return None
        if isinstance(stmt, JsVariableDeclaration):
            for decl in stmt.declarations:
                if not isinstance(decl, JsVariableDeclarator):
                    return None
                if not isinstance(decl.id, JsIdentifier):
                    return None
                if not _is_literal_initializer(decl.init):
                    return None
            closure_decls.append(stmt)
            continue
        if isinstance(stmt, JsReturnStatement):
            ret_arg = strip_parens(stmt.argument)
            if not isinstance(ret_arg, (JsFunctionExpression, JsArrowFunctionExpression)):
                return None
            if not isinstance(ret_arg.body, JsBlockStatement):
                return None
            inner_func = ret_arg
            continue
        return None
    if inner_func is None:
        return None
    return _Pattern(declaration, declarator.id.name, closure_decls, inner_func)


def _closure_names(closure_decls: list[JsVariableDeclaration]) -> set[str]:
    names: set[str] = set()
    for decl in closure_decls:
        for d in decl.declarations:
            if isinstance(d, JsVariableDeclarator) and isinstance(d.id, JsIdentifier):
                names.add(d.id.name)
    return names


def _is_safe_to_promote(
    inner: JsFunctionExpression | JsArrowFunctionExpression,
    closure_names: set[str],
) -> bool:
    param_names = extract_identifier_params(inner.params)
    if param_names is None:
        return False
    if any(p in closure_names for p in param_names):
        return False
    body = inner.body
    if not isinstance(body, JsBlockStatement):
        return False
    inner_name: str | None = None
    if isinstance(inner, JsFunctionExpression) and isinstance(inner.id, JsIdentifier):
        inner_name = inner.id.name
    if references_receiver_this(body):
        return False
    for node in walk_scope(body):
        if isinstance(node, JsIdentifier) and node.name == 'arguments':
            return False
        if inner_name is not None and isinstance(node, JsIdentifier) and node.name == inner_name:
            return False
    for node in body.walk():
        if isinstance(node, JsAssignmentExpression):
            if isinstance(node.left, JsIdentifier) and node.left.name in closure_names:
                return False
        if isinstance(node, JsUpdateExpression):
            if (
                isinstance(node.argument, JsIdentifier)
                and node.argument.name in closure_names
            ):
                return False
        if isinstance(node, JsVariableDeclarator):
            if isinstance(node.id, JsIdentifier) and node.id.name in closure_names:
                return False
        if isinstance(node, FUNCTION_NODE_TYPES) and node is not inner:
            for p in node.params:
                if isinstance(p, JsIdentifier) and p.name in closure_names:
                    return False
            if (
                isinstance(node, JsFunctionDeclaration)
                and isinstance(node.id, JsIdentifier)
                and node.id.name in closure_names
            ):
                return False
    return True


class JsIIFEAccessorPromoter(ScriptLevelTransformer):
    """
    Detect accessor variables built from an IIFE that closes over literal lookup tables, and
    rewrite each one into a plain named function declaration so that the function evaluator can
    fold its call sites.
    """

    def _process_script(self, node: JsScript) -> None:
        for declarator in list(node.walk()):
            if not isinstance(declarator, JsVariableDeclarator):
                continue
            pattern = _detect(declarator)
            if pattern is None:
                continue
            closure_names = _closure_names(pattern.closure_decls)
            if not _is_safe_to_promote(pattern.inner_func, closure_names):
                continue
            self._promote(pattern)

    def _promote(self, pattern: _Pattern) -> None:
        inner = pattern.inner_func
        inner_body = inner.body
        if not isinstance(inner_body, JsBlockStatement):
            return
        new_body_stmts = [_clone_node(d) for d in pattern.closure_decls]
        new_body_stmts.extend(_clone_node(s) for s in inner_body.body)
        new_func = JsFunctionDeclaration(
            id=JsIdentifier(name=pattern.name),
            params=[_clone_node(p) for p in inner.params],
            body=JsBlockStatement(body=new_body_stmts),
        )
        _replace_in_parent(pattern.declaration, new_func)
        self.mark_changed()
