"""
The obfuscator converts statement sequences into calls to a self-disabling no-op function whose
arguments carry all side effects. This transformer detects the pattern structurally, expands each
call back into individual statements, and removes the wrapper definition.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsScript,
    JsSequenceExpression,
)


def _is_expression_wrapper(node: JsFunctionDeclaration) -> bool:
    """
    Test whether a function declaration matches the self-disabling wrapper pattern:

        function NAME() {
            NAME = function() {};
        }
    """
    if node.id is None or node.body is None:
        return False
    if node.params:
        return False
    if not isinstance(node.body, JsBlockStatement):
        return False
    body = node.body.body
    if len(body) != 1:
        return False
    stmt = body[0]
    if not isinstance(stmt, JsExpressionStatement):
        return False
    expr = stmt.expression
    if not isinstance(expr, JsAssignmentExpression):
        return False
    if expr.operator != '=':
        return False
    if not isinstance(expr.left, JsIdentifier):
        return False
    if expr.left.name != node.id.name:
        return False
    rhs = expr.right
    if not isinstance(rhs, JsFunctionExpression):
        return False
    if rhs.params:
        return False
    if isinstance(rhs.body, JsBlockStatement) and rhs.body.body:
        return False
    return True


def _find_expression_wrappers(root: Node) -> set[str]:
    names: set[str] = set()
    for node in root.walk():
        if isinstance(node, JsFunctionDeclaration) and _is_expression_wrapper(node):
            assert node.id is not None
            names.add(node.id.name)
    return names


class JsAssignmentsAsFunctionArgs(Transformer):
    """
    Detect self-disabling wrapper functions and expand their call sites into individual expression
    statements.
    """

    def visit_JsScript(self, node: JsScript):
        wrapper_names = _find_expression_wrappers(node)
        if not wrapper_names:
            return None
        unwrapped = False
        for ast_node in list(node.walk()):
            if not isinstance(ast_node, JsCallExpression):
                continue
            if not isinstance(ast_node.callee, JsIdentifier):
                continue
            if ast_node.callee.name not in wrapper_names:
                continue
            if (
                isinstance(parent := ast_node.parent, JsExpressionStatement)
                and isinstance(pp := parent.parent, (JsBlockStatement, JsScript))
            ):
                body = pp.body
                try:
                    idx = body.index(parent)
                except ValueError:
                    continue
                new_stmts = [
                    JsExpressionStatement(expression=arg) for arg in ast_node.arguments
                ]
                body[idx:idx + 1] = new_stmts
                for stmt in new_stmts:
                    stmt.parent = pp
                unwrapped = True
            else:
                args = ast_node.arguments
                if not args:
                    replacement = JsIdentifier(name='undefined')
                elif len(args) == 1:
                    replacement = args[0]
                else:
                    replacement = JsSequenceExpression(expressions=list(args))
                _replace_in_parent(ast_node, replacement)
                unwrapped = True
        if not unwrapped:
            return None
        for ast_node in list(node.walk()):
            if not isinstance(ast_node, JsFunctionDeclaration):
                continue
            if ast_node.id is None:
                continue
            if ast_node.id.name not in wrapper_names:
                continue
            if not _has_remaining_references(node, ast_node.id.name, ast_node):
                _remove_from_parent(ast_node)
        self.mark_changed()

    def generic_visit(self, node: Node):
        pass


def _has_remaining_references(root: Node, name: str, decl: JsFunctionDeclaration) -> bool:
    decl_nodes: set[int] = {id(n) for n in decl.walk()}
    for node in root.walk():
        if id(node) in decl_nodes:
            continue
        if isinstance(node, JsIdentifier) and node.name == name:
            return True
    return False
