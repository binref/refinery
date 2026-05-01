"""
Remove unreachable function declarations and unused variable assignments.

This transformer performs two phases:

1. **Dead function removal** — transitive reachability analysis: starting from non-function
   statements, it collects all function names referenced directly or transitively. Function
   declarations not in the reachable set are removed.

2. **Dead variable removal** — collects assignment targets that are never read in the outer scope
   (excluding function bodies that might shadow the name). Dead assignment statements are removed,
   along with their hoisted `var` declarators when the declarator has no initializer.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, _remove_from_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    collect_identifier_names,
    remove_declarator,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsConditionalExpression,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsProperty,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    Statement,
)


def _reachable_functions(
    body: list[Statement],
    functions: dict[str, JsFunctionDeclaration],
) -> set[str]:
    """
    Compute the set of function names transitively reachable from non-function statements in
    *body*. A function is reachable if its name appears as any identifier in a reachable statement
    or in the body of another reachable function.
    """
    referenced: set[str] = set()
    for stmt in body:
        if isinstance(stmt, JsFunctionDeclaration):
            continue
        referenced |= collect_identifier_names(stmt)
    reachable = referenced & functions.keys()
    frontier = list(reachable)
    while frontier:
        name = frontier.pop()
        func = functions[name]
        for ident_name in collect_identifier_names(func):
            if ident_name in functions and ident_name not in reachable:
                reachable.add(ident_name)
                frontier.append(ident_name)
    return reachable


def _is_safe_property_base(node: Node, defunct: set[str] | None = None) -> bool:
    """
    Check whether property access on *node* is guaranteed to be side-effect-free. Returns `True`
    when the object is a value that cannot have custom getters: literals, fresh object/array/function
    expressions, or identifiers in the *defunct* set (being removed, so their getters are irrelevant
    to live code). Chained member expressions are safe when their root base is safe.
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


def _is_side_effect_free(node: Node, defunct: set[str] | None = None) -> bool:
    """
    Conservative check for whether an expression can be removed without observable side effects.
    When *defunct* is provided, calls to identifiers in that set are treated as side-effect-free
    (the function no longer exists in scope).
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
        return node.operand is not None and _is_side_effect_free(node.operand, defunct)
    if isinstance(node, JsMemberExpression):
        if node.object is None:
            return False
        if not _is_side_effect_free(node.object, defunct):
            return False
        if node.property is not None and not _is_side_effect_free(node.property, defunct):
            return False
        return _is_safe_property_base(node.object, defunct)
    if isinstance(node, (JsBinaryExpression, JsLogicalExpression)):
        return (
            node.left is not None and _is_side_effect_free(node.left, defunct)
            and node.right is not None and _is_side_effect_free(node.right, defunct)
        )
    if isinstance(node, JsConditionalExpression):
        return (
            node.test is not None and _is_side_effect_free(node.test, defunct)
            and node.consequent is not None and _is_side_effect_free(node.consequent, defunct)
            and node.alternate is not None and _is_side_effect_free(node.alternate, defunct)
        )
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                return False
            if prop.value is not None and not _is_side_effect_free(prop.value, defunct):
                return False
        return True
    if isinstance(node, JsArrayExpression):
        return all(
            elem is None or _is_side_effect_free(elem, defunct)
            for elem in node.elements
        )
    if isinstance(node, JsSequenceExpression):
        return all(_is_side_effect_free(e, defunct) for e in node.expressions)
    if isinstance(node, JsCallExpression):
        if defunct and isinstance(node.callee, JsIdentifier) and node.callee.name in defunct:
            return all(_is_side_effect_free(arg, defunct) for arg in node.arguments)
        if isinstance(node.callee, JsFunctionExpression):
            return all(_is_side_effect_free(arg, defunct) for arg in node.arguments)
    return False


class JsUnusedCodeRemoval(BodyProcessingTransformer):
    """
    Remove function declarations that are never referenced from live code, and remove assignments
    to variables that are never read in the outer scope.
    """

    def _process_body(self, parent: Node, body: list[Statement]):
        removed_functions = self._remove_dead_functions(body)
        dead_variables = self._remove_dead_variables(parent, body, removed_functions)
        self._remove_dead_expressions(body, removed_functions | dead_variables)

    def _remove_dead_functions(self, body: list[Statement]) -> set[str]:
        functions: dict[str, JsFunctionDeclaration] = {}
        for stmt in body:
            if isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
                functions[stmt.id.name] = stmt
        if not functions:
            return set()
        reachable = _reachable_functions(body, functions)
        unreachable = set(functions.keys()) - reachable
        if not unreachable:
            return set()
        non_func_stmts = [s for s in body if not isinstance(s, JsFunctionDeclaration)]
        if not non_func_stmts:
            return set()
        for name in unreachable:
            _remove_from_parent(functions[name])
        self.mark_changed()
        return unreachable

    def _remove_dead_variables(
        self, parent: Node, body: list[Statement], defunct: set[str],
    ) -> set[str]:
        """
        Remove assignments to variables that are never read in the outer scope. Handles both
        simple dead assignments and transitive chains where one dead variable is only read by
        another dead variable's RHS. Returns the set of dead variable names.
        """
        local_names = self._collect_local_names(parent, body)
        write_stmts: dict[str, list[JsExpressionStatement]] = {}
        for stmt in body:
            if not isinstance(stmt, JsExpressionStatement):
                continue
            expr = stmt.expression
            if not isinstance(expr, JsAssignmentExpression):
                continue
            if expr.operator != '=' or not isinstance(expr.left, JsIdentifier):
                continue
            name = expr.left.name
            if local_names is not None and name not in local_names:
                continue
            write_stmts.setdefault(name, []).append(stmt)
        if not write_stmts:
            return set()
        has_free_read: set[str] = set()
        read_in_assign: dict[str, set[str]] = {}
        for node in walk_scope(parent):
            if not isinstance(node, JsIdentifier):
                continue
            name = node.name
            if name not in write_stmts:
                continue
            if self._is_write_target(node):
                continue
            if self._is_binding_site(node):
                continue
            enclosing = self._enclosing_assignment_target(node)
            if enclosing is not None:
                read_in_assign.setdefault(name, set()).add(enclosing)
            else:
                has_free_read.add(name)
        dead: set[str] = set()
        for name in write_stmts:
            if name not in has_free_read and name not in read_in_assign:
                dead.add(name)
        changed = True
        while changed:
            changed = False
            for name, readers in read_in_assign.items():
                if name in dead or name in has_free_read:
                    continue
                if readers.issubset(dead):
                    dead.add(name)
                    changed = True
        if not dead:
            return set()
        all_defunct = defunct | dead
        for name in dead:
            for stmt in write_stmts[name]:
                expr = stmt.expression
                if not isinstance(expr, JsAssignmentExpression) or expr.right is None:
                    _remove_from_parent(stmt)
                    continue
                if _is_side_effect_free(expr.right, all_defunct):
                    _remove_from_parent(stmt)
                else:
                    stmt.expression = expr.right
                    expr.right.parent = stmt
        self._remove_empty_declarators(parent, body, dead)
        self.mark_changed()
        return dead

    def _remove_dead_expressions(self, body: list[Statement], defunct: set[str]):
        """
        Remove standalone expression statements that are side-effect-free given the set of
        known-removed names (removed functions and dead variables from this pass).
        """
        if not defunct:
            return
        for stmt in list(body):
            if not isinstance(stmt, JsExpressionStatement):
                continue
            if stmt.expression is None:
                continue
            if isinstance(stmt.expression, JsAssignmentExpression):
                continue
            if _is_side_effect_free(stmt.expression, defunct):
                _remove_from_parent(stmt)
                self.mark_changed()

    def _remove_empty_declarators(
        self, parent: Node, body: list[Statement], dead_names: set[str],
    ):
        """
        Remove `var X;` declarators (no initializer) for dead variable names or names that have
        no references in the outer scope. Variables used as `for-in` or `for-of` iteration targets
        are always considered referenced.
        """
        referenced: set[str] | None = None
        for stmt in list(body):
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in list(stmt.declarations):
                if not isinstance(decl, JsVariableDeclarator):
                    continue
                if not isinstance(decl.id, JsIdentifier):
                    continue
                if decl.init is not None:
                    continue
                name = decl.id.name
                if name in dead_names:
                    remove_declarator(decl)
                    continue
                if referenced is None:
                    referenced = set()
                    for node in walk_scope(parent):
                        if isinstance(node, JsIdentifier) and not self._is_binding_site(node):
                            referenced.add(node.name)
                        if (
                            isinstance(node, (JsForInStatement, JsForOfStatement))
                            and isinstance(node.left, JsIdentifier)
                        ):
                            referenced.add(node.left.name)
                if name not in referenced:
                    remove_declarator(decl)

    @staticmethod
    def _collect_local_names(parent: Node, body: list[Statement]) -> set[str] | None:
        """
        Collect names declared locally in this scope. Returns `None` for `JsScript` (top level)
        where all variables are local. For function bodies, returns parameter names, `var`, `let`,
        and `const` declarations.
        """
        if isinstance(parent, JsScript):
            return None
        names: set[str] = set()
        func_parent = parent.parent
        if isinstance(func_parent, (
            JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
        )):
            for p in func_parent.params:
                if isinstance(p, JsIdentifier):
                    names.add(p.name)
                else:
                    for n in p.walk():
                        if isinstance(n, JsIdentifier):
                            names.add(n.name)
        for stmt in body:
            for node in walk_scope(stmt):
                if isinstance(node, JsVariableDeclaration):
                    for decl in node.declarations:
                        if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                            names.add(decl.id.name)
        return names

    @staticmethod
    def _is_write_target(node: JsIdentifier) -> bool:
        """
        Return whether this identifier is a write target: the LHS of an assignment expression, or
        the iteration variable of a `for-in` / `for-of` statement.
        """
        p = node.parent
        if isinstance(p, JsAssignmentExpression) and p.left is node:
            return True
        if isinstance(p, (JsForInStatement, JsForOfStatement)) and p.left is node:
            return True
        return False

    @staticmethod
    def _is_binding_site(node: JsIdentifier) -> bool:
        """
        Return whether this identifier is in a binding position (variable declarator id or
        function declaration name) rather than a reference/read position.
        """
        p = node.parent
        if isinstance(p, JsVariableDeclarator) and p.id is node:
            return True
        if isinstance(p, JsFunctionDeclaration) and p.id is node:
            return True
        return False

    @staticmethod
    def _enclosing_assignment_target(node: JsIdentifier) -> str | None:
        """
        If *node* is read inside an assignment's RHS, return the target variable name.
        """
        cursor: Node = node
        while cursor.parent is not None:
            parent = cursor.parent
            if isinstance(parent, JsAssignmentExpression) and cursor is not parent.left:
                if isinstance(parent.left, JsIdentifier):
                    return parent.left.name
                return None
            if isinstance(parent, JsExpressionStatement):
                return None
            cursor = parent
        return None
