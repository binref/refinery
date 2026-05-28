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
    GLOBAL_OBJECT_ALIASES,
    collect_identifier_names,
    is_binding_site,
    is_side_effect_free,
    is_write_target,
    remove_declarator,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsScript,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    Statement,
)


def _const_global_alias_names(root: Node) -> frozenset[str]:
    names: set[str] = set()
    for node in root.walk():
        if not isinstance(node, JsVariableDeclaration) or node.kind is not JsVarKind.CONST:
            continue
        for decl in node.declarations:
            if (
                isinstance(decl, JsVariableDeclarator)
                and isinstance(decl.id, JsIdentifier)
                and isinstance(decl.init, JsIdentifier)
                and decl.init.name in GLOBAL_OBJECT_ALIASES
            ):
                names.add(decl.id.name)
    return frozenset(names)


def _global_alias_read_names(root: Node, aliases: frozenset[str]) -> frozenset[str]:
    names: set[str] = set()
    for node in root.walk():
        if not isinstance(node, JsMemberExpression) or node.computed:
            continue
        if not isinstance(node.property, JsIdentifier):
            continue
        if not isinstance(node.object, JsIdentifier):
            continue
        p = node.parent
        if isinstance(p, JsAssignmentExpression) and p.left is node:
            continue
        if node.object.name in GLOBAL_OBJECT_ALIASES or node.object.name in aliases:
            names.add(node.property.name)
    return frozenset(names)


def _reachable_functions(
    body: list[Statement],
    functions: dict[str, JsFunctionDeclaration],
) -> tuple[set[str], dict[str, list[Statement]]]:
    """
    Compute the set of function names transitively reachable from non-function statements in
    *body*. A function is reachable if its name appears as any identifier in a reachable statement
    or in the body of another reachable function.

    Functions that are only referenced as the object of property-write statements
    (`funcName.prop = ...`) where neither the function nor its properties are read anywhere else
    are considered unreachable. Returns a `(set, dict)` pair: the set of reachable function
    names and a dict mapping each write-only function name to the statements that are its only
    references.
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
    write_only_stmts: dict[str, list[Statement]] = {}
    for name in list(reachable):
        if name not in functions:
            continue
        stmts = _classify_property_write_only(body, name)
        if stmts is not None:
            reachable.discard(name)
            write_only_stmts[name] = stmts
    return reachable, write_only_stmts


def _classify_property_write_only(
    body: list[Statement], func_name: str,
) -> list[Statement] | None:
    """
    Check if ALL non-function-declaration references to `func_name` in `body` are property-write
    statements (`funcName.prop = ...`) with no reads of the function or its properties elsewhere.
    Returns the list of write-only statements if so, or `None` if the function has live usage.
    """
    write_stmts: list[Statement] = []
    for stmt in body:
        if isinstance(stmt, JsFunctionDeclaration):
            continue
        names_in_stmt = collect_identifier_names(stmt)
        if func_name not in names_in_stmt:
            continue
        if not _is_pure_property_write(stmt, func_name):
            return None
        write_stmts.append(stmt)
    if not write_stmts:
        return None
    for stmt in body:
        if isinstance(stmt, JsFunctionDeclaration):
            continue
        if stmt in write_stmts:
            continue
        if _has_property_read(stmt, func_name):
            return None
    return write_stmts


def _is_pure_property_write(stmt: Statement, func_name: str) -> bool:
    """
    Return True if `stmt` is an expression statement of the form `funcName.prop = expr` where
    `func_name` does not appear in the RHS.
    """
    if not isinstance(stmt, JsExpressionStatement):
        return False
    expr = stmt.expression
    if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
        return False
    lhs = expr.left
    if not isinstance(lhs, JsMemberExpression):
        return False
    if not isinstance(lhs.object, JsIdentifier) or lhs.object.name != func_name:
        return False
    if expr.right is not None and func_name in collect_identifier_names(expr.right):
        return False
    return True


def _has_property_read(stmt: Statement, func_name: str) -> bool:
    """
    Return True if `stmt` contains a member-expression read on `func_name` (e.g. `funcName.prop`
    used in a non-assignment-target context).
    """
    for node in stmt.walk():
        if not isinstance(node, JsMemberExpression):
            continue
        if not isinstance(node.object, JsIdentifier) or node.object.name != func_name:
            continue
        parent = node.parent
        if isinstance(parent, JsAssignmentExpression) and parent.left is node:
            continue
        return True
    return False


class JsUnusedCodeRemoval(BodyProcessingTransformer):
    """
    Remove function declarations that are never referenced from live code, and remove assignments
    to variables that are never read in the outer scope.
    """

    self_converging = True

    def __init__(self):
        super().__init__()
        self._enclosing_cache: set[str] | None = None

    def _process_body(self, parent: Node, body: list[Statement]):
        removed_functions = self._remove_dead_functions(body)
        dead_variables, preserved = self._remove_dead_variables(parent, body, removed_functions)
        if isinstance(parent, JsScript):
            dead_variables |= self._remove_dead_global_properties(parent, dead_variables)
        self._remove_dead_expressions(body, removed_functions | dead_variables, preserved)

    def _remove_dead_functions(self, body: list[Statement]) -> set[str]:
        functions: dict[str, JsFunctionDeclaration] = {}
        for stmt in body:
            if isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
                functions[stmt.id.name] = stmt
        if not functions:
            return set()
        reachable, write_only_stmts = _reachable_functions(body, functions)
        unreachable = set(functions.keys()) - reachable
        if not unreachable:
            return set()
        non_func_stmts = [s for s in body if not isinstance(s, JsFunctionDeclaration)]
        if not non_func_stmts:
            return set()
        for name in unreachable:
            _remove_from_parent(functions[name])
            for stmt in write_only_stmts.get(name, ()):
                _remove_from_parent(stmt)
        self.mark_changed()
        return unreachable

    def _remove_dead_variables(
        self, parent: Node, body: list[Statement], defunct: set[str],
    ) -> tuple[set[str], set[JsExpressionStatement]]:
        """
        Remove assignments to variables that are never read in the outer scope. Handles both
        simple dead assignments and transitive chains where one dead variable is only read by
        another dead variable's RHS. Returns the set of dead variable names and the set of
        expression statements created by preserving side-effectful RHS expressions.
        """
        local_names = self._collect_local_names(parent, body)
        write_stmts: dict[str, list[JsExpressionStatement]] = {}
        for node in walk_scope(parent):
            if not isinstance(node, JsExpressionStatement):
                continue
            expr = node.expression
            if not isinstance(expr, JsAssignmentExpression):
                continue
            if expr.operator != '=' or not isinstance(expr.left, JsIdentifier):
                continue
            name = expr.left.name
            if local_names is not None and name not in local_names:
                continue
            write_stmts.setdefault(name, []).append(node)
        if not write_stmts:
            return set(), set()
        has_free_read: set[str] = set()
        read_in_assign: dict[str, set[str]] = {}
        for node in walk_scope(parent):
            if not isinstance(node, JsIdentifier):
                continue
            name = node.name
            if name not in write_stmts:
                continue
            if is_write_target(node):
                continue
            if is_binding_site(node):
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
            return set(), set()
        all_defunct = defunct | dead
        preserved: set[JsExpressionStatement] = set()
        for name in dead:
            for stmt in write_stmts[name]:
                expr = stmt.expression
                if not isinstance(expr, JsAssignmentExpression) or expr.right is None:
                    _remove_from_parent(stmt)
                    continue
                if is_side_effect_free(expr.right, all_defunct):
                    _remove_from_parent(stmt)
                else:
                    stmt.expression = expr.right
                    expr.right.parent = stmt
                    preserved.add(stmt)
        self._remove_empty_declarators(parent, body, dead)
        self.mark_changed()
        return dead, preserved

    def _remove_dead_global_properties(
        self, parent: JsScript, defunct: set[str],
    ) -> set[str]:
        """
        Remove global-property write statements (`global.x = value`) where property name `x` is
        never referenced anywhere in the script (not by any identifier or member expression).
        """
        write_stmts: dict[str, list[JsExpressionStatement]] = {}
        for node in walk_scope(parent):
            if not isinstance(node, JsExpressionStatement):
                continue
            expr = node.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            lhs = expr.left
            if (
                isinstance(lhs, JsMemberExpression)
                and not lhs.computed
                and isinstance(lhs.object, JsIdentifier)
                and isinstance(lhs.property, JsIdentifier)
                and lhs.object.name in GLOBAL_OBJECT_ALIASES
            ):
                write_stmts.setdefault(lhs.property.name, []).append(node)
        if not write_stmts:
            return set()
        aliases = _const_global_alias_names(parent)
        alias_reads = _global_alias_read_names(parent, aliases)
        bare_refs: set[str] = set()
        for node in parent.walk():
            if not isinstance(node, JsIdentifier) or node.name not in write_stmts:
                continue
            if is_binding_site(node):
                continue
            p = node.parent
            if isinstance(p, JsMemberExpression) and p.property is node and not p.computed:
                continue
            bare_refs.add(node.name)
        dead: set[str] = set()
        for name, stmts in write_stmts.items():
            if name in alias_reads or name in bare_refs:
                continue
            dead.add(name)
            for stmt in stmts:
                expr = stmt.expression
                if not isinstance(expr, JsAssignmentExpression) or expr.right is None:
                    _remove_from_parent(stmt)
                elif is_side_effect_free(expr.right, defunct | dead):
                    _remove_from_parent(stmt)
                else:
                    stmt.expression = expr.right
                    expr.right.parent = stmt
        if dead:
            self.mark_changed()
        return dead

    def _remove_dead_expressions(
        self, body: list[Statement], defunct: set[str], preserved: set[JsExpressionStatement],
    ):
        """
        Remove standalone expression statements that are side-effect-free given the set of
        known-removed names. Also iteratively discovers orphan functions: functions whose only
        live references are from preserved RHS statements (created by dead variable removal)
        that would be side-effect-free if the function were defunct.
        """
        functions: dict[str, JsFunctionDeclaration] = {}
        for stmt in body:
            if isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
                if stmt.id.name not in defunct:
                    functions[stmt.id.name] = stmt
        if functions and preserved:
            stmt_names: dict[int, set[str]] = {
                id(stmt): collect_identifier_names(stmt)
                for stmt in body
                if not isinstance(stmt, JsFunctionDeclaration)
            }
            extended = True
            while extended:
                extended = False
                for name, func in list(functions.items()):
                    if name in defunct:
                        continue
                    orphan = True
                    has_reference = False
                    for stmt in body:
                        if stmt is func:
                            continue
                        if isinstance(stmt, JsFunctionDeclaration):
                            continue
                        names_in_stmt = stmt_names.get(id(stmt), set())
                        if name not in names_in_stmt:
                            continue
                        has_reference = True
                        if stmt not in preserved:
                            orphan = False
                            break
                        if not isinstance(stmt, JsExpressionStatement):
                            orphan = False
                            break
                        if (
                            stmt.expression is None
                            or isinstance(stmt.expression, JsAssignmentExpression)
                            or not is_side_effect_free(stmt.expression, defunct | {name})
                        ):
                            orphan = False
                            break
                    if orphan and has_reference:
                        defunct.add(name)
                        extended = True
        if not defunct:
            return
        for stmt in list(body):
            if not isinstance(stmt, JsExpressionStatement):
                continue
            if stmt.expression is None:
                continue
            if isinstance(stmt.expression, JsAssignmentExpression):
                continue
            if is_side_effect_free(stmt.expression, defunct):
                _remove_from_parent(stmt)
                self.mark_changed()
        for name in defunct:
            if name in functions:
                _remove_from_parent(functions[name])
                self.mark_changed()

    def _remove_empty_declarators(
        self, parent: Node, body: list[Statement], dead_names: set[str],
    ):
        """
        Remove `var X;` declarators (no initializer) for dead variable names or names that have
        no references in the outer scope. Also removes initialized declarators whose initializer
        is side-effect-free and whose name has no reads anywhere in the tree. Variables used as
        `for-in` or `for-of` iteration targets are always considered referenced.
        """
        referenced: set[str] | None = None
        referenced_deep: set[str] | None = None
        for stmt in list(body):
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in list(stmt.declarations):
                if not isinstance(decl, JsVariableDeclarator):
                    continue
                if not isinstance(decl.id, JsIdentifier):
                    continue
                name = decl.id.name
                if decl.init is None:
                    if name in dead_names:
                        remove_declarator(decl)
                        continue
                    if referenced is None:
                        referenced = set()
                        for node in walk_scope(parent):
                            if isinstance(node, JsIdentifier) and not is_binding_site(node):
                                referenced.add(node.name)
                            if (
                                isinstance(node, (JsForInStatement, JsForOfStatement))
                                and isinstance(node.left, JsIdentifier)
                            ):
                                referenced.add(node.left.name)
                    if name not in referenced:
                        remove_declarator(decl)
                else:
                    if referenced_deep is None:
                        referenced_deep = set()
                        for node in parent.walk():
                            if isinstance(node, JsIdentifier) and not is_binding_site(node):
                                referenced_deep.add(node.name)
                    if name not in referenced_deep and is_side_effect_free(decl.init):
                        remove_declarator(decl)
                        self.mark_changed()

    def _collect_local_names(self, parent: Node, body: list[Statement]) -> set[str] | None:
        """
        Collect names declared locally in this scope. Returns `None` for `JsScript` (top level)
        where all variables are local. For function bodies, returns parameter names, `var`, `let`,
        and `const` declarations, plus undeclared assignment targets that don't shadow any name in
        enclosing scopes.
        """
        if isinstance(parent, JsScript):
            return None
        names: set[str] = set()
        func_parent = parent.parent
        is_function_body = isinstance(func_parent, (
            JsFunctionDeclaration,
            JsFunctionExpression,
            JsArrowFunctionExpression,
        ))
        if is_function_body:
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
        if is_function_body:
            enclosing = self._gather_enclosing_declarations(func_parent)
            for node in walk_scope(parent):
                if (
                    isinstance(node, JsExpressionStatement)
                    and isinstance(node.expression, JsAssignmentExpression)
                    and node.expression.operator == '='
                    and isinstance(node.expression.left, JsIdentifier)
                ):
                    name = node.expression.left.name
                    if name not in names and name not in enclosing:
                        names.add(name)
        return names

    def _gather_enclosing_declarations(self, func: Node) -> set[str]:
        """
        Collect all variable names declared in scopes enclosing `func` (up to and including the
        script scope). Used to distinguish truly-undeclared assignment targets from outer-scope
        variables.
        """
        if self._enclosing_cache is not None:
            return self._enclosing_cache
        declared: set[str] = set()
        cursor = func.parent
        while cursor is not None:
            if isinstance(cursor, JsScript):
                for stmt in cursor.body:
                    for node in walk_scope(stmt):
                        if isinstance(node, JsVariableDeclaration):
                            for decl in node.declarations:
                                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                                    declared.add(decl.id.name)
                break
            cursor = cursor.parent
        self._enclosing_cache = declared
        return declared

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
