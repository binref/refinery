"""
Remove unreachable function declarations and unused variable assignments.

This transformer performs two phases:

1. **Dead function removal** — transitive reachability analysis: starting from non-function
   statements, it collects all function names referenced directly or transitively. Function
   declarations not in the reachable set are removed.

2. **Dead variable removal** — collects assignment targets that are never read anywhere in the
   enclosing function scope. Because `var` bindings are function-scoped, a name read through a
   closure in a nested function stays live unless that function shadows it. Dead assignment
   statements are removed, along with their hoisted `var` declarators when there is no initializer.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, _remove_from_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    GLOBAL_OBJECT_ALIASES,
    collect_identifier_names,
    function_binds_name,
    is_binding_site,
    is_reference,
    is_side_effect_free,
    is_write_target,
    property_key,
    remove_declarator,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsObjectPattern,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
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


def _pattern_target_names(left: Node) -> list[str] | None:
    """
    If *left* is a destructuring pattern composed entirely of plain identifier targets (`[a, b]` or
    `{a, b}`), return the list of target names. Returns `None` for anything with nesting, defaults,
    rest elements, holes, computed keys, or member-expression targets.
    """
    if isinstance(left, (JsArrayExpression, JsArrayPattern)):
        names: list[str] = []
        for elem in left.elements:
            if not isinstance(elem, JsIdentifier):
                return None
            names.append(elem.name)
        return names or None
    if isinstance(left, (JsObjectExpression, JsObjectPattern)):
        names = []
        for prop in left.properties:
            if not isinstance(prop, JsProperty) or prop.computed:
                return None
            if not isinstance(prop.value, JsIdentifier):
                return None
            names.append(prop.value.name)
        return names or None
    return None


def _destructuring_target_safe(left: Node, right: Node) -> bool:
    """
    Whether assigning *right* into the destructuring pattern *left* is guaranteed neither to throw
    nor to run observable code, even when *right* is side-effect-free as a plain expression. Array
    patterns require an iterable source, so only an array literal is accepted. Object patterns throw
    on `null`/`undefined` and additionally *read* their named keys from the source, so only an object
    literal whose members are all plain, statically-keyed data properties is accepted: a getter or
    setter, a computed key, or a `__proto__` member could execute code when the pattern is matched
    (and a computed key is not even covered by `is_side_effect_free`). Any other right-hand side is
    rejected conservatively.
    """
    if isinstance(left, (JsArrayExpression, JsArrayPattern)):
        return isinstance(right, JsArrayExpression)
    if isinstance(left, (JsObjectExpression, JsObjectPattern)):
        if not isinstance(right, JsObjectExpression):
            return False
        for prop in right.properties:
            if not isinstance(prop, JsProperty) or prop.computed:
                return False
            if prop.kind is not JsPropertyKind.INIT:
                return False
            if property_key(prop) == '__proto__':
                return False
        return True
    return False


def _in_assignment_target(node: JsIdentifier) -> bool:
    """
    Return whether *node* is a write-only target of a simple (`=`) assignment, including inside a
    destructuring pattern (`[a] = ...`, `{a} = ...`). Compound assignments (`a += 1`) read the
    target before writing, and `for-in`/`for-of` loop variables persist the binding into a surviving
    statement, so neither counts as a pure target here: both keep the name alive as a reference.
    Within a pattern property only the value position is a write target: a property key is never
    written, and a computed key (`{[a]: b} = ...`) is itself an ordinary read of `a` that must not
    be mistaken for a write.
    """
    cursor: Node = node
    parent = cursor.parent
    while parent is not None:
        if isinstance(parent, JsAssignmentExpression):
            return parent.operator == '=' and parent.left is cursor
        if isinstance(parent, JsProperty):
            if parent.value is not cursor:
                return False
            cursor = parent
            parent = cursor.parent
            continue
        if isinstance(parent, (
            JsArrayExpression, JsArrayPattern, JsObjectExpression, JsObjectPattern,
            JsRestElement,
        )):
            cursor = parent
            parent = cursor.parent
            continue
        return False
    return False


def _enclosing_scope_root(parent: Node) -> Node:
    """
    Return the node whose subtree spans the variable scope that *parent* belongs to: the nearest
    enclosing function body (a block whose parent is a function) or the script itself. Because `var`
    bindings are function-scoped, a name assigned inside a nested block (`if`/`for`/`while`/`try` or a
    bare `{}`) can be read anywhere in this scope, so read- and write-analysis must cover the whole
    scope rather than just the immediate block.
    """
    cursor = parent
    while True:
        grandparent = cursor.parent
        if grandparent is None or isinstance(grandparent, (
            JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
        )):
            return cursor
        cursor = grandparent


def _is_shadowed_within(node: Node, name: str, scope_root: Node) -> bool:
    """
    Whether *name*, used at *node*, is rebound by a function nested strictly inside *scope_root* —
    through a parameter, an inner function-declaration name, or a `var` declaration — so that the use
    resolves to that inner binding rather than to one in *scope_root*'s own scope. Only function
    boundaries between *node* and *scope_root* are considered: *scope_root*'s own scope is never a
    shadower, because its bindings are exactly the ones whose references are being counted.
    """
    cursor = node.parent
    while cursor is not None and cursor is not scope_root:
        if isinstance(cursor, (
            JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
        )) and function_binds_name(cursor, name):
            return True
        cursor = cursor.parent
    return False


def _within_nested_function(node: Node, scope_root: Node) -> bool:
    """
    Whether *node* lies inside a function nested below *scope_root*, i.e. a function boundary is
    crossed on the path from *node* up to *scope_root*. An identifier in such a position is a
    closure reference into *scope_root*'s scope rather than a direct use within it, so removing the
    binding it resolves to would change the closure's meaning.
    """
    cursor = node.parent
    while cursor is not None and cursor is not scope_root:
        if isinstance(cursor, (
            JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
        )):
            return True
        cursor = cursor.parent
    return False


def _scope_read_names(scope_root: Node) -> set[str]:
    """
    Names that appear in a non-binding position within *scope_root* (plus the targets of any
    `for-in`/`for-of` statements), restricted to references that resolve to *scope_root*'s own scope.
    The search descends into nested function bodies, because `var` bindings are function-scoped (and
    top-level bindings are global): a name captured by a closure stays live. A use that an inner
    function rebinds for itself is shadowed and therefore ignored.
    """
    names: set[str] = set()
    for node in scope_root.walk():
        if isinstance(node, JsIdentifier):
            if not is_binding_site(node) and not _is_shadowed_within(node, node.name, scope_root):
                names.add(node.name)
        elif (
            isinstance(node, (JsForInStatement, JsForOfStatement))
            and isinstance(node.left, JsIdentifier)
            and not _is_shadowed_within(node.left, node.left.name, scope_root)
        ):
            names.add(node.left.name)
    return names


def _script_scope_keep_names(script: JsScript) -> set[str]:
    """
    Names whose bare top-level declaration must be kept when removing unreferenced declarators at the
    script scope. Unlike `_scope_read_names`, which counts any non-shadowed use inside a nested
    function, this distinguishes uses that survive the declaration's removal. A name read at the top
    level is always kept, because execution order there cannot be assumed (a read may precede the
    write that would re-create it as an implicit global). A name read deep inside a function but never
    plainly assigned would become a free variable if the declaration went away, so it is kept too. A
    name that is read deep *and* re-created by a plain assignment is merely a redundant explicit form
    of an implicit global, so its hoisted declaration may be removed.
    """
    keep: set[str] = set()
    for node in walk_scope(script):
        if isinstance(node, JsIdentifier) and is_reference(node):
            keep.add(node.name)
        elif (
            isinstance(node, (JsForInStatement, JsForOfStatement))
            and isinstance(node.left, JsIdentifier)
        ):
            keep.add(node.left.name)
    read: set[str] = set()
    pure_assigned: set[str] = set()
    for node in script.walk():
        if not isinstance(node, JsIdentifier) or not is_reference(node):
            continue
        if _is_shadowed_within(node, node.name, script):
            continue
        if _in_assignment_target(node):
            pure_assigned.add(node.name)
        else:
            read.add(node.name)
    return keep | (read - pure_assigned)


class JsUnusedCodeRemoval(BodyProcessingTransformer):
    """
    Remove function declarations that are never referenced from live code, and remove assignments
    to variables that are never read in the outer scope.
    """

    self_converging = True

    def __init__(self, preserve_globals: bool = True):
        super().__init__()
        self._enclosing_cache: dict[int, set[str]] = {}
        self.preserve_globals = preserve_globals

    def _process_body(self, parent: Node, body: list[Statement]):
        removed_functions = self._remove_dead_functions(body)
        dead_variables, preserved = self._remove_dead_variables(parent, body, removed_functions)
        dead_variables |= self._remove_dead_destructuring(
            parent, body, removed_functions | dead_variables)
        if isinstance(parent, JsScript):
            dead_variables |= self._remove_dead_global_properties(parent, dead_variables)
        if not (self.preserve_globals and isinstance(_enclosing_scope_root(parent), JsScript)):
            self._remove_empty_declarators(parent, body, set())
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

        Reads are counted across the whole enclosing scope. At a function scope the scan descends
        into nested functions, so a closure read keeps the binding live. At the script scope it does
        not: a top-level binding that surviving code only reaches as an implicit-global use inside a
        function is still removable, matching the way such reads resolve to the global at runtime.
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
        scope_root = _enclosing_scope_root(parent)
        if isinstance(scope_root, JsScript):
            read_nodes = walk_scope(scope_root)
        else:
            read_nodes = scope_root.walk()
        for node in read_nodes:
            if not isinstance(node, JsIdentifier):
                continue
            name = node.name
            if name not in write_stmts:
                continue
            if is_binding_site(node):
                continue
            if _within_nested_function(node, scope_root):
                if not _is_shadowed_within(node, name, scope_root):
                    has_free_read.add(name)
                continue
            if is_write_target(node):
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

    def _remove_dead_destructuring(
        self, parent: Node, body: list[Statement], defunct: set[str],
    ) -> set[str]:
        """
        Remove destructuring-assignment statements (`[a, b] = rhs`) whose every target is a local
        name that is never read and whose right-hand side is side-effect-free. These arise from CFF
        recovery of vestigial state variables. Reads are counted across the whole enclosing function
        scope (including nested functions) so closure references and reads outside the immediate
        block conservatively keep a target alive.
        """
        local_names = self._collect_local_names(parent, body)
        candidates: list[tuple[JsExpressionStatement, list[str]]] = []
        for node in walk_scope(parent):
            if not isinstance(node, JsExpressionStatement):
                continue
            expr = node.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            targets = _pattern_target_names(expr.left)
            if not targets:
                continue
            if local_names is not None and any(t not in local_names for t in targets):
                continue
            if expr.right is None or not is_side_effect_free(expr.right, defunct):
                continue
            if not _destructuring_target_safe(expr.left, expr.right):
                continue
            candidates.append((node, targets))
        if not candidates:
            return set()
        scope_root = _enclosing_scope_root(parent)
        read_names: set[str] = set()
        for node in scope_root.walk():
            if not isinstance(node, JsIdentifier):
                continue
            if is_binding_site(node) or _in_assignment_target(node):
                continue
            read_names.add(node.name)
        removed: set[str] = set()
        for stmt, targets in candidates:
            if any(t in read_names for t in targets):
                continue
            _remove_from_parent(stmt)
            removed.update(targets)
        if not removed:
            return set()
        still_written = {
            node.name
            for node in scope_root.walk()
            if isinstance(node, JsIdentifier)
            and node.name in removed
            and _in_assignment_target(node)
        }
        dead = removed - still_written
        if dead:
            self._remove_empty_declarators(parent, body, dead)
        self.mark_changed()
        return dead

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
        no references in the enclosing scope. Also removes initialized declarators whose initializer
        is side-effect-free and whose name has no reads anywhere in the tree. Because `var` bindings
        are function-scoped, a name read inside a function scope is searched for across nested
        function bodies too, so a binding captured by a closure keeps its declaration. Variables used
        as `for-in` or `for-of` iteration targets are always considered referenced.

        At a function scope the reference set is the deep `_scope_read_names`. At the script scope the
        deep read of an implicit global from inside a function does not by itself keep its top-level
        declaration: `_script_scope_keep_names` keeps only names whose removal would change behavior
        (read at the top level, or read deep without ever being plainly assigned), so a redundant
        declaration of an implicit global that a function re-creates by assignment is still removed.
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
                        self.mark_changed()
                        continue
                    if referenced is None:
                        scope_root = _enclosing_scope_root(parent)
                        if isinstance(scope_root, JsScript):
                            referenced = _script_scope_keep_names(scope_root)
                        else:
                            referenced = _scope_read_names(scope_root)
                    if name not in referenced:
                        remove_declarator(decl)
                        self.mark_changed()
                else:
                    if referenced_deep is None:
                        referenced_deep = set()
                        for node in _enclosing_scope_root(parent).walk():
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
            names |= self._param_names(func_parent.params)
        names |= self._declared_names_in_scope(body)
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

    @staticmethod
    def _param_names(params: list) -> set[str]:
        """
        Names bound by a function's parameter list, including destructuring and default patterns.
        """
        names: set[str] = set()
        for p in params:
            if isinstance(p, JsIdentifier):
                names.add(p.name)
            else:
                for n in p.walk():
                    if isinstance(n, JsIdentifier):
                        names.add(n.name)
        return names

    @staticmethod
    def _declared_names_in_scope(body: list[Statement]) -> set[str]:
        """
        Names of all `var`/`let`/`const` declarators in *body*, descending into nested blocks but
        not into nested function scopes.
        """
        names: set[str] = set()
        for stmt in body:
            for node in walk_scope(stmt):
                if isinstance(node, JsVariableDeclaration):
                    for decl in node.declarations:
                        if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                            names.add(decl.id.name)
        return names

    def _gather_enclosing_declarations(self, func: Node) -> set[str]:
        """
        Collect the variable names bound in scopes enclosing `func`, up to and including the
        script scope: parameters and declarations of every enclosing function, plus the
        script's own declarations. Used to tell a truly-undeclared assignment target from an
        outer-scope variable a nested assignment writes through, so a closure assigning to a
        captured outer binding is not mistaken for a fresh local store and removed.
        """
        cached = self._enclosing_cache.get(id(func))
        if cached is not None:
            return cached
        declared: set[str] = set()
        cursor = func.parent
        while cursor is not None:
            if isinstance(cursor, (
                JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
            )):
                declared |= self._param_names(cursor.params)
                if isinstance(cursor.body, JsBlockStatement):
                    declared |= self._declared_names_in_scope(cursor.body.body)
            elif isinstance(cursor, JsScript):
                declared |= self._declared_names_in_scope(cursor.body)
                break
            cursor = cursor.parent
        self._enclosing_cache[id(func)] = declared
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
