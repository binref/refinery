"""
Inline constant variable references in JavaScript.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, _clone_node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.helpers import (
    FUNCTION_NODE_TYPES,
    ScopeProcessingTransformer,
    collect_identifier_names,
    get_body,
    is_literal,
    remove_declarator,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBlockStatement,
    JsCallExpression,
    JsClassExpression,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsScript,
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsYieldExpression,
)


def _pattern_identifiers(pattern: Node) -> set[str]:
    """
    Extract all identifier names from a destructuring pattern (array or object pattern). These are
    the variables being assigned to.
    """
    return {n.name for n in pattern.walk() if isinstance(n, JsIdentifier)}


class _BodyEntry(NamedTuple):
    body: list
    stmt_index: int


class _CandidateEntry(NamedTuple):
    declarator: JsVariableDeclarator | None
    value: Node
    scope: _BodyEntry | None


class _MemberArrayEntry(NamedTuple):
    assignment: JsAssignmentExpression
    array: JsArrayExpression
    scope: _BodyEntry | None


def _candidate_decl_ids(candidates: dict[str, list[_CandidateEntry]]) -> set[int]:
    """
    Collect the `id()` values of all declaration-site identifier nodes across candidate entries.
    Used to distinguish binding occurrences from reference occurrences during scope walks.
    """
    result: set[int] = set()
    for entries in candidates.values():
        for entry in entries:
            if (d := entry.declarator) is not None:
                result.add(id(d.id))
    return result


def _is_primitive_and_pure(node: Node) -> bool:
    """
    Return whether evaluating *node* is guaranteed to produce no observable side effects and the
    result is a primitive value (not an object, array, or function). This is stricter than
    `refinery.lib.scripts.js.deobfuscation.helpers.is_side_effect_free` — it rejects expressions
    that allocate objects or access properties, because inlining such expressions into a new
    location can change reference identity or trigger getters at a different point in execution.
    """
    for n in node.walk():
        if isinstance(n, (
            JsCallExpression,
            JsNewExpression,
            JsAssignmentExpression,
            JsUpdateExpression,
            JsYieldExpression,
            JsAwaitExpression,
            JsTaggedTemplateExpression,
            JsMemberExpression,
            JsObjectExpression,
            JsArrayExpression,
            JsFunctionExpression,
            JsArrowFunctionExpression,
            JsClassExpression,
        )):
            return False
    return True


def _count_scope_references(
    scope: Node,
    names: set[str],
    decl_ids: set[int],
    *,
    walk_full: bool = False,
    count_member_access: bool = False,
) -> dict[str, int]:
    """
    Count identifier references within *scope* for each name in *names*, excluding declaration
    sites in *decl_ids* and assignment write targets. When *walk_full* is True, the entire subtree
    is traversed (including nested function bodies); otherwise only the current scope is walked.
    When *count_member_access* is True, computed member accesses like `name[idx]` are counted
    separately (the identifier inside the member is counted and the walk continues so the member
    node itself is not double-counted).
    """
    walker = scope.walk() if walk_full else walk_scope(scope, include_root_body=True)
    counts: dict[str, int] = {}
    for node in walker:
        if count_member_access and isinstance(node, JsMemberExpression) and node.computed:
            obj = node.object
            if isinstance(obj, JsIdentifier) and id(obj) not in decl_ids and obj.name in names:
                counts[obj.name] = counts.get(obj.name, 0) + 1
                continue
        if not isinstance(node, JsIdentifier):
            continue
        if id(node) in decl_ids:
            continue
        name = node.name
        if name not in names:
            continue
        parent = node.parent
        if isinstance(parent, JsAssignmentExpression) and parent.left is node:
            continue
        if count_member_access:
            if isinstance(parent, JsMemberExpression) and parent.object is node and parent.computed:
                continue
        counts[name] = counts.get(name, 0) + 1
    return counts


def _is_literal_array(node: Node) -> bool:
    """
    Return whether *node* is a `refinery.lib.scripts.js.model.JsArrayExpression` where every element
    is a literal.
    """
    if not isinstance(node, JsArrayExpression):
        return False
    return all(el is not None and is_literal(el) for el in node.elements)


def _function_local_names(func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression) -> set[str]:
    """
    Collect names declared locally inside a function: parameter names, `var` declarations
    (function-scoped), and top-level `let`/`const` declarations. Inner-block `let`/`const`
    are block-scoped and do not shadow variables at the function level.
    """
    local_names: set[str] = set()
    for p in func.params:
        if isinstance(p, JsIdentifier):
            local_names.add(p.name)
        else:
            for n in p.walk():
                if isinstance(n, JsIdentifier):
                    local_names.add(n.name)
    if func.body is not None:
        for n in func.body.walk():
            if isinstance(n, JsVariableDeclaration) and n.kind is JsVarKind.VAR:
                for d in n.declarations:
                    if isinstance(d, JsVariableDeclarator) and isinstance(d.id, JsIdentifier):
                        local_names.add(d.id.name)
            if isinstance(n, FUNCTION_NODE_TYPES) and n is not func:
                if isinstance(n, JsFunctionDeclaration) and n.id is not None:
                    local_names.add(n.id.name)
        if isinstance(func.body, JsBlockStatement):
            for stmt in func.body.body:
                if (
                    isinstance(stmt, JsVariableDeclaration)
                    and stmt.kind in (JsVarKind.LET, JsVarKind.CONST)
                ):
                    for d in stmt.declarations:
                        if isinstance(d, JsVariableDeclarator) and isinstance(d.id, JsIdentifier):
                            local_names.add(d.id.name)
    return local_names


def _compute_function_mods(scope: Node) -> dict[str, set[str]]:
    """
    For each function defined at the top level of *scope* — a function declaration, or a function
    expression or arrow function bound to a `var`/`let`/`const` declarator — compute the set of
    outer-scope variable names it can modify (directly or transitively through calls to other known
    functions). A call to such a function then seals those variables, so a closure assigning to a
    captured variable (`var set = function(){ x = 2; }; set();`) is not inlined past the call.
    """
    functions: dict[str, JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression] = {}
    body = getattr(scope, 'body', None)
    if not isinstance(body, list):
        return {}
    for stmt in body:
        if isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
            functions[stmt.id.name] = stmt
        elif isinstance(stmt, JsVariableDeclaration):
            for decl in stmt.declarations:
                if (
                    isinstance(decl, JsVariableDeclarator)
                    and isinstance(decl.id, JsIdentifier)
                    and isinstance(decl.init, (JsFunctionExpression, JsArrowFunctionExpression))
                ):
                    functions[decl.id.name] = decl.init
    if not functions:
        return {}

    direct_mods: dict[str, set[str]] = {}
    calls: dict[str, set[str]] = {}

    for fname, func in functions.items():
        locals_ = _function_local_names(func)
        mods: set[str] = set()
        callees: set[str] = set()
        if func.body is None:
            direct_mods[fname] = mods
            calls[fname] = callees
            continue
        for node in func.body.walk():
            if isinstance(node, JsAssignmentExpression) and isinstance(node.left, JsIdentifier):
                name = node.left.name
                if name not in locals_:
                    mods.add(name)
            elif isinstance(node, JsAssignmentExpression) and isinstance(
                node.left, (JsArrayPattern, JsObjectPattern),
            ):
                for name in _pattern_identifiers(node.left):
                    if name not in locals_:
                        mods.add(name)
            elif isinstance(node, JsUpdateExpression) and isinstance(node.argument, JsIdentifier):
                if node.argument.name not in locals_:
                    mods.add(node.argument.name)
            elif isinstance(node, (JsForInStatement, JsForOfStatement)):
                if isinstance(node.left, JsIdentifier) and node.left.name not in locals_:
                    mods.add(node.left.name)
            if isinstance(node, JsCallExpression) and isinstance(node.callee, JsIdentifier):
                callee_name = node.callee.name
                if callee_name in functions and callee_name != fname:
                    callees.add(callee_name)
        direct_mods[fname] = mods
        calls[fname] = callees

    result: dict[str, set[str]] = {fname: set(mods) for fname, mods in direct_mods.items()}
    changed = True
    while changed:
        changed = False
        for fname, callees in calls.items():
            before = len(result[fname])
            for callee in callees:
                result[fname] |= result.get(callee, set())
            if len(result[fname]) > before:
                changed = True

    return result


def _is_member_array_safe(scope: Node, prefix_name: str, prop_name: str) -> bool:
    """
    Verify that `prefix.prop` (a member-expression array) is never mutated after its initial
    assignment. Checks that: (1) the property is never written to via element assignment
    (`prefix.prop[i] = ...`), (2) the property value is never passed as an argument or assigned
    to another variable (aliased), (3) no method calls that could mutate the array exist
    (`prefix.prop.push(...)` etc.).
    """
    for node in scope.walk():
        if not isinstance(node, JsMemberExpression):
            continue
        if node.object is None or node.property is None:
            continue
        obj = node.object
        if not isinstance(obj, JsIdentifier) or obj.name != prefix_name:
            continue
        if not isinstance(node.property, JsIdentifier) or node.property.name != prop_name:
            continue
        parent = node.parent
        if isinstance(parent, JsMemberExpression) and parent.object is node:
            if parent.computed:
                gp = parent.parent
                if isinstance(gp, JsAssignmentExpression) and gp.left is parent:
                    return False
            else:
                gp = parent.parent
                if isinstance(gp, JsCallExpression) and gp.callee is parent:
                    return False
            continue
        if isinstance(parent, JsAssignmentExpression) and parent.left is node:
            continue
        if isinstance(parent, JsCallExpression):
            if parent.callee is not node:
                return False
    return True


def _is_constant_value(node: Node) -> bool:
    """
    Return whether *node* is a constant value eligible for multi-use inlining: a scalar literal or
    an all-literal array.
    """
    return is_literal(node) or _is_literal_array(node)


def _is_const_qualified(declarator: JsVariableDeclarator) -> bool:
    """
    Return whether a declarator belongs to a `const` declaration.
    """
    parent = declarator.parent
    return isinstance(parent, JsVariableDeclaration) and parent.kind is JsVarKind.CONST


def _find_body_entry(node: Node) -> _BodyEntry | None:
    """
    Walk upward from *node* and return the first `_BodyEntry` where the node (or an ancestor)
    appears as an entry in a parent's body list.
    """
    entries = _find_all_body_entries(node)
    return entries[0] if entries else None


def _find_all_body_entries(node: Node) -> list[_BodyEntry]:
    """
    Walk upward from *node* and return a body-list position at every ancestor level.
    """
    result: list[_BodyEntry] = []
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        body = get_body(parent)
        if body is not None:
            for idx, entry in enumerate(body):
                if entry is cursor:
                    result.append(_BodyEntry(body, idx))
                    break
        cursor = parent
    return result


def _find_dominating_entry(
    node: Node,
    entries: list[_CandidateEntry],
    seal_points: list[_BodyEntry] | None = None,
) -> _CandidateEntry | None:
    """
    For a variable reference, find the assignment entry that dominates it. When multiple constant
    assignments exist, pick the latest one whose scope position precedes the reference without any
    seal point intervening.
    """
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        body = get_body(parent)
        if body is None:
            cursor = parent
            continue
        ref_idx: int | None = None
        for idx, entry in enumerate(body):
            if entry is cursor:
                ref_idx = idx
                break
        if ref_idx is not None:
            best: _CandidateEntry | None = None
            best_idx = -1
            for candidate_entry in entries:
                scope = candidate_entry.scope
                if scope is None:
                    continue
                if scope.body is body and scope.stmt_index < ref_idx and scope.stmt_index > best_idx:
                    best = candidate_entry
                    best_idx = scope.stmt_index
            if best is not None and seal_points:
                for sp in seal_points:
                    if sp.body is body and best_idx < sp.stmt_index <= ref_idx:
                        best = None
                        break
            if best is not None:
                return best
        cursor = parent
    if not entries:
        return None
    for candidate_entry in entries:
        if candidate_entry.scope is None:
            return candidate_entry
    return None


class JsConstantInlining(ScopeProcessingTransformer):
    """
    Inline variables that are assigned once and never mutated. Literal-valued variables are inlined
    at all use sites; single-use variables with side-effect-free initializers are inlined when no
    intervening mutation could alter the referenced identifiers. All-literal arrays declared with
    `const` are inlined element-by-element when accessed with numeric literal indices.
    """

    def __init__(self, max_inline_length: int = 64):
        super().__init__()
        self.max_inline_length = max_inline_length
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_scope(self, scope: Node) -> None:
        func_mods = _compute_function_mods(scope)
        while True:
            candidates, seal_points, mutated = self._collect_candidates(scope, func_mods)
            member_arrays = self._collect_member_array_candidates(scope)
            if not candidates and not member_arrays:
                return
            inlined = self._substitute_constants(scope, candidates, seal_points, func_mods)
            if member_arrays:
                self._substitute_member_arrays(scope, member_arrays, inlined)
            if inlined:
                self._remove_dead(scope, candidates, inlined)
                self._remove_dead_member_arrays(scope, member_arrays, inlined)
                continue
            inlined = self._substitute_expressions(
                scope, candidates, mutated, seal_points,
            )
            if inlined:
                self._remove_dead(scope, candidates, inlined)
                continue
            return

    @staticmethod
    def _collect_candidates(
        scope: Node,
        func_mods: dict[str, set[str]],
    ) -> tuple[dict[str, list[_CandidateEntry]], dict[str, list[_BodyEntry]], set[str]]:
        """
        Collect constant declaration entries per variable. Each entry is a `_CandidateEntry` of

            (declarator, constant_value, scope_entry)

        Also returns seal points (positions of non-constant `=` assignments) and the set of fully
        rejected (mutated) names.
        """
        candidates: dict[str, list[_CandidateEntry]] = {}
        seal_points: dict[str, list[_BodyEntry]] = {}
        rejected: set[str] = set()
        uninitialized: dict[str, JsVariableDeclarator] = {}

        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        continue
                    name = decl.id.name
                    if name in rejected:
                        continue
                    if decl.init is None:
                        if name not in candidates:
                            uninitialized[name] = decl
                        continue
                    if name in candidates:
                        rejected.add(name)
                        candidates.pop(name, None)
                        uninitialized.pop(name, None)
                        continue
                    if _is_constant_value(decl.init):
                        entry = _find_body_entry(node)
                        candidates[name] = [_CandidateEntry(decl, decl.init, entry)]
                    else:
                        entry = _find_body_entry(node)
                        seal_points.setdefault(name, []).extend(_find_all_body_entries(node))
                        candidates[name] = [_CandidateEntry(decl, decl.init, entry)]
                    uninitialized.pop(name, None)

            if isinstance(node, JsAssignmentExpression):
                if isinstance(node.left, JsIdentifier):
                    name = node.left.name
                    if name in uninitialized and name not in candidates and name not in rejected:
                        decl = uninitialized.pop(name)
                        rhs = node.right
                        if rhs is None:
                            rejected.add(name)
                        elif _is_constant_value(rhs):
                            entry = _find_body_entry(node)
                            candidates[name] = [_CandidateEntry(decl, rhs, entry)]
                        else:
                            entry = _find_body_entry(node)
                            seal_points.setdefault(name, []).extend(_find_all_body_entries(node))
                            candidates[name] = [_CandidateEntry(decl, rhs, entry)]
                    else:
                        rejected.add(name)
                        candidates.pop(name, None)
                        uninitialized.pop(name, None)
                elif isinstance(node.left, (JsArrayPattern, JsObjectPattern)):
                    for name in _pattern_identifiers(node.left):
                        rejected.add(name)
                        candidates.pop(name, None)
                        uninitialized.pop(name, None)

            if isinstance(node, JsUpdateExpression) and isinstance(node.argument, JsIdentifier):
                name = node.argument.name
                rejected.add(name)
                candidates.pop(name, None)

            if isinstance(node, (JsForInStatement, JsForOfStatement)):
                if isinstance(node.left, JsIdentifier):
                    name = node.left.name
                    rejected.add(name)
                    candidates.pop(name, None)

            if isinstance(node, JsCallExpression) and isinstance(node.callee, JsIdentifier):
                callee_name = node.callee.name
                mods = func_mods.get(callee_name)
                if mods:
                    call_entries = _find_all_body_entries(node)
                    for modified_var in mods:
                        if modified_var in candidates:
                            seal_points.setdefault(modified_var, []).extend(call_entries)

        return candidates, seal_points, rejected

    def _substitute_constants(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
        seal_points: dict[str, list[_BodyEntry]],
        func_mods: dict[str, set[str]],
    ) -> dict[str, int]:
        """
        Inline constant (literal and literal-array) variable references using domination. Handles
        both scalar references and computed index access into all-literal arrays.
        """
        inlined: dict[str, int] = {}
        bloat_blocked: set[str] = set()

        decl_ids = _candidate_decl_ids(candidates)
        ref_counts = _count_scope_references(
            scope, set(candidates), decl_ids, count_member_access=True,
        )

        for name, entries in candidates.items():
            if len(entries) != 1:
                continue
            value = entries[0].value
            count = ref_counts.get(name, 0)
            if count <= 1:
                continue
            if isinstance(value, JsStringLiteral) and len(value.value) > self.max_inline_length:
                bloat_blocked.add(name)

        constant_names = {
            name for name, entries in candidates.items()
            if any(_is_constant_value(e.value) for e in entries)
        }
        if not constant_names:
            return inlined

        for node in list(walk_scope(scope, include_root_body=True)):
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if (
                    isinstance(obj, JsIdentifier)
                    and id(obj) not in decl_ids
                    and obj.name in constant_names
                    and obj.name not in bloat_blocked
                ):
                    self._try_inline_index(
                        node, obj.name, candidates, seal_points, inlined,
                    )
                    continue
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            name = node.name
            if name not in constant_names or name in bloat_blocked:
                continue
            parent = node.parent
            if isinstance(parent, JsAssignmentExpression) and parent.left is node:
                continue
            if isinstance(parent, JsMemberExpression) and parent.object is node and parent.computed:
                continue
            entries = candidates[name]
            if not any(is_literal(e.value) for e in entries):
                continue
            sp = seal_points.get(name)
            entry = _find_dominating_entry(node, entries, sp)
            if entry is None or not is_literal(entry.value):
                continue
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1

        self._substitute_const_across_functions(
            scope, candidates, seal_points, decl_ids, bloat_blocked, func_mods, inlined,
        )

        return inlined

    def _try_inline_index(
        self,
        member: JsMemberExpression,
        name: str,
        candidates: dict[str, list[_CandidateEntry]],
        seal_points: dict[str, list[_BodyEntry]],
        inlined: dict[str, int],
    ) -> None:
        """
        Try to resolve `name[numericLiteral]` to the corresponding array element.
        """
        sp = seal_points.get(name)
        entry = _find_dominating_entry(member, candidates[name], sp)
        if entry is not None:
            self._apply_index_access_inline(member, entry, name, inlined)

    def _apply_index_access_inline(
        self,
        member: JsMemberExpression,
        entry: _CandidateEntry,
        name: str,
        inlined: dict[str, int],
    ) -> None:
        prop = member.property
        if not isinstance(prop, JsNumericLiteral):
            return
        idx = int(prop.value)
        value = entry.value
        if not isinstance(value, JsArrayExpression):
            return
        if not (0 <= idx < len(value.elements)):
            return
        element = value.elements[idx]
        if element is None or not is_literal(element):
            return
        _replace_in_parent(member, _clone_node(element))
        self.mark_changed()
        inlined[name] = inlined.get(name, 0) + 1

    def _substitute_const_across_functions(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
        seal_points: dict[str, list[_BodyEntry]],
        decl_ids: set[int],
        bloat_blocked: set[str],
        func_mods: dict[str, set[str]],
        inlined: dict[str, int],
    ) -> None:
        """
        For constant-valued candidates, walk the full subtree to inline references inside nested
        function bodies. `const`-qualified candidates are inlined unconditionally (they cannot be
        reassigned). `var`/`let`-qualified candidates are inlined only into functions that are
        actually called in the current scope and that do not modify the variable (per the mod/ref
        analysis). The call-site requirement prevents inlining into functions that may be invoked
        from elsewhere with a different value for the variable.
        """
        cross_candidates: dict[str, list[_CandidateEntry]] = {}
        const_names: set[str] = set()
        for name, entries in candidates.items():
            if name in bloat_blocked:
                continue
            if len(entries) != 1:
                continue
            entry = entries[0]
            if entry.declarator is None:
                continue
            if not _is_constant_value(entry.value):
                continue
            cross_candidates[name] = entries
            if _is_const_qualified(entry.declarator) or entry.declarator.init is None:
                const_names.add(name)

        if not cross_candidates:
            return

        assert self._root is not None
        model = build_semantic_model(self._root)
        outer = model.scope_of(scope)
        assert outer is not None

        called_functions: set[str] = set()
        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsCallExpression) and isinstance(node.callee, JsIdentifier):
                called_functions.add(node.callee.name)

        for node in list(scope.walk()):
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if (
                    isinstance(obj, JsIdentifier)
                    and id(obj) not in decl_ids
                    and obj.name in cross_candidates
                ):
                    name = obj.name
                    if name in const_names:
                        enclosing = self._enclosing_function_name(obj, func_mods)
                        if enclosing is None:
                            continue
                        if model.is_shadowed(name, obj, outer):
                            continue
                        self._apply_index_access_inline(
                            node, cross_candidates[name][0], name, inlined,
                        )
                    else:
                        enclosing = self._enclosing_function_name(obj, func_mods)
                        if (
                            enclosing is None
                            or enclosing not in called_functions
                            or name in func_mods.get(enclosing, set())
                        ):
                            continue
                        if model.is_shadowed(name, obj, outer):
                            continue
                        self._try_inline_index(
                            node, name, cross_candidates, seal_points, inlined,
                        )
                    continue
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            name = node.name
            if name not in cross_candidates:
                continue
            parent = node.parent
            if isinstance(parent, JsAssignmentExpression) and parent.left is node:
                continue
            if isinstance(parent, JsMemberExpression) and parent.object is node and parent.computed:
                continue
            if isinstance(parent, JsVariableDeclarator) and parent.id is node:
                continue
            if isinstance(parent, (JsFunctionDeclaration, JsFunctionExpression)) and parent.id is node:
                continue
            entry = cross_candidates[name][0]
            if not is_literal(entry.value):
                continue
            enclosing = self._enclosing_function_name(node, func_mods)
            if name in const_names:
                if enclosing is None:
                    continue
            elif (
                enclosing is None
                or enclosing not in called_functions
                or name in func_mods.get(enclosing, set())
            ):
                continue
            if model.is_shadowed(name, node, outer):
                continue
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1

    @staticmethod
    def _enclosing_function_name(
        node: Node,
        func_mods: dict[str, set[str]],
    ) -> str | None:
        """
        Walk upward from *node* to find the innermost enclosing function whose name appears in
        *func_mods*. For unnamed function expressions, returns a sentinel to indicate the reference
        is inside a nested function body (enabling const-qualified cross-function inlining).
        """
        cursor = node.parent
        while cursor is not None:
            if isinstance(cursor, JsFunctionDeclaration) and cursor.id is not None:
                if cursor.id.name in func_mods:
                    return cursor.id.name
                return ''
            if isinstance(cursor, (JsFunctionExpression, JsArrowFunctionExpression)):
                return ''
            cursor = cursor.parent
        return None

    def _substitute_expressions(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
        mutated: set[str],
        seal_points: dict[str, list[_BodyEntry]],
    ) -> dict[str, int]:
        """
        Inline single-use, side-effect-free, non-literal expressions. This is the second pass that
        runs after constant inlining and preserves the existing behavior.
        """
        decl_ids = _candidate_decl_ids(candidates)
        ref_counts = _count_scope_references(scope, set(candidates), decl_ids)

        to_inline: dict[str, _CandidateEntry] = {}
        for name, entries in candidates.items():
            if len(entries) != 1:
                continue
            entry = entries[0]
            init = entry.value
            count = ref_counts.get(name, 0)
            if is_literal(init) or _is_literal_array(init) or count != 1:
                continue
            if not _is_primitive_and_pure(init):
                continue
            if collect_identifier_names(init) & mutated:
                continue
            to_inline[name] = entry

        if not to_inline:
            return {}

        inlined: dict[str, int] = {}
        for node in list(walk_scope(scope, include_root_body=True)):
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            name = node.name
            if name not in to_inline:
                continue
            parent = node.parent
            if isinstance(parent, JsAssignmentExpression) and parent.left is node:
                continue
            entry = to_inline[name]
            if entry.scope is not None:
                assign_body, assign_idx = entry.scope
                ref_entry = _find_body_entry(node)
                if ref_entry is None or ref_entry[0] is not assign_body or ref_entry[1] <= assign_idx:
                    continue
                sp = seal_points.get(name)
                if sp is not None:
                    ref_idx = ref_entry[1]
                    sealed = any(
                        sp_body is assign_body and assign_idx < sp_idx <= ref_idx
                        for sp_body, sp_idx in sp
                    )
                    if sealed:
                        continue
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1
        return inlined

    def _remove_dead(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
        inlined: dict[str, int],
    ) -> None:
        """
        Remove declarators for variables where all references have been inlined. For `const`
        qualified candidates, check the full subtree since cross-function inlining may have
        replaced references inside nested functions.
        """
        decl_ids = _candidate_decl_ids(candidates)
        ref_counts = _count_scope_references(
            scope, set(inlined), decl_ids, walk_full=True,
        )

        for name in inlined:
            remaining = ref_counts.get(name, 0)
            if remaining > 0:
                continue
            entries = candidates.get(name)
            if entries is None:
                continue
            for entry in entries:
                if entry.declarator is None:
                    continue
                remove_declarator(entry.declarator)
                self.mark_changed()

    @staticmethod
    def _collect_member_array_candidates(scope: Node) -> dict[str, _MemberArrayEntry]:
        """
        Collect member-expression assignments of all-literal arrays: `X.Y = [literals...]`.
        Returns a dict keyed by `"X.Y"` to `_MemberArrayEntry`. Only single-assignment,
        non-aliased properties qualify.
        """
        candidates: dict[str, _MemberArrayEntry] = {}
        rejected: set[str] = set()
        prefix_rejected: set[str] = set()

        for node in walk_scope(scope, include_root_body=True):
            if not isinstance(node, JsAssignmentExpression) or node.operator != '=':
                continue
            lhs = node.left
            if not isinstance(lhs, JsMemberExpression) or lhs.computed:
                continue
            if not isinstance(lhs.object, JsIdentifier) or not isinstance(lhs.property, JsIdentifier):
                continue
            key = F'{lhs.object.name}.{lhs.property.name}'
            if key in rejected:
                continue
            rhs = node.right
            if not isinstance(rhs, JsArrayExpression) or not _is_literal_array(rhs):
                rejected.add(key)
                candidates.pop(key, None)
                continue
            if key in candidates:
                rejected.add(key)
                candidates.pop(key)
                continue
            entry = _find_body_entry(node)
            candidates[key] = _MemberArrayEntry(node, rhs, entry)

        if not candidates:
            return candidates

        prefix_names = {k.split('.', 1)[0] for k in candidates}
        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsAssignmentExpression) and node.operator == '=':
                if isinstance(node.left, JsIdentifier) and node.left.name in prefix_names:
                    prefix_rejected.add(node.left.name)
            if isinstance(node, JsUpdateExpression) and isinstance(node.argument, JsIdentifier):
                if node.argument.name in prefix_names:
                    prefix_rejected.add(node.argument.name)

        if prefix_rejected:
            candidates = {
                k: v for k, v in candidates.items()
                if k.split('.', 1)[0] not in prefix_rejected
            }

        for key in list(candidates):
            prefix, prop = key.split('.', 1)
            if not _is_member_array_safe(scope, prefix, prop):
                del candidates[key]

        return candidates

    def _substitute_member_arrays(
        self,
        scope: Node,
        member_arrays: dict[str, _MemberArrayEntry],
        inlined: dict[str, int],
    ) -> None:
        """
        Inline `X.Y[N]` → element for all collected member-array candidates. Walks the full
        subtree (including nested function bodies) since these arrays are scope-level constants.
        """
        for node in list(scope.walk()):
            if not isinstance(node, JsMemberExpression) or not node.computed:
                continue
            prop = node.property
            if not isinstance(prop, JsNumericLiteral):
                continue
            obj = node.object
            if not isinstance(obj, JsMemberExpression) or obj.computed:
                continue
            if not isinstance(obj.object, JsIdentifier) or not isinstance(obj.property, JsIdentifier):
                continue
            key = F'{obj.object.name}.{obj.property.name}'
            entry = member_arrays.get(key)
            if entry is None:
                continue
            idx = int(prop.value)
            if not (0 <= idx < len(entry.array.elements)):
                continue
            element = entry.array.elements[idx]
            if element is None or not is_literal(element):
                continue
            _replace_in_parent(node, _clone_node(element))
            self.mark_changed()
            inlined[key] = inlined.get(key, 0) + 1

    def _remove_dead_member_arrays(
        self,
        scope: Node,
        member_arrays: dict[str, _MemberArrayEntry],
        inlined: dict[str, int],
    ) -> None:
        """
        Remove the assignment statement for member arrays where all references were inlined.
        """
        remaining: dict[str, int] = {}
        for node in scope.walk():
            if not isinstance(node, JsMemberExpression) or not node.computed:
                continue
            obj = node.object
            if not isinstance(obj, JsMemberExpression) or obj.computed:
                continue
            if not isinstance(obj.object, JsIdentifier) or not isinstance(obj.property, JsIdentifier):
                continue
            key = F'{obj.object.name}.{obj.property.name}'
            if key in member_arrays:
                remaining[key] = remaining.get(key, 0) + 1

        for key, entry in member_arrays.items():
            if key not in inlined:
                continue
            if remaining.get(key, 0) > 0:
                continue
            stmt = entry.assignment.parent
            if isinstance(stmt, JsExpressionStatement):
                _remove_from_parent(stmt)
                self.mark_changed()
