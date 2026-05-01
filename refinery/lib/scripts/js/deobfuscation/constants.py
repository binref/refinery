"""
Inline constant variable references in JavaScript.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, _clone_node, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
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
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsUpdateExpression,
    JsVarKind,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsYieldExpression,
)

_FUNCTION_NODES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)


def _pattern_identifiers(pattern: Node) -> set[str]:
    """
    Extract all identifier names from a destructuring pattern (array or object pattern). These are
    the variables being assigned to.
    """
    return {n.name for n in pattern.walk() if isinstance(n, JsIdentifier)}


class _CandidateEntry(NamedTuple):
    declarator: JsVariableDeclarator | None
    value: Node
    scope: tuple[list, int] | None


def _is_primitive_and_pure(node: Node) -> bool:
    """
    Return whether evaluating *node* is guaranteed to produce no observable side effects and
    the result is a primitive value (not an object, array, or function).
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


def _is_literal_array(node: Node) -> bool:
    """
    Return whether *node* is a `JsArrayExpression` where every element is a literal.
    """
    if not isinstance(node, JsArrayExpression):
        return False
    return all(el is not None and is_literal(el) for el in node.elements)


def _function_local_names(func: JsFunctionDeclaration) -> set[str]:
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
            if isinstance(n, _FUNCTION_NODES) and n is not func:
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
    For each function declaration at the top level of *scope*, compute the set of outer-scope
    variable names it can modify (directly or transitively through calls to other known functions).
    """
    functions: dict[str, JsFunctionDeclaration] = {}
    body = getattr(scope, 'body', None)
    if not isinstance(body, list):
        return {}
    for stmt in body:
        if isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
            functions[stmt.id.name] = stmt
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


def _find_body_entry(node: Node) -> tuple[list, int] | None:
    """
    Walk upward from *node* and return the first `(body_list, index)` where the node (or an
    ancestor) appears as an entry in a parent's body list.
    """
    entries = _find_all_body_entries(node)
    return entries[0] if entries else None


def _find_all_body_entries(node: Node) -> list[tuple[list, int]]:
    """
    Walk upward from *node* and return a body-list position at every ancestor level.
    """
    result: list[tuple[list, int]] = []
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        body = get_body(parent)
        if body is not None:
            for idx, entry in enumerate(body):
                if entry is cursor:
                    result.append((body, idx))
                    break
        cursor = parent
    return result


def _find_dominating_entry(
    node: Node,
    entries: list[_CandidateEntry],
    seal_points: list[tuple[list, int]] | None = None,
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
                assign_body, assign_idx = scope
                if assign_body is body and assign_idx < ref_idx and assign_idx > best_idx:
                    best = candidate_entry
                    best_idx = assign_idx
            if best is not None and seal_points:
                for sp_body, sp_idx in seal_points:
                    if sp_body is body and best_idx < sp_idx <= ref_idx:
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

    def _process_scope(self, scope: Node) -> None:
        func_mods = _compute_function_mods(scope)
        while True:
            candidates, seal_points, mutated = self._collect_candidates(scope, func_mods)
            if not candidates:
                return
            inlined = self._substitute_constants(scope, candidates, seal_points, func_mods)
            if inlined:
                self._remove_dead(scope, candidates, inlined)
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
    ) -> tuple[dict[str, list[_CandidateEntry]], dict[str, list[tuple[list, int]]], set[str]]:
        """
        Collect constant declaration entries per variable. Each entry is a `_CandidateEntry` of

            (declarator, constant_value, scope_entry)

        Also returns seal points (positions of non-constant `=` assignments) and the set of fully
        rejected (mutated) names.
        """
        candidates: dict[str, list[_CandidateEntry]] = {}
        seal_points: dict[str, list[tuple[list, int]]] = {}
        rejected: set[str] = set()

        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        continue
                    if decl.init is None:
                        continue
                    name = decl.id.name
                    if name in rejected:
                        continue
                    if name in candidates:
                        rejected.add(name)
                        candidates.pop(name, None)
                        continue
                    if _is_constant_value(decl.init):
                        entry = _find_body_entry(node)
                        candidates[name] = [_CandidateEntry(decl, decl.init, entry)]
                    else:
                        entry = _find_body_entry(node)
                        seal_points.setdefault(name, []).extend(_find_all_body_entries(node))
                        candidates[name] = [_CandidateEntry(decl, decl.init, entry)]

            if isinstance(node, JsAssignmentExpression):
                if isinstance(node.left, JsIdentifier):
                    name = node.left.name
                    rejected.add(name)
                    candidates.pop(name, None)
                elif isinstance(node.left, (JsArrayPattern, JsObjectPattern)):
                    for name in _pattern_identifiers(node.left):
                        rejected.add(name)
                        candidates.pop(name, None)

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
        seal_points: dict[str, list[tuple[list, int]]],
        func_mods: dict[str, set[str]],
    ) -> dict[str, int]:
        """
        Inline constant (literal and literal-array) variable references using domination. Handles
        both scalar references and computed index access into all-literal arrays.
        """
        inlined: dict[str, int] = {}
        bloat_blocked: set[str] = set()

        decl_ids: set[int] = set()
        for entries in candidates.values():
            for entry in entries:
                if entry.declarator is not None:
                    decl_ids.add(id(entry.declarator.id))

        ref_counts: dict[str, int] = {}
        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if isinstance(obj, JsIdentifier) and id(obj) not in decl_ids and obj.name in candidates:
                    ref_counts[obj.name] = ref_counts.get(obj.name, 0) + 1
                    continue
            if isinstance(node, JsIdentifier) and id(node) not in decl_ids and node.name in candidates:
                parent = node.parent
                if isinstance(parent, JsAssignmentExpression) and parent.left is node:
                    continue
                if isinstance(parent, JsMemberExpression) and parent.object is node and parent.computed:
                    continue
                ref_counts[node.name] = ref_counts.get(node.name, 0) + 1

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
        seal_points: dict[str, list[tuple[list, int]]],
        inlined: dict[str, int],
    ) -> None:
        """
        Try to resolve `name[numericLiteral]` to the corresponding array element.
        """
        prop = member.property
        if not isinstance(prop, JsNumericLiteral):
            return
        idx = int(prop.value)
        sp = seal_points.get(name)
        entry = _find_dominating_entry(member, candidates[name], sp)
        if entry is None:
            return
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
        seal_points: dict[str, list[tuple[list, int]]],
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
            if _is_const_qualified(entry.declarator):
                const_names.add(name)

        if not cross_candidates:
            return

        called_functions: set[str] = set()
        for node in walk_scope(scope, include_root_body=True):
            if (
                isinstance(node, JsCallExpression)
                and isinstance(node.callee, JsIdentifier)
            ):
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
                    else:
                        enclosing = self._enclosing_function_name(obj, func_mods)
                        if (
                            enclosing is None
                            or enclosing not in called_functions
                            or name in func_mods.get(enclosing, set())
                        ):
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
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1

    @staticmethod
    def _enclosing_function_name(
        node: Node,
        func_mods: dict[str, set[str]],
    ) -> str | None:
        """
        Walk upward from *node* to find the innermost enclosing function declaration whose name
        appears in *func_mods*. Returns the function name or `None` if the node is at top scope.
        """
        cursor = node.parent
        while cursor is not None:
            if (
                isinstance(cursor, JsFunctionDeclaration)
                and cursor.id is not None
                and cursor.id.name in func_mods
            ):
                return cursor.id.name
            cursor = cursor.parent
        return None

    def _substitute_expressions(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
        mutated: set[str],
        seal_points: dict[str, list[tuple[list, int]]],
    ) -> dict[str, int]:
        """
        Inline single-use, side-effect-free, non-literal expressions. This is the second pass that
        runs after constant inlining and preserves the existing behavior.
        """
        decl_ids: set[int] = set()
        for entries in candidates.values():
            for entry in entries:
                if entry.declarator is not None:
                    decl_ids.add(id(entry.declarator.id))

        ref_counts: dict[str, int] = {}
        for node in walk_scope(scope, include_root_body=True):
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            if node.name not in candidates:
                continue
            parent = node.parent
            if isinstance(parent, JsAssignmentExpression) and parent.left is node:
                continue
            ref_counts[node.name] = ref_counts.get(node.name, 0) + 1

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
        decl_ids: set[int] = set()
        for entries in candidates.values():
            for entry in entries:
                if entry.declarator is not None:
                    decl_ids.add(id(entry.declarator.id))

        ref_counts: dict[str, int] = {}
        for node in scope.walk():
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            name = node.name
            if name not in inlined:
                continue
            ref_counts[name] = ref_counts.get(name, 0) + 1

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
