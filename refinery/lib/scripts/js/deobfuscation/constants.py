"""
Inline constant variable references in JavaScript.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, _clone_node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    FUNCTION_NODES,
    Role,
    SemanticModel,
    _strip_parens,
    enclosing_function,
    pattern_identifiers,
    reference_role,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    collect_identifier_names,
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


class _CandidateEntry(NamedTuple):
    declarator: JsVariableDeclarator | None
    value: Node


class _MemberArrayEntry(NamedTuple):
    assignment: JsAssignmentExpression
    array: JsArrayExpression


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
    `refinery.lib.scripts.js.analysis.effects.side_effect_free` — it rejects expressions
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
    sites in *decl_ids* and simple (`=`) assignment write targets. A compound assignment (`x += e`,
    `x <<= e`) reads its target, so its left side is counted as a reference and the variable stays
    live. When *walk_full* is True, the entire subtree
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
        if isinstance(parent, JsAssignmentExpression) and parent.left is node and parent.operator == '=':
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


def _collect_call_sites(
    scope: Node,
    effects: EffectModel,
) -> tuple[dict[int, list[Node]], list[Node]]:
    """
    Map each statically resolvable callee within *scope* to the call expressions that target it,
    and list those callees once each in first-seen order. A call whose target
    `EffectModel.static_callee` cannot pin down (a method, a reassigned or redeclared binding, an
    unresolved name) contributes nothing.
    """
    call_sites: dict[int, list[Node]] = {}
    called_funcs: list[Node] = []
    for node in walk_scope(scope, include_root_body=True):
        if isinstance(node, JsCallExpression):
            target = effects.static_callee(node)
            if target is not None:
                if id(target) not in call_sites:
                    called_funcs.append(target)
                call_sites.setdefault(id(target), []).append(node)
    return call_sites, called_funcs


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
        assert self._root is not None
        effects = model_cache(self, self._root).effects
        while True:
            candidates, mutated = self._collect_candidates(scope, effects)
            member_arrays = self._collect_member_array_candidates(scope)
            if not candidates and not member_arrays:
                return
            inlined = self._substitute_constants(scope, candidates)
            if member_arrays:
                self._substitute_member_arrays(scope, member_arrays, inlined)
            if inlined:
                self._remove_dead(scope, candidates, inlined)
                self._remove_dead_member_arrays(scope, member_arrays, inlined)
                continue
            inlined = self._substitute_expressions(scope, candidates, mutated)
            if inlined:
                self._remove_dead(scope, candidates, inlined)
                continue
            return

    @staticmethod
    def _collect_candidates(
        scope: Node,
        effects: EffectModel,
    ) -> tuple[dict[str, list[_CandidateEntry]], set[str]]:
        """
        Collect constant declaration entries per variable. Each entry is a `_CandidateEntry` of

            (declarator, constant_value)

        Also returns the set of fully rejected (mutated) names — those reassigned, updated,
        destructured, or written by an escaping function, whose value cannot be pinned to a single
        definition. A name a dynamic scope could rewrite with no referencing identifier is rejected
        the same way: an unresolved write in a `with` body, a write through a global-object alias,
        or a function-local a direct `eval` in its own function could rebind through a string. The
        points past which a surviving candidate's value no longer holds are not enumerated here; the
        reaching query derives them from the effect model at each use.
        """
        candidates: dict[str, list[_CandidateEntry]] = {}
        rejected: set[str] = set()
        uninitialized: dict[str, JsVariableDeclarator] = {}

        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        for ident in pattern_identifiers(decl.id):
                            rejected.add(ident.name)
                            candidates.pop(ident.name, None)
                            uninitialized.pop(ident.name, None)
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
                    candidates[name] = [_CandidateEntry(decl, decl.init)]
                    uninitialized.pop(name, None)

            if isinstance(node, JsAssignmentExpression):
                left = _strip_parens(node.left)
                if isinstance(left, JsIdentifier):
                    name = left.name
                    if (
                        node.operator == '='
                        and name in uninitialized
                        and name not in candidates
                        and name not in rejected
                    ):
                        decl = uninitialized.pop(name)
                        rhs = node.right
                        if rhs is None:
                            rejected.add(name)
                        else:
                            candidates[name] = [_CandidateEntry(decl, rhs)]
                    else:
                        rejected.add(name)
                        candidates.pop(name, None)
                        uninitialized.pop(name, None)
                elif isinstance(left, (JsArrayPattern, JsObjectPattern)):
                    for name in _pattern_identifiers(left):
                        rejected.add(name)
                        candidates.pop(name, None)
                        uninitialized.pop(name, None)

            if isinstance(node, JsUpdateExpression):
                target = _strip_parens(node.argument)
                if isinstance(target, JsIdentifier):
                    name = target.name
                    rejected.add(name)
                    candidates.pop(name, None)

            if isinstance(node, (JsForInStatement, JsForOfStatement)):
                left = _strip_parens(node.left)
                loop_targets: set[str] = set()
                if isinstance(left, JsVariableDeclaration):
                    for decl in left.declarations:
                        if isinstance(decl, JsVariableDeclarator) and decl.id is not None:
                            loop_targets |= _pattern_identifiers(decl.id)
                elif isinstance(left, JsIdentifier):
                    loop_targets.add(left.name)
                elif isinstance(left, (
                    JsArrayExpression, JsObjectExpression, JsArrayPattern, JsObjectPattern,
                )):
                    loop_targets |= _pattern_identifiers(left)
                for name in loop_targets:
                    rejected.add(name)
                    candidates.pop(name, None)
                    uninitialized.pop(name, None)

        model = effects.model
        candidate_bindings: dict[str, Binding] = {}
        for cand_name, cand_entries in candidates.items():
            decl = cand_entries[0].declarator
            if decl is not None and isinstance(decl.id, JsIdentifier):
                binding = model.binding_of(decl.id)
                if binding is not None:
                    candidate_bindings[cand_name] = binding

        def _reject(target_name: str) -> None:
            rejected.add(target_name)
            candidates.pop(target_name, None)
            uninitialized.pop(target_name, None)
            candidate_bindings.pop(target_name, None)

        unresolved_writes: set[str] = set()
        functions: list[Node] = []
        for node in scope.walk():
            if isinstance(node, FUNCTION_NODES):
                functions.append(node)
            elif (
                isinstance(node, JsIdentifier)
                and reference_role(node) is not Role.READ
                and model.resolve(node) is None
            ):
                unresolved_writes.add(node.name)

        for cand_name, binding in list(candidate_bindings.items()):
            if (
                cand_name in unresolved_writes
                or binding.has_global_member_write
                or model.local_reachable_by_direct_eval(binding)
            ):
                _reject(cand_name)

        for func in functions:
            written = effects.mutated_bindings(func)
            if not written:
                continue
            touched = [n for n, binding in candidate_bindings.items() if binding in written]
            if not touched:
                continue
            if effects.function_escapes(func):
                for cand_name in touched:
                    _reject(cand_name)

        return candidates, rejected

    @staticmethod
    def _candidate_binding(entry: _CandidateEntry, model: SemanticModel) -> Binding | None:
        """
        The binding a candidate entry defines, resolved through its declarator identifier, or `None` when
        the entry carries no single-identifier declarator. This is the binding whose value the reaching
        query tracks from the definition to a use.
        """
        decl = entry.declarator
        if decl is None or not isinstance(decl.id, JsIdentifier):
            return None
        return model.binding_of(decl.id)

    def _substitute_constants(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
    ) -> dict[str, int]:
        """
        Inline constant (literal and literal-array) variable references. A reference is inlined only
        where the definition's value provably reaches it unchanged (`ReachingModel.value_preserved`).
        Handles both scalar references and computed index access into all-literal arrays.
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

        assert self._root is not None
        cache = model_cache(self, self._root)
        effects = cache.effects
        dominance = cache.dominance
        reaching = cache.reaching
        model = effects.model

        for node in list(walk_scope(scope, include_root_body=True)):
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if (
                    isinstance(obj, JsIdentifier)
                    and id(obj) not in decl_ids
                    and obj.name in constant_names
                    and obj.name not in bloat_blocked
                    and self._index_array_immutable(obj, effects)
                ):
                    entry = candidates[obj.name][0]
                    binding = self._candidate_binding(entry, model)
                    if binding is not None and reaching.value_preserved(binding, entry.value, node):
                        self._apply_index_access_inline(node, entry, obj.name, inlined)
                    continue
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            name = node.name
            if name not in constant_names or name in bloat_blocked:
                continue
            parent = node.parent
            if reference_role(node) is not Role.READ:
                continue
            if isinstance(parent, JsMemberExpression) and parent.object is node and parent.computed:
                continue
            entry = candidates[name][0]
            if not is_literal(entry.value):
                continue
            binding = self._candidate_binding(entry, model)
            if binding is None or not reaching.value_preserved(binding, entry.value, node):
                continue
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1

        self._substitute_const_across_functions(
            scope, candidates, decl_ids, bloat_blocked, inlined, effects, dominance,
        )

        return inlined

    @staticmethod
    def _index_array_immutable(obj: JsIdentifier, effects: EffectModel) -> bool:
        """
        Whether the array binding referenced by *obj* is an immutable, non-escaping container, so that
        `obj[idx]` may be inlined to its literal element. Resolved through the binding (not the textual
        name), so shadowing is respected; the model memoizes the judgment for the model's lifetime. A
        name that does not resolve to a local binding (a free or global array) is treated as unsafe.
        """
        binding = effects.model.resolve(obj)
        if binding is None:
            return False
        return effects.binding_is_immutable_container(binding)

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
        decl_ids: set[int],
        bloat_blocked: set[str],
        inlined: dict[str, int],
        effects: EffectModel,
        dominance: DominanceModel,
    ) -> None:
        """
        For constant-valued candidates, walk the full subtree to inline references inside nested
        function bodies. A `const`-qualified candidate, or an uninitialized `var` later assigned a
        single constant, is inlined into a function only when the value provably runs before every
        invocation of that function (`DominanceModel.runs_before_function`) — otherwise a call could
        read the value early: a stale read for the `var` form, a temporal-dead-zone throw for the
        `const` form. A `var`/`let` candidate that carries its own initializer is additionally
        restricted to a named function declaration actually called in the current scope that the effect
        model proves does not mutate the binding. The interprocedural runs-before check subsumes the
        earlier escape and statement-position heuristics: a function cannot be invoked before a reference
        to it has been evaluated, so it orders the value against every point the function is referenced —
        recursing up the call graph for a reference that lies inside another function — and inlines only
        when the value dominates all of them, refusing whenever a reference cannot be ordered (its
        binding is reassigned or redeclared, or it lies on a call cycle).
        """
        model = effects.model
        cross_candidates: dict[str, list[_CandidateEntry]] = {}
        cross_bindings: dict[str, Binding] = {}
        const_names: set[str] = set()
        for name, entries in candidates.items():
            if name in bloat_blocked:
                continue
            if len(entries) != 1:
                continue
            entry = entries[0]
            if entry.declarator is None or not isinstance(entry.declarator.id, JsIdentifier):
                continue
            if not _is_constant_value(entry.value):
                continue
            binding = model.binding_of(entry.declarator.id)
            if binding is None:
                continue
            cross_candidates[name] = entries
            cross_bindings[name] = binding
            if _is_const_qualified(entry.declarator) or entry.declarator.init is None:
                const_names.add(name)

        if not cross_candidates:
            return

        outer = model.scope_of(scope)
        assert outer is not None
        owner = enclosing_function(scope)

        call_sites, called_funcs = _collect_call_sites(scope, effects)

        for name in [
            candidate for candidate, binding in cross_bindings.items()
            if any(effects.function_can_mutate(func, binding) for func in called_funcs)
        ]:
            del cross_candidates[name]
            del cross_bindings[name]
        if not cross_candidates:
            return

        for node in list(scope.walk()):
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if (
                    isinstance(obj, JsIdentifier)
                    and id(obj) not in decl_ids
                    and obj.name in cross_candidates
                    and self._index_array_immutable(obj, effects)
                ):
                    name = obj.name
                    enclosing = enclosing_function(obj)
                    if enclosing is None or enclosing is owner:
                        continue
                    if model.resolve(obj) is not cross_bindings[name]:
                        continue
                    if name not in const_names and (
                        not isinstance(enclosing, JsFunctionDeclaration)
                        or id(enclosing) not in call_sites
                        or effects.function_can_mutate(enclosing, cross_bindings[name])
                    ):
                        continue
                    if not dominance.runs_before_function(cross_candidates[name][0].value, enclosing):
                        continue
                    if model.is_shadowed(name, obj, outer):
                        continue
                    self._apply_index_access_inline(
                        node, cross_candidates[name][0], name, inlined,
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
            if reference_role(node) is not Role.READ:
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
            enclosing = enclosing_function(node)
            if enclosing is None or enclosing is owner:
                continue
            if model.resolve(node) is not cross_bindings[name]:
                continue
            if name not in const_names and (
                not isinstance(enclosing, JsFunctionDeclaration)
                or id(enclosing) not in call_sites
                or effects.function_can_mutate(enclosing, cross_bindings[name])
            ):
                continue
            if not dominance.runs_before_function(entry.value, enclosing):
                continue
            if model.is_shadowed(name, node, outer):
                continue
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1

    def _substitute_expressions(
        self,
        scope: Node,
        candidates: dict[str, list[_CandidateEntry]],
        mutated: set[str],
    ) -> dict[str, int]:
        """
        Inline single-use, side-effect-free, non-literal expressions. Relocating the initializer to its
        use is sound only when the value it computed still holds there — which means the candidate's own
        binding reaches the use unchanged *and* every variable the initializer reads holds, at the use,
        the value it held at the definition. `ReachingModel.value_preserved` decides each: the candidate
        binding for ordering and its own kills, then one query per resolved free variable. The
        `_is_primitive_and_pure` gate keeps the initializer free of side effects and reference identity,
        and the `mutated` gate rejects a free variable written through a name no binding resolves (a
        global reassigned in scope), which the binding-keyed reaching query cannot see.
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

        assert self._root is not None
        cache = model_cache(self, self._root)
        reaching = cache.reaching
        model = cache.effects.model

        inlined: dict[str, int] = {}
        for node in list(walk_scope(scope, include_root_body=True)):
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in decl_ids:
                continue
            name = node.name
            if name not in to_inline:
                continue
            if reference_role(node) is not Role.READ:
                continue
            entry = to_inline[name]
            binding = self._candidate_binding(entry, model)
            if binding is None or not reaching.value_preserved(binding, entry.value, node):
                continue
            if not self._free_variables_preserved(entry.value, node, model, reaching):
                continue
            _replace_in_parent(node, _clone_node(entry.value))
            self.mark_changed()
            inlined[name] = inlined.get(name, 0) + 1
        return inlined

    @staticmethod
    def _free_variables_preserved(
        value: Node, use: Node, model: SemanticModel, reaching: ReachingModel,
    ) -> bool:
        """
        Whether every variable *value* reads holds, at *use*, the value it held where *value* was defined
        — so re-evaluating *value* at *use* yields the same result. Each identifier that resolves to a
        binding is checked with `ReachingModel.value_preserved`; an identifier that resolves to no
        binding (a global) is left to the caller's `mutated` gate.
        """
        for ident in value.walk():
            if not isinstance(ident, JsIdentifier):
                continue
            binding = model.resolve(ident)
            if binding is not None and not reaching.value_preserved(binding, value, use):
                return False
        return True

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
            candidates[key] = _MemberArrayEntry(node, rhs)

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
