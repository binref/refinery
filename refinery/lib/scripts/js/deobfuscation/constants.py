"""
Inline constant variable references in JavaScript.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import (
    Node,
    _clone_node,
    _replace_in_parent,
    is_attached,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.evaluation import enclosing_run
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    Role,
    SemanticModel,
    pattern_identifiers,
    reference_role,
)
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BatchedScopeTransformer,
    collect_identifier_names,
    is_literal,
    names_global_value,
    remove_declarator,
    substitute_use_position,
    value_to_node,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBinaryExpression,
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
    JsScript,
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsYieldExpression,
    strip_parens,
)
from refinery.lib.scripts.js.numbers import exact_integer
from refinery.lib.scripts.js.values import GLOBAL_VALUE_NAMES


def _identifiers_in(pattern: Node) -> list[JsIdentifier]:
    """
    Every identifier in the subtree of a destructuring pattern or a loop head: the variables it
    assigns to, and the names its defaults and computed keys read.
    """
    return [n for n in pattern.walk() if isinstance(n, JsIdentifier)]


class _CandidateEntry(NamedTuple):
    declarator: JsVariableDeclarator
    binding: Binding
    value: Node


class _Substitution(NamedTuple):
    target: Node
    value: Node
    binding: Binding


class _DeclaratorRemoval(NamedTuple):
    declarator: JsVariableDeclarator
    binding: Binding


class _ScopePlan(NamedTuple):
    """
    The edits one scope decided in a round, with the *model* they were decided against, which is
    the one that tells the bindings of the identifiers the round leaves standing apart when the plan
    counts the references a removal waits on.
    """
    scope: Node
    substitutions: list[_Substitution]
    declarator_removals: list[_DeclaratorRemoval]
    decl_ids: set[int]
    model: SemanticModel


class _Candidates(NamedTuple):
    """
    What one scope walk found: the *entries*, a candidate binding mapped to the one declarator and
    the one value that define it, and the *mutated* names, those a store writes that no candidate
    survives for, the free names among them included. A binding the scope walk can reach is told
    apart from another of its name by `SemanticModel.binding_of` at a declaration and
    `SemanticModel.resolve` at a reference, so a store into a catch parameter or a block `let` is
    no value of the `var` its name also spells.
    """
    entries: dict[Binding, _CandidateEntry]
    mutated: set[str]


def _candidate_decl_ids(candidates: dict[Binding, _CandidateEntry]) -> set[int]:
    """
    Collect the `id()` values of all declaration-site identifier nodes across candidate entries.
    Used to distinguish binding occurrences from reference occurrences during scope walks.
    """
    return {id(entry.declarator.id) for entry in candidates.values()}


def _is_primitive_and_pure(node: Node) -> bool:
    """
    Return whether evaluating *node* is guaranteed to produce no observable side effects and the
    result is a primitive value (not an object, array, or function). This is stricter than
    `refinery.lib.scripts.js.analysis.effects.side_effect_free` — it rejects expressions
    that allocate objects or access properties, because inlining such expressions into a new
    location can change reference identity or trigger getters at a different point in execution.

    The deliberate complement of `EffectModel._fresh_kind`, over primitives rather than containers, and not
    to be merged with it: this admits exactly the values that have no identity to duplicate, where that one
    admits containers whose identity is known to be new. Their answers are disjoint by construction.

    A `delete` is observable — it removes a binding or property — so its unary form is rejected while
    the operator's other uses, none of which touch what they name, stay admitted. An `in` reads a
    property of its right operand and an `instanceof` the prototype chain of its left, so each is a
    property access by another spelling and is rejected as one.
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
        if isinstance(n, JsUnaryExpression) and n.operator == 'delete':
            return False
        if isinstance(n, JsBinaryExpression) and n.operator in ('in', 'instanceof'):
            return False
    return True


def _binding_reached(model: SemanticModel, ident: JsIdentifier) -> Binding | None:
    """
    The binding the reference *ident* reads or writes: the one it resolves to, and where a `with`
    body governs it, the lexical binding it may reach past the body
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.lookup`), or `None` where *ident* is no
    reference or reaches no binding.
    """
    if not model.is_reference(ident):
        return None
    binding = model.resolve(ident)
    if binding is None:
        binding = model.lookup(ident.name, model.scope_of(ident), cross_dynamic=True)
    return binding


def _counts_as_a_reference(node: JsIdentifier) -> bool:
    """
    Whether *node* keeps a declarator its binding would lose: anything but the target of a plain
    `=`, which stores and reads nothing, and the name of a property.
    """
    parent = node.parent
    if isinstance(parent, JsAssignmentExpression) and parent.left is node and parent.operator == '=':
        return False
    if isinstance(parent, JsMemberExpression) and parent.property is node and not parent.computed:
        return False
    return True


def _still_referenced(
    scope: Node,
    bindings: set[Binding],
    decl_ids: set[int],
    model: SemanticModel,
) -> set[Binding]:
    """
    The *bindings* that an identifier anywhere in the subtree of *scope* still references, nested
    functions included, excluding declaration sites in *decl_ids*. The count is taken on a tree the
    round's substitutions edited, against the *model* the round decided on: an identifier it knows
    counts for the binding it reaches (`_binding_reached`), and one it does not, which a
    substitution wrote, counts for every binding of its name, since no model of the round can say
    which one it reaches.
    """
    by_name: dict[str, list[Binding]] = {}
    for binding in bindings:
        by_name.setdefault(binding.name, []).append(binding)
    referenced: set[Binding] = set()
    for node in scope.walk():
        if not isinstance(node, JsIdentifier) or id(node) in decl_ids:
            continue
        if (named := by_name.get(node.name)) is None or not _counts_as_a_reference(node):
            continue
        if not model.knows(node):
            referenced.update(named)
        elif (reached := _binding_reached(model, node)) in bindings:
            referenced.add(reached)
    return referenced


def _references_in_scope(
    scope: Node,
    candidates: dict[Binding, _CandidateEntry],
    decl_ids: set[int],
    model: SemanticModel,
) -> dict[Binding, int]:
    """
    Count the references within the scope walk of *scope* that reach each candidate binding
    (`_binding_reached`), excluding declaration sites in *decl_ids* and the targets of a plain `=`.
    A compound assignment reads its target and counts.
    """
    counts: dict[Binding, int] = {}
    names = {binding.name for binding in candidates}
    for node in walk_scope(scope, include_root_body=True):
        if not isinstance(node, JsIdentifier) or id(node) in decl_ids:
            continue
        if node.name not in names or not _counts_as_a_reference(node):
            continue
        binding = _binding_reached(model, node)
        if binding is not None and binding in candidates:
            counts[binding] = counts.get(binding, 0) + 1
    return counts


def _constant_node(node: Node | None, model: SemanticModel) -> Node | None:
    """
    The node a read of a constant holding *node* is replaced with, or `None` where *node* is no
    constant. A literal writes itself. A name that still denotes `undefined`, `NaN` or `Infinity`
    where it stands (`refinery.lib.scripts.js.deobfuscation.helpers.names_global_value`) writes the
    value it denotes, never the name, which may mean another binding at the read.
    """
    if node is None:
        return None
    if is_literal(node):
        return node
    if isinstance(node, JsIdentifier) and names_global_value(node, model):
        return value_to_node(GLOBAL_VALUE_NAMES[node.name])
    return None


def _is_constant_array(node: Node, model: SemanticModel) -> bool:
    """
    Whether *node* is a `refinery.lib.scripts.js.model.JsArrayExpression` every element of which is
    a constant (`_constant_node`).
    """
    if not isinstance(node, JsArrayExpression):
        return False
    return all(_constant_node(el, model) is not None for el in node.elements)


def _is_constant_value(node: Node, model: SemanticModel) -> bool:
    """
    Whether *node* is a constant value eligible for multi-use inlining: a scalar constant or an
    array of them.
    """
    return _constant_node(node, model) is not None or _is_constant_array(node, model)


def _is_intrinsic_alias_value(effects: EffectModel, node: Node) -> bool:
    """
    Whether *node* is a bare identifier naming a pristine intrinsic (or the global object) — a stable,
    unshadowed value that may be inlined at a cross-function use as itself, emitting the same name. Like a
    literal it never goes stale (the intrinsic is pristine and the binding is single-assigned), so it
    joins the `const`-like class the cross-function inliner admits; the emitted name is separately checked
    unshadowed at each use, since intrinsic pristineness only rules out shadowing at the script scope.
    """
    return isinstance(node, JsIdentifier) and effects.intrinsic_of(node) is not None


def _is_const_qualified(declarator: JsVariableDeclarator) -> bool:
    parent = declarator.parent
    return isinstance(parent, JsVariableDeclaration) and parent.kind is JsVarKind.CONST


def _calls_a_function_of_this_file_by_an_unstated_name(scope: Node, effects: EffectModel) -> bool:
    """
    Whether *scope* holds a call naming its callee by an identifier this file binds while the model
    declines to say which function that name holds.

    Such a call may run any function written here, one that writes a candidate included, and
    `_collect_call_sites` cannot report it: that answers with the functions a call may reach, and
    this one reaches none it can name. Where it is true, a candidate survives only if no function of
    this file writes it at all, which is what the substitution needs: it is the only guard standing
    between a non-escaping mutator and a constant inlined past its write.
    """
    return any(
        effects.a_name_this_file_binds_holds_the_callee(node)
        for node in walk_scope(scope, include_root_body=True)
        if isinstance(node, JsCallExpression)
    )


def _collect_called_functions(scope: Node, effects: EffectModel) -> list[Node]:
    """
    The statically resolvable callees within *scope*, each listed once in first-seen order. A call
    whose target `EffectModel.static_callee` cannot pin down (a method, a reassigned or redeclared
    binding, an unresolved name) contributes nothing.
    """
    called_funcs: list[Node] = []
    seen: set[int] = set()
    for node in walk_scope(scope, include_root_body=True):
        if isinstance(node, JsCallExpression):
            target = effects.static_callee(node)
            if target is not None and id(target) not in seen:
                seen.add(id(target))
                called_funcs.append(target)
    return called_funcs


def _reader_qualifies(
    value: Node, reader: Node, binding: Binding,
    effects: EffectModel, dominance: DominanceModel,
) -> bool:
    """
    Whether a candidate that is not `const`-qualified — a `var` carrying its own initializer,
    whose value a call could rewrite — may be inlined into the reader function *reader* holding
    *value*, the question both arms of the cross-function substitution ask, stated once so the
    computed-member and plain-identifier arms cannot disagree. The reader must not write the
    binding, and the value must run before every one of its invocations, of which it must have at
    least one (`runs_before_every_invocation`): a reader nothing invokes answers the ordering
    vacuously and is refused, while an anonymous IIFE or arrow is always orderable, its single
    reference point being the function expression itself — the closure cannot be invoked before it
    is created. A `const`-qualified candidate, or an intrinsic alias, needs neither: its value
    cannot be replaced short of a dynamic rebind, which the candidate collection has already
    refused.
    """
    if effects.function_can_mutate(reader, binding):
        return False
    return dominance.runs_before_every_invocation(value, reader)


class JsConstantInlining(BatchedScopeTransformer[_ScopePlan]):
    """
    Inline variables that are assigned once and never mutated. Literal-valued variables are inlined
    at all use sites; single-use variables with side-effect-free initializers are inlined when no
    intervening mutation could alter the referenced identifiers. All-literal arrays declared with
    `const` are inlined element-by-element when accessed with numeric literal indices.

    One invocation decides in rounds: each round traverses the tree once, every scope decides one
    round of edits against the model snapshot the round opened with, and the round's plans apply
    once the traversal ends, inner scopes first. A round that lands no edit ends the invocation.

    Every edit the batch applies removes something — a read, an index access, a declarator — and
    installs no binding, so the emission registry has no reader here: the one bare name a
    substitution can write is an intrinsic alias, checked unshadowed at the site it goes.

    Non-interference, per fact the decisions read:

    - `refinery.lib.scripts.js.analysis.reaching.ReachingModel.value_preserved` — whether a
      definition's value reaches a read unchanged. Batch edits remove reads, write sites, and
      declarators; none adds a kill, so a value that reached a read unchanged still does. A
      declined read — one a kill stood between — may become inlinable once the edit removing the
      kill applies, which the next round decides; the refusal the batch acted on stays valid.
    - `refinery.lib.scripts.js.analysis.dominance.DominanceModel.runs_before_function` and
      `refinery.lib.scripts.js.analysis.dominance.DominanceModel.runs_before_every_invocation` —
      whether a value runs before a function, or before every invocation of one. Batch edits
      remove statements and reads, so the set of invocation points can only shrink; a value that
      preceded them all still does.
    - The effect summaries over functions the batch never rewrites:
      `refinery.lib.scripts.js.analysis.effects.EffectModel.mutators_escape`,
      `refinery.lib.scripts.js.analysis.effects.EffectModel.static_callee`,
      `refinery.lib.scripts.js.analysis.effects.EffectModel.function_can_mutate` and
      `refinery.lib.scripts.js.analysis.effects.EffectModel.some_function_can_mutate`. Removing
      a call site removes a mutation opportunity rather than adding one, so a function that could
      not write a binding still cannot.
    - The reference counts that gate removals: no removal decision reads one — a count taken
      before the round's plans apply cannot see the reads another plan of the same round deletes,
      and a substitution whose value is an identifier adds a read the entry snapshot never saw —
      so the plan counts at apply time, on the tree its substitutions leave behind, and
      `refinery.lib.scripts.is_attached` refuses the substitutions an earlier plan detached.
    - The values the substitutions write: each is a node of the entry tree, an initializer that a
      substitution of the same round can rewrite in place before the one writing it lands. In
      `var x = p; var y = x; f(); g(y);` the round substitutes `p` for the `x` in `y`'s initializer
      and that initializer for the `y` in `g(y)`, so a copy taken at apply time would carry the
      read of `p` past `f()`. The plan holds a copy made at decision and writes what it checked.
    """

    def __init__(self, max_inline_length: int = 64):
        super().__init__()
        self.max_inline_length = max_inline_length
        self._root: JsScript | None = None
        self._edits_applied = 0

    def visit_JsScript(self, node: JsScript):
        self._root = node
        while True:
            self._edits_applied = 0
            super().visit_JsScript(node)
            if not self._edits_applied:
                break
        return None

    def _process_scope(self, scope: Node) -> None:
        assert self._root is not None
        cache = model_cache(self, self._root)
        candidates, mutated = self._collect_candidates(scope, cache.effects)
        if not candidates:
            return
        decl_ids = _candidate_decl_ids(candidates)
        substitutions = self._decide_constants(scope, candidates, decl_ids, cache)
        if not substitutions:
            substitutions = self._decide_expressions(scope, candidates, mutated, decl_ids, cache)
        if not substitutions:
            return
        self._submit(_ScopePlan(
            scope,
            [sub._replace(value=_clone_node(sub.value)) for sub in substitutions],
            self._decide_dead_declarators(candidates, substitutions, cache),
            decl_ids,
            cache.model,
        ))

    def _collect_candidates(self, scope: Node, effects: EffectModel) -> _Candidates:
        """
        Collect the candidate bindings of *scope*, each with the one declarator and the one value
        that define it (`_Candidates`), from a walk of the scope that does not enter a nested
        function. A binding is a candidate where the walk meets exactly one store of it: a
        declarator with a value, or a bare `var` the walk meets first and one plain `=` into the
        same binding after it. A second store of the binding, an update, a destructuring target and
        a loop head reject it. Every store is filed under the binding it writes: a declarator under
        the binding it declares, a reference under the one it resolves to, and a reference a `with`
        body governs under the lexical binding it may reach past the body, which it may write as
        well. A store into another binding of the same name, a catch parameter or a block `let`, is
        a store of that binding only. The names the rejected stores write, and the free names any
        store writes, are returned as the mutated names.

        A candidate is rejected as well where a run that escapes writes it
        (`refinery.lib.scripts.js.analysis.effects.EffectModel.mutators_escape`), be it a function
        or the initializer of a field, whose value cannot be pinned to a single definition. A
        candidate a dynamic scope could rewrite with no static write site is no longer rejected
        outright: the reaching query orders every located rebind hazard
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.binding_reflection_kill_sites`)
        against each read, so the reads that stand before the hazard fold and the ones after it
        stay. The one rebind that keeps its rejection is the nodeless one — the write a call makes
        on entry, which the text does not spell and no ordering can place
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.binding_dynamic_rebind_sites`
        answering `None`) — and a candidate the analyst declared a host reaches by name is rejected
        the same way: the host reads it once the file has run, and may have rewritten it before any
        read the substitution would fold, so neither its declarator nor any read of it may be
        replaced. A write through a global-object alias is rejected alongside. The points past
        which a surviving candidate's value no longer holds are not enumerated here; the reaching
        query derives them from the effect model at each use.
        """
        model = effects.model
        candidates: dict[Binding, _CandidateEntry] = {}
        rejected: set[Binding] = set()
        uninitialized: dict[Binding, JsVariableDeclarator] = {}
        mutated: set[str] = set()

        def reject(target: JsIdentifier) -> None:
            mutated.add(target.name)
            binding = model.binding_of(target) or _binding_reached(model, target)
            if binding is None:
                return
            rejected.add(binding)
            candidates.pop(binding, None)
            uninitialized.pop(binding, None)

        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        for ident in pattern_identifiers(decl.id):
                            reject(ident)
                        continue
                    binding = model.binding_of(decl.id)
                    if binding is None or binding in rejected:
                        continue
                    if decl.init is None:
                        if binding not in candidates:
                            uninitialized[binding] = decl
                        continue
                    if binding in candidates:
                        reject(decl.id)
                        continue
                    candidates[binding] = _CandidateEntry(decl, binding, decl.init)
                    uninitialized.pop(binding, None)

            if isinstance(node, JsAssignmentExpression):
                left = strip_parens(node.left)
                if isinstance(left, JsIdentifier):
                    binding = _binding_reached(model, left)
                    if (
                        node.operator == '='
                        and binding is not None
                        and binding in uninitialized
                        and binding not in candidates
                        and binding not in rejected
                    ):
                        decl = uninitialized.pop(binding)
                        if node.right is None:
                            reject(left)
                        else:
                            candidates[binding] = _CandidateEntry(decl, binding, node.right)
                    else:
                        reject(left)
                elif isinstance(left, (JsArrayPattern, JsObjectPattern)):
                    for ident in _identifiers_in(left):
                        reject(ident)

            if isinstance(node, JsUpdateExpression):
                target = strip_parens(node.argument)
                if isinstance(target, JsIdentifier):
                    reject(target)

            if isinstance(node, (JsForInStatement, JsForOfStatement)):
                left = strip_parens(node.left)
                if isinstance(left, JsVariableDeclaration):
                    for decl in left.declarations:
                        if isinstance(decl, JsVariableDeclarator) and decl.id is not None:
                            for ident in _identifiers_in(decl.id):
                                reject(ident)
                elif isinstance(left, (
                    JsIdentifier, JsArrayExpression, JsObjectExpression, JsArrayPattern, JsObjectPattern,
                )):
                    for ident in _identifiers_in(left):
                        reject(ident)

        for binding in list(candidates):
            if (
                binding.has_global_member_write
                or model.binding_dynamic_rebind_sites(binding) is None
                or model.reached_from_outside(binding)
                or effects.mutators_escape(binding)
            ):
                del candidates[binding]
                mutated.add(binding.name)

        return _Candidates(candidates, mutated)

    def _decide_constants(
        self,
        scope: Node,
        candidates: dict[Binding, _CandidateEntry],
        decl_ids: set[int],
        cache: ModelCache,
    ) -> list[_Substitution]:
        """
        Decide the constant (literal and literal-array) inlines of one round. A reference is inlined
        only where the definition's value provably reaches it unchanged
        (`ReachingModel.value_preserved`), covering both scalar references and computed index access
        into all-literal arrays. The value each decision records is the entry snapshot's own node,
        which `_process_scope` copies into the plan, or the node `_constant_node` writes for a name
        denoting a global value. A string too long to paste is inlined only where its binding is
        read once, wherever that read stands: the reads counted are the binding's own, in a `with`
        body too, so a name a nested function binds for itself never counts against it. A read is
        paired with a candidate by the binding it resolves to, so a read of another binding of the
        name, a catch parameter's, takes nothing of the candidate's value.
        """
        effects = cache.effects
        reaching = cache.reaching
        model = effects.model

        bloat_blocked: set[Binding] = set()
        for binding, entry in candidates.items():
            value = entry.value
            if not isinstance(value, JsStringLiteral) or value.value is None:
                continue
            if len(value.value) <= self.max_inline_length:
                continue
            if len(binding.reads) + len(binding.dynamic_refs) > 1:
                bloat_blocked.add(binding)

        constants = {
            binding: entry for binding, entry in candidates.items()
            if binding not in bloat_blocked and (
                _is_constant_value(entry.value, model) or _is_intrinsic_alias_value(effects, entry.value)
            )
        }
        if not constants:
            return []
        names = {binding.name for binding in constants}

        substitutions: list[_Substitution] = []
        for node in walk_scope(scope, include_root_body=True):
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if isinstance(obj, JsIdentifier) and obj.name in names and id(obj) not in decl_ids:
                    binding = model.resolve(obj)
                    entry = constants.get(binding) if binding is not None else None
                    if (
                        binding is not None
                        and entry is not None
                        and self._index_array_immutable(obj, effects, direct_eval_ordered=True)
                        and reaching.value_preserved(binding, entry.value, node)
                    ):
                        element = self._index_access_element(node, entry, model)
                        if element is not None:
                            substitutions.append(_Substitution(node, element, binding))
                continue
            if not isinstance(node, JsIdentifier) or node.name not in names:
                continue
            if id(node) in decl_ids:
                continue
            parent = node.parent
            if reference_role(node) is not Role.READ:
                continue
            if isinstance(parent, JsMemberExpression) and parent.object is node and parent.computed:
                continue
            binding = model.resolve(node)
            if binding is None or (entry := constants.get(binding)) is None:
                continue
            value = _constant_node(entry.value, model)
            if value is None:
                continue
            if not reaching.value_preserved(binding, entry.value, node):
                continue
            substitutions.append(_Substitution(node, value, binding))

        substitutions.extend(self._decide_const_across_functions(scope, constants, decl_ids, cache))

        return substitutions

    @staticmethod
    def _index_array_immutable(
        obj: JsIdentifier, effects: EffectModel, direct_eval_ordered: bool = False,
    ) -> bool:
        """
        Whether the array binding referenced by *obj* is an immutable, non-escaping container, so that
        `obj[idx]` may be inlined to its literal element. Resolved through the binding (not the textual
        name), so shadowing is respected; the model memoizes the judgment for the model's lifetime. A
        name that does not resolve to a local binding (a free or global array) is treated as unsafe.
        *direct_eval_ordered* carries the caller's promise that it has ordered the direct-`eval`
        sites against the read it is folding — the `value_preserved` check the same arm
        makes — so a local array in a function holding a direct `eval` stays inlinable where the
        read is ordered before every eval site.
        """
        binding = effects.model.resolve(obj)
        if binding is None:
            return False
        return effects.binding_is_immutable_container(
            binding, direct_eval_ordered=direct_eval_ordered)

    @staticmethod
    def _index_access_element(
        member: JsMemberExpression,
        entry: _CandidateEntry,
        model: SemanticModel,
    ) -> Node | None:
        """
        The node an index access into a candidate's array of constants is replaced with
        (`_constant_node`), or `None` when the access names no in-bounds constant element.
        """
        prop = member.property
        if not isinstance(prop, JsNumericLiteral):
            return None
        idx = exact_integer(prop.value)
        if idx is None:
            return None
        value = entry.value
        if not isinstance(value, JsArrayExpression):
            return None
        if not (0 <= idx < len(value.elements)):
            return None
        return _constant_node(value.elements[idx], model)

    def _decide_const_across_functions(
        self,
        scope: Node,
        constants: dict[Binding, _CandidateEntry],
        decl_ids: set[int],
        cache: ModelCache,
    ) -> list[_Substitution]:
        """
        Decide the constant-valued inlines of one round that cross into nested function bodies, for
        the *constants* the same-function arm admitted. A
        `const`-qualified candidate, or an uninitialized `var` later assigned a single constant, is
        inlined into a function only when the value provably runs before every invocation of that
        function (`DominanceModel.runs_before_function`) — otherwise a call could read the value
        early: a stale read for the `var` form, a temporal-dead-zone throw for the `const` form. A
        `var`/`let` candidate that carries its own initializer is additionally restricted by
        `_reader_qualifies` to a reader that neither writes the binding nor runs an invocation the
        value does not precede — a named function invoked in scope, an anonymous IIFE, an arrow, or
        a function stored in a binding, each of whose invocation points is enumerable and ordered;
        an uncalled named function is refused, since its ordering answer is the vacuous one an
        empty set of reference points gives. The interprocedural runs-before check subsumes the
        earlier escape and statement-position heuristics: a function cannot be invoked before a
        reference to it has been evaluated, so it orders the value against every point the function
        is referenced — recursing up the call graph for a reference that lies inside another
        function, and ordering functions that call each other by the references from outside
        their cycle — and inlines only when the value dominates all of them, refusing whenever a
        reference cannot be ordered (its binding is reassigned or redeclared).

        A candidate a dynamic scope could rewrite is refused here
        (`binding_maybe_reassigned_dynamically`): this consumer's ordering runs the value before an
        *invocation*, and an invocation cannot be ordered against the site that rewrites the value
        — a name read once can be stored and invoked arbitrarily later, past the hazard — so the
        reads that fold on the located hazards are the same-function ones, which the reaching
        query answers at the use itself.
        """
        effects = cache.effects
        dominance = cache.dominance
        model = effects.model

        called_funcs = _collect_called_functions(scope, effects)
        a_callee_is_unstated = _calls_a_function_of_this_file_by_an_unstated_name(scope, effects)

        crossing = {
            binding: entry for binding, entry in constants.items()
            if not (
                model.binding_maybe_reassigned_dynamically(binding)
                or binding.copies_received
                or (a_callee_is_unstated and effects.some_function_can_mutate(binding))
                or any(effects.function_can_mutate(func, binding) for func in called_funcs)
            )
        }
        if not crossing:
            return []
        const_like = {
            binding for binding, entry in crossing.items()
            if _is_const_qualified(entry.declarator)
            or entry.declarator.init is None
            or _is_intrinsic_alias_value(effects, entry.value)
        }

        outer = model.scope_of(scope)
        assert outer is not None
        owner = enclosing_run(scope)

        def reader_admitted(node: JsIdentifier, binding: Binding, entry: _CandidateEntry) -> bool:
            enclosing = enclosing_run(node)
            if enclosing is None or enclosing is owner:
                return False
            if binding in const_like:
                if not dominance.runs_before_function(entry.value, enclosing):
                    return False
            elif not _reader_qualifies(entry.value, enclosing, binding, effects, dominance):
                return False
            return not model.is_shadowed(node.name, node, outer)

        names = {binding.name for binding in crossing}
        substitutions: list[_Substitution] = []
        for node in scope.walk():
            if isinstance(node, JsMemberExpression) and node.computed:
                obj = node.object
                if isinstance(obj, JsIdentifier) and obj.name in names and id(obj) not in decl_ids:
                    binding = model.resolve(obj)
                    entry = crossing.get(binding) if binding is not None else None
                    if (
                        binding is not None
                        and entry is not None
                        and self._index_array_immutable(obj, effects)
                        and reader_admitted(obj, binding, entry)
                    ):
                        element = self._index_access_element(node, entry, model)
                        if element is not None:
                            substitutions.append(_Substitution(node, element, binding))
                continue
            if not isinstance(node, JsIdentifier) or node.name not in names:
                continue
            if id(node) in decl_ids:
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
            binding = model.resolve(node)
            if binding is None or (entry := crossing.get(binding)) is None:
                continue
            intrinsic_alias = _is_intrinsic_alias_value(effects, entry.value)
            value = entry.value if intrinsic_alias else _constant_node(entry.value, model)
            if value is None:
                continue
            if not reader_admitted(node, binding, entry):
                continue
            if (
                intrinsic_alias
                and isinstance(entry.value, JsIdentifier)
                and model.lookup(entry.value.name, model.scope_of(node)) is not None
            ):
                continue
            substitutions.append(_Substitution(node, value, binding))
        return substitutions

    def _decide_expressions(
        self,
        scope: Node,
        candidates: dict[Binding, _CandidateEntry],
        mutated: set[str],
        decl_ids: set[int],
        cache: ModelCache,
    ) -> list[_Substitution]:
        """
        Decide the single-use, side-effect-free, non-literal expression inlines of one round.
        Relocating the initializer to its use is sound only when the value it computed still holds
        there — which means the candidate's own binding reaches the use unchanged *and* every
        variable the initializer reads holds, at the use, the value it held at the definition.
        `ReachingModel.value_preserved` decides each: the candidate binding for ordering and its
        own kills, then one query per resolved free variable. The `_is_primitive_and_pure` gate
        keeps the initializer free of side effects and reference identity, and the `mutated` gate
        rejects a free variable written through a name no binding resolves (a global reassigned in
        scope), which the binding-keyed reaching query cannot see. A candidate whose initializer
        reads a bare name through a `with` body's dynamic scope needs no separate gate here: such
        an initializer is inside the `with` body, so the candidate's own binding is written in a
        dynamic scope and the reaching query orders that hazard against the relocated read. The one
        use is counted among the references of the scope walk that reach the binding, so a read of
        another binding of the name, a catch parameter's, is no use of it.
        """
        model = cache.effects.model
        ref_counts = _references_in_scope(scope, candidates, decl_ids, model)

        to_inline: dict[Binding, _CandidateEntry] = {}
        for binding, entry in candidates.items():
            init = entry.value
            if _is_constant_value(init, model) or ref_counts.get(binding, 0) != 1:
                continue
            if not _is_primitive_and_pure(init):
                continue
            if collect_identifier_names(init) & mutated:
                continue
            to_inline[binding] = entry

        if not to_inline:
            return []

        reaching = cache.reaching
        names = {binding.name for binding in to_inline}

        substitutions: list[_Substitution] = []
        for node in walk_scope(scope, include_root_body=True):
            if not isinstance(node, JsIdentifier) or node.name not in names:
                continue
            if id(node) in decl_ids:
                continue
            if reference_role(node) is not Role.READ:
                continue
            binding = model.resolve(node)
            if binding is None or (entry := to_inline.get(binding)) is None:
                continue
            if not reaching.value_preserved(binding, entry.value, node):
                continue
            if not self._free_variables_preserved(entry.value, node, model, reaching):
                continue
            substitutions.append(_Substitution(node, entry.value, binding))
        return substitutions

    @staticmethod
    def _free_variables_preserved(
        value: Node, use: Node, model: SemanticModel, reaching: ReachingModel,
    ) -> bool:
        """
        Whether re-evaluating *value* at *use* yields the same result it had where *value* was
        defined. Each name *value* reads must resolve, from *use*'s scope, to the binding it read
        where it was defined — a name a block or function around *use* shadows would read a
        different binding there, so a global read at the definition becomes a local read once
        substituted — and, where that binding exists, must still hold the value it held
        (`ReachingModel.value_preserved`). A free name that stays free preserves its value by the
        caller's `mutated` gate, so only its resolution is checked here. This is the twin of
        `JsCallWrapperInliner._forwarded_callee_reaches`, which guards the same capture for a
        forwarded callee.
        """
        use_scope = model.scope_of(use)
        for ident in value.walk():
            if not isinstance(ident, JsIdentifier) or not model.is_reference(ident):
                continue
            binding = model.resolve(ident)
            if model.lookup(ident.name, use_scope) is not binding:
                return False
            if binding is not None and not reaching.value_preserved(binding, value, use):
                return False
        return True

    def _decide_dead_declarators(
        self,
        candidates: dict[Binding, _CandidateEntry],
        substitutions: list[_Substitution],
        cache: ModelCache,
    ) -> list[_DeclaratorRemoval]:
        """
        Decide which declarators of the round-inlined bindings are up for removal. No reference
        count is read here — one taken before the round's plans apply cannot see the reads another
        plan of the same round deletes — so every binding the round substitutes is proposed and the
        plan counts references at apply time. Only a declarator that holds the inlined value is
        proposed: where the value came from a store after a bare `var b;`, removing the declaration
        would leave that store writing a global, and a dead store goes with its declaration in
        `refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval`. An exported binding
        keeps its declarator even with every local read inlined, because an importer still reads it
        across the module boundary; removing it would leave an `export` naming a binding the module
        no longer declares. A binding that code the model cannot read could name keeps its
        declarator for the same reason: every read this file spells may have folded, and the surface
        — a direct `eval`, a span of source the model never read, a `with` body — reads the binding
        through no reference the inlining counted, so removing the declaration would turn its value
        into a `ReferenceError`. So does a binding the model records code seeing without its name
        (`refinery.lib.scripts.js.analysis.model.Binding.seen_without_a_spelling`): a read through
        the global object or a listing of its names counts as no spelled reference either. An opaque
        global write is not such a surface: it stores a property and runs nothing, and the reads it
        could replace were ordered against it before they folded, so the property it may write is
        the same residual the fold already concedes.
        """
        model = cache.model
        removals: list[_DeclaratorRemoval] = []
        for binding in dict.fromkeys(sub.binding for sub in substitutions):
            entry = candidates.get(binding)
            if entry is None or entry.declarator.init is None:
                continue
            if (
                binding.seen_without_a_spelling
                or model.reachable_by_opaque_reflection(binding)
                or bool(binding.dynamic_refs)
            ):
                continue
            removals.append(_DeclaratorRemoval(entry.declarator, binding))
        return removals

    def _apply_plan(self, plan: _ScopePlan) -> None:
        for sub in plan.substitutions:
            if not is_attached(sub.target):
                continue
            if isinstance(sub.target, JsIdentifier):
                substituted = substitute_use_position(sub.target, sub.value)
            else:
                substituted = _replace_in_parent(sub.target, sub.value)
            if not substituted:
                continue
            self.mark_changed()
            self._edits_applied += 1
        if plan.declarator_removals:
            referenced = _still_referenced(
                plan.scope,
                {removal.binding for removal in plan.declarator_removals},
                plan.decl_ids,
                plan.model,
            )
            for removal in plan.declarator_removals:
                if removal.binding in referenced:
                    continue
                if not is_attached(removal.declarator):
                    continue
                remove_declarator(removal.declarator)
                self.mark_changed()
                self._edits_applied += 1
