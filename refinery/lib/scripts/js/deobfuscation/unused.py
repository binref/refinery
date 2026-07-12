"""
Remove unreachable function declarations and unused variable assignments.

This transformer performs four phases:

1. **Dead function removal** — transitive reachability analysis: starting from non-function
   statements, it collects all function names referenced directly or transitively. Function
   declarations not in the reachable set are removed.

2. **Dead variable removal** — collects assignment targets that are never read anywhere in the
   enclosing function scope. Because `var` bindings are function-scoped, a name read through a
   closure in a nested function stays live unless that function shadows it. Dead assignment
   statements are removed, along with their hoisted `var` declarators when there is no initializer.

3. **Dead store removal** — a flow-sensitive sweep that drops an individual write whose stored value
   the liveness analysis proves is never read, even when the binding is read elsewhere (so phase 2
   keeps it). Only an uncaptured function-local `var`/`let` store qualifies; the side effects of the
   value expression are preserved.

4. **Pseudo-global localization** — a script-scope `var` whose every reference is owned by one
   function, and which that function overwrites before any read, is relocated into that function as a
   true local, tightening a global the obfuscator hoisted back to where it is used. The liveness model
   proves the move observes no value carried across calls or from load; the later sweeps then act on
   the tightened scope.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel, object_member_access_runs_accessor
from refinery.lib.scripts.js.analysis.liveness import LivenessModel
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    FUNCTION_NODES,
    Scope,
    ScopeKind,
    SemanticModel,
    is_simple_assignment_target,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    GLOBAL_OBJECT_ALIASES,
    collect_identifier_names,
    is_binding_site,
    remove_declarator,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsObjectExpression,
    JsObjectPattern,
    JsProperty,
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
        if is_simple_assignment_target(node):
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


def _pattern_target_idents(left: Node | None) -> list[JsIdentifier] | None:
    """
    If *left* is a destructuring pattern composed entirely of plain identifier targets (`[a, b]` or
    `{a, b}`), return those identifier nodes. Returns `None` for anything with nesting, defaults, rest
    elements, holes, computed keys, or member-expression targets.
    """
    if isinstance(left, (JsArrayExpression, JsArrayPattern)):
        idents: list[JsIdentifier] = []
        for elem in left.elements:
            if not isinstance(elem, JsIdentifier):
                return None
            idents.append(elem)
        return idents or None
    if isinstance(left, (JsObjectExpression, JsObjectPattern)):
        idents = []
        for prop in left.properties:
            if not isinstance(prop, JsProperty) or prop.computed:
                return None
            if not isinstance(prop.value, JsIdentifier):
                return None
            idents.append(prop.value)
        return idents or None
    return None


def _destructuring_target_safe(left: Node | None, right: Node | None) -> bool:
    """
    Whether assigning *right* into the destructuring pattern *left* is guaranteed neither to throw
    nor to run observable code, even when *right* is side-effect-free as a plain expression. Array
    patterns require an iterable source, so only an array literal is accepted. Object patterns throw
    on `null`/`undefined` and additionally *read* their named keys from the source, so only an object
    literal on which a plain member access can run no user-defined accessor is accepted: a getter or
    setter, or a `__proto__:` data property that installs a custom prototype (which may carry an
    inherited accessor), could execute code when the pattern matches, and a computed key — not even
    covered by `refinery.lib.scripts.js.analysis.effects.side_effect_free` — or a spread element could
    too. A `__proto__` method or shorthand defines an ordinary own property and stays safe. The
    accessor-and-prototype test is the shared `object_member_access_runs_accessor` the effect model
    uses; the spread and computed-key rejections it does not cover are kept explicit. Any other
    right-hand side is rejected conservatively.
    """
    if isinstance(left, (JsArrayExpression, JsArrayPattern)):
        return isinstance(right, JsArrayExpression)
    if isinstance(left, (JsObjectExpression, JsObjectPattern)):
        if not isinstance(right, JsObjectExpression):
            return False
        for prop in right.properties:
            if not isinstance(prop, JsProperty) or prop.computed:
                return False
        return not object_member_access_runs_accessor(right)
    return False


class JsUnusedCodeRemoval(BodyProcessingTransformer):
    """
    Remove function declarations that are never referenced from live code, and remove assignments
    to variables that are never read in the outer scope.
    """

    self_converging = True

    def __init__(self, preserve_globals: bool = True):
        super().__init__()
        self.preserve_globals = preserve_globals
        self._has_reflection = False
        self._model: SemanticModel | None = None
        self._effects: EffectModel | None = None
        self._liveness: LivenessModel | None = None
        self._reaching: ReachingModel | None = None

    def visit_JsScript(self, node: JsScript):
        """
        Rebuild the semantic model and sweep the whole script until a fixpoint. The model is computed
        once per pass and queried by every removal below; mutations within a pass only ever delete
        references, so a fact taken from the pass-start model can never wrongly classify a live binding
        as dead, and the next pass — over a freshly-built model — sweeps anything the staleness held
        back. Transitive deadness therefore falls out of the loop rather than needing the pipeline.
        """
        while True:
            previously_changed = self.changed
            self.changed = False
            cache = model_cache(self, node)
            self._model = cache.model
            self._effects = cache.effects
            self._liveness = cache.liveness
            self._reaching = cache.reaching
            self._has_reflection = self._model.has_reflection_surface()
            self._remove_dead_stores(node)
            self._localize_pseudo_globals(node)
            self.generic_visit(node)
            self._process_body(node, node.body)
            pass_changed = self.changed
            # Carry the cumulative change flag without going through the setter: this is bookkeeping,
            # not a tree mutation, so it must not drop the shared model cache.
            self._changed = previously_changed or pass_changed
            if not pass_changed:
                break
        return None

    @property
    def model(self) -> SemanticModel:
        assert self._model is not None
        return self._model

    @property
    def effects(self) -> EffectModel:
        assert self._effects is not None
        return self._effects

    @property
    def liveness(self) -> LivenessModel:
        assert self._liveness is not None
        return self._liveness

    @property
    def reaching(self) -> ReachingModel:
        assert self._reaching is not None
        return self._reaching

    def _remove_dead_stores(self, root: JsScript):
        """
        Drop writes whose stored value the flow-sensitive liveness proves dead while the binding is
        still read elsewhere — the case the binding-level sweep in `_remove_dead_variables` cannot see,
        because it reasons per binding rather than per store. Only an unconditional store to an
        uncaptured function-local `var`/`let` qualifies (the liveness model enforces this and reports
        nothing under any reflection surface); a fully dead binding is left to the binding-level sweep.

        Candidates are collected over the pristine tree before any removal, which keeps the verdicts
        mutually consistent: removing a dead store deletes no read, so it cannot revive another store's
        value. A dead assignment statement is dropped when its right-hand side is itself removable and
        otherwise kept as a bare expression for its effect; a dead declarator initializer is dropped
        only when removable, leaving `var x;` so the still-live binding keeps its declaration.
        """
        assignments: list[JsExpressionStatement] = []
        declarators: list[JsVariableDeclarator] = []
        for node in root.walk():
            if isinstance(node, JsExpressionStatement):
                expr = node.expression
                if (
                    isinstance(expr, JsAssignmentExpression)
                    and expr.operator == '='
                    and isinstance(expr.left, JsIdentifier)
                    and self._is_flow_dead_store(expr.left)
                ):
                    assignments.append(node)
            elif isinstance(node, JsVariableDeclarator):
                if (
                    isinstance(node.id, JsIdentifier)
                    and node.init is not None
                    and self._is_flow_dead_store(node.id)
                ):
                    declarators.append(node)
        for stmt in assignments:
            expr = stmt.expression
            assert isinstance(expr, JsAssignmentExpression)
            if expr.right is None or self._is_removable(expr.right):
                if _remove_from_parent(stmt):
                    self.mark_changed()
            else:
                stmt.expression = expr.right
                expr.right.parent = stmt
                self.mark_changed()
        for decl in declarators:
            if decl.init is not None and self._is_removable(decl.init):
                decl.init = None
                self.mark_changed()

    def _is_flow_dead_store(self, write: JsIdentifier) -> bool:
        """
        Whether *write* is a dead store the binding-level sweep would miss: its value is dead by
        flow-sensitive liveness, yet the binding is still read somewhere (a binding with no read at all
        is left to `_remove_dead_variables`, which also removes its declaration).
        """
        if not self.liveness.is_dead_store(write):
            return False
        binding = self.model.binding_of(write) or self.model.resolve(write)
        return binding is not None and binding.is_read

    def _localize_pseudo_globals(self, root: JsScript):
        """
        Relocate a script-scope `var` that behaves as one function's local into that function. The
        liveness model identifies a binding every reference of which is owned by a single function that
        overwrites it before any read and whose declaration carries no initializer — a global the
        obfuscator hoisted that observes no value across calls or from load. Its script-scope declarator
        is removed and a bare `var` for the name is hoisted into the function body, where the later
        sweeps act on the tightened scope; the next pass, over a fresh model, sees it as a local.

        Targets are gathered from the pass-start liveness before any mutation. Relocating one binding
        removes no reference to another, and a localization candidate is never a dead-store candidate
        (one is script-scope, the other strictly function-local), so the batch stays mutually consistent.
        """
        relocations: dict[int, tuple[JsBlockStatement, list[str]]] = {}
        declarators: list[JsVariableDeclarator] = []
        for binding, function in self.liveness.localizable_bindings():
            body = getattr(function, 'body', None)
            if not isinstance(body, JsBlockStatement):
                continue
            sites = self._declarators_of(binding)
            if sites is None:
                continue
            declarators.extend(sites)
            relocations.setdefault(id(body), (body, []))[1].append(binding.name)
        if not declarators:
            return
        for declarator in declarators:
            remove_declarator(declarator)
        for body, names in relocations.values():
            declaration = JsVariableDeclaration(
                kind=JsVarKind.VAR,
                declarations=[JsVariableDeclarator(id=JsIdentifier(name=name)) for name in names],
            )
            declaration.parent = body
            body.body.insert(0, declaration)
        self.mark_changed()

    @staticmethod
    def _declarators_of(binding: Binding) -> list[JsVariableDeclarator] | None:
        """
        The `var` declarators that introduce *binding* at script scope, or `None` if any declaration
        site is not a plain declarator, so the binding cannot be cleanly relocated.
        """
        declarators: list[JsVariableDeclarator] = []
        for site in binding.declarations:
            declarator = site.parent
            if not isinstance(declarator, JsVariableDeclarator):
                return None
            declarators.append(declarator)
        return declarators or None

    def _is_removable(self, node: Node, defunct: set[str] | None = None) -> bool:
        """
        Whether evaluating *node* can be dropped without losing an observable effect, via
        `refinery.lib.scripts.js.analysis.effects.EffectModel.is_side_effect_free`: a call proven pure
        under a pristine intrinsic surface is removable when its arguments are, so a dead binding whose
        initializer is a pure decoder or factory can be dropped even though it is a call. A member read
        through a local global-object alias is cleared only where the alias is established before it, and
        a pure call only where its callee is established before it. Every call site of this method drops
        *node*'s value outright — a dead store, a bare expression statement, an unreferenced initializer —
        so it is scanned as *discarded*: a call whose sole residual effect is a mutation of a local it
        returns (a decoder-factory IIFE building a scratch container) is removable, its mutation being
        unobservable once the result is thrown away.
        """
        return self.effects.is_side_effect_free(
            node, defunct, member_safe=self._member_read_ok, call_established=self._call_established,
            discarded=True)

    def _call_established(self, call: JsCallExpression | JsNewExpression) -> bool:
        """
        Whether a pure call may be dropped: its callee is a trusted intrinsic, or a local function whose
        definition reaches the call, so a call textually before a not-yet-established function keeps its
        runtime throw.
        """
        return self.effects.call_clearable(
            call, lambda func: self.reaching.dominance.established_before(func, call))

    def _member_read_ok(self, member: JsMemberExpression) -> bool:
        """
        Whether a member read is getter-free for removal: a trusted global data-property read, including
        one through a local global-object alias proven to hold the global object before the read.
        """
        return self.effects.member_read_getter_free(member, self._alias_established)

    def _alias_established(self, binding: Binding, member: JsMemberExpression) -> bool:
        """
        Whether *binding*'s single global-valued definition reaches *member*'s base unchanged, so the
        alias holds the global object where it is read and the read cannot throw on a nullish base.
        """
        value = self.model.singular_value(binding)
        base = member.object
        if value is None or base is None:
            return False
        return self.reaching.value_preserved(binding, value, base)

    def _reflection_reachable(self, binding: Binding | None) -> bool:
        """
        Whether reflection could read *binding* by name without a reference the model records, so its
        declaration and assignments must be kept even when no static reference remains. A function-local
        is at risk only from a `with` or direct `eval` inside its own function; a global, from any
        surface. The model decides; a `None` binding (a synthesized node the model never saw) is treated
        as not reachable, matching the surrounding removal logic.
        """
        return binding is not None and self.model.reflection_can_reach(binding)

    def _at_script_scope(self, parent: Node) -> bool:
        """
        Whether *parent* (a body) lies at the script scope rather than inside any function, so the
        names it binds are globals. When a reflection surface is present these must be preserved,
        because reflective code could read them by name.
        """
        scope = self.model.scope_of(parent)
        while scope is not None:
            if scope.kind is ScopeKind.FUNCTION:
                return False
            scope = scope.parent
        return True

    @staticmethod
    def _owns(scope: Scope, binding: Binding | None) -> bool:
        """
        Whether removing dead assignments to *binding* is the responsibility of the variable scope
        *scope*: a binding declared in this very scope, or an implicit global (which the program may
        write from anywhere). A *live* binding from an enclosing scope is left alone here — the
        assignment writes through a closure into a still-reachable outer variable — though a write to a
        dead enclosing binding is still removable and is admitted separately by the caller.
        """
        if binding is None:
            return False
        if binding.kind is BindingKind.IMPLICIT_GLOBAL:
            return True
        return binding.scope is scope

    @staticmethod
    def _is_var_scope_root(parent: Node) -> bool:
        """
        Whether *parent* is the body that introduces a variable scope — the script, or a function's own
        body block — as opposed to a nested block. Dead assignments and destructuring are swept once per
        variable scope from its root, so the whole scope (across its nested blocks, but not nested
        functions) is considered together and no statement is examined twice. The model maps a nested
        block to its *enclosing* scope, so a structural test, not `scope_of`, identifies the root.
        """
        if isinstance(parent, JsScript):
            return True
        return isinstance(parent, JsBlockStatement) and isinstance(parent.parent, FUNCTION_NODES)

    def _process_body(self, parent: Node, body: list[Statement]):
        if self.preserve_globals and self._has_reflection and self._at_script_scope(parent):
            return
        removed_functions = self._remove_dead_functions(body)
        dead_variables, preserved = self._remove_dead_variables(parent, body, removed_functions)
        dead_variables |= self._remove_dead_destructuring(
            parent, body, removed_functions | dead_variables)
        if isinstance(parent, JsScript):
            dead_variables |= self._remove_dead_global_properties(parent, dead_variables)
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
        kept_by_reflection = {
            name for name, func in functions.items()
            if isinstance(func.id, JsIdentifier)
            and self._reflection_reachable(self.model.binding_of(func.id))
        }
        unreachable = (set(functions.keys()) - reachable) - kept_by_reflection
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
        Remove simple assignments (`T = rhs`) whose target is never read. A target is a candidate when
        it resolves to a binding this variable scope owns — a local declaration or an implicit global —
        or to any binding that is already dead everywhere (a write-through to a never-read outer
        variable). A candidate is removed when it is dead: every read of it lies within the right-hand
        side of an assignment to another dead target, so nothing observes its value. Reads come from the
        whole-program model, so a binding read across a function boundary or captured by a closure stays
        live. A side-effect-free right-hand side is dropped with the statement; an effectful one is kept
        as a bare expression. Returns the dead target names and the statements kept for their side effects.
        """
        if not self._is_var_scope_root(parent):
            return set(), set()
        scope = self.model.scope_of(parent)
        assert scope is not None
        stores: dict[Binding, list[JsExpressionStatement]] = {}
        for node in walk_scope(parent):
            if not isinstance(node, JsExpressionStatement):
                continue
            expr = node.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            if not isinstance(expr.left, JsIdentifier):
                continue
            binding = self.model.resolve(expr.left)
            if binding is None or self._reflection_reachable(binding):
                continue
            if self._owns(scope, binding) or binding.is_dead:
                stores.setdefault(binding, []).append(node)
        if not stores:
            return set(), set()
        dead = self._dead_store_bindings(stores)
        if not dead:
            return set(), set()
        dead_names = {binding.name for binding in dead}
        all_defunct = defunct | dead_names
        preserved: set[JsExpressionStatement] = set()
        for binding in dead:
            for stmt in stores[binding]:
                expr = stmt.expression
                assert isinstance(expr, JsAssignmentExpression)
                if expr.right is None or self._is_removable(expr.right, all_defunct):
                    _remove_from_parent(stmt)
                else:
                    stmt.expression = expr.right
                    expr.right.parent = stmt
                    preserved.add(stmt)
        self._remove_empty_declarators(parent, body, dead_names)
        self.mark_changed()
        return dead_names, preserved

    def _dead_store_bindings(
        self, stores: dict[Binding, list[JsExpressionStatement]],
    ) -> set[Binding]:
        """
        From candidate bindings mapped to their removable assignments, return those that are dead. A
        binding is live if it has a read that is *not* contained in the right-hand side of any candidate
        assignment — a use in live code, in a live function, a closure, or a non-candidate assignment.
        Liveness then propagates back along right-hand sides: if a live binding's assignment reads another
        candidate, that candidate is live too. The rest, whose every read sits inside the right-hand side
        of an assignment that is itself dead, are dead — removing those assignments removes the reads, so
        nothing observes the value. A read nested arbitrarily deep inside a candidate's right-hand side
        (for instance within an assigned function body) is covered by the outermost candidate, which is
        what distinguishes a read inside a dead store from one inside a live function declaration.
        """
        candidates = set(stores)
        rhs_owner: dict[int, Binding] = {}
        for binding, statements in stores.items():
            for stmt in statements:
                expr = stmt.expression
                if isinstance(expr, JsAssignmentExpression) and expr.right is not None:
                    rhs_owner[id(expr.right)] = binding
        readers: dict[Binding, set[Binding]] = {binding: set() for binding in candidates}
        live: set[Binding] = set()
        for binding in candidates:
            for read in binding.reads:
                owner = self._covering_store(read, rhs_owner)
                if owner is None or owner is binding:
                    live.add(binding)
                else:
                    readers[binding].add(owner)
        changed = True
        while changed:
            changed = False
            for binding in candidates - live:
                if readers[binding] & live:
                    live.add(binding)
                    changed = True
        return candidates - live

    @staticmethod
    def _covering_store(node: Node, rhs_owner: dict[int, Binding]) -> Binding | None:
        """
        The candidate binding whose assignment right-hand side encloses *node*, taken at the outermost
        such right-hand side, or `None` when *node* lies outside every candidate right-hand side.
        Removing that binding's assignment would delete *node* along with it.
        """
        owner: Binding | None = None
        cursor: Node | None = node
        while cursor is not None:
            found = rhs_owner.get(id(cursor))
            if found is not None:
                owner = found
            cursor = cursor.parent
        return owner

    def _remove_dead_destructuring(
        self, parent: Node, body: list[Statement], defunct: set[str],
    ) -> set[str]:
        """
        Remove destructuring-assignment statements (`[a, b] = rhs`) whose every target the variable
        scope owns, that are never read, and whose right-hand side is side-effect-free. These arise from
        CFF recovery of vestigial state variables. Reads are taken over the whole scope including nested
        functions, so a closure reference or any use other than a plain assignment keeps a target alive.
        """
        if not self._is_var_scope_root(parent):
            return set()
        scope = self.model.scope_of(parent)
        assert scope is not None
        candidates: list[tuple[JsExpressionStatement, list[str]]] = []
        for node in walk_scope(parent):
            if not isinstance(node, JsExpressionStatement):
                continue
            expr = node.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            targets = _pattern_target_idents(expr.left)
            if not targets:
                continue
            if any(not self._owns(scope, self.model.resolve(t)) for t in targets):
                continue
            if any(self._reflection_reachable(self.model.resolve(t)) for t in targets):
                continue
            if expr.right is None or not self._is_removable(expr.right, defunct):
                continue
            if not _destructuring_target_safe(expr.left, expr.right):
                continue
            candidates.append((node, [t.name for t in targets]))
        if not candidates:
            return set()
        read_names: set[str] = set()
        for node in parent.walk():
            if not isinstance(node, JsIdentifier):
                continue
            if is_binding_site(node) or is_simple_assignment_target(node):
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
            for node in parent.walk()
            if isinstance(node, JsIdentifier)
            and node.name in removed
            and is_simple_assignment_target(node)
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
                elif self._is_removable(expr.right, defunct | dead):
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
        that would be side-effect-free if the function were defunct. A reference that *calls* the
        function only counts as removable when the function is itself pure — dropping a call to an
        impure function would discard its effect — whereas a bare reference is removable regardless.
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
                    assumed_pure = defunct
                    if self.effects.summary_of(func).is_pure:
                        assumed_pure = defunct | {name}
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
                            or not self._is_removable(stmt.expression, assumed_pure)
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
            if self._is_removable(stmt.expression, defunct):
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
        Remove `var X;` declarators whose binding is wholly unreferenced. A bare declarator (no
        initializer) is dropped when its name is in *dead_names* — a binding found dead while removing
        its assignments, whose references the pass-start model may still record because they sat in
        now-removed statements — or when its binding has no reads and no writes at all. An initialized
        declarator is dropped only when its binding is wholly unreferenced and the initializer is
        side-effect-free. A binding still written by a surviving statement keeps its declaration, so it
        does not silently become an implicit global; a binding read across a function boundary or
        captured by a closure likewise keeps its declaration.
        """
        for stmt in list(body):
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in list(stmt.declarations):
                if not isinstance(decl, JsVariableDeclarator) or not isinstance(decl.id, JsIdentifier):
                    continue
                binding = self.model.binding_of(decl.id)
                if self._reflection_reachable(binding):
                    continue
                unreferenced = binding is not None and not binding.reads and not binding.writes
                if decl.init is None:
                    if decl.id.name in dead_names or unreferenced:
                        remove_declarator(decl)
                        self.mark_changed()
                elif unreferenced and self._is_removable(decl.init):
                    remove_declarator(decl)
                    self.mark_changed()
