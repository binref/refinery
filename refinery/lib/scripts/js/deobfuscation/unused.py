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
from refinery.lib.scripts.js.analysis.effects import EffectModel, build_effects
from refinery.lib.scripts.js.analysis.liveness import LivenessModel, build_liveness
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    FUNCTION_NODES,
    Scope,
    ScopeKind,
    SemanticModel,
    build_semantic_model,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    GLOBAL_OBJECT_ALIASES,
    collect_identifier_names,
    is_binding_site,
    is_side_effect_free,
    property_key,
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
            self._model = build_semantic_model(node)
            self._effects = build_effects(self._model)
            self._liveness = build_liveness(self._model)
            self._has_reflection = self._model.has_reflection_surface()
            self._remove_dead_stores(node)
            self._localize_pseudo_globals(node)
            self.generic_visit(node)
            self._process_body(node, node.body)
            pass_changed = self.changed
            self.changed = previously_changed or pass_changed
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
        Whether evaluating *node* can be dropped without losing an observable effect. This extends the
        syntactic `is_side_effect_free` with the effect model: a call to a function proven pure under a
        pristine intrinsic surface is removable when its arguments are too, so a dead binding whose
        initializer is a pure decoder or factory can be dropped even though it is a call.
        """
        if is_side_effect_free(node, defunct):
            return True
        if isinstance(node, (JsCallExpression, JsNewExpression)):
            return self.effects.is_pure_call(node) and all(
                self._is_removable(arg, defunct) for arg in node.arguments
            )
        return False

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
            if binding is None:
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
            if expr.right is None or not is_side_effect_free(expr.right, defunct):
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
            for node in parent.walk()
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
                unreferenced = binding is not None and not binding.reads and not binding.writes
                if decl.init is None:
                    if decl.id.name in dead_names or unreferenced:
                        remove_declarator(decl)
                        self.mark_changed()
                elif unreferenced and self._is_removable(decl.init):
                    remove_declarator(decl)
                    self.mark_changed()
