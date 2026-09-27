"""
Flatten empty namespace objects into bare variable declarations.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

from refinery.lib.scripts import (
    BodyEdit,
    Expression,
    Node,
    _replace_in_parent,
    is_attached,
    set_child_list,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Scope,
    SemanticModel,
    enclosing_operator,
    is_member_write_target,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BatchedScopeTransformer,
    a_host_reaches_the_binding,
    access_key,
    function_binds_name,
    insert_after_prologue,
    is_receiver_binding_call,
    is_valid_identifier,
    property_absent_from_written_chain,
    references_receiver_this,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsScript,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    is_async_function,
    is_generator_function,
    strip_parens,
)


class _PropertyAssignment(NamedTuple):
    rhs: Expression
    statement: JsExpressionStatement
    write: Node


class _NamespacePlan(NamedTuple):
    scope: Node
    name: str
    declarator: JsVariableDeclarator
    declaration: JsVariableDeclaration
    flattenable: set[str]
    hoisted: dict[str, _PropertyAssignment]
    declarations: set[str]
    remove_declarator: bool


class JsNamespaceFlattening(BatchedScopeTransformer):
    """
    Replace `NS.prop` member accesses with bare identifiers when `NS` is declared as an empty
    object literal and is only ever used via property access. Emits `var` declarations for the
    flattened property names. A property whose name conflicts with an existing variable in the
    scope, or that a plain object inherits, is left on the namespace object. A namespace that a
    method may read through `this` is left whole.

    The pass is batched: every scope's decisions read the models the invocation entered with, and
    the edits run once the traversal ends. The decisions read four kinds of model fact, and the
    batch's own edits leave each of them valid on the tree it writes:

    - `a_host_reaches_the_binding` over the namespace's binding. The batch neither adds a reference
      to a namespace variable nor hands one to a host — its rewrites remove the last references
      there are — so a binding unreachable at entry stays unreachable.
    - `is_shadowed` answers for conflicting names, including the object-position uses the conflict
      check counts, and for the bare identifier each rewrite writes where an access stood. A
      rewrite does create bare identifiers, but only for names the emission registry already
      covers: a later candidate in the same scope holds a colliding key back, a candidate of an
      enclosing scope holds back a key a nested plan declares around one of its accesses, and a
      binding's shadowing answer for a name nothing in the batch emits is untouched.
    - `DominanceModel.runs_before_all` for hoisting. A hoisted declaration moves a function body to
      the prologue without moving when it executes — the body still runs only when called, from
      call sites no batch edit reorders — and the removed assignment's binding of the property is
      re-established no later than the assignment established it. A read the assignment provably
      preceded is preceded by the declaration as well.
    - `property_absent_from_written_chain` for inherited keys. No batch edit writes a prototype or
      a global, so the written chain the effects model read is the one the batch leaves behind.

    A hoist moves the function expression's body into the declaration rather than copying it, so
    the declaration carries every edit a plan of a scope inside that body applied first. Such a
    plan flattens a namespace its own scope declares: it rewrites accesses to that namespace only
    and binds the keys inside that scope. The inner name, the outer namespace's accesses, and the
    names the body reads from outside, which the hoist decision checked, are left as they were.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_scope_body(self, scope: Node, body: list) -> None:
        assert self._root is not None
        for name, declarator, decl_stmt in list(self._find_candidates(body)):
            plan = self._decide(scope, body, name, declarator, decl_stmt)
            if plan is not None:
                self._submit(plan)

    def _decide(
        self,
        scope: Node,
        body: list,
        name: str,
        declarator: JsVariableDeclarator,
        decl_stmt: JsVariableDeclaration,
    ) -> _NamespacePlan | None:
        assert self._root is not None
        if not self._is_safe(scope, name, declarator):
            return None
        props = self._collect_properties(scope, name, declarator)
        if not props:
            return None
        cache = model_cache(self, self._root)
        model = cache.model
        namespace_id = declarator.id
        if isinstance(namespace_id, JsIdentifier):
            binding = model.binding_of(namespace_id)
            if (
                binding is not None
                and (
                    a_host_reaches_the_binding(model, binding, self.options)
                    or model.local_reachable_by_direct_eval(binding)
                )
            ):
                return None
        scope_obj = model.scope_of(scope)
        if scope_obj is None:
            return None
        conflicts = self._find_conflicting_names(model, scope, scope_obj, props, declarator)
        references_by_key = self._property_references_by_key(scope, name)
        if self._a_method_may_observe_the_namespace(references_by_key):
            return None
        captured = self._captured_keys(model, scope, scope_obj, references_by_key)
        inherited = self._inherited_keys(props, cache.effects)
        flattenable = props - conflicts - captured - inherited
        flattenable = {
            key for key in flattenable
            if is_valid_identifier(key) and not self.name_emitted_in(scope, key)
        }
        if not flattenable:
            return None
        func_assigns = self._detect_function_assignments(body, name, flattenable)
        hoisted_keys = (
            self._hoistable_functions(func_assigns, references_by_key, cache.dominance)
            if func_assigns else set()
        )
        hoisted = {k: v for k, v in func_assigns.items() if k in hoisted_keys}
        declarations = flattenable - set(hoisted) - self._declared_var_names(body)
        for key in declarations:
            self.emits(scope, key)
        for key in hoisted:
            self.emits(scope, key)
        return _NamespacePlan(
            scope=scope,
            name=name,
            declarator=declarator,
            declaration=decl_stmt,
            flattenable=flattenable,
            hoisted=hoisted,
            declarations=declarations,
            remove_declarator=not (props - flattenable),
        )

    def _apply_plan(self, plan: _NamespacePlan) -> None:
        """
        Apply one decided plan to the live tree, standing down when the rewrite finds every target
        already replaced by an earlier plan claiming the same member accesses.
        """
        anchors: list[Node] = [entry.statement for entry in plan.hoisted.values()]
        if plan.remove_declarator:
            anchors.append(plan.declaration)
        if not all(is_attached(anchor) for anchor in anchors):
            return
        if not self._rewrite(plan.scope, plan.name, plan.declarator, plan.flattenable):
            return
        self._remove_hoisted_statements(plan.scope, plan.hoisted)
        self._emit_declarations(plan.scope, plan.declarations)
        self._emit_function_declarations(plan.scope, plan.hoisted)
        if plan.remove_declarator:
            self._remove_declarator(plan.scope, plan.declarator, plan.declaration)
        self.changed = True

    @staticmethod
    def _walk_pruning_shadows(scope: Node, name: str) -> Iterator[Node]:
        """
        Yield all nodes in the scope subtree, pruning at function boundaries that shadow `name`
        with their own binding (parameter, function name, or var declaration).
        """
        stack: list[Node] = [scope]
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, FUNCTION_NODES):
                if function_binds_name(node, name):
                    continue
            for child in node.children():
                stack.append(child)

    @staticmethod
    def _find_candidates(body: list) -> Iterator[tuple[str, JsVariableDeclarator, JsVariableDeclaration]]:
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            if stmt.kind != JsVarKind.VAR:
                continue
            for decl in stmt.declarations:
                if not isinstance(decl, JsVariableDeclarator):
                    continue
                if not isinstance(decl.id, JsIdentifier):
                    continue
                if not isinstance(decl.init, JsObjectExpression):
                    continue
                if decl.init.properties:
                    continue
                yield decl.id.name, decl, stmt

    @staticmethod
    def _is_safe(scope: Node, name: str, declarator: JsVariableDeclarator) -> bool:
        """
        Verify every reference to the namespace variable is a member-expression access with a
        statically extractable key, and that none is the operand of a `delete`. Identifiers in
        non-computed property position (e.g. `other.NS`) do not reference the variable and are
        ignored. A `delete NS.p` cannot survive flattening — `delete p` on a bare `var` binding is a
        no-op (or a strict-mode SyntaxError), not a property removal — so a namespace whose property
        is deleted is left intact.
        """
        decl_id = declarator.id
        for node in JsNamespaceFlattening._walk_pruning_shadows(scope, name):
            if node is decl_id:
                continue
            if not isinstance(node, JsIdentifier) or node.name != name:
                continue
            parent = node.parent
            if isinstance(parent, JsMemberExpression) and parent.property is node and not parent.computed:
                continue
            if not isinstance(parent, JsMemberExpression) or parent.object is not node:
                return False
            if access_key(parent) is None:
                return False
            grandparent = parent.parent
            if isinstance(grandparent, JsUnaryExpression) and grandparent.operator == 'delete':
                return False
        return True

    @staticmethod
    def _collect_properties(
        scope: Node,
        name: str,
        declarator: JsVariableDeclarator,
    ) -> set[str]:
        decl_id = declarator.id
        props: set[str] = set()
        for node in JsNamespaceFlattening._walk_pruning_shadows(scope, name):
            if node is decl_id:
                continue
            if not isinstance(node, JsIdentifier) or node.name != name:
                continue
            parent = node.parent
            if isinstance(parent, JsMemberExpression) and parent.object is node:
                key = access_key(parent)
                if key is not None:
                    props.add(key)
        return props

    @staticmethod
    def _inherited_keys(props: set[str], effects: EffectModel) -> set[str]:
        """
        The subset of *props* the flattening has to leave on the namespace object, because a read of
        one is answered by something other than that object's own slot.

        Two ways that happens and one question holds back both. A name every plain object has is
        answered off `Object.prototype`, where a bare `var` nothing assigns answers `undefined`, so
        `NS.toString` would come back as no function where the language gives one on every object.
        And a name the file itself put on that prototype is answered the same way, which no table
        can enumerate: `Object.prototype.z = 9` makes `NS.z` read `9` off a namespace that never
        held it, while the flattened variable reads nothing.

        `property_absent_from_written_chain` answers both at once — every key it cannot prove reads
        `undefined` is held back — and it is the arm that does not refuse under a reflective
        surface, for the reason it gives: refusing here costs the pass rather than one fold, and
        this pass is among those that clear the surface a stricter question would refuse under.
        """
        return {
            key for key in props
            if not property_absent_from_written_chain(effects, dict, key)
        }

    @staticmethod
    def _find_conflicting_names(
        model: SemanticModel,
        scope: Node,
        scope_obj: Scope,
        props: set[str],
        declarator: JsVariableDeclarator,
    ) -> set[str]:
        """
        Return the subset of property names that cannot be flattened because they already appear
        as variable references in the scope. An occurrence that resolves to a binding strictly
        nested below *scope_obj* shadows the would-be declaration and is therefore not a conflict.

        An occurrence in object position (`k.y`) counts the same way a bare one does: it reads the
        binding, so the declaration the flattening emits would capture it. Only an occurrence in
        non-computed property position (`x.k`) names a property rather than a variable and is
        ignored. The whole subtree is walked: a function that binds the namespace's own name holds
        no access to the namespace, but a name it reads from outside is captured all the same.
        """
        decl_id = declarator.id
        conflicts: set[str] = set()
        for node in scope.walk():
            if not isinstance(node, JsIdentifier):
                continue
            if node.name not in props or node.name in conflicts:
                continue
            if node is decl_id:
                continue
            parent = node.parent
            if isinstance(parent, JsMemberExpression) and parent.property is node and not parent.computed:
                continue
            if model.is_shadowed(node.name, node, scope_obj):
                continue
            conflicts.add(node.name)
        return conflicts

    def _captured_keys(
        self,
        model: SemanticModel,
        scope: Node,
        scope_obj: Scope,
        references_by_key: dict[str, list[Node]],
    ) -> set[str]:
        """
        The keys some access `NS.k` of which the bare `k` that replaces it would not carry to the
        declaration the flattening emits in *scope*: between the access and *scope* the name is
        bound anew, by a binding of the program
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.is_shadowed`), by a declaration an
        earlier plan of the batch emits into a scope nested below this one
        (`refinery.lib.scripts.js.deobfuscation.helpers.BatchedScopeTransformer.name_emitted_in`),
        or at runtime: by the object of a `with` body the access stands in, or by a `var` a direct
        `eval` declares below *scope* where the access can see it
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.direct_eval_declares_below`).
        Scopes are decided innermost first, so every such plan is decided before this one.
        """
        captured: set[str] = set()
        for key, references in references_by_key.items():
            for reference in references:
                assert isinstance(reference, JsMemberExpression) and reference.object is not None
                if (
                    model.is_shadowed(key, reference.object, scope_obj)
                    or self._crosses_a_with_body(model, reference, scope_obj)
                    or model.direct_eval_declares_below(reference, scope_obj)
                    or any(
                        self.name_emitted_in(enclosing, key)
                        for enclosing in self._scopes_between(reference, scope)
                    )
                ):
                    captured.add(key)
                    break
        return captured

    @staticmethod
    def _crosses_a_with_body(model: SemanticModel, node: Node, outer: Scope) -> bool:
        """
        Whether a name written at *node* is resolved through the object of a `with` body before
        the lookup reaches the scope *outer*.
        """
        cursor = model.scope_of(node)
        while cursor is not None and cursor is not outer:
            if cursor.is_dynamic:
                return True
            cursor = cursor.parent
        return False

    @staticmethod
    def _scopes_between(node: Node, scope: Node) -> Iterator[Node]:
        """
        The nodes strictly between *node* and its ancestor *scope*, innermost first.
        """
        cursor = node.parent
        while cursor is not None and cursor is not scope:
            yield cursor
            cursor = cursor.parent

    @staticmethod
    def _rewrite(
        scope: Node,
        name: str,
        declarator: JsVariableDeclarator,
        flattenable: set[str],
    ) -> bool:
        """
        Replace every flattenable `NS.prop` member access in the scope subtree with a bare
        identifier, walking the tree as it stands. Returns whether any replacement landed.
        """
        decl_id = declarator.id
        moved = False
        for node in list(JsNamespaceFlattening._walk_pruning_shadows(scope, name)):
            if node is decl_id:
                continue
            if not isinstance(node, JsIdentifier) or node.name != name:
                continue
            parent = node.parent
            if not isinstance(parent, JsMemberExpression) or parent.object is not node:
                continue
            key = access_key(parent)
            if key is None or key not in flattenable:
                continue
            replacement = JsIdentifier(name=key, offset=parent.offset)
            if _replace_in_parent(parent, replacement):
                moved = True
        return moved

    @staticmethod
    def _detect_single_assignments(
        body: list,
        name: str,
        flattenable: set[str],
        rhs_predicate,
    ) -> dict[str, _PropertyAssignment]:
        """
        Scan body-level statements for `NS.X = <rhs>` patterns where the RHS satisfies the given
        predicate. Only returns entries where the property was assigned exactly once.
        """
        counts: dict[str, int] = {}
        found: dict[str, _PropertyAssignment] = {}
        for stmt in body:
            if not isinstance(stmt, JsExpressionStatement):
                continue
            expr = stmt.expression
            if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
                continue
            lhs = expr.left
            if not isinstance(lhs, JsMemberExpression) or lhs.computed:
                continue
            if not isinstance(lhs.object, JsIdentifier) or lhs.object.name != name:
                continue
            key = access_key(lhs)
            if key is None or key not in flattenable:
                continue
            counts[key] = counts.get(key, 0) + 1
            if expr.right is not None and rhs_predicate(expr.right):
                found[key] = _PropertyAssignment(expr.right, stmt, lhs)
        return {k: v for k, v in found.items() if counts.get(k) == 1}

    @staticmethod
    def _remove_hoisted_statements(scope: Node, hoisted: dict[str, _PropertyAssignment]) -> None:
        """
        Delete the `NS.f = function…` statements whose properties are being raised to hoisted
        `function f(){}` declarations.
        """
        edit = BodyEdit(scope, 'body')
        for entry in hoisted.values():
            edit.splice(entry.statement, [])
        edit.apply()

    @staticmethod
    def _detect_function_assignments(
        body: list,
        name: str,
        flattenable: set[str],
    ) -> dict[str, _PropertyAssignment]:
        """
        Detect single assignments of function expressions to namespace properties:

            NS.X = function(...) { ... }
        """
        return JsNamespaceFlattening._detect_single_assignments(
            body,
            name,
            flattenable,
            lambda rhs: isinstance(rhs, JsFunctionExpression),
        )

    @staticmethod
    def _hoistable_functions(
        func_assigns: dict[str, _PropertyAssignment],
        references_by_key: dict[str, list[Node]],
        dominance: DominanceModel,
    ) -> set[str]:
        """
        The function properties whose single `NS.f = function…` assignment may be raised to a hoisted
        `function f(){}` declaration. Hoisting makes the function reachable from the top of the scope,
        so it is sound only when the assignment provably runs before every reference to the property —
        a `DominanceModel.runs_before_all` query over every `NS.f` access, computed forms included, so
        a read that could run first (earlier in the scope, or inside a function invoked earlier) keeps
        the property in place. The rewrite to a declaration also drops the function expression's own
        name, so a differing live inner name (a recursive `function fact` assigned to `NS.other`) would
        become unbound; such a property is likewise held back. A property failing either test keeps its
        assignment in place behind a bare `var f;`, reproducing the original member's
        `undefined`-until-assigned semantics.
        """
        hoistable: set[str] = set()
        for key, entry in func_assigns.items():
            func_expr = entry.rhs
            if not isinstance(func_expr, JsFunctionExpression):
                continue
            if func_expr.id is not None and func_expr.id.name != key:
                continue
            statement = entry.statement
            references = [ref for ref in references_by_key.get(key, ()) if ref is not entry.write]
            if dominance.runs_before_all(statement, references):
                hoistable.add(key)
        return hoistable

    @staticmethod
    def _property_references_by_key(scope: Node, name: str) -> dict[str, list[Node]]:
        """
        Every `NS.<key>` member access in the scope subtree, bucketed by property key, in a single walk.
        Computed accesses `NS["key"]` are bucketed with the static reads through `access_key`, so a read
        that spells the property dynamically still blocks an unsound hoist. The initializing write of a
        property is included here and excluded by the caller, which alone knows which reference it is.
        """
        buckets: dict[str, list[Node]] = {}
        for node in JsNamespaceFlattening._walk_pruning_shadows(scope, name):
            if not isinstance(node, JsMemberExpression):
                continue
            obj = node.object
            if not isinstance(obj, JsIdentifier) or obj.name != name:
                continue
            key = access_key(node)
            if key is not None:
                buckets.setdefault(key, []).append(node)
        return buckets

    @staticmethod
    def _a_method_may_observe_the_namespace(references_by_key: dict[str, list[Node]]) -> bool:
        """
        Whether some call binds `this` to the namespace object (`NS.key(...)`, `NS.key` as a template
        tag) and invokes a value that may observe it. Such a value is handed the object itself, which
        it can read any key of, return, store, or pass on, so no key can move off the object and the
        namespace stays whole. A key's value is provably `this`-free only when every write to `NS.key`
        is a plain `NS.key = rhs` binding a function expression that does not observe its receiver,
        and at least one such write exists. Anything else — a value observing `this`, a compound
        assignment, a destructuring or `for-in`/`for-of` target whose value is not written beside
        it, an arrow (conservatively, though its `this` is lexical), or a key never assigned a
        function — may observe it.
        """
        for nodes in references_by_key.values():
            if not any(is_receiver_binding_call(node) for node in nodes):
                continue
            values: list[Expression | None] = []
            for node in nodes:
                if not is_member_write_target(node):
                    continue
                governor = enclosing_operator(node)
                if (
                    isinstance(governor, JsAssignmentExpression)
                    and governor.operator == '='
                    and strip_parens(governor.left) is node
                ):
                    values.append(governor.right)
                else:
                    values.append(None)
            if not values or not all(
                isinstance(rhs, JsFunctionExpression) and not references_receiver_this(rhs)
                for rhs in values
            ):
                return True
        return False

    @staticmethod
    def _emit_function_declarations(
        scope: Node,
        func_assigns: dict[str, _PropertyAssignment],
    ) -> None:
        """
        Hoist a function declaration for each flattened property that held a function expression, all
        spliced in one call.

        The names are sorted in reverse because one splice keeps the order it is handed, where the
        head-insertion it replaced reversed it. The emitted order is the one that was emitted before,
        and sorting them forward would silently change the output of every flattened namespace.
        """
        declarations = []
        for name in sorted(func_assigns, reverse=True):
            func_expr = func_assigns[name].rhs
            assert isinstance(func_expr, JsFunctionExpression)
            declarations.append(JsFunctionDeclaration(
                id=JsIdentifier(name=name),
                params=func_expr.params or [],
                body=func_expr.body,
                generator=is_generator_function(func_expr),
                is_async=is_async_function(func_expr),
            ))
        if declarations:
            insert_after_prologue(scope, declarations)

    @staticmethod
    def _declared_var_names(body: list) -> set[str]:
        existing: set[str] = set()
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            if stmt.kind != JsVarKind.VAR:
                continue
            for decl in stmt.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    existing.add(decl.id.name)
        return existing

    @staticmethod
    def _emit_declarations(scope: Node, names: set[str]) -> None:
        """
        Insert a hoisted `var` declaration at the top of the scope for each of *names*. The
        declarations are uninitialized: a flattened property's value is established by its
        (in-place) assignment, so a bare `var p;` reproduces the `undefined`-until-assigned
        semantics of the original `NS.p` member exactly.
        """
        needed = sorted(names)
        if not needed:
            return
        declarations = [
            JsVariableDeclarator(id=JsIdentifier(name=n), init=None)
            for n in needed
        ]
        decl = JsVariableDeclaration(declarations=declarations, kind=JsVarKind.VAR)
        insert_after_prologue(scope, [decl])

    @staticmethod
    def _remove_declarator(
        scope: Node,
        declarator: JsVariableDeclarator,
        decl_stmt: JsVariableDeclaration,
    ) -> None:
        if len(decl_stmt.declarations) == 1:
            edit = BodyEdit(scope, 'body')
            edit.splice(decl_stmt, [])
            edit.apply()
        else:
            set_child_list(decl_stmt, 'declarations', [
                d for d in decl_stmt.declarations if d is not declarator
            ])
