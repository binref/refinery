"""
Flatten empty namespace objects into bare variable declarations.
"""
from __future__ import annotations

from typing import Iterable, Iterator, NamedTuple

from refinery.lib.scripts import (
    BodyEdit,
    Expression,
    Node,
    _remove_from_parent,
    _replace_in_parent,
    is_attached,
    set_child_list,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Scope,
    SemanticModel,
    enclosing_operator,
    is_member_write_target,
    statement_list_of,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BatchedScopeTransformer,
    access_key,
    collect_identifier_names,
    function_binds_name,
    insert_after_prologue,
    is_receiver_binding_call,
    is_valid_identifier,
    name_off_the_host,
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


def namespace_accesses(references: Iterable[Node]) -> dict[str, list[Node]] | None:
    """
    The member accesses through which *references*, every reference to the object a namespace
    variable holds, reach that object, by the key each names; `None` where one of them does anything
    else with the object, which then has to stay whole. Each reference has to be the variable
    itself, not an object aliasing it as `this.NS` does a global, and the object of an access under
    a static key (`refinery.lib.scripts.js.deobfuscation.helpers.access_key`). That access may not
    be the operand of a `delete`: `delete p` on a bare `var` binding is a no-op (or a strict-mode
    SyntaxError), not a property removal. And a call through it may not hand the object to a
    function that can observe it as `this` (`_a_method_may_observe_the_namespace`).
    """
    accesses: dict[str, list[Node]] = {}
    for node in references:
        if not isinstance(node, JsIdentifier):
            return None
        access = node.parent
        if not isinstance(access, JsMemberExpression) or access.object is not node:
            return None
        if (key := access_key(access)) is None:
            return None
        if (
            isinstance(grandparent := access.parent, JsUnaryExpression)
            and grandparent.operator == 'delete'
        ):
            return None
        accesses.setdefault(key, []).append(access)
    if _a_method_may_observe_the_namespace(accesses):
        return None
    return accesses


def _a_method_may_observe_the_namespace(accesses: dict[str, list[Node]]) -> bool:
    """
    Whether some call binds `this` to the namespace object (`NS.key(...)`, `NS.key` as a template
    tag) and invokes a value that may observe it. Such a value is handed the object itself, which it
    can read any key of, return, store, or pass on, so no key can move off the object and the
    namespace stays whole. A key's value is provably `this`-free only when every write to `NS.key`
    is a plain `NS.key = rhs` binding a function expression that does not observe its receiver, and
    at least one such write exists. Anything else — a value observing `this`, a compound
    assignment, a destructuring or `for-in`/`for-of` target whose value is not written beside it, an
    arrow (conservatively, though its `this` is lexical), or a key never assigned a function — may
    observe it.
    """
    for nodes in accesses.values():
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


class _PropertyAssignment(NamedTuple):
    rhs: Expression
    statement: JsExpressionStatement
    write: Node


class _NamespacePlan(NamedTuple):
    scope: Node
    name: str
    declarator: JsVariableDeclarator
    declaration: JsVariableDeclaration
    creation: JsExpressionStatement | None
    names: dict[str, str]
    hoisted: dict[str, _PropertyAssignment]
    declarations: set[str]
    remove_declarator: bool


class JsNamespaceFlattening(BatchedScopeTransformer):
    """
    Replace `NS.prop` member accesses with bare identifiers when `NS` is declared as an empty
    object literal and is only ever used via property access. Emits `var` declarations for the
    flattened property names. A property whose name conflicts with an existing variable in the
    scope, or that a plain object inherits, is left on the namespace object. A property whose
    variable would be the property of the global object a host reads becomes a variable of another
    name (`_variable_names`). A namespace that a method may read through `this` is left whole. A
    namespace may also be declared bare and made by one statement of its scope that runs at most
    once whenever the scope does, and before every access of the namespace (`_creation`):

        var NS;
        if (c) { NS = {}; NS.f = function () { ... }; NS.f(); }

    holds one object wherever an access runs, as `var NS = {}` does, and the statement goes with
    the declaration.

    The pass is batched: every scope's decisions read the models the invocation entered with, and
    the edits run once the traversal ends. The decisions read four kinds of model fact, and the
    batch's own edits leave each of them valid on the tree it writes:

    - `refinery.lib.scripts.js.analysis.model.SemanticModel.reached_from_outside` over the
      namespace's binding. The batch neither adds a reference to a namespace variable nor hands one
      to a host — its rewrites remove the last references there are — so a binding unreachable at
      entry stays unreachable.
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
    - `DominanceModel.runs_before_all` and `refinery.lib.scripts.analysis.cycles.CycleModel` for
      the statement creating a namespace declared bare. The statement the batch removes with such a
      namespace stores an object into a declared name and cannot throw, so no other statement runs
      earlier or more often without it.

    A hoist moves the function expression's body into the declaration rather than copying it, so
    the declaration carries every edit a plan of a scope inside that body applied first. Such a
    plan flattens a namespace its own scope declares: it rewrites accesses to that namespace only
    and binds the keys inside that scope. The inner name, the outer namespace's accesses, and the
    names the body reads from outside, which the hoist decision checked, are left as they were.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None
        self._spelled: set[str] | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        self._spelled = None
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
        cache = model_cache(self, self._root)
        creation = None
        if declarator.init is None:
            if (creation := self._creation(scope, declarator, cache)) is None:
                return None
        accesses = namespace_accesses(self._references(scope, name, declarator, creation))
        if not accesses:
            return None
        if creation is not None and not cache.dominance.runs_before_all(
            creation,
            [access for nodes in accesses.values() for access in nodes],
        ):
            return None
        props = set(accesses)
        model = cache.model
        namespace_id = declarator.id
        if isinstance(namespace_id, JsIdentifier):
            binding = model.binding_of(namespace_id)
            if (
                binding is not None
                and (
                    model.reached_from_outside(binding)
                    or model.local_reachable_by_direct_eval(binding)
                )
            ):
                return None
        scope_obj = model.scope_of(scope)
        if scope_obj is None:
            return None
        names = self._variable_names(model, scope, scope_obj, props)
        conflicts = self._find_conflicting_names(model, scope, scope_obj, names, declarator)
        captured = self._captured_keys(model, scope, scope_obj, accesses, names)
        inherited = self._inherited_keys(props, cache.effects)
        flattenable = set(names) - conflicts - captured - inherited
        flattenable = {
            key for key in flattenable
            if is_valid_identifier(names[key]) and not self.name_emitted_in(scope, names[key])
        }
        if not flattenable:
            return None
        func_assigns = self._detect_function_assignments(body, name, flattenable)
        hoisted_keys = (
            self._hoistable_functions(func_assigns, accesses, cache.dominance, names)
            if func_assigns else set()
        )
        hoisted = {k: v for k, v in func_assigns.items() if k in hoisted_keys}
        declarations = {names[key] for key in flattenable - set(hoisted)}
        declarations -= self._declared_var_names(body)
        for variable in declarations:
            self.emits(scope, variable)
        for key in hoisted:
            self.emits(scope, names[key])
        return _NamespacePlan(
            scope=scope,
            name=name,
            declarator=declarator,
            declaration=decl_stmt,
            creation=creation,
            names={key: names[key] for key in flattenable},
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
            if plan.creation is not None:
                anchors.append(plan.creation)
        if not all(is_attached(anchor) for anchor in anchors):
            return
        if not self._rewrite(plan.scope, plan.name, plan.declarator, plan.names):
            return
        self._remove_hoisted_statements(plan.scope, plan.hoisted)
        self._emit_declarations(plan.scope, plan.declarations)
        self._emit_function_declarations(plan.scope, plan.hoisted, plan.names)
        if plan.remove_declarator:
            self._remove_declarator(plan.scope, plan.declarator, plan.declaration)
            if plan.creation is not None:
                _remove_from_parent(plan.creation)
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
        """
        The `var` declarators of the scope body *body* that may declare a namespace: one with an
        empty object literal, and one with no value, which `_creation` reads further.
        """
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
                if decl.init is not None and (
                    not isinstance(decl.init, JsObjectExpression)
                    or decl.init.properties
                ):
                    continue
                yield decl.id.name, decl, stmt

    @staticmethod
    def _creation(
        scope: Node,
        declarator: JsVariableDeclarator,
        cache: ModelCache,
    ) -> JsExpressionStatement | None:
        """
        The statement `NS = {};` creating the object of a namespace declared without a value,
        `var NS;`: the one write of the name, a statement of the code of *scope* itself that control
        reaches at most once whenever the scope runs
        (`refinery.lib.scripts.analysis.cycles.CycleModel`). Every access of the namespace that runs
        after it then reaches the one object it made, as one after `var NS = {}` does; that every
        access runs after it is the caller's to ask. The statement goes with the declaration, so it
        stands in a statement list (`refinery.lib.scripts.js.analysis.model.statement_list_of`) and
        not as the body of a label, whose store would outlive the declaration.
        """
        if not isinstance(declarator.id, JsIdentifier):
            return None
        binding = cache.model.binding_of(declarator.id)
        if (
            binding is None
            or binding.declarations != [declarator.id]
            or binding.has_indefinite_write
            or len(binding.writes) != 1
        ):
            return None
        target = binding.writes[0]
        if not (
            isinstance(store := target.parent, JsAssignmentExpression)
            and store.operator == '='
            and store.left is target
            and isinstance(created := store.right, JsObjectExpression)
            and not created.properties
            and isinstance(statement := store.parent, JsExpressionStatement)
            and (holder := statement.parent) is not None
            and statement_list_of(holder) is not None
        ):
            return None
        owner = scope if isinstance(scope, JsScript) else scope.parent
        located = cache.control_flow.locate(statement)
        if (
            owner is None
            or located is None
            or located[0] is not cache.control_flow.graph_of(owner)
            or cache.cycles.on_a_cycle(*located)
        ):
            return None
        return statement

    @staticmethod
    def _references(
        scope: Node,
        name: str,
        declarator: JsVariableDeclarator,
        creation: JsExpressionStatement | None,
    ) -> list[Node]:
        """
        Every reference to the namespace variable in the scope subtree: each identifier spelling its
        name but its declaration, the target of the statement creating it, and one in non-computed
        property position (`other.NS`), which names a property rather than the variable.
        """
        created = None
        if creation is not None and isinstance(creation.expression, JsAssignmentExpression):
            created = creation.expression.left
        return [
            node for node in JsNamespaceFlattening._walk_pruning_shadows(scope, name)
            if node is not declarator.id
            and node is not created
            and isinstance(node, JsIdentifier)
            and node.name == name
            and not (
                isinstance(parent := node.parent, JsMemberExpression)
                and parent.property is node
                and not parent.computed
            )
        ]

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

    def _variable_names(
        self,
        model: SemanticModel,
        scope: Node,
        scope_obj: Scope,
        props: set[str],
    ) -> dict[str, str]:
        """
        The name of the variable each key of *props* becomes in *scope*: the key itself, unless a
        declaration of it there would be the property of the global object a host reads
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.lands_on_the_host`). Such a key takes
        the name `refinery.lib.scripts.js.deobfuscation.helpers.name_off_the_host` finds, which the
        text spells nowhere and no declaration of the batch takes, and is left out where there is
        none, which keeps it on the namespace: the object the program stored into was its own, and
        `cfg.location = u` at the top of a script becomes a variable `location_1`, where a variable
        `location` would navigate the window.
        """
        names = {key: key for key in props}

        def taken(name: str) -> bool:
            return (
                name in names.values()
                or name in self._spelled_names()
                or self.name_emitted_in(scope, name)
            )

        for key in sorted(props):
            if not is_valid_identifier(key) or not model.lands_on_the_host(key, scope_obj):
                continue
            variable = name_off_the_host(key, scope_obj, model, taken)
            if variable is None:
                del names[key]
            else:
                names[key] = variable
        return names

    def _spelled_names(self) -> set[str]:
        """
        Every name an identifier of the script spells, read once per invocation and only once a key
        needs another name (`_variable_names`). A name an earlier plan of the invocation writes into
        the tree, which a plan applied at once does, is one it emits, and `name_emitted_in` holds it
        back.
        """
        if self._spelled is None:
            assert self._root is not None
            self._spelled = collect_identifier_names(self._root)
        return self._spelled

    @staticmethod
    def _find_conflicting_names(
        model: SemanticModel,
        scope: Node,
        scope_obj: Scope,
        names: dict[str, str],
        declarator: JsVariableDeclarator,
    ) -> set[str]:
        """
        Return the keys of *names* that cannot be flattened because the name of the variable each
        becomes (`_variable_names`) already appears as a variable reference in the scope. An
        occurrence that resolves to a binding strictly nested below *scope_obj* shadows the
        would-be declaration and is therefore not a conflict.

        An occurrence in object position (`k.y`) counts the same way a bare one does: it reads the
        binding, so the declaration the flattening emits would capture it. Only an occurrence in
        non-computed property position (`x.k`) names a property rather than a variable and is
        ignored. The whole subtree is walked: a function that binds the namespace's own name holds
        no access to the namespace, but a name it reads from outside is captured all the same.
        """
        decl_id = declarator.id
        keys = {name: key for key, name in names.items()}
        conflicts: set[str] = set()
        for node in scope.walk():
            if not isinstance(node, JsIdentifier):
                continue
            key = keys.get(node.name)
            if key is None or key in conflicts:
                continue
            if node is decl_id:
                continue
            parent = node.parent
            if isinstance(parent, JsMemberExpression) and parent.property is node and not parent.computed:
                continue
            if model.is_shadowed(node.name, node, scope_obj):
                continue
            conflicts.add(key)
        return conflicts

    def _captured_keys(
        self,
        model: SemanticModel,
        scope: Node,
        scope_obj: Scope,
        references_by_key: dict[str, list[Node]],
        names: dict[str, str],
    ) -> set[str]:
        """
        The keys some access `NS.k` of which the bare name that replaces it, the variable *names*
        maps the key to, would not carry to the declaration the flattening emits in *scope*: between
        the access and *scope* the name is bound anew, by a binding of the program
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.is_shadowed`), by a declaration an
        earlier plan of the batch emits into a scope nested below this one
        (`refinery.lib.scripts.js.deobfuscation.helpers.BatchedScopeTransformer.name_emitted_in`),
        or at runtime: by the object of a `with` body the access stands in, or by a `var` a direct
        `eval` declares below *scope* where the access can see it
        (`refinery.lib.scripts.js.analysis.model.SemanticModel.direct_eval_declares_below`).
        Scopes are decided innermost first, so every such plan is decided before this one.
        """
        captured: set[str] = set()
        for key, variable in names.items():
            for reference in references_by_key[key]:
                assert isinstance(reference, JsMemberExpression) and reference.object is not None
                if (
                    model.is_shadowed(variable, reference.object, scope_obj)
                    or self._crosses_a_with_body(model, reference, scope_obj)
                    or model.direct_eval_declares_below(reference, scope_obj)
                    or any(
                        self.name_emitted_in(enclosing, variable)
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
        names: dict[str, str],
    ) -> bool:
        """
        Replace every flattenable `NS.prop` member access in the scope subtree with the bare name of
        the variable *names* maps its key to, walking the tree as it stands. Returns whether any
        replacement landed.
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
            if key is None or key not in names:
                continue
            replacement = JsIdentifier(name=names[key], offset=parent.offset)
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
        names: dict[str, str],
    ) -> set[str]:
        """
        The function properties whose single `NS.f = function…` assignment may be raised to a hoisted
        `function f(){}` declaration. Hoisting makes the function reachable from the top of the scope,
        so it is sound only when the assignment provably runs before every reference to the property —
        a `DominanceModel.runs_before_all` query over every `NS.f` access, computed forms included, so
        a read that could run first (earlier in the scope, or inside a function invoked earlier) keeps
        the property in place. The rewrite to a declaration also drops the function expression's own
        name, so an inner name other than that of the variable the key becomes (*names*), as a
        recursive `function fact` assigned to `NS.other` has, would become unbound; such a property
        is likewise held back. A property failing either test keeps its assignment in place behind
        a bare `var f;`, reproducing the original member's `undefined`-until-assigned semantics.
        """
        hoistable: set[str] = set()
        for key, entry in func_assigns.items():
            func_expr = entry.rhs
            if not isinstance(func_expr, JsFunctionExpression):
                continue
            if func_expr.id is not None and func_expr.id.name != names[key]:
                continue
            statement = entry.statement
            references = [ref for ref in references_by_key.get(key, ()) if ref is not entry.write]
            if dominance.runs_before_all(statement, references):
                hoistable.add(key)
        return hoistable

    @staticmethod
    def _emit_function_declarations(
        scope: Node,
        func_assigns: dict[str, _PropertyAssignment],
        names: dict[str, str],
    ) -> None:
        """
        Hoist a function declaration for each flattened property that held a function expression,
        under the name of the variable *names* maps its key to, all spliced in one call.

        The names are sorted in reverse because one splice keeps the order it is handed, where the
        head-insertion it replaced reversed it. The emitted order is the one that was emitted before,
        and sorting them forward would silently change the output of every flattened namespace.
        """
        declarations = []
        for key in sorted(func_assigns, reverse=True):
            func_expr = func_assigns[key].rhs
            assert isinstance(func_expr, JsFunctionExpression)
            declarations.append(JsFunctionDeclaration(
                id=JsIdentifier(name=names[key]),
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
