"""
Flatten empty namespace objects into bare variable declarations.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

from refinery.lib.scripts import Expression, Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.model import Scope, SemanticModel, build_semantic_model
from refinery.lib.scripts.js.deobfuscation.helpers import (
    FUNCTION_NODE_TYPES,
    ScopeProcessingTransformer,
    access_key,
    function_binds_name,
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
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)


class _PropertyAssignment(NamedTuple):
    rhs: Expression
    stmt_index: int


class JsNamespaceFlattening(ScopeProcessingTransformer):
    """
    Replace `NS.prop` member accesses with bare identifiers when `NS` is declared as an empty
    object literal and is only ever used via property access. Emits `var` declarations for the
    flattened property names. Properties whose names conflict with existing variables in the scope
    are left on the namespace object.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_scope_body(self, scope: Node, body: list) -> None:
        assert self._root is not None
        for name, declarator, decl_stmt in self._find_candidates(body):
            if not self._is_safe(scope, name, declarator):
                continue
            props = self._collect_properties(scope, name, declarator)
            if not props:
                continue
            model = build_semantic_model(self._root)
            scope_obj = model.scope_of(scope)
            if scope_obj is None:
                continue
            conflicts = self._find_conflicting_names(model, scope, scope_obj, name, props, declarator)
            flattenable = props - conflicts
            if not flattenable:
                continue
            inits = self._detect_init_assignments(body, name, flattenable)
            func_assigns = self._detect_function_assignments(body, name, flattenable)
            self._rewrite(scope, name, declarator, flattenable)
            all_removals: dict[str, _PropertyAssignment] = {}
            all_removals.update(inits)
            all_removals.update(func_assigns)
            self._remove_init_statements(body, all_removals)
            self._emit_declarations(scope, body, flattenable - set(func_assigns), inits)
            self._emit_function_declarations(scope, body, func_assigns)
            if not conflicts:
                self._remove_declarator(body, declarator, decl_stmt)
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
            if isinstance(node, FUNCTION_NODE_TYPES):
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
        statically extractable key. Identifiers in non-computed property position (e.g.
        `other.NS`) do not reference the variable and are ignored.
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
    def _find_conflicting_names(
        model: SemanticModel,
        scope: Node,
        scope_obj: Scope,
        name: str,
        props: set[str],
        declarator: JsVariableDeclarator,
    ) -> set[str]:
        """
        Return the subset of property names that cannot be flattened because they already appear
        as variable references in the scope. An occurrence that resolves to a binding strictly
        nested below *scope_obj* shadows the would-be declaration and is therefore not a conflict.
        """
        decl_id = declarator.id
        conflicts: set[str] = set()
        for node in JsNamespaceFlattening._walk_pruning_shadows(scope, name):
            if not isinstance(node, JsIdentifier):
                continue
            if node.name not in props or node.name in conflicts:
                continue
            if node is decl_id:
                continue
            parent = node.parent
            if isinstance(parent, JsMemberExpression) and parent.property is node and not parent.computed:
                continue
            if isinstance(parent, JsMemberExpression) and parent.object is node:
                continue
            if model.is_shadowed(node.name, node, scope_obj):
                continue
            conflicts.add(node.name)
        return conflicts

    @staticmethod
    def _rewrite(
        scope: Node,
        name: str,
        declarator: JsVariableDeclarator,
        flattenable: set[str],
    ) -> None:
        decl_id = declarator.id
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
            _replace_in_parent(parent, replacement)

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
        for idx, stmt in enumerate(body):
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
                found[key] = _PropertyAssignment(expr.right, idx)
        return {k: v for k, v in found.items() if counts.get(k) == 1}

    @staticmethod
    def _detect_init_assignments(
        body: list,
        name: str,
        flattenable: set[str],
    ) -> dict[str, _PropertyAssignment]:
        """
        Scan body-level statements for `NS.X = {}` patterns that represent namespace property
        initializations.
        """
        return JsNamespaceFlattening._detect_single_assignments(
            body,
            name,
            flattenable,
            lambda rhs: isinstance(rhs, JsObjectExpression) and not rhs.properties,
        )

    @staticmethod
    def _remove_init_statements(body: list, inits: dict[str, _PropertyAssignment]) -> None:
        for _, entry in sorted(inits.items(), key=lambda x: x[1].stmt_index, reverse=True):
            del body[entry.stmt_index]

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
    def _emit_function_declarations(
        scope: Node,
        body: list,
        func_assigns: dict[str, _PropertyAssignment],
    ) -> None:
        for name in sorted(func_assigns):
            func_expr = func_assigns[name].rhs
            assert isinstance(func_expr, JsFunctionExpression)
            decl = JsFunctionDeclaration(
                id=JsIdentifier(name=name),
                params=func_expr.params or [],
                body=func_expr.body,
                generator=func_expr.generator,
                is_async=func_expr.is_async,
            )
            decl.parent = scope
            body.insert(0, decl)

    @staticmethod
    def _emit_declarations(
        scope: Node,
        body: list,
        props: set[str],
        inits: dict[str, _PropertyAssignment] | None = None,
    ) -> None:
        existing: set[str] = set()
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            if stmt.kind != JsVarKind.VAR:
                continue
            for decl in stmt.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    existing.add(decl.id.name)
        needed = sorted(props - existing)
        if not needed:
            return
        declarations: list[JsVariableDeclarator] = []
        for n in needed:
            init_expr: Expression | None = None
            if inits and n in inits:
                init_expr = JsObjectExpression(properties=[])
            declarations.append(JsVariableDeclarator(id=JsIdentifier(name=n), init=init_expr))
        decl = JsVariableDeclaration(declarations=declarations, kind=JsVarKind.VAR)
        decl.parent = scope
        body.insert(0, decl)

    @staticmethod
    def _remove_declarator(
        body: list,
        declarator: JsVariableDeclarator,
        decl_stmt: JsVariableDeclaration,
    ) -> None:
        if len(decl_stmt.declarations) == 1:
            body.remove(decl_stmt)
        else:
            decl_stmt.declarations.remove(declarator)
