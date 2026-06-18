"""
A lexical semantic model for JavaScript: a tree of scopes with resolved bindings, computed once over
an AST and then queried by deobfuscation transforms instead of each transform re-deriving scope and
binding facts on its own.

This is the foundation layer of the analysis substrate. Its public surface is intentionally
representation-agnostic: callers receive `Scope` and `Binding` objects and ask questions about AST
nodes by identity, never about how the facts were computed. Later layers (control-flow graphs, effect
summaries) attach behind the same surface without changing it.

The model is *flow-insensitive*. It answers lexical questions — which declaration a name resolves to,
what a scope binds, where a binding lives — but not control-flow questions such as which definition
reaches a use. Definition/use sets and reflection-surface detection are layered on top separately.

Where JavaScript scoping is genuinely ambiguous the model is deliberately conservative, resolving a
name to a *wider* binding rather than risk treating a live reference as free: a function declaration
nested in a block is hoisted to the enclosing function scope (legacy/Annex-B semantics), and a name
used inside a `with` body or any dynamically-scoped region resolves to `None` (unknown) rather than to
a guessed binding.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentPattern,
    JsBlockStatement,
    JsBreakStatement,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsContinueStatement,
    JsExportSpecifier,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsMemberExpression,
    JsObjectPattern,
    JsProperty,
    JsRestElement,
    JsScript,
    JsSwitchStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWithStatement,
)

FUNCTION_NODES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)

_FunctionNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression


class ScopeKind(enum.Enum):
    SCRIPT   = 'script'    # noqa
    FUNCTION = 'function'  # noqa
    BLOCK    = 'block'     # noqa
    CATCH    = 'catch'     # noqa
    CLASS    = 'class'     # noqa
    WITH     = 'with'      # noqa


class BindingKind(enum.Enum):
    VAR       = 'var'        # noqa
    LET       = 'let'        # noqa
    CONST     = 'const'      # noqa
    PARAM     = 'param'      # noqa
    FUNCTION  = 'function'   # noqa
    CLASS     = 'class'      # noqa
    CATCH     = 'catch'      # noqa
    IMPORT    = 'import'     # noqa
    ARGUMENTS = 'arguments'  # noqa
    FUNC_NAME = 'func_name'  # noqa  the own name of a named function expression


@dataclass(eq=False)
class Binding:
    """
    A single declared name within one scope. `declarations` holds the binding-site identifier nodes
    that introduce the name (a name may be introduced more than once, e.g. a repeated `var`).
    """
    name: str
    kind: BindingKind
    scope: Scope
    declarations: list[JsIdentifier] = field(default_factory=list)


@dataclass(eq=False)
class Scope:
    """
    A lexical scope. `node` is the AST node that introduces it (the script, a function, a block, a
    catch clause, a class, or a `with`). `is_dynamic` marks a region whose bindings cannot be resolved
    statically because names may be injected at runtime (`with`, direct `eval`).
    """
    kind: ScopeKind
    node: Node
    parent: Scope | None = None
    children: list[Scope] = field(default_factory=list)
    bindings: dict[str, Binding] = field(default_factory=dict)
    is_dynamic: bool = False

    @property
    def is_var_scope(self) -> bool:
        """
        Whether this scope is the target of `var`/function-declaration hoisting: a function body or
        the script itself.
        """
        return self.kind is ScopeKind.FUNCTION or self.kind is ScopeKind.SCRIPT


def is_use_position(node: JsIdentifier) -> bool:
    """
    Whether an identifier occupies a position where it reads a value, as opposed to naming a property,
    an object-literal key, a label, or an import/export specifier. Binding sites are not excluded here;
    callers separate those via `SemanticModel.binding_of`.
    """
    p = node.parent
    if p is None:
        return False
    if isinstance(p, JsMemberExpression) and p.property is node and not p.computed:
        return False
    if isinstance(p, JsProperty) and p.key is node and not p.computed and not p.shorthand:
        return False
    if isinstance(p, (JsBreakStatement, JsContinueStatement, JsLabeledStatement)) and p.label is node:
        return False
    if isinstance(p, (
        JsImportSpecifier,
        JsImportDefaultSpecifier,
        JsImportNamespaceSpecifier,
        JsExportSpecifier,
    )):
        return False
    return True


def pattern_identifiers(target: Node | None) -> Iterator[JsIdentifier]:
    """
    Yield every binding-site identifier introduced by a declaration target, descending through
    destructuring patterns (`[a, {b: c}]`, `{x, ...rest}`), default patterns, and rest elements. A
    member-expression target (`[a.b] = ...`) introduces no binding and yields nothing.
    """
    if target is None:
        return
    if isinstance(target, JsIdentifier):
        yield target
    elif isinstance(target, JsArrayPattern):
        for element in target.elements:
            yield from pattern_identifiers(element)
    elif isinstance(target, JsObjectPattern):
        for prop in target.properties:
            if isinstance(prop, JsRestElement):
                yield from pattern_identifiers(prop.argument)
            elif isinstance(prop, JsProperty):
                yield from pattern_identifiers(prop.value)
    elif isinstance(target, JsAssignmentPattern):
        yield from pattern_identifiers(target.left)
    elif isinstance(target, JsRestElement):
        yield from pattern_identifiers(target.argument)


def _walk_skipping_functions(stmts: list) -> Iterator[Node]:
    """
    Yield the statements in *stmts* and all their descendants, but do not descend into nested function
    bodies (the function nodes themselves are yielded so their declared names can be read).
    """
    stack: list[Node] = list(reversed(stmts))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FUNCTION_NODES):
            continue
        stack.extend(reversed(node.children()))


class SemanticModel:
    """
    The resolved scope/binding model for one script. Build it with `build_semantic_model` and query it
    through `resolve`, `scope_of`, and `binding_of`.
    """

    def __init__(self, root: JsScript):
        self.root = root
        self._node_scope: dict[int, Scope] = {}
        self._binding_of: dict[int, Binding] = {}
        self.root_scope: Scope = _ScopeBuilder(self).build(root)

    def scope_of(self, node: Node) -> Scope | None:
        """
        The innermost scope that lexically contains *node*, or `None` if the node was not part of the
        script the model was built from.
        """
        return self._node_scope.get(id(node))

    def binding_of(self, decl_id: JsIdentifier) -> Binding | None:
        """
        The binding introduced by a binding-site identifier (a declarator id, parameter, function or
        class name, catch parameter, or import local), or `None` if the identifier is not a binding
        site.
        """
        return self._binding_of.get(id(decl_id))

    def resolve(self, ref: JsIdentifier) -> Binding | None:
        """
        The binding a referencing identifier reads, found by walking outward from its scope. Returns
        `None` when the name is free (a global or implicit global), when the identifier is not a read
        (a property name, key, or label), or when resolution crosses a dynamically-scoped region where
        the name could be injected at runtime.
        """
        if id(ref) in self._binding_of:
            return None
        if not is_use_position(ref):
            return None
        scope = self._node_scope.get(id(ref))
        name = ref.name
        while scope is not None:
            binding = scope.bindings.get(name)
            if binding is not None:
                return binding
            if scope.is_dynamic:
                return None
            scope = scope.parent
        return None


class _ScopeBuilder:
    """
    Single-pass scope and binding construction. Bindings are collected when a scope is created
    (parameters and hoisted `var`/function names for function scopes, lexical `let`/`const`/`class`
    for block scopes); the recursive walk only records which scope each node belongs to.
    """

    def __init__(self, model: SemanticModel):
        self.model = model

    def build(self, root: JsScript) -> Scope:
        scope = Scope(kind=ScopeKind.SCRIPT, node=root)
        self.model._node_scope[id(root)] = scope
        self._hoist(root.body, scope)
        self._collect_imports(root.body, scope)
        for stmt in root.body:
            self._visit(stmt, scope)
        return scope

    def _new_scope(self, kind: ScopeKind, node: Node, parent: Scope) -> Scope:
        scope = Scope(kind=kind, node=node, parent=parent)
        parent.children.append(scope)
        return scope

    def _declare(
        self, scope: Scope, name: str, kind: BindingKind, decl_id: JsIdentifier | None,
    ) -> Binding:
        binding = scope.bindings.get(name)
        if binding is None:
            binding = Binding(name=name, kind=kind, scope=scope)
            scope.bindings[name] = binding
        if decl_id is not None:
            binding.declarations.append(decl_id)
            self.model._binding_of[id(decl_id)] = binding
        return binding

    def _hoist(self, stmts: list, func_scope: Scope):
        for node in _walk_skipping_functions(stmts):
            if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        for ident in pattern_identifiers(decl.id):
                            self._declare(func_scope, ident.name, BindingKind.VAR, ident)
            elif isinstance(node, JsFunctionDeclaration) and node.id is not None:
                self._declare(func_scope, node.id.name, BindingKind.FUNCTION, node.id)

    def _collect_imports(self, stmts: list, scope: Scope):
        for stmt in stmts:
            if not isinstance(stmt, JsImportDeclaration):
                continue
            for spec in stmt.specifiers:
                local = spec.local
                if isinstance(local, JsIdentifier):
                    self._declare(scope, local.name, BindingKind.IMPORT, local)

    def _collect_lexical(self, stmts: list, scope: Scope):
        for stmt in stmts:
            if isinstance(stmt, JsVariableDeclaration) and stmt.kind in (
                JsVarKind.LET, JsVarKind.CONST,
            ):
                kind = BindingKind.LET if stmt.kind is JsVarKind.LET else BindingKind.CONST
                for decl in stmt.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        for ident in pattern_identifiers(decl.id):
                            self._declare(scope, ident.name, kind, ident)
            elif isinstance(stmt, JsClassDeclaration) and stmt.id is not None:
                self._declare(scope, stmt.id.name, BindingKind.CLASS, stmt.id)

    def _visit(self, node: Node, scope: Scope):
        self.model._node_scope[id(node)] = scope
        if isinstance(node, (
            JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
        )):
            self._visit_function(node, scope)
        elif isinstance(node, JsBlockStatement):
            self._visit_block(node, scope)
        elif isinstance(node, JsForStatement):
            self._visit_for(node, scope)
        elif isinstance(node, (JsForInStatement, JsForOfStatement)):
            self._visit_for_in_of(node, scope)
        elif isinstance(node, JsSwitchStatement):
            self._visit_switch(node, scope)
        elif isinstance(node, JsCatchClause):
            self._visit_catch(node, scope)
        elif isinstance(node, JsWithStatement):
            self._visit_with(node, scope)
        elif isinstance(node, (JsClassDeclaration, JsClassExpression)):
            self._visit_class(node, scope)
        else:
            for child in node.children():
                self._visit(child, scope)

    def _visit_function(self, node: _FunctionNode, enclosing: Scope):
        fscope = self._new_scope(ScopeKind.FUNCTION, node, enclosing)
        is_arrow = isinstance(node, JsArrowFunctionExpression)
        if isinstance(node, JsFunctionExpression) and node.id is not None:
            self._declare(fscope, node.id.name, BindingKind.FUNC_NAME, node.id)
        for param in node.params:
            for ident in pattern_identifiers(param):
                self._declare(fscope, ident.name, BindingKind.PARAM, ident)
        if not is_arrow:
            self._declare(fscope, 'arguments', BindingKind.ARGUMENTS, None)
        body = node.body
        if isinstance(body, JsBlockStatement):
            self._hoist(body.body, fscope)
        for param in node.params:
            self._visit(param, fscope)
        if isinstance(body, JsBlockStatement):
            self.model._node_scope[id(body)] = fscope
            for stmt in body.body:
                self._visit(stmt, fscope)
        elif body is not None:
            self._visit(body, fscope)

    def _visit_block(self, node: JsBlockStatement, enclosing: Scope):
        bscope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
        self._collect_lexical(node.body, bscope)
        for stmt in node.body:
            self._visit(stmt, bscope)

    def _visit_for(self, node: JsForStatement, enclosing: Scope):
        init = node.init
        if isinstance(init, JsVariableDeclaration) and init.kind in (JsVarKind.LET, JsVarKind.CONST):
            scope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
            self._collect_lexical([init], scope)
        else:
            scope = enclosing
        for part in (node.init, node.test, node.update, node.body):
            if part is not None:
                self._visit(part, scope)

    def _visit_for_in_of(self, node: JsForInStatement | JsForOfStatement, enclosing: Scope):
        left = node.left
        if isinstance(left, JsVariableDeclaration) and left.kind in (JsVarKind.LET, JsVarKind.CONST):
            scope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
            self._collect_lexical([left], scope)
        else:
            scope = enclosing
        if node.right is not None:
            self._visit(node.right, enclosing)
        if left is not None:
            self._visit(left, scope)
        if node.body is not None:
            self._visit(node.body, scope)

    def _visit_switch(self, node: JsSwitchStatement, enclosing: Scope):
        if node.discriminant is not None:
            self._visit(node.discriminant, enclosing)
        sscope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
        for case in node.cases:
            self._collect_lexical(case.body, sscope)
        for case in node.cases:
            self.model._node_scope[id(case)] = sscope
            if case.test is not None:
                self._visit(case.test, sscope)
            for stmt in case.body:
                self._visit(stmt, sscope)

    def _visit_catch(self, node: JsCatchClause, enclosing: Scope):
        cscope = self._new_scope(ScopeKind.CATCH, node, enclosing)
        if node.param is not None:
            for ident in pattern_identifiers(node.param):
                self._declare(cscope, ident.name, BindingKind.CATCH, ident)
            self._visit(node.param, cscope)
        if node.body is not None:
            self._visit(node.body, cscope)

    def _visit_with(self, node: JsWithStatement, enclosing: Scope):
        if node.object is not None:
            self._visit(node.object, enclosing)
        wscope = self._new_scope(ScopeKind.WITH, node, enclosing)
        wscope.is_dynamic = True
        if node.body is not None:
            self._visit(node.body, wscope)

    def _visit_class(self, node: JsClassDeclaration | JsClassExpression, enclosing: Scope):
        if isinstance(node, JsClassDeclaration) and node.id is not None:
            self._declare(enclosing, node.id.name, BindingKind.CLASS, node.id)
        if node.super_class is not None:
            self._visit(node.super_class, enclosing)
        cscope = self._new_scope(ScopeKind.CLASS, node, enclosing)
        if isinstance(node, JsClassExpression) and node.id is not None:
            self._declare(cscope, node.id.name, BindingKind.CLASS, node.id)
        body = node.body
        if body is not None:
            self.model._node_scope[id(body)] = cscope
            for member in body.body:
                self._visit(member, cscope)


def build_semantic_model(root: JsScript) -> SemanticModel:
    """
    Build the `SemanticModel` for a parsed script.
    """
    return SemanticModel(root)
