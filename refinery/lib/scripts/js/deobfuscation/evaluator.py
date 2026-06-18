"""
Evaluate pure JavaScript functions called with constant arguments and replace call sites with
computed results.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from refinery.lib.scripts.js.deobfuscation.interpreter import Value

from refinery.lib.scripts import Node, _clone_node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel, build_semantic_model
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    binding_has_references,
    extract_literal_value,
    is_reference,
    references_receiver_this,
    remove_declarator,
    value_to_node,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    InterpreterError,
    IrreducibleExpression,
    JsInterpreter,
    _contains_jsbuffer,
    is_runtime_name,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsCatchClause,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)

MAX_RESULT_ARRAY_LEN = 260

_FuncNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression

_MISSING = object()

_MUTATING_ARRAY_METHODS = frozenset({
    'push', 'pop', 'shift', 'unshift', 'splice', 'reverse', 'sort', 'fill', 'copyWithin',
})


def _is_inplace_mutation(node: JsIdentifier) -> bool:
    """
    Return whether the reference *node* mutates the value bound to its name in place: a member-target
    write (`x[i] = v`, `x.p = v`, `x[i]++`, `delete x.p`) or a call to a known mutating array method
    (`x.push(...)`, `x.reverse()`, ...). Such mutations are invisible to closure / const-argument
    capture, which snapshots only the declared initializer value.
    """
    parent = node.parent
    if not isinstance(parent, JsMemberExpression) or parent.object is not node:
        return False
    grand = parent.parent
    if isinstance(grand, JsAssignmentExpression) and grand.left is parent:
        return True
    if isinstance(grand, JsUpdateExpression) and grand.argument is parent:
        return True
    if isinstance(grand, JsUnaryExpression) and grand.operator == 'delete' and grand.operand is parent:
        return True
    if isinstance(grand, (JsForOfStatement, JsForInStatement)) and grand.left is parent:
        return True
    if isinstance(grand, JsCallExpression) and grand.callee is parent:
        return access_key(parent) in _MUTATING_ARRAY_METHODS
    return False


class _Scope:
    __slots__ = ('functions', 'parent')

    def __init__(self, parent: _Scope | None = None):
        self.functions: dict[str, _FuncNode] = {}
        self.parent = parent

    def resolve(self, name: str) -> _FuncNode | None:
        scope: _Scope | None = self
        while scope is not None:
            func = scope.functions.get(name)
            if func is not None:
                return func
            scope = scope.parent
        return None


def _is_pure_function(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known_pure: set[str],
) -> bool:
    """
    Check whether a function is eligible for evaluation. A function is eligible if its body is
    closed — it only references its own parameters, variables declared within its body, functions
    in the known-pure set, built-in methods from the registry, or well-known globals. Functions
    whose body is a single switch-return pattern (globalConcealing shape) are also eligible even
    if their return expressions reference external names — the irreducible fallback handles those.
    """
    for param in func.params:
        if not isinstance(param, JsIdentifier):
            return False
    body = func.body
    if body is None:
        return True
    local_names = {p.name for p in func.params if isinstance(p, JsIdentifier)}
    _collect_declared_names(body, local_names)
    func_own_name: str | None = None
    if isinstance(func, JsFunctionDeclaration) and isinstance(func.id, JsIdentifier):
        func_own_name = func.id.name
        local_names.add(func_own_name)
    elif isinstance(func, JsFunctionExpression) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    if references_receiver_this(body):
        return False
    if _is_switch_return_pattern(body, local_names):
        return True
    for node in walk_scope(body):
        if isinstance(node, JsAssignmentExpression):
            if isinstance(node.left, JsIdentifier) and node.left.name == func_own_name:
                return False
            if isinstance(node.left, JsMemberExpression):
                return False
        if isinstance(node, JsIdentifier):
            if is_reference(node) and node.name not in local_names:
                name = node.name
                if name in known_pure:
                    continue
                if name in ('undefined', 'NaN', 'Infinity'):
                    continue
                if is_runtime_name(name):
                    continue
                return False
    return True


def _is_switch_return_pattern(body, local_names: set[str]) -> bool:
    """
    Check whether the function body is a switch statement where every case returns an expression.
    This is the globalConcealing pattern where return expressions may reference external names
    but the dispatch logic itself is pure (switch on a parameter).
    """
    if not isinstance(body, JsBlockStatement):
        return False
    stmts = body.body
    if not stmts:
        return False
    switch = stmts[0]
    if not isinstance(switch, JsSwitchStatement):
        return False
    for remaining in stmts[1:]:
        if isinstance(remaining, JsReturnStatement) and remaining.argument is None:
            continue
        return False
    if switch.discriminant is None:
        return False
    if isinstance(switch.discriminant, JsIdentifier):
        if switch.discriminant.name not in local_names:
            return False
    elif not _all_refs_local(switch.discriminant, local_names):
        return False
    if not switch.cases:
        return False
    for case in switch.cases:
        if not isinstance(case, JsSwitchCase):
            return False
        if case.test is not None and not isinstance(case.test, (JsStringLiteral, JsNumericLiteral)):
            return False
        case_body = case.body
        if len(case_body) != 1:
            return False
        stmt = case_body[0]
        if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
            return False
    return True


def _all_refs_local(node: Node, local_names: set[str]) -> bool:
    for child in node.walk():
        if isinstance(child, JsIdentifier) and is_reference(child):
            if child.name not in local_names:
                return False
    return True


def _collect_declared_names(body, names: set[str]) -> None:
    if not isinstance(body, JsBlockStatement):
        return
    for node in walk_scope(body):
        if isinstance(node, JsVariableDeclaration):
            for decl in node.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    names.add(decl.id.name)
        if isinstance(node, JsFunctionDeclaration) and isinstance(node.id, JsIdentifier):
            names.add(node.id.name)
        if isinstance(node, JsCatchClause) and isinstance(node.param, JsIdentifier):
            names.add(node.param.name)


def _has_external_side_effects(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
) -> bool:
    """
    Return whether *func* performs observable side effects beyond simple identifier assignments.
    Member-expression writes (e.g. `obj.prop = x`), delete expressions, and self-assignment
    (reassigning the function's own name) are considered external side effects. Simple identifier
    assignments (e.g. `rr = x`) to undeclared names are treated as harmless obfuscator temporaries.
    """
    body = func.body
    if body is None:
        return False
    func_own_name: str | None = None
    if isinstance(func, JsFunctionDeclaration) and isinstance(func.id, JsIdentifier):
        func_own_name = func.id.name
    elif isinstance(func, (JsFunctionExpression, JsArrowFunctionExpression)):
        declarator = func.parent
        if isinstance(declarator, JsVariableDeclarator) and isinstance(declarator.id, JsIdentifier):
            func_own_name = declarator.id.name
    for node in walk_scope(body, include_root_body=True):
        if isinstance(node, JsAssignmentExpression):
            if isinstance(node.left, JsMemberExpression):
                return True
            if (
                func_own_name is not None
                and isinstance(node.left, JsIdentifier)
                and node.left.name == func_own_name
            ):
                return True
        if isinstance(node, JsUnaryExpression) and node.operator == 'delete':
            return True
    return False


def _unwrap_callee(node: Node) -> Node:
    while isinstance(node, JsParenthesizedExpression):
        if node.expression is None:
            break
        node = node.expression
    return node


def _unresolved_names(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known_pure: set[str],
) -> set[str]:
    """
    Return the set of external names referenced by *func* that are not locally declared, not in
    *known_pure*, and not well-known globals or runtime names. Names that are plain-assigned (`=`)
    within the function body AND also read within the same body are treated as implicit locals
    (obfuscator temporaries like `rr = expr; ... use(rr)`) and excluded. Names that are only
    plain-assigned but never read are also excluded (write-only temps). Compound-assigned names
    (`+=`, `|=`, etc.) that were NOT also plain-initialized are always retained — they perform a
    read-modify-write of the external binding and are never a local temp.
    """
    body = func.body
    if body is None:
        return set()
    local_names = {p.name for p in func.params if isinstance(p, JsIdentifier)}
    _collect_declared_names(body, local_names)
    if isinstance(func, JsFunctionDeclaration) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    elif isinstance(func, JsFunctionExpression) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    plain_assigned: set[str] = set()
    compound_assigned: set[str] = set()
    read: set[str] = set()
    for node in walk_scope(body, include_root_body=True):
        if not isinstance(node, JsIdentifier) or not is_reference(node):
            continue
        name = node.name
        if name in local_names:
            continue
        if isinstance(node.parent, JsAssignmentExpression) and node.parent.left is node:
            if node.parent.operator == '=':
                plain_assigned.add(name)
            else:
                compound_assigned.add(name)
                read.add(name)
        else:
            read.add(name)
    external_names: set[str] = set()
    for name in read - plain_assigned:
        if name in known_pure or name in ('undefined', 'NaN', 'Infinity') or is_runtime_name(name):
            continue
        external_names.add(name)
    return external_names


class JsFunctionEvaluator(ScriptLevelTransformer):
    """
    Evaluate pure JavaScript functions called with constant arguments, replacing call sites with
    computed results. Handles named function calls and IIFEs.
    """

    def __init__(self):
        super().__init__()
        self._script: JsScript | None = None
        self._scope_map: dict[int, _Scope] = {}
        self._pure_nodes: set[int] = set()
        self._closure_env: dict[int, dict[str, Value]] = {}
        self._call_counts: dict[int, int] = {}
        self._resolved_counts: dict[int, int] = {}
        self._failed_counts: dict[int, int] = {}

    def _process_script(self, node: JsScript) -> None:
        self._script = node
        self._build_scope_tree(node)
        self._analyze_purity()
        self._evaluate_calls(node)
        self._remove_resolved_definitions(node)

    def _build_scope_tree(self, script: JsScript) -> None:
        self._scope_map.clear()
        self._pure_nodes.clear()
        self._closure_env.clear()
        self._call_counts.clear()
        self._resolved_counts.clear()
        self._failed_counts.clear()
        root_scope = _Scope()
        self._scope_map[id(script)] = root_scope
        self._populate_scope(script, root_scope)

    def _populate_scope(self, scope_node: Node, scope: _Scope) -> None:
        for node in walk_scope(scope_node, include_root_body=True):
            if node is scope_node:
                continue
            if isinstance(node, JsFunctionDeclaration):
                if not isinstance(node.id, JsIdentifier) or node.body is None:
                    continue
                name = node.id.name
                scope.functions[name] = node
                child_scope = _Scope(parent=scope)
                self._scope_map[id(node)] = child_scope
                self._populate_scope(node, child_scope)
            elif isinstance(node, JsVariableDeclaration) and node.kind == JsVarKind.CONST:
                if not self._is_direct_body_child(node, scope_node):
                    continue
                for decl in node.declarations:
                    if not isinstance(decl, JsVariableDeclarator):
                        continue
                    if not isinstance(decl.id, JsIdentifier):
                        continue
                    init = decl.init
                    if not isinstance(init, (JsFunctionExpression, JsArrowFunctionExpression)):
                        continue
                    if init.body is None:
                        continue
                    name = decl.id.name
                    if name in scope.functions:
                        continue
                    scope.functions[name] = init
                    child_scope = _Scope(parent=scope)
                    self._scope_map[id(init)] = child_scope
                    self._populate_scope(init, child_scope)

    @staticmethod
    def _is_direct_body_child(node: Node, scope_node: Node) -> bool:
        """
        Return whether *node* is a direct statement of *scope_node*'s body — i.e. not inside
        a nested block. For function scope nodes, the body block is checked.
        """
        parent = node.parent
        if parent is scope_node:
            return True
        if isinstance(scope_node, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
            return parent is scope_node.body
        return False

    def _scope_for_node(self, node: Node) -> _Scope | None:
        current = node.parent
        while current is not None:
            scope = self._scope_map.get(id(current))
            if scope is not None:
                return scope
            current = current.parent
        return None

    def _resolve_function(self, call_node: Node, name: str) -> _FuncNode | None:
        scope = self._scope_for_node(call_node)
        if scope is None:
            return None
        func = scope.resolve(name)
        if func is None:
            return None
        current = call_node.parent
        while current is not None:
            if current is func:
                break
            if isinstance(current, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
                if any(isinstance(p, JsIdentifier) and p.name == name for p in current.params):
                    return None
            current = current.parent
        return func

    def _all_functions(self) -> Iterator[_FuncNode]:
        for scope in self._scope_map.values():
            yield from scope.functions.values()

    def _value_safe_to_capture(self, name: str, value: Value, owner: Node | None) -> bool:
        """
        Return whether a `const`-bound *value* can be safely inlined for *name*. A `const` binding is
        immutable, so primitive values are always safe. Arrays and objects, however, are mutated in
        place even when const-bound, and capture snapshots only the declared initializer — so they
        are unsafe if *name* is mutated in place anywhere except inside *owner*. The interpreter
        models *owner*'s own mutations (per-call deep copy plus cross-call writeback); mutations by
        any other code (a sibling statement, or a different capturing function) are not. When *owner*
        is None (const-argument resolution), any in-place mutation makes the value unsafe.
        """
        if not isinstance(value, (list, dict)):
            return True
        script = self._script
        if script is None:
            return False
        for node in script.walk():
            if not isinstance(node, JsIdentifier) or node.name != name:
                continue
            if not is_reference(node) or not _is_inplace_mutation(node):
                continue
            if owner is not None and node.is_descendant_of(owner):
                continue
            return False
        return True

    def _collect_closure_constants(self, func: _FuncNode) -> dict[str, Value]:
        child: Node | None
        own_declarator: JsVariableDeclarator | None = None
        scope_node: Node | None
        if isinstance(func, (JsFunctionExpression, JsArrowFunctionExpression)):
            declarator = func.parent
            if isinstance(declarator, JsVariableDeclarator):
                declaration = declarator.parent
                if isinstance(declaration, JsVariableDeclaration):
                    scope_node = declaration.parent
                    child = declaration
                    own_declarator = declarator
                else:
                    scope_node = func.parent
                    child = func
            else:
                scope_node = func.parent
                child = func
        else:
            scope_node = func.parent
            child = func
        result: dict[str, Value] = {}
        shadowed: set[str] = set()
        while scope_node is not None:
            if isinstance(scope_node, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
                for p in scope_node.params:
                    if isinstance(p, JsIdentifier):
                        shadowed.add(p.name)
            if isinstance(scope_node, JsCatchClause) and isinstance(scope_node.param, JsIdentifier):
                shadowed.add(scope_node.param.name)
            if isinstance(scope_node, (JsScript, JsBlockStatement)):
                self._collect_hoisted_vars(scope_node, shadowed)
                found_child = False
                for stmt in scope_node.body:
                    if stmt is child:
                        found_child = True
                        if own_declarator is not None and isinstance(stmt, JsVariableDeclaration):
                            if stmt.kind == JsVarKind.CONST:
                                for decl in stmt.declarations:
                                    if decl is own_declarator:
                                        break
                                    if (
                                        not isinstance(decl, JsVariableDeclarator)
                                        or not isinstance(decl.id, JsIdentifier)
                                    ):
                                        continue
                                    name = decl.id.name
                                    if name in result or name in shadowed:
                                        continue
                                    init = decl.init
                                    if init is None:
                                        shadowed.add(name)
                                        continue
                                    if isinstance(init, (JsFunctionExpression, JsArrowFunctionExpression)):
                                        result[name] = init
                                    else:
                                        ok, val = extract_literal_value(init)
                                        if ok and self._value_safe_to_capture(name, val, func):
                                            result[name] = val
                                        else:
                                            shadowed.add(name)
                            own_declarator = None
                        continue
                    if not found_child:
                        if isinstance(stmt, JsVariableDeclaration):
                            if stmt.kind == JsVarKind.CONST:
                                for decl in stmt.declarations:
                                    if (
                                        not isinstance(decl, JsVariableDeclarator)
                                        or not isinstance(decl.id, JsIdentifier)
                                    ):
                                        continue
                                    name = decl.id.name
                                    if name in result or name in shadowed:
                                        continue
                                    init = decl.init
                                    if init is None:
                                        shadowed.add(name)
                                        continue
                                    if isinstance(init, (JsFunctionExpression, JsArrowFunctionExpression)):
                                        result[name] = init
                                    else:
                                        ok, val = extract_literal_value(init)
                                        if ok and self._value_safe_to_capture(name, val, func):
                                            result[name] = val
                                        else:
                                            shadowed.add(name)
                            elif stmt.kind == JsVarKind.LET:
                                for decl in stmt.declarations:
                                    if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                                        shadowed.add(decl.id.name)
                        elif isinstance(stmt, JsFunctionDeclaration):
                            if isinstance(stmt.id, JsIdentifier):
                                shadowed.add(stmt.id.name)
                    else:
                        if isinstance(stmt, JsVariableDeclaration) and stmt.kind != JsVarKind.VAR:
                            for decl in stmt.declarations:
                                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                                    shadowed.add(decl.id.name)
            child = scope_node
            scope_node = scope_node.parent
        return result

    @staticmethod
    def _collect_hoisted_vars(scope_node: Node, shadowed: set[str]) -> None:
        """
        Recursively scan a block for `var` declarations and add their names to *shadowed*.
        In JavaScript, `var` is hoisted to the enclosing function scope regardless of textual
        position or block nesting, so a `var x` anywhere (including inside if/for/while/try)
        shadows an outer `const x`.
        """
        for node in walk_scope(scope_node):
            if isinstance(node, JsVariableDeclaration) and node.kind == JsVarKind.VAR:
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                        shadowed.add(decl.id.name)

    def _analyze_purity(self) -> None:
        closure_cache: dict[int, dict[str, Value]] = {
            id(func): self._collect_closure_constants(func)
            for func in self._all_functions()
            if not isinstance(func, JsFunctionDeclaration)
        }
        changed = True
        while changed:
            changed = False
            for func in self._all_functions():
                if id(func) in self._pure_nodes:
                    continue
                scope = self._scope_map.get(id(func))
                if scope is None:
                    continue
                visible_pure: set[str] = set()
                s: _Scope | None = scope
                while s is not None:
                    for name, f in s.functions.items():
                        if id(f) in self._pure_nodes:
                            visible_pure.add(name)
                    s = s.parent
                if _is_pure_function(func, visible_pure):
                    self._pure_nodes.add(id(func))
                    changed = True
                    continue
                if (
                    not isinstance(func, JsFunctionDeclaration)
                    and not _has_external_side_effects(func)
                    and func.body is not None
                    and not references_receiver_this(func.body)
                ):
                    unresolved = _unresolved_names(func, visible_pure)
                    if not unresolved:
                        self._pure_nodes.add(id(func))
                        changed = True
                        continue
                    closure = closure_cache.get(id(func), {})
                    if unresolved <= closure.keys():
                        self._pure_nodes.add(id(func))
                        self._closure_env[id(func)] = {n: closure[n] for n in unresolved}
                        changed = True

    def _evaluate_calls(self, script: JsScript) -> None:
        for node in list(script.walk_in_order()):
            if not isinstance(node, JsCallExpression):
                continue
            if node.callee is None:
                continue
            callee = _unwrap_callee(node.callee)
            if isinstance(callee, JsIdentifier):
                self._try_named_call(node, callee.name)
            elif isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
                self._try_iife(node, callee)

    def _try_named_call(self, node: JsCallExpression, name: str) -> None:
        func = self._resolve_function(node, name)
        if func is None or id(func) not in self._pure_nodes:
            return
        if node.is_descendant_of(func):
            return
        func_id = id(func)
        self._call_counts[func_id] = self._call_counts.get(func_id, 0) + 1
        args = self._extract_constant_args(node.arguments, node)
        if args is None:
            return
        success = self._evaluate_and_replace(node, func, args, gate_unresolved=True)
        if success:
            self._resolved_counts[func_id] = self._resolved_counts.get(func_id, 0) + 1
        else:
            self._failed_counts[func_id] = self._failed_counts.get(func_id, 0) + 1

    def _visible_functions(self, node: Node) -> dict[str, _FuncNode]:
        result: dict[str, _FuncNode] = {}
        scope = self._scope_for_node(node)
        while scope is not None:
            for name, func in scope.functions.items():
                if name not in result:
                    result[name] = func
            scope = scope.parent
        return result

    def _try_iife(
        self,
        node: JsCallExpression,
        func: JsFunctionExpression | JsArrowFunctionExpression,
    ) -> None:
        pure_names: set[str] = set()
        scope = self._scope_for_node(node)
        while scope is not None:
            for name, f in scope.functions.items():
                if id(f) in self._pure_nodes:
                    pure_names.add(name)
            scope = scope.parent
        if _is_pure_function(func, pure_names):
            args = self._extract_constant_args(node.arguments, node)
            if args is None:
                return
            self._evaluate_and_replace(node, func, args, gate_unresolved=False)
            return
        if (
            not _has_external_side_effects(func)
            and func.body is not None
            and not references_receiver_this(func.body)
        ):
            unresolved = _unresolved_names(func, pure_names)
            closure = self._collect_closure_constants(func)
            if unresolved <= closure.keys():
                args = self._extract_constant_args(node.arguments, node)
                if args is None:
                    return
                closure_env = {n: closure[n] for n in unresolved}
                self._evaluate_and_replace(node, func, args, gate_unresolved=False, closure_override=closure_env)

    def _evaluate_and_replace(
        self,
        node: JsCallExpression,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        args: list,
        gate_unresolved: bool,
        closure_override: dict | None = None,
    ) -> bool:
        """
        Run the interpreter on *func* with *args* and, on success, replace *node* with the result.
        Returns True if the call site was resolved (either to a value or a substituted expression).
        """
        functions_for_interpreter = self._visible_functions(node)
        closure = closure_override if closure_override is not None else self._closure_env.get(id(func))
        interpreter = JsInterpreter(
            functions=functions_for_interpreter,
            closure=closure,
            closure_env=self._closure_env,
        )
        try:
            result = interpreter.execute(func, args)
        except IrreducibleExpression as irr:
            if gate_unresolved and self._is_unresolved_call(irr.node):
                return False
            replacement = self._substitute_params_in_clone(irr.node, func, args)
            if replacement is not None:
                _replace_in_parent(node, replacement)
                self.mark_changed()
                return True
            return False
        except InterpreterError:
            return False
        if _contains_jsbuffer(result):
            return False
        if isinstance(result, list) and len(result) > MAX_RESULT_ARRAY_LEN:
            return False
        replacement = value_to_node(result)
        if replacement is None:
            return False
        if closure is not None and closure_override is None:
            for name in closure:
                if name in interpreter._env:
                    closure[name] = interpreter._env[name]
        _replace_in_parent(node, replacement)
        self.mark_changed()
        return True

    def _remove_resolved_definitions(self, script: JsScript) -> None:
        removed: set[int] = set()
        while True:
            model = build_semantic_model(script)
            before = len(removed)
            for func in self._all_functions():
                func_id = id(func)
                if func_id in removed:
                    continue
                call_count = self._call_counts.get(func_id, 0)
                if call_count == 0:
                    continue
                resolved = self._resolved_counts.get(func_id, 0)
                failed = self._failed_counts.get(func_id, 0)
                if (resolved + failed) < call_count:
                    continue
                name = self._function_name(func)
                if name is None:
                    continue
                exclude = self._function_exclude_node(func)
                binding = self._function_binding(model, func)
                if not binding_has_references(model, binding, exclude=exclude):
                    self._remove_function(func)
                    removed.add(func_id)
                    self.mark_changed()
            for func in self._all_functions():
                func_id = id(func)
                if func_id in removed:
                    continue
                if func_id not in self._pure_nodes:
                    continue
                name = self._function_name(func)
                if name is None:
                    continue
                call_count = self._call_counts.get(func_id, 0)
                if call_count == 0:
                    continue
                exclude = self._function_exclude_node(func)
                binding = self._function_binding(model, func)
                if not binding_has_references(model, binding, exclude=exclude):
                    self._remove_function(func)
                    removed.add(func_id)
                    self.mark_changed()
            if len(removed) == before:
                break
        self._remove_orphaned_closure_constants(script, removed)

    @staticmethod
    def _function_name(func: _FuncNode) -> str | None:
        if isinstance(func, JsFunctionDeclaration):
            return func.id.name if isinstance(func.id, JsIdentifier) else None
        declarator = func.parent
        if isinstance(declarator, JsVariableDeclarator) and isinstance(declarator.id, JsIdentifier):
            return declarator.id.name
        return None

    @staticmethod
    def _function_exclude_node(func: _FuncNode) -> Node:
        if isinstance(func, JsFunctionDeclaration):
            return func
        declarator = func.parent
        if isinstance(declarator, JsVariableDeclarator):
            return declarator
        return func

    @staticmethod
    def _function_binding(model: SemanticModel, func: _FuncNode) -> Binding | None:
        """
        The binding introduced by *func*'s name — the function declaration's own identifier, or the
        declarator that a named function expression is assigned to — or `None` when the function is
        anonymous and so has no name to reference.
        """
        if isinstance(func, JsFunctionDeclaration):
            ident = func.id
        else:
            declarator = func.parent
            ident = declarator.id if isinstance(declarator, JsVariableDeclarator) else None
        return model.binding_of(ident) if isinstance(ident, JsIdentifier) else None

    def _remove_function(self, func: _FuncNode) -> None:
        if isinstance(func, JsFunctionDeclaration):
            _remove_from_parent(func)
        else:
            declarator = func.parent
            if isinstance(declarator, JsVariableDeclarator):
                remove_declarator(declarator)
            else:
                _remove_from_parent(func)

    def _remove_orphaned_closure_constants(
        self, script: JsScript, removed: set[int],
    ) -> None:
        closure_names: set[str] = set()
        for func_id in removed:
            env = self._closure_env.get(func_id)
            if env:
                closure_names.update(env.keys())
        if not closure_names:
            return
        model = build_semantic_model(script)
        for node in list(script.walk()):
            if not isinstance(node, JsVariableDeclaration) or node.kind != JsVarKind.CONST:
                continue
            for decl in list(node.declarations):
                if not isinstance(decl, JsVariableDeclarator) or not isinstance(decl.id, JsIdentifier):
                    continue
                if decl.id.name not in closure_names:
                    continue
                binding = model.binding_of(decl.id)
                if not binding_has_references(model, binding, exclude=decl):
                    remove_declarator(decl)
                    self.mark_changed()

    def _extract_constant_args(
        self,
        arguments: list,
        call_node: JsCallExpression,
    ) -> list[Value] | None:
        args: list[Value] = []
        for arg in arguments:
            ok, value = extract_literal_value(arg)
            if not ok:
                if isinstance(arg, JsIdentifier):
                    resolved = self._resolve_const_identifier(arg, call_node)
                    if resolved is not _MISSING:
                        args.append(resolved)  # type: ignore[arg-type]
                        continue
                return None
            args.append(value)
        return args

    def _resolve_const_identifier(self, node: JsIdentifier, context: Node) -> object:
        name = node.name
        child: Node = context
        current = context.parent
        while current is not None:
            if isinstance(current, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
                if any(isinstance(p, JsIdentifier) and p.name == name for p in current.params):
                    return _MISSING
            if isinstance(current, JsCatchClause) and isinstance(current.param, JsIdentifier):
                if current.param.name == name:
                    return _MISSING
            if isinstance(current, (JsForOfStatement, JsForInStatement)):
                if self._decl_binds_name(current.left, name):
                    return _MISSING
            if isinstance(current, JsForStatement):
                if self._decl_binds_name(current.init, name):
                    return _MISSING
            if isinstance(current, (JsScript, JsBlockStatement)):
                body = current.body
                if self._has_hoisted_var(current, name):
                    return _MISSING
                for stmt in body:
                    if isinstance(stmt, JsVariableDeclaration):
                        if stmt.kind == JsVarKind.CONST:
                            for decl in stmt.declarations:
                                if context.is_descendant_of(decl):
                                    break
                                if (
                                    isinstance(decl, JsVariableDeclarator)
                                    and isinstance(decl.id, JsIdentifier)
                                    and decl.id.name == name
                                    and decl.init is not None
                                ):
                                    ok, val = extract_literal_value(decl.init)
                                    if ok and self._value_safe_to_capture(name, val, None):
                                        return val
                                    return _MISSING
                        elif stmt.kind == JsVarKind.LET:
                            for decl in stmt.declarations:
                                if (
                                    isinstance(decl, JsVariableDeclarator)
                                    and isinstance(decl.id, JsIdentifier)
                                    and decl.id.name == name
                                ):
                                    return _MISSING
                    elif isinstance(stmt, JsFunctionDeclaration):
                        if isinstance(stmt.id, JsIdentifier) and stmt.id.name == name:
                            return _MISSING
                    if stmt is child:
                        break
            child = current
            current = current.parent
        return _MISSING

    @staticmethod
    def _has_hoisted_var(scope_node: Node, name: str) -> bool:
        """
        Return whether *scope_node* contains any `var` declaration for *name* at any nesting depth.
        """
        for node in walk_scope(scope_node):
            if isinstance(node, JsVariableDeclaration) and node.kind == JsVarKind.VAR:
                for decl in node.declarations:
                    if (
                        isinstance(decl, JsVariableDeclarator)
                        and isinstance(decl.id, JsIdentifier)
                        and decl.id.name == name
                    ):
                        return True
        return False

    @staticmethod
    def _decl_binds_name(node: Node | None, name: str) -> bool:
        """
        Return whether *node* is a `JsVariableDeclaration` (e.g. a `for`/`for-of`/`for-in` loop
        header) that declares *name*. A bare identifier loop target assigns to an outer binding and
        does not shadow, so it is not treated as a binding here.
        """
        if not isinstance(node, JsVariableDeclaration):
            return False
        for decl in node.declarations:
            if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                if decl.id.name == name:
                    return True
        return False

    def _is_unresolved_call(self, node: Node) -> bool:
        """
        Check whether the irreducible expression contains any function call. If so, the wrapper
        inliner or string-array resolver should handle it — the evaluator should not substitute
        parameters into a call that it couldn't fully evaluate.
        """
        for child in node.walk():
            if isinstance(child, JsCallExpression):
                return True
        return False

    @staticmethod
    def _substitute_params_in_clone(
        node: Node,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        args: list[Value],
    ) -> Node | None:
        param_map: dict[str, Value] = {
            p.name: args[i] if i < len(args) else None
            for i, p in enumerate(func.params)
            if isinstance(p, JsIdentifier)
        }
        cloned = _clone_node(node)
        for n in list(cloned.walk()):
            if isinstance(n, JsIdentifier) and is_reference(n) and n.name in param_map:
                replacement = value_to_node(param_map[n.name])
                if replacement is not None:
                    _replace_in_parent(n, replacement)
        return cloned
