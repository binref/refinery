"""
Evaluate pure JavaScript functions called with constant arguments and replace call sites with
computed results.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from refinery.lib.scripts.js.deobfuscation.interpreter import Value

from refinery.lib.scripts import Node, _clone_node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    extract_literal_value,
    has_remaining_references,
    is_reference,
    references_receiver_this,
    value_to_node,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    InterpreterError,
    IrreducibleExpression,
    JsInterpreter,
    is_runtime_name,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
)

MAX_RESULT_ARRAY_LEN = 260


class _Scope:
    __slots__ = ('functions', 'parent')

    def __init__(self, parent: _Scope | None = None):
        self.functions: dict[str, JsFunctionDeclaration] = {}
        self.parent = parent

    def resolve(self, name: str) -> JsFunctionDeclaration | None:
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
    if references_receiver_this(body):
        return False
    if _is_switch_return_pattern(body, local_names):
        return True
    for node in walk_scope(body):
        if isinstance(node, JsAssignmentExpression):
            if isinstance(node.left, JsIdentifier) and node.left.name == func_own_name:
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


def _unwrap_callee(node: Node) -> Node:
    while isinstance(node, JsParenthesizedExpression):
        if node.expression is None:
            break
        node = node.expression
    return node


class JsFunctionEvaluator(ScriptLevelTransformer):
    """
    Evaluate pure JavaScript functions called with constant arguments, replacing call sites with
    computed results. Handles named function calls and IIFEs.
    """

    def __init__(self):
        super().__init__()
        self._scope_map: dict[int, _Scope] = {}
        self._pure_nodes: set[int] = set()
        self._call_counts: dict[int, int] = {}
        self._resolved_counts: dict[int, int] = {}
        self._failed_counts: dict[int, int] = {}

    def _process_script(self, node: JsScript) -> None:
        self._build_scope_tree(node)
        self._analyze_purity()
        self._evaluate_calls(node)
        self._remove_resolved_definitions(node)

    def _build_scope_tree(self, script: JsScript) -> None:
        self._scope_map.clear()
        self._pure_nodes.clear()
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
            if not isinstance(node, JsFunctionDeclaration):
                continue
            if not isinstance(node.id, JsIdentifier) or node.body is None:
                continue
            name = node.id.name
            scope.functions[name] = node
            child_scope = _Scope(parent=scope)
            self._scope_map[id(node)] = child_scope
            self._populate_scope(node, child_scope)

    def _scope_for_node(self, node: Node) -> _Scope | None:
        current = node.parent
        while current is not None:
            scope = self._scope_map.get(id(current))
            if scope is not None:
                return scope
            current = current.parent
        return None

    def _resolve_function(self, call_node: Node, name: str) -> JsFunctionDeclaration | None:
        scope = self._scope_for_node(call_node)
        if scope is None:
            return None
        return scope.resolve(name)

    def _all_functions(self) -> Iterator[JsFunctionDeclaration]:
        for scope in self._scope_map.values():
            yield from scope.functions.values()

    def _analyze_purity(self) -> None:
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
                s: _Scope | None = scope.parent
                while s is not None:
                    for name, f in s.functions.items():
                        if id(f) in self._pure_nodes:
                            visible_pure.add(name)
                    s = s.parent
                for name, f in scope.functions.items():
                    if id(f) in self._pure_nodes:
                        visible_pure.add(name)
                if _is_pure_function(func, visible_pure):
                    self._pure_nodes.add(id(func))
                    changed = True

    def _evaluate_calls(self, script: JsScript) -> None:
        for node in list(script.walk()):
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
        args = self._extract_constant_args(node.arguments)
        if args is None:
            return
        success = self._evaluate_and_replace(node, func, args, gate_unresolved=True)
        if success:
            self._resolved_counts[func_id] = self._resolved_counts.get(func_id, 0) + 1
        else:
            self._failed_counts[func_id] = self._failed_counts.get(func_id, 0) + 1

    def _visible_functions(self, node: Node) -> dict[str, JsFunctionDeclaration]:
        result: dict[str, JsFunctionDeclaration] = {}
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
        if not _is_pure_function(func, pure_names):
            return
        args = self._extract_constant_args(node.arguments)
        if args is None:
            return
        self._evaluate_and_replace(node, func, args, gate_unresolved=False)

    def _evaluate_and_replace(
        self,
        node: JsCallExpression,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        args: list,
        gate_unresolved: bool,
    ) -> bool:
        """
        Run the interpreter on *func* with *args* and, on success, replace *node* with the result.
        Returns True if the call site was resolved (either to a value or a substituted expression).
        """
        functions_for_interpreter = self._visible_functions(node)
        interpreter = JsInterpreter(functions=functions_for_interpreter)
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
        replacement = value_to_node(result)
        if replacement is None:
            return False
        if isinstance(result, list) and len(result) > MAX_RESULT_ARRAY_LEN:
            return False
        _replace_in_parent(node, replacement)
        self.mark_changed()
        return True

    def _remove_resolved_definitions(self, script: JsScript) -> None:
        removed: set[int] = set()
        for func in self._all_functions():
            func_id = id(func)
            call_count = self._call_counts.get(func_id, 0)
            if call_count == 0:
                continue
            resolved = self._resolved_counts.get(func_id, 0)
            failed = self._failed_counts.get(func_id, 0)
            if (resolved + failed) < call_count:
                continue
            if not isinstance(func.id, JsIdentifier):
                continue
            name = func.id.name
            if not has_remaining_references(script, name, exclude=func, check_shadowing=True):
                _remove_from_parent(func)
                removed.add(func_id)
                self.mark_changed()
        for func in self._all_functions():
            func_id = id(func)
            if func_id in removed:
                continue
            if func_id not in self._pure_nodes:
                continue
            if not isinstance(func.id, JsIdentifier):
                continue
            name = func.id.name
            call_count = self._call_counts.get(func_id, 0)
            if call_count == 0:
                continue
            if not has_remaining_references(script, name, exclude=func, check_shadowing=True):
                _remove_from_parent(func)
                removed.add(func_id)
                self.mark_changed()

    @staticmethod
    def _extract_constant_args(arguments: list) -> list[Value] | None:
        args: list[Value] = []
        for arg in arguments:
            ok, value = extract_literal_value(arg)
            if not ok:
                return None
            args.append(value)
        return args

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
            if isinstance(n, JsIdentifier) and n.name in param_map:
                replacement = value_to_node(param_map[n.name])
                if replacement is not None:
                    _replace_in_parent(n, replacement)
        return cloned
