"""
Unpack rest-parameter arrays that pack multiple variables into a single parameter.

Some obfuscation transforms replace named function parameters and locals with indexed accesses
on a single rest parameter array:

    function(...stack) { stack.length = N; ... }

This transformer detects the pattern, builds a variable map from collected access keys, and
replaces indexed accesses with fresh named identifiers.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import SemanticModel
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    member_key,
    numeric_value,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsBlockStatement,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsRestElement,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)


class _TruncationInfo(NamedTuple):
    param_count: int
    stack_chain: str | None


class _NestedFrameAccess(Exception):
    pass


def _extract_truncation(
    stmts: list,
    rest_name: str,
) -> _TruncationInfo | None:
    """
    Find the `.length = N` truncation statement in the function body. Returns the param count
    and the stack chain key (None for simple case where rest param IS the stack). Returns None
    if no truncation pattern is found.
    """
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
            continue
        lhs = expr.left
        if not isinstance(lhs, JsMemberExpression):
            continue
        if lhs.computed:
            continue
        if not isinstance(lhs.property, JsIdentifier) or lhs.property.name != 'length':
            continue
        rhs = expr.right
        if rhs is None:
            continue
        n = numeric_value(rhs)
        if n is None or not isinstance(n, int) or n < 0:
            continue
        obj = lhs.object
        if isinstance(obj, JsIdentifier) and obj.name == rest_name:
            return _TruncationInfo(n, None)
        if isinstance(obj, JsMemberExpression):
            chain = member_key(obj)
            if chain is not None:
                return _TruncationInfo(n, chain)
    return None


def _collect_accesses_simple(
    body: JsBlockStatement,
    rest_name: str,
) -> dict[str, list[JsMemberExpression]] | None:
    """
    Collect all `restParam[key]` and `restParam.key` accesses in the immediate function body
    (not descending into nested functions). Returns a map from string key to list of AST nodes.
    Returns None if the rest param is used in a way that prevents demasking.
    """
    accesses: dict[str, list[JsMemberExpression]] = {}
    if not _walk_collect_simple(body, rest_name, accesses):
        return None
    return accesses


def _walk_collect_simple(
    node: Node,
    rest_name: str,
    accesses: dict[str, list[JsMemberExpression]],
) -> bool:
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration)):
            continue
        if isinstance(child, JsMemberExpression):
            obj = child.object
            if isinstance(obj, JsIdentifier) and obj.name == rest_name:
                if (
                    not child.computed
                    and isinstance(child.property, JsIdentifier)
                    and child.property.name == 'length'
                ):
                    continue
                key = _extract_access_key(child)
                if key is None:
                    return False
                accesses.setdefault(key, []).append(child)
                continue
        if isinstance(child, JsIdentifier) and child.name == rest_name:
            parent = child.parent
            if isinstance(parent, JsMemberExpression) and parent.object is child:
                continue
            return False
        if not _walk_collect_simple(child, rest_name, accesses):
            return False
    return True


def _collect_accesses_frame(
    body: JsBlockStatement,
    stack_chain: str,
) -> dict[str, list[JsMemberExpression]] | None:
    """
    Collect all accesses to the frame-qualified stack chain. Returns None if any access exists
    inside a nested function (closure capture prevents demasking).
    """
    accesses: dict[str, list[JsMemberExpression]] = {}
    try:
        _walk_collect_frame(body, stack_chain, accesses, depth=0)
    except _NestedFrameAccess:
        return None
    return accesses


def _walk_collect_frame(
    node: Node,
    stack_chain: str,
    accesses: dict[str, list[JsMemberExpression]],
    depth: int,
) -> None:
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration)):
            _walk_collect_frame(child, stack_chain, accesses, depth + 1)
            continue
        if isinstance(child, JsMemberExpression):
            obj = child.object
            if isinstance(obj, JsMemberExpression):
                chain = member_key(obj)
                if chain == stack_chain:
                    key = _extract_access_key(child)
                    if key is not None:
                        if depth > 0:
                            raise _NestedFrameAccess
                        accesses.setdefault(key, []).append(child)
                        continue
        _walk_collect_frame(child, stack_chain, accesses, depth)


def _extract_access_key(node: JsMemberExpression) -> str | None:
    """
    Extract the key from a stack access expression. Returns a string representation of the key
    or None if the key cannot be statically resolved.
    """
    if node.computed:
        prop = node.property
        if isinstance(prop, JsNumericLiteral):
            return str(int(prop.value)) if prop.value == int(prop.value) else None
        if isinstance(prop, JsStringLiteral):
            return prop.value
        if (
            isinstance(prop, JsUnaryExpression)
            and prop.operator == '-'
            and isinstance(prop.operand, JsNumericLiteral)
        ):
            return str(-int(prop.operand.value))
        return None
    if isinstance(node.property, JsIdentifier):
        if node.property.name == 'length':
            return None
        return node.property.name
    return None


def _generate_names(param_count: int, keys: set[str]) -> dict[str, str]:
    """
    Generate fresh identifier names for stack keys. Keys with index 0..N-1 get param names,
    all others get local names.
    """
    mapping: dict[str, str] = {}
    param_idx = 0
    local_idx = 0
    param_keys = set()
    for i in range(param_count):
        param_keys.add(str(i))
    for key in sorted(keys, key=_sort_key):
        if key in param_keys:
            mapping[key] = F'p{param_idx}'
            param_idx += 1
        else:
            mapping[key] = F'v{local_idx}'
            local_idx += 1
    return mapping


def _sort_key(key: str) -> tuple[int, int | str]:
    try:
        n = int(key)
        return (0, n)
    except ValueError:
        return (1, key)


def _remove_truncation(body: JsBlockStatement, rest_name: str, stack_chain: str | None) -> None:
    """
    Remove the `.length = N` truncation statement from the function body.
    """
    stmts = body.body
    for i, stmt in enumerate(stmts):
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
            continue
        lhs = expr.left
        if not isinstance(lhs, JsMemberExpression) or lhs.computed:
            continue
        if not isinstance(lhs.property, JsIdentifier) or lhs.property.name != 'length':
            continue
        obj = lhs.object
        if stack_chain is None:
            if isinstance(obj, JsIdentifier) and obj.name == rest_name:
                stmts.pop(i)
                return
        else:
            if isinstance(obj, JsMemberExpression) and member_key(obj) == stack_chain:
                stmts.pop(i)
                return


class JsRestArrayUnpacking(ScriptLevelTransformer):
    """
    Unpack rest-param arrays back into named identifiers. Detects functions where all parameters
    and locals are packed into a single rest parameter accessed by index, and replaces indexed
    accesses with fresh named variables.
    """

    def _process_script(self, node: JsScript) -> None:
        count = 0
        model = model_cache(self, node).model
        for fn_node in node.walk():
            if not isinstance(fn_node, (JsFunctionExpression, JsFunctionDeclaration)):
                continue
            if self._demask_function(fn_node, model):
                count += 1
        if count > 0:
            self.mark_changed()

    def _demask_function(
        self,
        fn: JsFunctionExpression | JsFunctionDeclaration,
        model: SemanticModel,
    ) -> bool:
        if len(fn.params) != 1:
            return False
        param = fn.params[0]
        if not isinstance(param, JsRestElement):
            return False
        if not isinstance(param.argument, JsIdentifier):
            return False
        binding = model.binding_of(param.argument)
        if binding is None or binding.captured or model.reflection_can_reach(binding):
            return False
        rest_name = param.argument.name
        if fn.body is None or not isinstance(fn.body, JsBlockStatement):
            return False
        if not fn.body.body:
            return False
        result = _extract_truncation(fn.body.body, rest_name)
        if result is None:
            return False
        param_count, stack_chain = result
        if stack_chain is None:
            accesses = _collect_accesses_simple(fn.body, rest_name)
        else:
            accesses = _collect_accesses_frame(fn.body, stack_chain)
        if accesses is None:
            return False
        if param_count > 0 and not any(str(i) in accesses for i in range(param_count)):
            return False
        if not accesses:
            _remove_truncation(fn.body, rest_name, stack_chain)
            fn.params.clear()
            return True
        mapping = _generate_names(param_count, set(accesses.keys()))
        for key, nodes in accesses.items():
            name = mapping[key]
            for access_node in nodes:
                replacement = JsIdentifier(name=name)
                _replace_in_parent(access_node, replacement)
        _remove_truncation(fn.body, rest_name, stack_chain)
        fn.params.clear()
        for i in range(param_count):
            key = str(i)
            name = mapping.get(key, F'p{i}')
            fn.params.append(JsIdentifier(name=name))
        if stack_chain is None:
            self._add_local_declarations(fn.body, mapping, param_count)
        return True

    def _add_local_declarations(
        self,
        body: JsBlockStatement,
        mapping: dict[str, str],
        param_count: int,
    ) -> None:
        """
        Insert `var` declarations for local variables (keys that aren't parameters).
        """
        locals_: list[str] = []
        for key, name in mapping.items():
            try:
                idx = int(key)
                if 0 <= idx < param_count:
                    continue
            except ValueError:
                pass
            locals_.append(name)
        if not locals_:
            return
        declarators = [
            JsVariableDeclarator(id=JsIdentifier(name=n), init=None)
            for n in locals_
        ]
        decl = JsVariableDeclaration(declarations=declarators, kind=JsVarKind.VAR)
        decl.parent = body
        for d in declarators:
            d.parent = decl
            if d.id is not None:
                d.id.parent = d
        body.body.insert(0, decl)
