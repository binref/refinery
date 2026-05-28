"""
JavaScript syntax normalization transforms.
"""
from __future__ import annotations

from typing import Sequence, TypeGuard

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.js.deobfuscation.helpers import (
    FUNCTION_NODE_TYPES,
    RELATIONAL_OPS,
    access_key,
    escape_js_string,
    eval_binary_op,
    extract_identifier_params,
    is_closed_expression,
    is_literal,
    is_nullish,
    is_safe_iife_inline,
    is_simple_expression,
    is_statically_evaluable,
    is_truthy,
    is_valid_identifier,
    js_parse_int,
    make_numeric_literal,
    make_string_literal,
    numeric_value,
    string_value,
    substitute_params,
    value_to_node,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import BUILTIN_REGISTRY, STATIC_OBJECTS
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsClassDeclaration,
    JsConditionalExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)

_OBJECT_PROTO_PROPERTIES = frozenset({
    '__defineGetter__',
    '__defineSetter__',
    '__lookupGetter__',
    '__lookupSetter__',
    '__proto__',
    'constructor',
    'hasOwnProperty',
    'isPrototypeOf',
    'propertyIsEnumerable',
    'toLocaleString',
    'toString',
    'valueOf',
})

_FUNCTION_PROPERTIES = _OBJECT_PROTO_PROPERTIES | frozenset({
    'apply',
    'arguments',
    'bind',
    'call',
    'caller',
    'length',
    'name',
    'prototype',
})

_EMPTY_OBJECT_PROPERTIES = _OBJECT_PROTO_PROPERTIES

_GLOBAL_OBJECT_ALIASES: frozenset[str] = frozenset({
    'globalThis',
    'global',
    'window',
    'self',
})


def _is_locally_shadowed(node: Node, name: str) -> bool:
    """
    Checks whether ANY scope in the ancestor chain (including script-level) binds the given name.
    Used for globalThis simplification: `globalThis.x` must not become `x` if `x` is declared
    anywhere. Must not be confused with `_is_shadowed` from helpers, which by design only checks
    function boundaries for use with `has_remaining_references`.
    """
    parent = node.parent
    while parent is not None:
        if isinstance(parent, FUNCTION_NODE_TYPES):
            for param in getattr(parent, 'params', ()):
                if isinstance(param, JsIdentifier) and param.name == name:
                    return True
                for child in param.walk():
                    if isinstance(child, JsIdentifier) and child.name == name:
                        return True
        if isinstance(parent, (JsBlockStatement, JsScript)):
            for stmt in parent.body:
                if isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
                    if stmt.id.name == name:
                        return True
                if isinstance(stmt, JsVariableDeclaration):
                    for decl in stmt.declarations:
                        if (
                            isinstance(decl, JsVariableDeclarator)
                            and isinstance(decl.id, JsIdentifier)
                            and decl.id.name == name
                        ):
                            return True
        parent = parent.parent
    return False


def _resolve_in_expression(node: Node, key: str, name: str) -> bool | None:
    """
    Attempt to statically resolve `key in name` by walking up from *node* through all enclosing
    scopes. Recognizes empty function declarations, empty class declarations (no super, no body),
    and const empty object literals. Returns `True` when *key* is a known built-in property of the
    resolved type or has been explicitly assigned, `False` when it is provably absent, or `None`
    when the result cannot be determined.
    """
    scope = node.parent
    while scope is not None:
        if isinstance(scope, (JsScript, JsBlockStatement)):
            for stmt in scope.body:
                if (
                    isinstance(stmt, JsFunctionDeclaration)
                    and isinstance(stmt.id, JsIdentifier)
                    and stmt.id.name == name
                ):
                    stores = _collect_property_stores(scope.body, name)
                    if key in _FUNCTION_PROPERTIES:
                        return True
                    if key in stores:
                        return True
                    if stores:
                        return None
                    return False
                if (
                    isinstance(stmt, JsClassDeclaration)
                    and isinstance(stmt.id, JsIdentifier)
                    and stmt.id.name == name
                    and stmt.super_class is None
                    and stmt.body is not None
                    and not stmt.body.body
                ):
                    stores = _collect_property_stores(scope.body, name)
                    if key in _FUNCTION_PROPERTIES:
                        return True
                    if key in stores:
                        return True
                    if stores:
                        return None
                    return False
                if (
                    isinstance(stmt, JsVariableDeclaration)
                    and stmt.kind is JsVarKind.CONST
                ):
                    for decl in stmt.declarations:
                        if (
                            isinstance(decl, JsVariableDeclarator)
                            and isinstance(decl.id, JsIdentifier)
                            and decl.id.name == name
                            and isinstance(decl.init, JsObjectExpression)
                            and not decl.init.properties
                        ):
                            return key in _EMPTY_OBJECT_PROPERTIES
        scope = scope.parent
    return None


def _collect_property_stores(body: list, name: str) -> set[str]:
    """
    Collect property names assigned via `name.prop = ...` in the given body.
    """
    props: set[str] = set()
    for stmt in body:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if not isinstance(expr, JsAssignmentExpression):
            continue
        lhs = expr.left
        if not isinstance(lhs, JsMemberExpression) or lhs.computed:
            continue
        if not isinstance(lhs.object, JsIdentifier) or lhs.object.name != name:
            continue
        if isinstance(lhs.property, JsIdentifier):
            props.add(lhs.property.name)
    return props


def _all_numeric_literals(args: Sequence[Node]) -> TypeGuard[list[JsNumericLiteral]]:
    return all(isinstance(a, JsNumericLiteral) for a in args)


class JsSimplifications(Transformer):

    def visit_JsBinaryExpression(self, node: JsBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        op = node.operator
        left_str = string_value(node.left)
        right_str = string_value(node.right)
        if op == '+' and left_str is not None and right_str is not None:
            return make_string_literal(left_str + right_str)
        left_num = numeric_value(node.left)
        right_num = numeric_value(node.right)
        if left_num is not None and right_num is not None:
            result = eval_binary_op(op, left_num, right_num)
            if result is None:
                pass
            elif isinstance(result, bool):
                return JsBooleanLiteral(value=result)
            elif isinstance(result, (int, float)):
                if result != result or result == float('inf') or result == float('-inf'):
                    return None
                return make_numeric_literal(result)
        if op in ('===', '!==', '==', '!='):
            equal: bool | None = None
            if left_str is not None and right_str is not None:
                equal = left_str == right_str
            elif (
                isinstance(node.left, JsBooleanLiteral)
                and isinstance(node.right, JsBooleanLiteral)
            ):
                equal = node.left.value == node.right.value
            elif isinstance(node.left, JsNullLiteral) and isinstance(node.right, JsNullLiteral):
                equal = True
            if equal is not None:
                return JsBooleanLiteral(value=equal if op in ('===', '==') else not equal)
        if op in RELATIONAL_OPS:
            if left_str is not None and right_str is not None:
                return JsBooleanLiteral(value=RELATIONAL_OPS[op](left_str, right_str))
        if (
            op == 'in'
            and isinstance(node.left, JsStringLiteral)
            and isinstance(node.right, JsIdentifier)
        ):
            result = _resolve_in_expression(node, node.left.value, node.right.name)
            if result is not None:
                return JsBooleanLiteral(value=result)
        return None

    def visit_JsCallExpression(self, node: JsCallExpression):
        self.generic_visit(node)
        callee = node.callee
        if isinstance(callee, JsIdentifier) and callee.name == 'parseInt':
            return self._fold_parseint(node)
        fn = callee
        if isinstance(fn, JsParenthesizedExpression):
            fn = fn.expression
        if isinstance(fn, JsFunctionExpression):
            return self._try_inline_iife(node, fn)
        return (
            self._try_fold_static_method(node)
            or self._try_fold_split(node)
            or self._try_fold_join(node)
        )

    @staticmethod
    def _fold_parseint(node: JsCallExpression) -> JsNumericLiteral | None:
        if len(node.arguments) < 1:
            return None
        radix = 10
        if len(node.arguments) >= 2:
            radix_value = numeric_value(node.arguments[1])
            if radix_value is None:
                return None
            radix = int(radix_value)
        sv = string_value(node.arguments[0])
        if sv is not None:
            result = js_parse_int(sv, radix)
            if result is not None:
                return make_numeric_literal(result)
        return None

    @staticmethod
    def _try_inline_iife(node: JsCallExpression, fn: JsFunctionExpression) -> Node | None:
        if fn.body is None or not isinstance(fn.body, JsBlockStatement):
            return None
        body = fn.body.body
        if len(body) != 1:
            return None
        stmt = body[0]
        if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
            return None
        param_names = extract_identifier_params(fn.params)
        if param_names is None or len(node.arguments) != len(param_names):
            return None
        expr = stmt.argument
        if not is_closed_expression(expr, set(param_names)):
            return None
        if not is_safe_iife_inline(expr, param_names, node.arguments):
            return None
        return substitute_params(expr, param_names, node.arguments)

    @staticmethod
    def _try_fold_static_method(node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        if not isinstance(callee.object, JsIdentifier):
            return None
        static_name = callee.object.name
        if static_name not in STATIC_OBJECTS:
            return None
        method_name = access_key(callee)
        if method_name is None:
            return None
        builtin = BUILTIN_REGISTRY.get((static_name, method_name))
        if builtin is None:
            return None
        if not _all_numeric_literals(node.arguments):
            return None
        args = [a.value for a in node.arguments]
        try:
            result = builtin(args)
        except Exception:
            return None
        return value_to_node(result)

    @staticmethod
    def _try_fold_split(node: JsCallExpression) -> JsArrayExpression | None:
        if len(node.arguments) != 1:
            return None
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        obj_str = string_value(callee.object)
        if obj_str is None:
            return None
        method_name = access_key(callee)
        if method_name != 'split':
            return None
        sep = string_value(node.arguments[0])
        if sep is None:
            return None
        if sep:
            parts = obj_str.split(sep)
        else:
            parts = []
            for ch in obj_str:
                cp = ord(ch)
                if cp > 0xFFFF:
                    hi = 0xD800 + ((cp - 0x10000) >> 10)
                    lo = 0xDC00 + ((cp - 0x10000) & 0x3FF)
                    parts.append(chr(hi))
                    parts.append(chr(lo))
                else:
                    parts.append(ch)
        return JsArrayExpression(
            elements=[make_string_literal(p) for p in parts],
        )

    @staticmethod
    def _try_fold_join(node: JsCallExpression) -> JsStringLiteral | None:
        if len(node.arguments) > 1:
            return None
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        method_name = access_key(callee)
        if method_name != 'join':
            return None
        obj = callee.object
        if not isinstance(obj, JsArrayExpression):
            return None
        parts: list[str] = []
        for e in obj.elements:
            if not isinstance(e, JsStringLiteral):
                return None
            parts.append(e.value)
        if node.arguments:
            sep = string_value(node.arguments[0])
            if sep is None:
                return None
        else:
            sep = ','
        return make_string_literal(sep.join(parts))

    def visit_JsConditionalExpression(self, node: JsConditionalExpression):
        self.generic_visit(node)
        if node.test is None or not is_statically_evaluable(node.test):
            return None
        truthy = is_truthy(node.test)
        if truthy is None:
            return None
        return node.consequent if truthy else node.alternate

    def visit_JsSequenceExpression(self, node: JsSequenceExpression):
        self.generic_visit(node)
        if not node.expressions:
            return None
        filtered = [
            e for i, e in enumerate(node.expressions)
            if i == len(node.expressions) - 1 or not is_simple_expression(e)
        ]
        if len(filtered) == len(node.expressions):
            return None
        if len(filtered) == 1:
            return filtered[0]
        node.expressions = filtered
        self.mark_changed()
        return None

    def visit_JsParenthesizedExpression(self, node: JsParenthesizedExpression):
        self.generic_visit(node)
        inner = node.expression
        if inner is None:
            return None
        if isinstance(inner, (
            JsSequenceExpression,
            JsFunctionExpression,
            JsArrowFunctionExpression,
            JsObjectExpression,
        )):
            return None
        return inner

    def visit_JsMemberExpression(self, node: JsMemberExpression):
        self.generic_visit(node)
        if (
            not node.computed
            and isinstance(node.object, JsIdentifier)
            and node.object.name in _GLOBAL_OBJECT_ALIASES
            and isinstance(node.property, JsIdentifier)
            and not _is_locally_shadowed(node, node.property.name)
        ):
            return node.property
        if node.computed and node.object is not None and node.property is not None:
            if (
                isinstance(node.object, JsArrayExpression)
                and isinstance(node.property, JsNumericLiteral)
            ):
                idx = node.property.value
                elements = node.object.elements
                if (
                    isinstance(idx, int)
                    and 0 <= idx < len(elements)
                    and all(e is not None and is_literal(e) for e in elements)
                ):
                    return elements[idx]
            prop_str = string_value(node.property)
            if prop_str is not None and is_valid_identifier(prop_str):
                node.computed = False
                node.property = JsIdentifier(name=prop_str)
                self.mark_changed()
                return None
        return None

    def visit_JsUnaryExpression(self, node: JsUnaryExpression):
        self.generic_visit(node)
        if node.operand is None:
            return None
        op = node.operator
        if op == '!' and is_statically_evaluable(node.operand):
            truthy = is_truthy(node.operand)
            if truthy is not None:
                return JsBooleanLiteral(value=not truthy)
        if op == '-' and isinstance(node.operand, JsNumericLiteral):
            value = node.operand.value
            if value == 0 and isinstance(value, int):
                value = -0.0
            else:
                value = -value
            return make_numeric_literal(value)
        if op == '+' and isinstance(node.operand, JsNumericLiteral):
            return node.operand
        if op == '~' and isinstance(node.operand, JsNumericLiteral):
            try:
                v = int(node.operand.value) & 0xFFFFFFFF
                v = ~v & 0xFFFFFFFF
                if v >= 0x80000000:
                    v -= 0x100000000
                return make_numeric_literal(v)
            except (ValueError, OverflowError):
                pass
        if op == 'typeof' and is_literal(node.operand):
            if isinstance(node.operand, JsNumericLiteral):
                return make_string_literal('number')
            if isinstance(node.operand, JsStringLiteral):
                return make_string_literal('string')
            if isinstance(node.operand, JsBooleanLiteral):
                return make_string_literal('boolean')
        return None

    def visit_JsStringLiteral(self, node: JsStringLiteral):
        quote = node.raw[0] if node.raw else '\''
        rebuilt = quote + escape_js_string(node.value, quote) + quote
        if rebuilt != node.raw:
            node.raw = rebuilt
            self.mark_changed()
        return None

    def visit_JsLogicalExpression(self, node: JsLogicalExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        if not is_statically_evaluable(node.left):
            return None
        op = node.operator
        if op == '??':
            if is_nullish(node.left):
                return node.right
            return node.left
        truthy = is_truthy(node.left)
        if truthy is None:
            return None
        if op == '&&':
            return node.right if truthy else node.left
        if op == '||':
            return node.left if truthy else node.right
        return None
