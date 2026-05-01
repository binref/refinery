"""
JavaScript syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BINARY_OPS,
    RELATIONAL_OPS,
    escape_js_string,
    is_literal,
    is_nullish,
    is_simple_expression,
    is_statically_evaluable,
    is_truthy,
    is_valid_identifier,
    js_parse_int,
    make_numeric_literal,
    make_string_literal,
    numeric_value,
    string_value,
    try_inline_trivial_function,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsClassDeclaration,
    JsConditionalExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    JsVarKind,
    JsVariableDeclaration,
    JsVariableDeclarator,
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


def _resolve_in_expression(node: Node, key: str, name: str) -> bool | None:
    """
    Attempt to statically resolve `key in name` by walking up from *node* through all enclosing
    scopes. Recognizes empty function declarations, empty class declarations (no super, no body),
    and const empty object literals. Returns `True` when *key* is a known built-in property of the
    resolved type, `False` when it is not, or `None` when the identifier cannot be resolved.
    """
    scope = node.parent
    while scope is not None:
        if isinstance(scope, (JsScript, JsBlockStatement)):
            for stmt in scope.body:
                if (
                    isinstance(stmt, JsFunctionDeclaration)
                    and isinstance(stmt.id, JsIdentifier)
                    and stmt.id.name == name
                    and isinstance(stmt.body, JsBlockStatement)
                    and not stmt.body.body
                ):
                    return key in _FUNCTION_PROPERTIES
                if (
                    isinstance(stmt, JsClassDeclaration)
                    and isinstance(stmt.id, JsIdentifier)
                    and stmt.id.name == name
                    and stmt.super_class is None
                    and stmt.body is not None
                    and not stmt.body.body
                ):
                    return key in _FUNCTION_PROPERTIES
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
            fn = BINARY_OPS.get(op)
            if fn is not None:
                try:
                    result = fn(left_num, right_num)
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                if isinstance(result, float) and (
                    result != result or result == float('inf') or result == float('-inf')
                ):
                    return None
                return make_numeric_literal(result)
            if op == '>>>':
                try:
                    left_i = int(left_num) & 0xFFFFFFFF
                    shift = int(right_num) & 0x1F
                    result = (left_i >> shift) & 0xFFFFFFFF
                except (ValueError, OverflowError):
                    return None
                return make_numeric_literal(result)
        if op in ('===', '!==', '==', '!='):
            equal: bool | None = None
            if left_str is not None and right_str is not None:
                equal = left_str == right_str
            elif left_num is not None and right_num is not None:
                equal = left_num == right_num
            elif (
                isinstance(node.left, JsBooleanLiteral)
                and isinstance(node.right, JsBooleanLiteral)
            ):
                equal = node.left.value == node.right.value
            elif (
                isinstance(node.left, JsNullLiteral)
                and isinstance(node.right, JsNullLiteral)
            ):
                equal = True
            if equal is not None:
                return JsBooleanLiteral(value=equal if op in ('===', '==') else not equal)
        if op in RELATIONAL_OPS:
            if left_num is not None and right_num is not None:
                return JsBooleanLiteral(value=RELATIONAL_OPS[op](left_num, right_num))
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
        return self._try_fold_split(node)

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
        if not all(is_simple_expression(a) for a in node.arguments):
            return None
        return try_inline_trivial_function(fn, node.arguments)

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
        method = callee.property
        if isinstance(method, JsStringLiteral):
            method_name = method.value
        elif isinstance(method, JsIdentifier) and not callee.computed:
            method_name = method.name
        else:
            return None
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

    def visit_JsConditionalExpression(self, node: JsConditionalExpression):
        self.generic_visit(node)
        if node.test is None or not is_statically_evaluable(node.test):
            return None
        truthy = is_truthy(node.test)
        if truthy is None:
            return None
        return node.consequent if truthy else node.alternate

    def visit_JsParenthesizedExpression(self, node: JsParenthesizedExpression):
        self.generic_visit(node)
        inner = node.expression
        if inner is None:
            return None
        if is_literal(inner):
            return inner
        if isinstance(inner, JsSequenceExpression) and inner.expressions:
            if all(is_literal(e) for e in inner.expressions):
                return inner.expressions[-1]
        return None

    def visit_JsMemberExpression(self, node: JsMemberExpression):
        self.generic_visit(node)
        if node.computed and node.object is not None and node.property is not None:
            if (
                isinstance(node.object, JsArrayExpression)
                and isinstance(node.property, JsNumericLiteral)
            ):
                idx = node.property.value
                elements = node.object.elements
                if (
                    isinstance(idx, int) and 0 <= idx < len(elements)
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
            return make_numeric_literal(-node.operand.value)
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
        quote = node.raw[0] if node.raw else "'"
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
