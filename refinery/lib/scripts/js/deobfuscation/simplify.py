"""
JavaScript syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BINARY_OPS,
    is_literal,
    is_valid_identifier,
    make_numeric_literal,
    make_string_literal,
    numeric_value,
    string_value,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
)


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
        return None

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
        if op == '!' and isinstance(node.operand, JsNumericLiteral):
            if node.operand.value == 0:
                return JsBooleanLiteral(value=True)
            if node.operand.value == 1:
                return JsBooleanLiteral(value=False)
        if op == '-' and isinstance(node.operand, JsNumericLiteral):
            return make_numeric_literal(-node.operand.value)
        if op == '+' and isinstance(node.operand, JsNumericLiteral):
            return node.operand
        if op == 'typeof' and is_literal(node.operand):
            if isinstance(node.operand, JsNumericLiteral):
                return make_string_literal('number')
            if isinstance(node.operand, JsStringLiteral):
                return make_string_literal('string')
            if isinstance(node.operand, JsBooleanLiteral):
                return make_string_literal('boolean')
        if op == 'void' and isinstance(node.operand, JsNumericLiteral):
            if node.operand.value == 0:
                return JsIdentifier(name='undefined')
        return None
