from __future__ import annotations

import operator
import re

from typing import Callable

from refinery.lib.scripts import Expression, Transformer
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsIdentifier,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
)
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS

_SIMPLE_IDENT = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

_JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})

_BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : operator.mul,
    '/'  : operator.truediv,
    '%'  : operator.mod,
    '**' : operator.pow,
    '|'  : operator.or_,
    '&'  : operator.and_,
    '^'  : operator.xor,
    '<<' : operator.lshift,
    '>>' : operator.rshift,
}


def _string_value(node: Expression) -> str | None:
    if isinstance(node, JsStringLiteral):
        return node.value
    return None


def _make_string_literal(value: str) -> JsStringLiteral:
    escaped = value.replace('\\', '\\\\').replace("'", "\\'")
    raw = F"'{escaped}'"
    return JsStringLiteral(value=value, raw=raw)


def _numeric_value(node: Expression) -> int | float | None:
    if isinstance(node, JsNumericLiteral):
        return node.value
    return None


def _make_numeric_literal(value: int | float) -> JsNumericLiteral:
    if isinstance(value, float):
        if value == int(value) and not (value == 0.0 and str(value).startswith('-')):
            raw = str(int(value))
        else:
            raw = str(value)
    else:
        raw = str(value)
    return JsNumericLiteral(value=value, raw=raw)


def _is_literal(node: Expression) -> bool:
    return isinstance(node, (
        JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral,
    ))


def _is_valid_identifier(name: str) -> bool:
    return bool(_SIMPLE_IDENT.match(name)) and name not in _JS_RESERVED


class JsDeobfuscator(Transformer):

    def visit_JsBinaryExpression(self, node: JsBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        op = node.operator
        left_str = _string_value(node.left)
        right_str = _string_value(node.right)
        if op == '+' and left_str is not None and right_str is not None:
            return _make_string_literal(left_str + right_str)
        left_num = _numeric_value(node.left)
        right_num = _numeric_value(node.right)
        if left_num is not None and right_num is not None:
            fn = _BINARY_OPS.get(op)
            if fn is not None:
                try:
                    result = fn(left_num, right_num)
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                if isinstance(result, float) and (
                    result != result or result == float('inf') or result == float('-inf')
                ):
                    return None
                return _make_numeric_literal(result)
            if op == '>>>':
                try:
                    left_i = int(left_num) & 0xFFFFFFFF
                    shift = int(right_num) & 0x1F
                    result = (left_i >> shift) & 0xFFFFFFFF
                except (ValueError, OverflowError):
                    return None
                return _make_numeric_literal(result)
        return None

    def visit_JsParenthesizedExpression(self, node: JsParenthesizedExpression):
        self.generic_visit(node)
        inner = node.expression
        if inner is None:
            return None
        if _is_literal(inner):
            return inner
        if isinstance(inner, JsSequenceExpression) and inner.expressions:
            if all(_is_literal(e) for e in inner.expressions):
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
                    and all(e is not None and _is_literal(e) for e in elements)
                ):
                    return elements[idx]
            prop_str = _string_value(node.property)
            if prop_str is not None and _is_valid_identifier(prop_str):
                node.computed = False
                node.property = JsIdentifier(name=prop_str)
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
            return _make_numeric_literal(-node.operand.value)
        if op == '+' and isinstance(node.operand, JsNumericLiteral):
            return node.operand
        if op == 'typeof' and _is_literal(node.operand):
            if isinstance(node.operand, JsNumericLiteral):
                return _make_string_literal('number')
            if isinstance(node.operand, JsStringLiteral):
                return _make_string_literal('string')
            if isinstance(node.operand, JsBooleanLiteral):
                return _make_string_literal('boolean')
        if op == 'void' and isinstance(node.operand, JsNumericLiteral):
            if node.operand.value == 0:
                return JsIdentifier(name='undefined')
        return None
