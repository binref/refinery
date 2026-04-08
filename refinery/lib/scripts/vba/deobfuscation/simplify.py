"""
VBA expression simplification and constant folding transforms.
"""
from __future__ import annotations

import operator

from typing import Callable

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import (
    _is_literal,
    _make_integer_literal,
    _make_numeric_literal,
    _make_string_literal,
    _numeric_value,
    _string_value,
)
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaIdentifier,
    VbaParenExpression,
    VbaUnaryExpression,
)

_BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : operator.mul,
    '/'  : operator.truediv,
}

_INTEGER_OPS: dict[str, Callable] = {
    '\\' : lambda a, b: int(a) // int(b),
    'Mod': lambda a, b: int(a) % int(b),
}


def _is_chr_call(node: VbaCallExpression) -> int | None:
    if (
        isinstance(node.callee, VbaIdentifier)
        and node.callee.name.lower() in ('chr', 'chrw', 'chr$', 'chrw$')
        and len(node.arguments) == 1
        and node.arguments[0] is not None
    ):
        val = _numeric_value(node.arguments[0])
        if val is not None and isinstance(val, int) and 0 <= val <= 0xFFFF:
            return val
    return None


def _is_asc_call(node: VbaCallExpression) -> str | None:
    if (
        isinstance(node.callee, VbaIdentifier)
        and node.callee.name.lower() in ('asc', 'ascw')
        and len(node.arguments) == 1
        and node.arguments[0] is not None
    ):
        val = _string_value(node.arguments[0])
        if val is not None and len(val) >= 1:
            return val[0]
    return None


def _try_string_function(node: VbaCallExpression) -> str | None:
    if not isinstance(node.callee, VbaIdentifier):
        return None
    name = node.callee.name.lower().rstrip('$')
    args = [a for a in node.arguments if a is not None]
    if name == 'mid' and len(args) in (2, 3):
        s = _string_value(args[0])
        start_val = _numeric_value(args[1])
        if s is None or start_val is None or not isinstance(start_val, int):
            return None
        start_idx = start_val - 1
        if start_idx < 0:
            return None
        if len(args) == 3:
            length_val = _numeric_value(args[2])
            if length_val is None or not isinstance(length_val, int):
                return None
            return s[start_idx:start_idx + length_val]
        return s[start_idx:]
    if name == 'left' and len(args) == 2:
        s = _string_value(args[0])
        n = _numeric_value(args[1])
        if s is not None and isinstance(n, int):
            return s[:n]
    if name == 'right' and len(args) == 2:
        s = _string_value(args[0])
        n = _numeric_value(args[1])
        if s is not None and isinstance(n, int):
            return s[-n:] if n > 0 else ''
    if name == 'strreverse' and len(args) == 1:
        s = _string_value(args[0])
        if s is not None:
            return s[::-1]
    if name == 'lcase' and len(args) == 1:
        s = _string_value(args[0])
        if s is not None:
            return s.lower()
    if name == 'ucase' and len(args) == 1:
        s = _string_value(args[0])
        if s is not None:
            return s.upper()
    if name == 'len' and len(args) == 1:
        s = _string_value(args[0])
        if s is not None:
            return None
    if name == 'string' and len(args) == 2:
        n = _numeric_value(args[0])
        c = _string_value(args[1])
        if isinstance(n, int) and c is not None and len(c) >= 1:
            return c[0] * n
    if name == 'space' and len(args) == 1:
        n = _numeric_value(args[0])
        if isinstance(n, int) and 0 <= n <= 10000:
            return ' ' * n
    if name == 'replace' and len(args) >= 3:
        haystack = _string_value(args[0])
        needle = _string_value(args[1])
        insert = _string_value(args[2])
        if haystack is not None and needle is not None and insert is not None and needle:
            return haystack.replace(needle, insert)
    return None


class VbaSimplifications(Transformer):

    def visit_VbaBinaryExpression(self, node: VbaBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        op = node.operator

        left_str = _string_value(node.left)
        right_str = _string_value(node.right)
        if op == '&' and left_str is not None and right_str is not None:
            return _make_string_literal(left_str + right_str)
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
                    result != result
                    or result == float('inf')
                    or result == float('-inf')
                ):
                    return None
                return _make_numeric_literal(result)
            fn = _INTEGER_OPS.get(op)
            if fn is not None:
                try:
                    result = fn(left_num, right_num)
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                return _make_integer_literal(int(result))
            if op == '^':
                try:
                    result = left_num ** right_num
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                return _make_numeric_literal(result)
        return None

    def visit_VbaCallExpression(self, node: VbaCallExpression):
        self.generic_visit(node)
        code_point = _is_chr_call(node)
        if code_point is not None:
            try:
                return _make_string_literal(chr(code_point))
            except (ValueError, OverflowError):
                return None
        char = _is_asc_call(node)
        if char is not None:
            return _make_integer_literal(ord(char))
        result = _try_string_function(node)
        if result is not None:
            return _make_string_literal(result)
        if (
            isinstance(node.callee, VbaIdentifier)
            and node.callee.name.lower() == 'len'
            and len(node.arguments) == 1
            and node.arguments[0] is not None
        ):
            s = _string_value(node.arguments[0])
            if s is not None:
                return _make_integer_literal(len(s))
        return None

    def visit_VbaParenExpression(self, node: VbaParenExpression):
        self.generic_visit(node)
        inner = node.expression
        if inner is None:
            return None
        if _is_literal(inner):
            return inner
        return None

    def visit_VbaUnaryExpression(self, node: VbaUnaryExpression):
        self.generic_visit(node)
        if node.operand is None:
            return None
        op = node.operator
        if op == '-':
            val = _numeric_value(node.operand)
            if val is not None:
                return _make_numeric_literal(-val)
        if op == 'Not':
            if isinstance(node.operand, VbaBooleanLiteral):
                return VbaBooleanLiteral(value=not node.operand.value)
            val = _numeric_value(node.operand)
            if isinstance(val, int):
                return _make_integer_literal(~val)
        return None
