"""
VBA expression simplification and constant folding transforms.
"""
from __future__ import annotations

import operator

from typing import Callable

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import (
    _CHR_NAMES,
    _eval_string_builtin,
    _is_literal,
    _make_integer_literal,
    _make_numeric_literal,
    _make_string_literal,
    _numeric_value,
    _string_value,
)
from refinery.lib.scripts.vba.deobfuscation.builtins import VBA_BUILTIN_CONSTANTS
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaConstDeclaration,
    VbaForEachStatement,
    VbaForStatement,
    VbaFunctionDeclaration,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
    VbaOnErrorAction,
    VbaOnErrorStatement,
    VbaParenExpression,
    VbaSubDeclaration,
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
        and node.callee.name.lower() in _CHR_NAMES
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
    if name == 'len' and len(args) == 1:
        return None
    values: list = []
    for arg in args:
        s = _string_value(arg)
        if s is not None:
            values.append(s)
            continue
        n = _numeric_value(arg)
        if n is not None:
            values.append(n)
            continue
        return None
    try:
        result = _eval_string_builtin(name, values)
    except (ValueError, OverflowError, TypeError):
        return None
    return result


class VbaSimplifications(Transformer):

    def __init__(self):
        super().__init__()
        self._assigned_names: set[str] = set()
        self._oern_bodies: set[int] = set()

    def visit(self, node):
        if isinstance(node, VbaModule):
            self._collect_context(node)
        return super().visit(node)

    def _collect_context(self, module: VbaModule):
        self._assigned_names = set(VBA_BUILTIN_CONSTANTS)
        self._oern_bodies = set()
        for n in module.walk():
            if isinstance(n, VbaLetStatement) and isinstance(n.target, VbaIdentifier):
                self._assigned_names.add(n.target.name.lower())
            elif isinstance(n, VbaConstDeclaration):
                for d in n.declarators:
                    self._assigned_names.add(d.name.lower())
            elif isinstance(n, (VbaForStatement, VbaForEachStatement)):
                if isinstance(n.variable, VbaIdentifier):
                    self._assigned_names.add(n.variable.name.lower())
            if isinstance(n, (VbaFunctionDeclaration, VbaSubDeclaration)):
                if n.params:
                    for p in n.params:
                        self._assigned_names.add(p.name.lower())
                if n.name:
                    self._assigned_names.add(n.name.lower())
                if n.body and any(
                    isinstance(s, VbaOnErrorStatement)
                    and s.action is VbaOnErrorAction.RESUME_NEXT
                    for s in n.body
                ):
                    self._oern_bodies.add(id(n.body))
        if module.body and any(
            isinstance(s, VbaOnErrorStatement)
            and s.action is VbaOnErrorAction.RESUME_NEXT
            for s in module.body
        ):
            self._oern_bodies.add(id(module.body))

    def _is_oern_undefined(self, node) -> bool:
        if not isinstance(node, VbaIdentifier):
            return False
        if node.name.lower() in self._assigned_names:
            return False
        parent = node.parent
        while parent is not None:
            if isinstance(parent, (VbaFunctionDeclaration, VbaSubDeclaration)):
                return id(parent.body) in self._oern_bodies
            if isinstance(parent, VbaModule):
                return id(parent.body) in self._oern_bodies
            parent = parent.parent
        return False

    def visit_VbaBinaryExpression(self, node: VbaBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        op = node.operator

        if op in ('&', '+'):
            if self._is_oern_undefined(node.left) and _string_value(node.right) is not None:
                return node.right
            if self._is_oern_undefined(node.right) and _string_value(node.left) is not None:
                return node.left

        left_str = _string_value(node.left)
        right_str = _string_value(node.right)
        if op in ('&', '+') and left_str is not None and right_str is not None:
            return _make_string_literal(left_str + right_str)
        if op in ('&', '+') and right_str is not None:
            if (
                isinstance(node.left, VbaBinaryExpression)
                and node.left.operator in ('&', '+')
            ):
                inner_right_str = _string_value(node.left.right)
                if inner_right_str is not None:
                    node.left.right = _make_string_literal(inner_right_str + right_str)
                    node.left.right.parent = node.left
                    return node.left
        if op in ('&', '+') and left_str is not None:
            inner = node.right
            while (
                isinstance(inner, VbaBinaryExpression)
                and inner.operator in ('&', '+')
                and isinstance(inner.left, VbaBinaryExpression)
                and inner.left.operator in ('&', '+')
            ):
                inner = inner.left
            if (
                isinstance(inner, VbaBinaryExpression)
                and inner.operator in ('&', '+')
            ):
                inner_left_str = _string_value(inner.left)
                if inner_left_str is not None:
                    inner.left = _make_string_literal(left_str + inner_left_str)
                    inner.left.parent = inner
                    return node.right

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
            c = chr(code_point)
            if c.isprintable():
                return _make_string_literal(c)
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

    def visit_VbaIdentifier(self, node: VbaIdentifier):
        value = VBA_BUILTIN_CONSTANTS.get(node.name.lower())
        if value is None:
            return None
        return _make_integer_literal(value)

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
