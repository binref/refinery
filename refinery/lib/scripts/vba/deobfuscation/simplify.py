"""
VBA expression simplification and constant folding transforms.
"""
from __future__ import annotations

import copy
import operator

from typing import Callable

from refinery.lib.scripts import Expression, Statement, Transformer
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaConstDeclaration,
    VbaFloatLiteral,
    VbaForEachStatement,
    VbaForStatement,
    VbaIdentifier,
    VbaIntegerLiteral,
    VbaLetStatement,
    VbaModule,
    VbaParenExpression,
    VbaStringLiteral,
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


def _string_value(node: Expression) -> str | None:
    if isinstance(node, VbaStringLiteral):
        return node.value
    return None


def _make_string_literal(value: str) -> VbaStringLiteral:
    escaped = value.replace('"', '""')
    raw = F'"{escaped}"'
    return VbaStringLiteral(value=value, raw=raw)


def _numeric_value(node: Expression) -> int | float | None:
    if isinstance(node, VbaIntegerLiteral):
        return node.value
    if isinstance(node, VbaFloatLiteral):
        return node.value
    return None


def _make_integer_literal(value: int) -> VbaIntegerLiteral:
    return VbaIntegerLiteral(value=value, raw=str(value))


def _make_float_literal(value: float) -> VbaFloatLiteral:
    return VbaFloatLiteral(value=value, raw=str(value))


def _make_numeric_literal(value: int | float) -> VbaIntegerLiteral | VbaFloatLiteral:
    if isinstance(value, float):
        if value == int(value) and abs(value) < 2 ** 53:
            return _make_integer_literal(int(value))
        return _make_float_literal(value)
    return _make_integer_literal(value)


def _is_literal(node: Expression) -> bool:
    return isinstance(node, (
        VbaStringLiteral, VbaIntegerLiteral, VbaFloatLiteral,
        VbaBooleanLiteral,
    ))


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

    @staticmethod
    def _body_lists(module: VbaModule):
        for node in module.walk():
            for attr_name in vars(node):
                if attr_name in ('parent', 'offset'):
                    continue
                value = getattr(node, attr_name)
                if isinstance(value, list) and value and isinstance(value[0], Statement):
                    yield value

    def _inline_constants(self, module: VbaModule) -> bool:
        candidates: dict[str, list[tuple[Expression, list[Statement], int]]] = {}
        assignment_counts: dict[str, int] = {}
        for body in self._body_lists(module):
            for idx, stmt in enumerate(body):
                if (
                    isinstance(stmt, VbaConstDeclaration)
                    and stmt.value is not None
                    and _is_literal(stmt.value)
                ):
                    key = stmt.name.lower()
                    candidates.setdefault(key, []).append((stmt.value, body, idx))
                    assignment_counts[key] = assignment_counts.get(key, 0) + 1
                elif (
                    isinstance(stmt, VbaLetStatement)
                    and isinstance(stmt.target, VbaIdentifier)
                    and stmt.value is not None
                ):
                    key = stmt.target.name.lower()
                    assignment_counts[key] = assignment_counts.get(key, 0) + 1
                    if _is_literal(stmt.value):
                        candidates.setdefault(key, []).append((stmt.value, body, idx))
        loop_variables: set[str] = set()
        for node in module.walk():
            if isinstance(node, (VbaForStatement, VbaForEachStatement)):
                if isinstance(node.variable, VbaIdentifier):
                    loop_variables.add(node.variable.name.lower())
        candidates = {k: v for k, v in candidates.items() if len(v) == 1 and k not in loop_variables and assignment_counts.get(k, 0) == 1}
        if not candidates:
            return False
        reads: dict[str, list[VbaIdentifier]] = {}
        for node in module.walk():
            if not isinstance(node, VbaIdentifier):
                continue
            parent = node.parent
            if isinstance(parent, VbaLetStatement) and parent.target is node:
                continue
            if isinstance(parent, VbaConstDeclaration):
                continue
            if isinstance(parent, (VbaForStatement, VbaForEachStatement)) and parent.variable is node:
                continue
            key = node.name.lower()
            if key in candidates:
                reads.setdefault(key, []).append(node)
        removals: list[tuple[list[Statement], int]] = []
        for key, refs in reads.items():
            literal_node, body, idx = candidates[key][0]
            for ref in refs:
                replacement = copy.copy(literal_node)
                replacement.parent = ref.parent
                parent = ref.parent
                for attr_name in vars(parent):
                    if attr_name in ('parent', 'offset'):
                        continue
                    value = getattr(parent, attr_name)
                    if value is ref:
                        setattr(parent, attr_name, replacement)
                    elif isinstance(value, list):
                        for i, item in enumerate(value):
                            if item is ref:
                                value[i] = replacement
            removals.append((body, idx))
        for body, idx in sorted(removals, key=lambda t: t[1], reverse=True):
            del body[idx]
        return bool(removals)

    def _remove_dead_variables(self, module: VbaModule) -> bool:
        assignments: dict[str, list[tuple[VbaLetStatement, list[Statement], int]]] = {}
        for body in self._body_lists(module):
            if body is module.body:
                continue
            for idx, stmt in enumerate(body):
                if (
                    isinstance(stmt, VbaLetStatement)
                    and isinstance(stmt.target, VbaIdentifier)
                    and stmt.value is not None
                ):
                    has_call = False
                    for child in stmt.value.walk():
                        if isinstance(child, VbaCallExpression):
                            has_call = True
                            break
                    if not has_call:
                        key = stmt.target.name.lower()
                        assignments.setdefault(key, []).append((stmt, body, idx))
        read_names: set[str] = set()
        for node in module.walk():
            if not isinstance(node, VbaIdentifier):
                continue
            parent = node.parent
            if isinstance(parent, VbaLetStatement) and parent.target is node:
                continue
            read_names.add(node.name.lower())
        removals: list[tuple[list[Statement], int]] = []
        for key, entries in assignments.items():
            if key not in read_names:
                for _stmt, body, idx in entries:
                    removals.append((body, idx))
        for body, idx in sorted(removals, key=lambda t: t[1], reverse=True):
            del body[idx]
        return bool(removals)

    def deobfuscate(self, module: VbaModule) -> bool:
        self.changed = False
        self.visit(module)
        changed = self.changed
        changed |= self._inline_constants(module)
        self.changed = False
        self.visit(module)
        changed |= self.changed
        changed |= self._remove_dead_variables(module)
        return changed
