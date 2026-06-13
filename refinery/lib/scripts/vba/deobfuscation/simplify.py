"""
VBA expression simplification and constant folding transforms.
"""
from __future__ import annotations

import operator

from typing import Callable

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.vba.deobfuscation.builtins import VBA_BUILTIN_CONSTANTS
from refinery.lib.scripts.vba.deobfuscation.helpers import (
    apply_removals,
    body_lists,
    is_literal,
    is_nan_or_inf,
    literal_value,
    make_integer_literal,
    make_numeric_literal,
    make_string_literal,
    numeric_value,
    string_value,
    value_to_node,
    vba_int_div,
    vba_mod,
)
from refinery.lib.scripts.vba.deobfuscation.names import (
    CHR_NAMES,
    Value,
    dispatch_builtin,
)
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaConstDeclaration,
    VbaEmptyLiteral,
    VbaForEachStatement,
    VbaForStatement,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
    VbaOnErrorAction,
    VbaOnErrorStatement,
    VbaParenExpression,
    VbaProcedureDeclaration,
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
    '\\' : vba_int_div,
    'Mod': vba_mod,
}


class _EvaluationFailed(Exception):
    pass


def _try_evaluate_call(node: VbaCallExpression) -> Value:
    """
    Try to statically evaluate a VBA builtin call with constant arguments. Raises `_EvaluationFailed`
    if the call cannot be evaluated; otherwise returns the evaluated Python value (may be `None` for
    VBA Empty).
    """
    if not isinstance(node.callee, VbaIdentifier):
        raise _EvaluationFailed
    args = [a for a in node.arguments if a is not None]
    values: list[Value] = []
    for arg in args:
        if not is_literal(arg):
            raise _EvaluationFailed
        values.append(literal_value(arg))
    name = node.callee.name.lower()
    try:
        matched, result = dispatch_builtin(name, values)
    except (ValueError, OverflowError, TypeError, IndexError):
        raise _EvaluationFailed
    if not matched:
        raise _EvaluationFailed
    return result


def _has_oern(body: list) -> bool:
    return any(
        isinstance(s, VbaOnErrorStatement) and s.action is VbaOnErrorAction.RESUME_NEXT
        for s in body
    )


class VbaSimplifications(Transformer):

    def __init__(self):
        super().__init__()
        self._assigned_names: set[str] = set()
        self._oern_bodies: set[int] = set()

    def visit(self, node):
        if isinstance(node, VbaModule):
            self._collect_context(node)
            super().visit(node)
            if self._remove_self_assignments(node):
                self.mark_changed()
            return None
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
            if isinstance(n, VbaProcedureDeclaration):
                if n.params:
                    for p in n.params:
                        self._assigned_names.add(p.name.lower())
                if n.name:
                    self._assigned_names.add(n.name.lower())
                if n.body and _has_oern(n.body):
                    self._oern_bodies.add(id(n.body))
        if module.body and _has_oern(module.body):
            self._oern_bodies.add(id(module.body))

    @staticmethod
    def _remove_self_assignments(module: VbaModule) -> bool:
        removals: list[tuple[int, list]] = []
        for body in body_lists(module):
            for idx, stmt in enumerate(body):
                if (
                    isinstance(stmt, VbaLetStatement)
                    and isinstance(stmt.target, VbaIdentifier)
                    and isinstance(stmt.value, VbaIdentifier)
                    and stmt.target.name.lower() == stmt.value.name.lower()
                ):
                    removals.append((idx, body))
        return apply_removals(removals)

    def _is_oern_undefined(self, node) -> bool:
        if not isinstance(node, VbaIdentifier):
            return False
        if node.name.lower() in self._assigned_names:
            return False
        parent = node.parent
        while parent is not None:
            if isinstance(parent, VbaProcedureDeclaration):
                return id(parent.body) in self._oern_bodies
            if isinstance(parent, VbaModule):
                return id(parent.body) in self._oern_bodies
            parent = parent.parent
        return False

    def visit_VbaBinaryExpression(self, node: VbaBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        if node.operator in ('&', '+'):
            result = self._fold_string_concat(node)
            if result is not None:
                return result
        return self._fold_numeric_binary(node)

    def _fold_string_concat(self, node: VbaBinaryExpression):
        if node.operator == '&':
            if isinstance(node.right, (VbaEmptyLiteral, VbaStringLiteral)) and not node.right.value:
                return node.left
            if isinstance(node.left, (VbaEmptyLiteral, VbaStringLiteral)) and not node.left.value:
                return node.right
        if self._is_oern_undefined(node.left) and string_value(node.right) is not None:
            return node.right
        if self._is_oern_undefined(node.right) and string_value(node.left) is not None:
            return node.left
        lhs = string_value(node.left)
        rhs = string_value(node.right)
        if lhs is not None and rhs is not None:
            return make_string_literal(lhs + rhs)
        if rhs is not None:
            if (
                isinstance(node.left, VbaBinaryExpression)
                and node.left.operator in ('&', '+')
            ):
                inner_right_str = string_value(node.left.right)
                if inner_right_str is not None:
                    node.left.right = make_string_literal(inner_right_str + rhs)
                    node.left.right.parent = node.left
                    return node.left
        if lhs is not None:
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
                inner_left_str = string_value(inner.left)
                if inner_left_str is not None:
                    inner.left = make_string_literal(lhs + inner_left_str)
                    inner.left.parent = inner
                    return node.right
        return None

    @staticmethod
    def _fold_numeric_binary(node: VbaBinaryExpression):
        lhs = numeric_value(node.left)
        rhs = numeric_value(node.right)
        if lhs is not None and rhs is not None:
            fn = _BINARY_OPS.get(node.operator)
            if fn is not None:
                try:
                    result = fn(lhs, rhs)
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                if is_nan_or_inf(result):
                    return None
                return make_numeric_literal(result)
            fn = _INTEGER_OPS.get(node.operator)
            if fn is not None:
                try:
                    result = fn(lhs, rhs)
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                return make_integer_literal(int(result))
            if node.operator == '^':
                try:
                    result = lhs ** rhs
                except (ZeroDivisionError, ValueError, OverflowError):
                    return None
                return make_numeric_literal(result)
        return None

    def visit_VbaCallExpression(self, node: VbaCallExpression):
        self.generic_visit(node)
        try:
            result = _try_evaluate_call(node)
        except _EvaluationFailed:
            return None
        if isinstance(result, str) and len(result) == 1 and not result.isprintable():
            if (
                isinstance(node.callee, VbaIdentifier)
                and node.callee.name.lower() in CHR_NAMES
            ):
                return None
        return value_to_node(result)

    def visit_VbaIdentifier(self, node: VbaIdentifier):
        value = VBA_BUILTIN_CONSTANTS.get(node.name.lower())
        if value is None:
            return None
        return make_integer_literal(value)

    def visit_VbaParenExpression(self, node: VbaParenExpression):
        self.generic_visit(node)
        inner = node.expression
        if inner is None:
            return None
        if isinstance(node.parent, VbaCallExpression) and node in node.parent.arguments:
            return None
        if isinstance(inner, (VbaIdentifier, VbaParenExpression)) or is_literal(inner):
            return inner
        return None

    def visit_VbaUnaryExpression(self, node: VbaUnaryExpression):
        self.generic_visit(node)
        if node.operand is None:
            return None
        op = node.operator
        if op == '-':
            val = numeric_value(node.operand)
            if val is not None:
                return make_numeric_literal(-val)
        if op == 'Not':
            if isinstance(node.operand, VbaBooleanLiteral):
                return VbaBooleanLiteral(value=not node.operand.value)
            val = numeric_value(node.operand)
            if isinstance(val, int):
                return make_integer_literal(~val)
        return None
