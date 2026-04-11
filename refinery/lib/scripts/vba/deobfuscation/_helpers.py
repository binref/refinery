"""
Shared utilities for VBA deobfuscation transforms.
"""
from __future__ import annotations

import copy

from typing import TYPE_CHECKING, Union, Optional

if TYPE_CHECKING:
    from typing import TypeAlias

from refinery.lib.scripts import Expression, Node, Statement
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaFloatLiteral,
    VbaIdentifier,
    VbaIntegerLiteral,
    VbaModule,
    VbaStringLiteral,
)

_Value: TypeAlias = Optional[Union[str, int, float, bool]]


def _make_string_literal(value: str) -> VbaStringLiteral:
    escaped = value.replace('"', '""')
    raw = F'"{escaped}"'
    return VbaStringLiteral(value=value, raw=raw)


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


def _is_constant_expr(node: Expression) -> bool:
    """
    Returns True for expressions that can be safely propagated as constants: literals, Chr/ChrW
    calls with literal integer arguments, and concatenations of such expressions.
    """
    if _is_literal(node):
        return True
    if isinstance(node, VbaCallExpression):
        if (
            isinstance(node.callee, VbaIdentifier)
            and node.callee.name.lower() in ('chr', 'chrw', 'chr$', 'chrw$')
            and len(node.arguments) == 1
            and node.arguments[0] is not None
            and isinstance(node.arguments[0], VbaIntegerLiteral)
        ):
            return True
        return False
    if isinstance(node, VbaBinaryExpression):
        if node.operator in ('&', '+'):
            return (
                node.left is not None
                and node.right is not None
                and _is_constant_expr(node.left)
                and _is_constant_expr(node.right)
            )
    return False


def _literal_value(node: Expression) -> _Value:
    if isinstance(node, VbaStringLiteral):
        return node.value
    if isinstance(node, VbaIntegerLiteral):
        return node.value
    if isinstance(node, VbaFloatLiteral):
        return node.value
    if isinstance(node, VbaBooleanLiteral):
        return node.value
    return None


def _string_value(node: Expression) -> str | None:
    if isinstance(node, VbaStringLiteral):
        return node.value
    return None


def _numeric_value(node: Expression) -> int | float | None:
    if isinstance(node, VbaIntegerLiteral):
        return node.value
    if isinstance(node, VbaFloatLiteral):
        return node.value
    return None


def _make_chr_call(code_point: int) -> VbaCallExpression:
    return VbaCallExpression(
        callee=VbaIdentifier(name='Chr'),
        arguments=[_make_integer_literal(code_point)],
    )


def _string_to_expr(value: str) -> Expression:
    """
    Convert a Python string to a VBA AST expression. Printable-only strings become a single string
    literal; strings with non-printable characters become concatenated expressions using Chr calls.
    """
    if not value:
        return _make_string_literal('')
    if all(c.isprintable() for c in value):
        return _make_string_literal(value)
    parts: list[Expression] = []
    run: list[str] = []
    for c in value:
        if c.isprintable():
            run.append(c)
        else:
            if run:
                parts.append(_make_string_literal(''.join(run)))
                run.clear()
            parts.append(_make_chr_call(ord(c)))
    if run:
        parts.append(_make_string_literal(''.join(run)))
    result = parts[0]
    for part in parts[1:]:
        result = VbaBinaryExpression(left=result, operator='&', right=part)
    return result


def _value_to_node(value: _Value) -> Expression | None:
    if isinstance(value, str):
        return _string_to_expr(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _make_integer_literal(value)
    if isinstance(value, float):
        return _make_numeric_literal(value)
    return None


def _body_lists(module: VbaModule):
    """
    Yield every statement-list body reachable from the module.
    """
    for node in module.walk():
        for attr_name in vars(node):
            if attr_name in ('parent', 'offset'):
                continue
            value = getattr(node, attr_name)
            if isinstance(value, list) and value and isinstance(value[0], Statement):
                yield value


def _clone_expression(node: Expression) -> Expression:
    """
    Deep-clone an expression tree downward without following parent pointers.
    """
    clone = copy.copy(node)
    clone.parent = None
    for attr_name in vars(node):
        if attr_name in ('parent', 'offset', 'leading_comments'):
            continue
        value = getattr(node, attr_name)
        if isinstance(value, Node):
            child = _clone_expression(value)
            child.parent = clone
            setattr(clone, attr_name, child)
        elif isinstance(value, list):
            cloned = []
            for item in value:
                if isinstance(item, Node):
                    child = _clone_expression(item)
                    child.parent = clone
                    cloned.append(child)
                else:
                    cloned.append(item)
            setattr(clone, attr_name, cloned)
    return clone
