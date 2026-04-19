"""
Shared AST utilities for VBA deobfuscation transforms.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

from refinery.lib.scripts import Expression, Kind, Statement, _classify_fields
from refinery.lib.scripts.vba.deobfuscation.names import CHR_NAMES, Value
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaConstDeclaration,
    VbaConstDeclarator,
    VbaExpressionStatement,
    VbaFloatLiteral,
    VbaForEachStatement,
    VbaForStatement,
    VbaIdentifier,
    VbaIntegerLiteral,
    VbaLetStatement,
    VbaModule,
    VbaStringLiteral,
)

LITERAL_TYPES = (VbaStringLiteral, VbaIntegerLiteral, VbaFloatLiteral, VbaBooleanLiteral)


def make_string_literal(value: str) -> VbaStringLiteral:
    escaped = value.replace('"', '""')
    raw = F'"{escaped}"'
    return VbaStringLiteral(value=value, raw=raw)


def is_nan_or_inf(value) -> bool:
    return isinstance(value, float) and (value != value or abs(value) == float('inf'))


def make_integer_literal(value: int) -> VbaIntegerLiteral:
    return VbaIntegerLiteral(value=value, raw=str(value))


def make_float_literal(value: float) -> VbaFloatLiteral:
    return VbaFloatLiteral(value=value, raw=str(value))


def make_numeric_literal(value: int | float) -> VbaIntegerLiteral | VbaFloatLiteral:
    if isinstance(value, float):
        if value == int(value) and abs(value) < 2 ** 53:
            return make_integer_literal(int(value))
        return make_float_literal(value)
    return make_integer_literal(value)


def is_literal(node: Expression) -> bool:
    return isinstance(node, LITERAL_TYPES)


def is_constant_expr(node: Expression) -> bool:
    """
    Returns True for expressions that can be safely propagated as constants: literals, Chr/ChrW
    calls with literal integer arguments, and concatenations of such expressions.
    """
    if is_literal(node):
        return True
    if isinstance(node, VbaCallExpression):
        if (
            isinstance(node.callee, VbaIdentifier)
            and node.callee.name.lower() in CHR_NAMES
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
                and is_constant_expr(node.left)
                and is_constant_expr(node.right)
            )
    return False


def is_identifier_read(node: VbaIdentifier) -> bool:
    """
    Return whether an identifier node is in a read position. Returns False for identifiers that
    appear as assignment targets, declaration names, call targets, or loop variables.
    """
    parent = node.parent
    if isinstance(parent, VbaLetStatement) and parent.target is node:
        return False
    if isinstance(parent, (VbaConstDeclaration, VbaConstDeclarator)):
        return False
    if isinstance(parent, VbaCallExpression) and parent.callee is node:
        return False
    if isinstance(parent, VbaExpressionStatement) and parent.expression is node:
        return False
    if (
        isinstance(parent, (VbaForStatement, VbaForEachStatement))
        and parent.variable is node
    ):
        return False
    return True


def literal_value(node: Expression) -> Value:
    if isinstance(node, LITERAL_TYPES):
        return node.value
    return None


def string_value(node: Expression | None) -> str | None:
    if isinstance(node, VbaStringLiteral):
        return node.value
    return None


def numeric_value(node: Expression | None) -> int | float | None:
    if isinstance(node, VbaIntegerLiteral):
        return node.value
    if isinstance(node, VbaFloatLiteral):
        return node.value
    return None


def make_chr_call(code_point: int) -> VbaCallExpression:
    return VbaCallExpression(
        callee=VbaIdentifier(name='Chr'),
        arguments=[make_integer_literal(code_point)],
    )


def string_to_expr(value: str) -> Expression:
    """
    Convert a Python string to a VBA AST expression. Printable-only strings become a single string
    literal; strings with non-printable characters become concatenated expressions using Chr calls.
    """
    if not value:
        return make_string_literal('')
    if all(c.isprintable() for c in value):
        return make_string_literal(value)
    parts: list[Expression] = []
    run: list[str] = []
    for c in value:
        if c.isprintable():
            run.append(c)
        else:
            if run:
                parts.append(make_string_literal(''.join(run)))
                run.clear()
            parts.append(make_chr_call(ord(c)))
    if run:
        parts.append(make_string_literal(''.join(run)))
    result = parts[0]
    for part in parts[1:]:
        result = VbaBinaryExpression(left=result, operator='&', right=part)
    return result


def value_to_node(value: Value) -> Expression | None:
    if isinstance(value, str):
        return string_to_expr(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return make_integer_literal(value)
    if isinstance(value, float):
        return make_numeric_literal(value)
    return None


def body_lists(module: VbaModule) -> Generator[list[Statement]]:
    """
    Yield every statement-list body reachable from the module.
    """
    for node in module.walk():
        for field_name, kind in _classify_fields(type(node)):
            if kind != Kind.ChildList:
                continue
            body = getattr(node, field_name)
            if body and isinstance(body[0], Statement):
                yield body
