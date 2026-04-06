"""
Shared utilities for VBA deobfuscation transforms.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import TypeAlias

from refinery.lib.scripts import Expression
from refinery.lib.scripts.vba.model import (
    VbaBooleanLiteral,
    VbaFloatLiteral,
    VbaIntegerLiteral,
    VbaStringLiteral,
)

_Value: TypeAlias = str | int | float | bool | None


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


def _value_to_node(value: _Value) -> Expression | None:
    if isinstance(value, str):
        return _make_string_literal(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _make_integer_literal(value)
    if isinstance(value, float):
        return _make_numeric_literal(value)
    return None
