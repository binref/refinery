"""
Shared utilities for JavaScript deobfuscation transforms.
"""
from __future__ import annotations

import operator
import re

from typing import Callable

from refinery.lib.scripts import Expression
from refinery.lib.scripts.js.model import (
    JsBooleanLiteral,
    JsNullLiteral,
    JsNumericLiteral,
    JsStringLiteral,
)
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})

BINARY_OPS: dict[str, Callable] = {
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


def string_value(node: Expression) -> str | None:
    if isinstance(node, JsStringLiteral):
        return node.value
    return None


def make_string_literal(value: str) -> JsStringLiteral:
    escaped = value.replace('\\', '\\\\').replace("'", "\\'")
    raw = F"'{escaped}'"
    return JsStringLiteral(value=value, raw=raw)


def numeric_value(node: Expression) -> int | float | None:
    if isinstance(node, JsNumericLiteral):
        return node.value
    return None


def make_numeric_literal(value: int | float) -> JsNumericLiteral:
    if isinstance(value, float):
        if value == int(value) and not (value == 0.0 and str(value).startswith('-')):
            raw = str(int(value))
        else:
            raw = str(value)
    else:
        raw = str(value)
    return JsNumericLiteral(value=value, raw=raw)


def is_literal(node: Expression) -> bool:
    return isinstance(node, (
        JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral,
    ))


def is_valid_identifier(name: str) -> bool:
    return bool(SIMPLE_IDENTIFIER.match(name)) and name not in JS_RESERVED
