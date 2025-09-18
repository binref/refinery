"""
Contains functions to aid in deobfuscation.
"""
from __future__ import annotations

import ast
import re

from typing import Any


class ExpressionParsingFailure(ValueError):
    pass


_ALLOWED_NODE_TYPES = frozenset({
    ast.Add,
    ast.BinOp,
    ast.BitAnd,
    ast.BitAnd,
    ast.BitOr,
    ast.BitXor,
    ast.Constant,
    ast.Div,
    ast.FloorDiv,
    ast.Invert,
    ast.LShift,
    ast.Mod,
    ast.Mult,
    ast.Not,
    ast.NotEq,
    ast.Or,
    ast.Pow,
    ast.RShift,
    ast.Sub,
    ast.UAdd,
    ast.UnaryOp,
    ast.USub
})


def cautious_eval(
    definition: str,
    size_limit: int | None = None,
    walker: ast.NodeTransformer | None = None,
    environment: dict[str, Any] | None = None,
) -> Any:
    """
    Very, very, very, very, very carefully evaluate a Python expression.
    """
    definition = re.sub(R'\s+', '', definition)

    class Abort(ExpressionParsingFailure):
        def __init__(self, msg):
            super().__init__(F'{msg}: {definition}')

    if size_limit and len(definition) > size_limit:
        raise Abort(F'Size limit {size_limit} was exceeded while parsing')

    test = definition
    if environment:
        for symbol in environment:
            test = re.sub(RF'\b{symbol}\b', '', test)
    if any(x not in '.^%|&~<>()-+/*0123456789xabcdefABCDEF' for x in test):
        raise Abort('Unknown characters in expression')
    try:
        expression = ast.parse(definition)
    except Exception:
        raise Abort('Python AST parser failed')

    if walker is not None:
        expression = ast.fix_missing_locations(walker.visit(expression))

    nodes = ast.walk(expression)

    try:
        assert type(next(nodes)) == ast.Module
        assert type(next(nodes)) == ast.Expr
    except (StopIteration, AssertionError):
        raise Abort('Not a Python expression')

    nodes = list(nodes)
    types = {type(node) for node in nodes}

    if not types <= _ALLOWED_NODE_TYPES:
        problematic = types - _ALLOWED_NODE_TYPES
        raise Abort('Expression contains operations that are not allowed: {}'.format(', '.join(str(p) for p in problematic)))

    return eval(definition, environment)


def cautious_eval_or_default(
    definition: str,
    default: Any | None = None,
    size_limit: int | None = None,
    walker: ast.NodeTransformer | None = None,
    environment: dict[str, Any] | None = None,
):
    try:
        return cautious_eval(definition, size_limit, walker, environment)
    except ExpressionParsingFailure:
        return default
