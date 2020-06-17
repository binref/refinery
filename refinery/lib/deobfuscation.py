#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contains functions to aid in deobfuscation.
"""
from typing import Optional, Any

import ast
import re


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
    ast.Num,
    ast.Or,
    ast.RShift,
    ast.Sub,
    ast.UAdd,
    ast.UnaryOp,
    ast.USub
})


def cautious_eval(definition: str, size_limit: Optional[int] = None) -> Any:
    """
    Very, very, very, very, very carefully evaluate a Python expression.
    """
    definition = re.sub(R'\s+', '', definition)

    class Abort(ExpressionParsingFailure):
        def __init__(self, msg):
            super().__init__(F'{msg}: {definition}')

    if size_limit and len(definition) > size_limit:
        raise Abort(F'Size limit {size_limit} was exceeded while parsing')
    if any(x not in '.^%|&~<>()-+/*0123456789xabcdefABCDEF' for x in definition):
        raise Abort('Unknown characters in expression')
    try:
        expression = ast.parse(definition)
        nodes = ast.walk(expression)
    except Exception:
        raise Abort('Python AST parser failed')

    try:
        assert type(next(nodes)) == ast.Module
        assert type(next(nodes)) == ast.Expr
    except (StopIteration, AssertionError):
        raise Abort('Not a Python expression')

    nodes = list(nodes)
    types = set(type(node) for node in nodes)

    if not types <= _ALLOWED_NODE_TYPES:
        problematic = types - _ALLOWED_NODE_TYPES
        raise Abort('Expression contains operations that are not allowed: {}'.format(', '.join(str(p) for p in problematic)))

    return eval(definition)


def cautious_eval_or_default(definition: str, default: Optional[Any] = None, size_limit: Optional[int] = None) -> Any:
    try:
        return cautious_eval(definition)
    except ExpressionParsingFailure:
        return default
