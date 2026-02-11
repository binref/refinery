"""
Contains functions to aid in deobfuscation.
"""
from __future__ import annotations

import ast
import re

from typing import Any, NamedTuple


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
    ast.Name,
    ast.Load,
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


def cautious_parse(
    definition: str,
    size_limit: int | None = None,
    walker: ast.NodeTransformer | None = None,
    environment: dict[str, Any] | None = None,
    allow_variables: bool = True,
) -> ast.Expression:
    """
    Very, very, very, very, very carefully parse a Python expression.
    """
    definition = re.sub(R'\s+', '', definition)

    class Abort(ExpressionParsingFailure):
        def __init__(self, msg):
            super().__init__(F'{msg}: {definition}')

    if size_limit and len(definition) > size_limit:
        raise Abort(F'Size limit {size_limit} was exceeded while parsing')

    if not allow_variables:
        test = definition
        if environment:
            for symbol in environment:
                test = re.sub(RF'\b{symbol}\b', '', test)
        if any(x not in '.^%|&~<>()-+/*0123456789xabcdefABCDEF' for x in test):
            raise Abort('Unknown characters in expression')
    try:
        expression = ast.parse(definition, mode='eval')
    except Exception:
        raise Abort('Python AST parser failed')

    if walker is not None:
        expression = ast.fix_missing_locations(walker.visit(expression))

    nodes = ast.walk(expression)

    try:
        if type(next(nodes)) != ast.Expression:
            raise ValueError
    except (StopIteration, ValueError):
        raise Abort('Not a Python expression')

    nodes = list(nodes)
    types = {type(node) for node in nodes}

    if not types <= _ALLOWED_NODE_TYPES:
        problematic = types - _ALLOWED_NODE_TYPES
        raise ExpressionParsingFailure(
            'Expression contains operations that are not allowed: {}'.format(
                ', '.join(str(p) for p in problematic)))

    return expression


def cautious_eval(
    definition: str,
    size_limit: int | None = None,
    walker: ast.NodeTransformer | None = None,
    environment: dict[str, Any] | None = None,
) -> Any:
    """
    Very, very, very, very, very carefully parse a Python expression.
    """
    tree = cautious_parse(
        definition,
        size_limit,
        walker,
        environment,
        allow_variables=False
    )
    code = compile(tree, filename='[code]', mode='eval')
    return eval(code, environment)


def cautious_eval_or_default(
    definition: str,
    default: Any | None = None,
    size_limit: int | None = None,
    walker: ast.NodeTransformer | None = None,
    environment: dict[str, Any] | None = None,
):
    """
    Very, very, very, very, very carefully parse a Python expression or return a default value.
    """
    try:
        return cautious_eval(definition, size_limit, walker, environment)
    except ExpressionParsingFailure:
        return default


class NamesInExpression(NamedTuple):
    loaded: dict[str, ast.Name]
    stored: dict[str, ast.Name]
    others: dict[str, ast.Name]


def names_in_expression(expression: ast.Expression):
    """
    Take a parsed expression and extract the names of all variables that are accessed.
    This returns a `refinery.lib.deobfuscation.NamesInExpression` tuple where loaded,
    stored, and otherwise accessed variables are exposed as dictionaries that map their
    name to the corresponding AST node.
    """
    result = NamesInExpression({}, {}, {})
    for node in ast.walk(expression):
        if not isinstance(node, ast.Name):
            continue
        if isinstance(node.ctx, ast.Load):
            result.loaded[node.id] = node
            continue
        if isinstance(node.ctx, ast.Store):
            result.stored[node.id] = node
            continue
        result.others[node.id] = node
    return result
