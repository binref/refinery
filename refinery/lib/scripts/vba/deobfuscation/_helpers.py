"""
Shared utilities for VBA deobfuscation transforms.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from typing import TypeAlias

from refinery.lib.scripts import Expression, Kind, Statement, _classify_fields
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

_Value: TypeAlias = str | int | float | bool | None

_CHR_NAMES = frozenset({'chr', 'chrw', 'chr$', 'chrw$'})

_LITERAL_TYPES = (VbaStringLiteral, VbaIntegerLiteral, VbaFloatLiteral, VbaBooleanLiteral)


def _make_string_literal(value: str) -> VbaStringLiteral:
    escaped = value.replace('"', '""')
    raw = F'"{escaped}"'
    return VbaStringLiteral(value=value, raw=raw)


def _is_nan_or_inf(value) -> bool:
    return isinstance(value, float) and (value != value or abs(value) == float('inf'))


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
    return isinstance(node, _LITERAL_TYPES)


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
            and node.callee.name.lower() in _CHR_NAMES
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


def _is_identifier_read(node: VbaIdentifier) -> bool:
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


def _literal_value(node: Expression) -> _Value:
    if isinstance(node, _LITERAL_TYPES):
        return node.value
    return None


def _string_value(node: Expression | None) -> str | None:
    if isinstance(node, VbaStringLiteral):
        return node.value
    return None


def _numeric_value(node: Expression | None) -> int | float | None:
    if isinstance(node, VbaIntegerLiteral):
        return node.value
    if isinstance(node, VbaFloatLiteral):
        return node.value
    return None


def _str_arg(args: list, index: int = 0) -> str:
    return str(args[index]) if args[index] is not None else ''


def _eval_mid(args: list) -> str | None:
    if len(args) not in (2, 3):
        return None
    s = _str_arg(args)
    start = int(args[1]) - 1
    if start < 0:
        raise ValueError
    if len(args) == 3:
        length = int(args[2])
        return s[start:start + length]
    return s[start:]


def _eval_left(args: list) -> str | None:
    if len(args) != 2:
        return None
    return _str_arg(args)[:int(args[1])]


def _eval_right(args: list) -> str | None:
    if len(args) != 2:
        return None
    n = int(args[1])
    return _str_arg(args)[-n:] if n > 0 else ''


def _eval_strreverse(args: list) -> str | None:
    if len(args) != 1:
        return None
    return _str_arg(args)[::-1]


def _eval_string_fn(args: list) -> str | None:
    if len(args) != 2:
        return None
    n = int(args[0])
    c = _str_arg(args, 1)
    if not c:
        raise ValueError
    return c[0] * n


def _eval_space(args: list) -> str | None:
    if len(args) != 1:
        return None
    n = int(args[0])
    if n < 0 or n > 10000:
        raise ValueError
    return ' ' * n


def _eval_replace(args: list) -> str | None:
    if len(args) < 3:
        return None
    haystack = _str_arg(args)
    needle = _str_arg(args, 1)
    insert = _str_arg(args, 2)
    if not needle:
        raise ValueError
    return haystack.replace(needle, insert)


_STRING_DISPATCH: dict[str, Callable[[list], str | None]] = {
    'mid'        : _eval_mid,
    'left'       : _eval_left,
    'right'      : _eval_right,
    'strreverse' : _eval_strreverse,
    'lcase'      : lambda a: _str_arg(a).lower() if len(a) == 1 else None,
    'ucase'      : lambda a: _str_arg(a).upper() if len(a) == 1 else None,
    'trim'       : lambda a: _str_arg(a).strip() if len(a) == 1 else None,
    'ltrim'      : lambda a: _str_arg(a).lstrip() if len(a) == 1 else None,
    'rtrim'      : lambda a: _str_arg(a).rstrip() if len(a) == 1 else None,
    'cstr'       : lambda a: _str_arg(a) if len(a) == 1 else None,
    'string'     : _eval_string_fn,
    'space'      : _eval_space,
    'replace'    : _eval_replace,
}


def _eval_string_builtin(name: str, args: list) -> str | None:
    """
    Evaluate a VBA string built-in on plain Python values. The `name` must already be lowercased
    and stripped of a trailing `$`. Returns `None` when the function name is not recognized; raises
    `ValueError` on domain errors (bad arg count, negative index, etc.).
    """
    handler = _STRING_DISPATCH.get(name)
    if handler is None:
        return None
    return handler(args)


_STRING_BUILTINS = frozenset(_STRING_DISPATCH) | frozenset({'instr'})


def _cast_to_int(value):
    as_flt = float(value)
    as_int = int(as_flt)
    if as_flt < 0 and as_flt != int(as_flt):
        as_int -= 1
    return as_int


_SINGLE_ARG_BUILTINS: dict[str, Callable[[Any], _Value]] = {
    'chr'   : lambda v: chr(int(v)),
    'chrw'  : lambda v: chr(int(v)),
    'chr$'  : lambda v: chr(int(v)),
    'chrw$' : lambda v: chr(int(v)),
    'asc'   : lambda v: ord(str(v)[0]),
    'ascw'  : lambda v: ord(str(v)[0]),
    'len'   : lambda v: len(str(v)),
    'cint'  : lambda v: int(round(float(v))),
    'clng'  : lambda v: int(round(float(v))),
    'cdbl'  : lambda v: float(v),
    'csng'  : lambda v: float(v),
    'cbool' : lambda v: bool(v),
    'abs'   : lambda v: abs(v),
    'sgn'   : lambda v: (1 if v > 0 else (-1 if v < 0 else 0)),
    'int'   : _cast_to_int,
    'fix'   : lambda v: int(float(v)),
    'hex'   : lambda v: format(int(v), 'X'),
    'hex$'  : lambda v: format(int(v), 'X'),
    'oct'   : lambda v: format(int(v), 'o'),
    'oct$'  : lambda v: format(int(v), 'o'),
    'cbyte' : lambda v: int(v) & 0xFF,
}


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
        for field_name, kind in _classify_fields(type(node)):
            if kind != Kind.ChildList:
                continue
            body = getattr(node, field_name)
            if body and isinstance(body[0], Statement):
                yield body
