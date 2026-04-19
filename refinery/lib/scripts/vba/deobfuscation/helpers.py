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

Value: TypeAlias = str | int | float | bool | None

CHR_NAMES = frozenset({'chr', 'chrw', 'chr$', 'chrw$'})

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


def str_arg(args: list, index: int = 0) -> str:
    return str(args[index]) if args[index] is not None else ''


def eval_mid(args: list) -> str | None:
    if len(args) not in (2, 3):
        return None
    s = str_arg(args)
    start = int(args[1]) - 1
    if start < 0:
        raise ValueError
    if len(args) == 3:
        length = int(args[2])
        return s[start:start + length]
    return s[start:]


def eval_left(args: list) -> str | None:
    if len(args) != 2:
        return None
    return str_arg(args)[:int(args[1])]


def eval_right(args: list) -> str | None:
    if len(args) != 2:
        return None
    n = int(args[1])
    return str_arg(args)[-n:] if n > 0 else ''


def eval_strreverse(args: list) -> str | None:
    if len(args) != 1:
        return None
    return str_arg(args)[::-1]


def eval_string_fn(args: list) -> str | None:
    if len(args) != 2:
        return None
    n = int(args[0])
    c = str_arg(args, 1)
    if not c:
        raise ValueError
    return c[0] * n


def eval_space(args: list) -> str | None:
    if len(args) != 1:
        return None
    n = int(args[0])
    if n < 0 or n > 10000:
        raise ValueError
    return ' ' * n


def eval_replace(args: list) -> str | None:
    if len(args) < 3:
        return None
    haystack = str_arg(args)
    needle = str_arg(args, 1)
    insert = str_arg(args, 2)
    if not needle:
        raise ValueError
    return haystack.replace(needle, insert)


STRING_DISPATCH: dict[str, Callable[[list], str | None]] = {
    'mid'        : eval_mid,
    'left'       : eval_left,
    'right'      : eval_right,
    'strreverse' : eval_strreverse,
    'lcase'      : lambda a: str_arg(a).lower() if len(a) == 1 else None,
    'ucase'      : lambda a: str_arg(a).upper() if len(a) == 1 else None,
    'trim'       : lambda a: str_arg(a).strip() if len(a) == 1 else None,
    'ltrim'      : lambda a: str_arg(a).lstrip() if len(a) == 1 else None,
    'rtrim'      : lambda a: str_arg(a).rstrip() if len(a) == 1 else None,
    'cstr'       : lambda a: str_arg(a) if len(a) == 1 else None,
    'string'     : eval_string_fn,
    'space'      : eval_space,
    'replace'    : eval_replace,
}


def eval_string_builtin(name: str, args: list) -> str | None:
    """
    Evaluate a VBA string built-in on plain Python values. The `name` must already be lowercased
    and stripped of a trailing `$`. Returns `None` when the function name is not recognized; raises
    `ValueError` on domain errors (bad arg count, negative index, etc.).
    """
    handler = STRING_DISPATCH.get(name)
    if handler is None:
        return None
    return handler(args)


STRING_BUILTINS = frozenset(STRING_DISPATCH) | frozenset({'instr'})


def cast_to_int(value):
    as_flt = float(value)
    as_int = int(as_flt)
    if as_flt < 0 and as_flt != int(as_flt):
        as_int -= 1
    return as_int


SINGLE_ARG_BUILTINS: dict[str, Callable[[Any], Value]] = {
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
    'int'   : cast_to_int,
    'fix'   : lambda v: int(float(v)),
    'hex'   : lambda v: format(int(v), 'X'),
    'hex$'  : lambda v: format(int(v), 'X'),
    'oct'   : lambda v: format(int(v), 'o'),
    'oct$'  : lambda v: format(int(v), 'o'),
    'cbyte' : lambda v: int(v) & 0xFF,
}


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


def body_lists(module: VbaModule):
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
