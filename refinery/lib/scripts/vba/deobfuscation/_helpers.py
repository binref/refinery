"""
Shared utilities for VBA deobfuscation transforms.
"""
from __future__ import annotations

import copy

from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from typing import TypeAlias

from refinery.lib.scripts import Expression, Kind, Node, Statement, _classify_fields
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
    if isinstance(node, VbaStringLiteral):
        return node.value
    if isinstance(node, VbaIntegerLiteral):
        return node.value
    if isinstance(node, VbaFloatLiteral):
        return node.value
    if isinstance(node, VbaBooleanLiteral):
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


def _eval_string_builtin(name: str, args: list) -> str | None:
    """
    Evaluate a VBA string built-in on plain Python values. The `name` must already be lowercased
    and stripped of a trailing `$`. Returns `None` when the function name is not recognized; raises
    `ValueError` on domain errors (bad arg count, negative index, etc.).
    """
    if name == 'mid' and len(args) in (2, 3):
        s = str(args[0]) if args[0] is not None else ''
        start = int(args[1]) - 1
        if start < 0:
            raise ValueError
        if len(args) == 3:
            length = int(args[2])
            return s[start:start + length]
        return s[start:]
    if name == 'left' and len(args) == 2:
        s = str(args[0]) if args[0] is not None else ''
        n = int(args[1])
        return s[:n]
    if name == 'right' and len(args) == 2:
        s = str(args[0]) if args[0] is not None else ''
        n = int(args[1])
        return s[-n:] if n > 0 else ''
    if name == 'strreverse' and len(args) == 1:
        return str(args[0])[::-1] if args[0] is not None else ''
    if name == 'lcase' and len(args) == 1:
        return str(args[0]).lower() if args[0] is not None else ''
    if name == 'ucase' and len(args) == 1:
        return str(args[0]).upper() if args[0] is not None else ''
    if name == 'trim' and len(args) == 1:
        return str(args[0]).strip() if args[0] is not None else ''
    if name == 'ltrim' and len(args) == 1:
        return str(args[0]).lstrip() if args[0] is not None else ''
    if name == 'rtrim' and len(args) == 1:
        return str(args[0]).rstrip() if args[0] is not None else ''
    if name == 'cstr' and len(args) == 1:
        return str(args[0]) if args[0] is not None else ''
    if name == 'string' and len(args) == 2:
        n = int(args[0])
        c = str(args[1]) if args[1] is not None else ''
        if not c:
            raise ValueError
        return c[0] * n
    if name == 'space' and len(args) == 1:
        n = int(args[0])
        if n < 0 or n > 10000:
            raise ValueError
        return ' ' * n
    if name == 'replace' and len(args) >= 3:
        haystack = str(args[0]) if args[0] is not None else ''
        needle = str(args[1]) if args[1] is not None else ''
        insert = str(args[2]) if args[2] is not None else ''
        if not needle:
            raise ValueError
        return haystack.replace(needle, insert)
    return None


_STRING_BUILTINS = frozenset({
    'cstr',
    'instr',
    'lcase',
    'left',
    'ltrim',
    'mid',
    'replace',
    'right',
    'rtrim',
    'space',
    'string',
    'strreverse',
    'trim',
    'ucase',
})


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


def _clone_expression(node: Node) -> Node:
    """
    Deep-clone an expression tree downward without following parent pointers.
    """
    clone = copy.copy(node)
    clone.parent = None
    for field_name, kind in _classify_fields(type(node)):
        if kind == Kind.ChildNode:
            value = getattr(node, field_name)
            if isinstance(value, Node):
                child = _clone_expression(value)
                child.parent = clone
                setattr(clone, field_name, child)
        elif kind == Kind.ChildList:
            items = getattr(node, field_name)
            cloned = []
            for item in items:
                if isinstance(item, Node):
                    child = _clone_expression(item)
                    child.parent = clone
                    cloned.append(child)
                else:
                    cloned.append(item)
            setattr(clone, field_name, cloned)
        elif kind == Kind.TupleList:
            items = getattr(node, field_name)
            cloned = []
            for tup in items:
                new_tup = []
                for elem in tup:
                    if isinstance(elem, Node):
                        child = _clone_expression(elem)
                        child.parent = clone
                        new_tup.append(child)
                    else:
                        new_tup.append(elem)
                cloned.append(tuple(new_tup))
            setattr(clone, field_name, cloned)
    return clone
