"""
VBA name constants, dispatch tables, and string-only evaluation functions used by multiple
deobfuscation transforms.
"""
from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

if TYPE_CHECKING:
    from typing import TypeAlias

Value: TypeAlias = Optional[Union[str, int, float, bool]]

CHR_NAMES = frozenset({'chr', 'chrw', 'chr$', 'chrw$'})


def str_arg(args: list[Value], index: int = 0) -> str:
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


def eval_strreverse(args: list[Value]) -> str | None:
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


def eval_replace(args: list[Value]) -> str | None:
    if len(args) < 3:
        return None
    haystack = str_arg(args)
    needle = str_arg(args, 1)
    insert = str_arg(args, 2)
    if not needle:
        raise ValueError
    return haystack.replace(needle, insert)


def _stringop(a: list[Value], op: Callable[[str], str] | None = None):
    try:
        value, = a
    except Exception:
        return None
    else:
        value = str(value)
    if op is not None:
        value = op(value)
    return value


STRING_DISPATCH: dict[str, Callable[[list[Value]], str | None]] = {
    'mid'        : eval_mid,
    'left'       : eval_left,
    'right'      : eval_right,
    'strreverse' : eval_strreverse,
    'lcase'      : partial(_stringop, op=str.lower),
    'ucase'      : partial(_stringop, op=str.upper),
    'trim'       : partial(_stringop, op=str.strip),
    'ltrim'      : partial(_stringop, op=str.lstrip),
    'rtrim'      : partial(_stringop, op=str.rstrip),
    'cstr'       : _stringop,
    'string'     : eval_string_fn,
    'space'      : eval_space,
    'replace'    : eval_replace,
}


def eval_string_builtin(name: str, args: list[Value]) -> str | None:
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


def _cast_to_int(value: Any) -> int:
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
    'int'   : _cast_to_int,
    'fix'   : lambda v: int(float(v)),
    'hex'   : lambda v: format(int(v), 'X'),
    'hex$'  : lambda v: format(int(v), 'X'),
    'oct'   : lambda v: format(int(v), 'o'),
    'oct$'  : lambda v: format(int(v), 'o'),
    'cbyte' : lambda v: int(v) & 0xFF,
}
