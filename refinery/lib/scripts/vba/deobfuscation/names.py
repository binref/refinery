"""
VBA name constants, dispatch tables, and builtin evaluation functions used by multiple
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


def eval_instr(args: list[Value]) -> int | None:
    if len(args) == 2:
        haystack = str_arg(args)
        needle = str_arg(args, 1)
        idx = haystack.find(needle)
        return idx + 1 if idx >= 0 else 0
    if len(args) == 3:
        start = int(args[0])  # type: ignore
        if start < 1:
            raise ValueError
        haystack = str_arg(args, 1)
        needle = str_arg(args, 2)
        idx = haystack.find(needle, start - 1)
        return idx + 1 if idx >= 0 else 0
    return None


def eval_instrrev(args: list[Value]) -> int | None:
    if len(args) == 2:
        haystack = str_arg(args)
        needle = str_arg(args, 1)
        idx = haystack.rfind(needle)
        return idx + 1 if idx >= 0 else 0
    if len(args) == 3:
        haystack = str_arg(args)
        needle = str_arg(args, 1)
        start = int(args[2])  # type: ignore
        if start < 1:
            raise ValueError
        idx = haystack.rfind(needle, 0, start)
        return idx + 1 if idx >= 0 else 0
    return None


def eval_strcomp(args: list[Value]) -> int | None:
    if len(args) not in (2, 3):
        return None
    s1 = str_arg(args)
    s2 = str_arg(args, 1)
    if len(args) == 3 and int(args[2]) == 1:  # type: ignore
        s1 = s1.lower()
        s2 = s2.lower()
    if s1 == s2:
        return 0
    return -1 if s1 < s2 else 1


def eval_str(a: list[Value], then: Callable | None = None) -> Value:
    try:
        value, = a
    except Exception:
        return None
    else:
        value = str(value)
    if then is not None:
        value = then(value)
    return value


BUILTIN_DISPATCH: dict[str, Callable[[list[Value]], Value]] = {
    'mid'        : eval_mid,
    'left'       : eval_left,
    'right'      : eval_right,
    'cstr'       : eval_str,
    'strreverse' : eval_strreverse,
    'lcase'      : partial(eval_str, then=str.lower),
    'ucase'      : partial(eval_str, then=str.upper),
    'trim'       : partial(eval_str, then=str.strip),
    'ltrim'      : partial(eval_str, then=str.lstrip),
    'rtrim'      : partial(eval_str, then=str.rstrip),
    'len'        : partial(eval_str, then=len),
    'string'     : eval_string_fn,
    'space'      : eval_space,
    'replace'    : eval_replace,
    'instr'      : eval_instr,
    'instrrev'   : eval_instrrev,
    'strcomp'    : eval_strcomp,
}


def eval_builtin(name: str, args: list[Value]) -> Value:
    """
    Evaluate a VBA built-in on plain Python values. The name must already be lowercased and
    stripped of a trailing $. Returns None when the function name is not recognized; raises
    ValueError on domain errors (bad arg count, negative index, etc.).
    """
    handler = BUILTIN_DISPATCH.get(name)
    if handler is None:
        return None
    return handler(args)


STRING_BUILTINS = frozenset(BUILTIN_DISPATCH) | frozenset({'format'})


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
