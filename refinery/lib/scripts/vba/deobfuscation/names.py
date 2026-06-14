"""
VBA name constants, dispatch tables, and builtin evaluation functions used by multiple
deobfuscation transforms.
"""
from __future__ import annotations

import enum
import re

from functools import partial
from typing import Any, Callable, TypeAlias

Value: TypeAlias = str | int | float | bool | None

CHR_NAMES = frozenset({'chr', 'chrw', 'chr$', 'chrw$'})


class CompareMode(enum.Enum):
    """
    The module-level VBA `Option Compare` setting. Values mirror the `vb*Compare` constants:
    `Binary` is case-sensitive, `Text` is case-insensitive, and `Database` (Access) uses the
    database's locale-dependent sort order, which cannot be reproduced statically.
    """
    BINARY = 0
    TEXT = 1
    DATABASE = 2


def str_arg(args: list[Value], index: int = 0) -> str:
    return str(args[index]) if args[index] is not None else ''


def text_compare_safe(value: str) -> bool:
    """
    Return `True` if a case-insensitive comparison of `value` is locale-independent. This holds for
    strings built only from ASCII digits and ASCII letters other than `I` and `i`: the dotted and
    dotless `I` are the one ASCII letter pair whose case folding is locale-dependent (Turkic), and
    any symbol, whitespace, or non-ASCII character can be reweighted or treated as equivalent by a
    locale's collation. Within the safe set, two strings match under `Option Compare Text` in every
    locale exactly when they match case-insensitively.
    """
    for c in value:
        if '0' <= c <= '9':
            continue
        if ('A' <= c <= 'Z' or 'a' <= c <= 'z') and c != 'I' and c != 'i':
            continue
        return False
    return True


def _use_text_compare(args: list[Value], index: int, default: CompareMode) -> bool:
    """
    Resolve whether a builtin call uses case-insensitive (`Text`) comparison. An explicit
    `vbBinaryCompare` (0) or `vbTextCompare` (1) argument at `index` overrides the module `default`.
    Raises `ValueError` to bail out of folding when the effective mode cannot be reproduced
    statically: an explicit `vbDatabaseCompare` (or any other value), or a module `default` of
    `CompareMode.DATABASE`.
    """
    if index < len(args) and args[index] is not None:
        c = int(args[index])
        if c == 0:
            return False
        if c == 1:
            return True
        raise ValueError
    if default is CompareMode.BINARY:
        return False
    if default is CompareMode.TEXT:
        return True
    raise ValueError


def eval_mid(args: list) -> str | None:
    if len(args) not in (2, 3):
        return None
    s = str_arg(args)
    start = int(args[1]) - 1
    if start < 0:
        raise ValueError
    if len(args) == 3:
        length = int(args[2])
        if length < 0:
            raise ValueError
        return s[start:start + length]
    return s[start:]


def eval_left(args: list) -> str | None:
    if len(args) != 2:
        return None
    n = int(args[1])
    if n < 0:
        raise ValueError
    return str_arg(args)[:n]


def eval_right(args: list) -> str | None:
    if len(args) != 2:
        return None
    n = int(args[1])
    if n < 0:
        raise ValueError
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


def eval_replace(args: list[Value], compare_mode: CompareMode = CompareMode.BINARY) -> str | None:
    if not 3 <= len(args) <= 6:
        return None
    haystack = str_arg(args)
    needle = str_arg(args, 1)
    insert = str_arg(args, 2)
    if not needle:
        raise ValueError
    start = int(args[3]) if len(args) > 3 and args[3] is not None else 1
    count = int(args[4]) if len(args) > 4 and args[4] is not None else -1
    use_text = _use_text_compare(args, 5, compare_mode)
    if start < 1 or count < -1:
        raise ValueError
    haystack = haystack[start - 1:]
    if count == 0:
        return haystack
    if use_text:
        if not (text_compare_safe(haystack) and text_compare_safe(needle)):
            raise ValueError
        return re.sub(
            re.escape(needle), lambda _: insert, haystack,
            count=0 if count < 0 else count, flags=re.IGNORECASE,
        )
    if count < 0:
        return haystack.replace(needle, insert)
    return haystack.replace(needle, insert, count)


def eval_instr(args: list[Value], compare_mode: CompareMode = CompareMode.BINARY) -> int | None:
    if len(args) == 2:
        start = 1
        haystack = str_arg(args)
        needle = str_arg(args, 1)
    elif len(args) in (3, 4):
        start = int(args[0])  # type: ignore
        if start < 1:
            raise ValueError
        haystack = str_arg(args, 1)
        needle = str_arg(args, 2)
    else:
        return None
    use_text = _use_text_compare(args, 3, compare_mode)
    if use_text:
        if not (text_compare_safe(haystack) and text_compare_safe(needle)):
            raise ValueError
        idx = haystack.lower().find(needle.lower(), start - 1)
    else:
        idx = haystack.find(needle, start - 1)
    return idx + 1 if idx >= 0 else 0


def eval_instrrev(args: list[Value], compare_mode: CompareMode = CompareMode.BINARY) -> int | None:
    if len(args) not in (2, 3, 4):
        return None
    haystack = str_arg(args)
    needle = str_arg(args, 1)
    end: int | None = None
    if len(args) >= 3 and args[2] is not None:
        end = int(args[2])
        if end < 1:
            raise ValueError
    if _use_text_compare(args, 3, compare_mode):
        if not (text_compare_safe(haystack) and text_compare_safe(needle)):
            raise ValueError
        haystack = haystack.lower()
        needle = needle.lower()
    idx = haystack.rfind(needle) if end is None else haystack.rfind(needle, 0, end)
    return idx + 1 if idx >= 0 else 0


def eval_strcomp(args: list[Value], compare_mode: CompareMode = CompareMode.BINARY) -> int | None:
    if len(args) not in (2, 3):
        return None
    s1 = str_arg(args)
    s2 = str_arg(args, 1)
    if _use_text_compare(args, 2, compare_mode):
        if not (text_compare_safe(s1) and text_compare_safe(s2)):
            raise ValueError
        if s1.lower() != s2.lower():
            raise ValueError
        return 0
    if s1 == s2:
        return 0
    return -1 if s1 < s2 else 1


def eval_str(a: list[Value], then: Callable | None = None) -> Value:
    try:
        value, = a
    except ValueError:
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
}

COMPARE_AWARE_DISPATCH: dict[str, Callable[[list[Value], CompareMode], Value]] = {
    'replace'    : eval_replace,
    'instr'      : eval_instr,
    'instrrev'   : eval_instrrev,
    'strcomp'    : eval_strcomp,
}


def eval_builtin(name: str, args: list[Value], compare_mode: CompareMode = CompareMode.BINARY) -> Value:
    """
    Evaluate a VBA built-in on plain Python values. The name must already be lowercased and
    stripped of a trailing `$`. Returns `None` when the function name is not recognized; raises
    ValueError on domain errors (bad arg count, negative index, etc.). The `compare_mode` flag
    carries the module `Option Compare` mode to the comparison builtins.
    """
    aware = COMPARE_AWARE_DISPATCH.get(name)
    if aware is not None:
        return aware(args, compare_mode)
    handler = BUILTIN_DISPATCH.get(name)
    if handler is None:
        return None
    return handler(args)


STRING_BUILTINS = frozenset(BUILTIN_DISPATCH) | frozenset(COMPARE_AWARE_DISPATCH) | frozenset({'format'})


def dispatch_builtin(name: str, args: list, compare_mode: CompareMode = CompareMode.BINARY) -> tuple[bool, Value]:
    """
    Two-phase dispatch for VBA builtin calls. Tries SINGLE_ARG_BUILTINS with the exact
    lowercased name first, then strips a trailing $ and tries BUILTIN_DISPATCH. Returns
    (matched, result). Does not catch exceptions — callers handle errors differently. The
    `compare_mode` flag carries the module `Option Compare` mode to the comparison builtins.
    """
    handler = SINGLE_ARG_BUILTINS.get(name)
    if handler is not None and len(args) == 1:
        return True, handler(args[0])
    stripped = name.rstrip('$')
    result = eval_builtin(stripped, args, compare_mode)
    if result is not None:
        return True, result
    return False, None


def _cast_to_int(value: Any) -> int:
    as_flt = float(value)
    as_int = int(as_flt)
    if as_flt < 0 and as_flt != int(as_flt):
        as_int -= 1
    return as_int


def _chr_builtin(v):
    return chr(int(v))


def _asc_builtin(v):
    return ord(str(v)[0])


def _round_to_int(v):
    return int(round(float(v)))


def _to_hex(v):
    n = int(v)
    if n < 0:
        raise ValueError
    return format(n, 'X')


def _to_oct(v):
    n = int(v)
    if n < 0:
        raise ValueError
    return format(n, 'o')


def _to_byte(v):
    n = int(round(float(v)))
    if not 0 <= n <= 255:
        raise ValueError
    return n


SINGLE_ARG_BUILTINS: dict[str, Callable[[Any], Value]] = {
    'chr'   : _chr_builtin,
    'chrw'  : _chr_builtin,
    'chr$'  : _chr_builtin,
    'chrw$' : _chr_builtin,
    'asc'   : _asc_builtin,
    'ascw'  : _asc_builtin,
    'cint'  : _round_to_int,
    'clng'  : _round_to_int,
    'cdbl'  : float,
    'csng'  : float,
    'cbool' : bool,
    'abs'   : abs,
    'sgn'   : lambda v: (1 if v > 0 else (-1 if v < 0 else 0)),
    'int'   : _cast_to_int,
    'fix'   : lambda v: int(float(v)),
    'hex'   : _to_hex,
    'hex$'  : _to_hex,
    'oct'   : _to_oct,
    'oct$'  : _to_oct,
    'cbyte' : _to_byte,
}
