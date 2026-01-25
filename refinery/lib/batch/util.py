from __future__ import annotations

import codecs
import re
import typing

if typing.TYPE_CHECKING:
    from array import array


class batchrange:
    def __init__(self, min: int, inc: int, max: int):
        self.min = min
        self.inc = inc
        self.max = max

    def __iter__(self):
        val = self.min
        inc = self.inc
        max = self.max
        while val <= max:
            yield str(val)
            val += inc


def batchint(expr: str, default: int | None = None):
    m = int(expr.startswith('-'))
    if expr[m:m + 2] in ('0x', '0X'):
        base = 16
    elif expr[m:m + 1] == '0':
        base = 8
    else:
        base = 10
    try:
        return int(expr, base)
    except ValueError:
        if default is None:
            raise
        return default


@typing.overload
def u16(t: str) -> memoryview:
    ...


@typing.overload
def u16(t: memoryview | bytes | bytearray | array) -> str:
    ...


def u16(t):
    if isinstance(t, str):
        return memoryview(codecs.encode(t, 'utf-16le')).cast('H')
    else:
        return codecs.decode(memoryview(t), 'utf-16le')


def unquote(token: str) -> str:
    return re.sub('"(.*?)"', '\\1', token)


def uncaret(token: str, ignore_quotes: bool = False) -> tuple[bool, str]:
    trailing_caret = False
    if ignore_quotes:
        def repl(match: re.Match[str]):
            nonlocal trailing_caret
            if escaped := match[1]:
                return escaped
            trailing_caret = True
            return '^'
        out = re.sub('\\^(.|$)', repl, token)
        return trailing_caret, out
    else:
        parts = re.split('(".*?")', token)
        count = len(parts)
        for k in range(0, count, 2):
            trailing_caret, parts[k] = uncaret(parts[k], True)
        return trailing_caret, ''.join(parts)
