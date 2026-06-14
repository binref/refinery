from __future__ import annotations

import codecs
import re
import typing

if typing.TYPE_CHECKING:
    from array import array


class batchrange:
    def __init__(self, start: int, step: int, stop: int):
        self.start = start
        self.step = step
        self.stop = stop

    @property
    def infinite(self) -> bool:
        return self.step == 0 and self.start <= self.stop

    def __len__(self):
        if self.step == 0:
            return 0
        return max(0, (self.stop - self.start) // self.step + 1)

    def __iter__(self):
        index = self.start
        step = self.step
        stop = self.stop
        if step < 0:
            while index >= stop:
                yield str(index)
                index += step
        else:
            while index <= stop:
                yield str(index)
                index += step


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
    return re.sub('"(.*?)("|$)', '\\1', token)


def enquote(token: str) -> str:
    if re.search('[\\x20\\t\\v&<>^|]', token):
        token = '"""'.join(token.split('"'))
        token = F'"{token}"'
    return token.replace('%', '%%')


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


def _findstr_class_end(pattern: str, start: int) -> int | None:
    j = start + 1
    if j < len(pattern) and pattern[j] == '^':
        j += 1
    if j < len(pattern) and pattern[j] == ']':
        j += 1
    while j < len(pattern):
        if pattern[j] == ']':
            return j
        j += 1
    return None


def _findstr_class(text: str) -> str:
    inner = text[1:-1]
    negate = ''
    if inner.startswith('^'):
        negate, inner = '^', inner[1:]
    inner = inner.replace('\\', '\\\\').replace(']', '\\]')
    return F'[{negate}{inner}]'


def findstr_to_regex(pattern: str) -> str:
    """
    Translate a single findstr search expression into an equivalent Python regular
    expression. The findstr dialect is limited: the only metacharacters are
    `. * [..] ^ $ \\< \\>` and the backslash escape; everything else, in particular
    `+ ? { } ( ) |`, is matched literally.
    """
    out = []
    i = 0
    size = len(pattern)
    prev_atom = False
    while i < size:
        c = pattern[i]
        if c == '\\':
            nxt = pattern[i + 1:i + 2]
            if nxt in ('<', '>'):
                out.append('\\b')
                prev_atom = False
            elif nxt == '':
                out.append('\\\\')
                prev_atom = True
            elif nxt in '.*[]^$\\':
                out.append(re.escape(nxt))
                prev_atom = True
            else:
                out.append(re.escape(F'\\{nxt}'))
                prev_atom = True
            i += 2
            continue
        if c == '[' and (end := _findstr_class_end(pattern, i)) is not None:
            out.append(_findstr_class(pattern[i:end + 1]))
            prev_atom = True
            i = end + 1
            continue
        if c == '.':
            out.append('.')
            prev_atom = True
        elif c == '*' and prev_atom:
            out.append('*')
            prev_atom = False
        elif c == '^' and i == 0:
            out.append('^')
            prev_atom = False
        elif c == '$' and i == size - 1:
            out.append('$')
            prev_atom = False
        else:
            out.append(re.escape(c))
            prev_atom = True
        i += 1
    return ''.join(out)
