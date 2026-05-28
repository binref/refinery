"""
Functions to help with ANSI colored terminal text.
"""
from __future__ import annotations

from io import StringIO
from unicodedata import combining, east_asian_width

from refinery.lib.patterns import AnsiColor as ac


def unicode_char_width(c: str) -> int:
    if combining(c):
        return 0
    elif east_asian_width(c) in 'WF':
        return 2
    else:
        return 1


def colored_text_bleach(string: str):
    """
    Removes all ANSI color code sequences from the input string.
    """
    return ac.str.sub('', string)


def colored_text_length(string: str) -> int:
    """
    Compute the display length of text containing ANSI color codes.
    """
    if string.isascii():
        n = len(string)
    else:
        n = sum(unicode_char_width(c) for c in string)
    return n - sum(m.end() - m.start() for m in ac.finditer(string))


def colored_text_truncate_ascii(string: str, end: int):
    """
    Truncate a colored text string to the given display length.
    """
    length = 0
    cursor = 0
    clipat = end
    for match in ac.finditer(string):
        a, b = match.span()
        length += a - cursor
        if length >= end:
            break
        cursor = b
        clipat += b - a
    return string[:clipat]


def colored_text_truncate(string: str, end: int) -> str:
    """
    Truncate a colored text string to the given display length, accounting for the display width of
    Unicode characters such as East Asian wide characters.
    """
    if string.isascii():
        return colored_text_truncate_ascii(string, end)

    length = 0
    cursor = 0
    parts = StringIO()

    def consume(segment: str) -> bool:
        nonlocal length
        if segment.isascii():
            remaining = end - length
            if len(segment) <= remaining:
                length += len(segment)
                parts.write(segment)
                return False
            parts.write(segment[:remaining])
            return True
        for k, c in enumerate(segment):
            w = unicode_char_width(c)
            if length + w > end:
                parts.write(segment[:k])
                if length < end:
                    parts.write(' ')
                return True
            length += w
        parts.write(segment)
        return False

    for match in ac.finditer(string):
        a, b = match.span()
        if consume(string[cursor:a]):
            return parts.getvalue()
        parts.write(match.group())
        cursor = b

    consume(string[cursor:])
    return parts.getvalue()
