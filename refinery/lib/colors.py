"""
Functions to help with ANSI colored terminal text.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, overload

from refinery.lib.patterns import AnsiColor as ac
from refinery.lib.types import buf

if TYPE_CHECKING:
    @overload
    def colored_text_truncate(string: str, end: int) -> str:
        ...

    @overload
    def colored_text_truncate(string: buf, end: int) -> bytes:
        ...

    @overload
    def colored_text_bleach(string: str) -> str:
        ...

    @overload
    def colored_text_bleach(string: buf) -> bytes:
        ...


def colored_text_bleach(string: str | buf):
    """
    Removes all ANSI color code sequences from the input string.
    """
    if isinstance(string, str):
        return ac.str.sub(r'', string)
    else:
        return ac.bin.sub(B'', string)


def colored_text_length(string: str | buf) -> int:
    """
    Compute the display length of text containing ANSI color codes.
    """
    return len(string) - sum(m.end() - m.start() for m in ac.finditer(string))


def colored_text_truncate(string: str | buf, end: int):
    """
    Truncate a colored text string to the given display length.
    """
    length = 0
    cursor = 0
    clipat = end
    for match in ac.finditer(string):
        length = length - cursor + match.start()
        cursor = match.end()
        if length >= end:
            break
        clipat += match.end() - match.start()
    return string[:clipat]
