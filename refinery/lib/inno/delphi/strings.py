"""
The functions of Delphi's `SysUtils` that trim texts, as Pascal Script calls them for a script and
Setup calls them for its own texts.
"""
from __future__ import annotations


def _start(text: str) -> int:
    start = 0
    while start < len(text) and text[start] <= ' ':
        start += 1
    return start


def _end(text: str, start: int = 0) -> int:
    end = len(text)
    while end > start and text[end - 1] <= ' ':
        end -= 1
    return end


def trim(text: str) -> str:
    """
    Delphi's `Trim`: removes every character up to the space from both ends.
    """
    start = _start(text)
    return text[start:_end(text, start)]


def trim_left(text: str) -> str:
    """
    Delphi's `TrimLeft`: removes every character up to the space from the start.
    """
    return text[_start(text):]


def trim_right(text: str) -> str:
    """
    Delphi's `TrimRight`: removes every character up to the space from the end.
    """
    return text[:_end(text)]
