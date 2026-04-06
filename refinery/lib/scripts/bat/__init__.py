"""

## Set Statement

There are two kinds of set statement:
The quoted and the unquoted set.
A quoted set looks like this:

    set "name=var" (...)

It is interpreted as follows:

- Everything between the first and the last quote in the command is extracted.
- The resulting string is split at the first equals symbol.
- The LHS is the variable name.
- The RHS is unescaped once **not** respecting quotes, then becomes the variable content.

Examples:

    > set  "name="a"^^"b"c
    > echo %name%
    "a"^"b

    > set  "name="a"^^"b"c
    > echo %name%
    a"^"b

Note how the trailing c is always discarded because it occurs after the last quote.
The unquoted set looks like this:

    set name=var

It is parsed as follows:

- The entire command is parsed and unescaped respecting quotes as usual.
- The set expression starts with the first non-whitespace character after the set keyword.
- This expression is split at the first equals symbol.
- The LHS is the variable name.
- The RHS is unescaped once respecting quotes, then becomes the variable content.

Input redirection may occur in a set line, basically anywhere:

    > set 1>"NUL" "var=val
    > echo %var%
    val
"""
from __future__ import annotations

from .emulator import BatchEmulator
from .lexer import BatchLexer
from .parser import BatchParser
from .state import BatchState

__all__ = [
    'BatchEmulator',
    'BatchLexer',
    'BatchParser',
    'BatchState',
]
