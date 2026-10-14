"""
The reader for source text the parser could not read: an error node's verbatim line, or an
`Execute` payload this parser refuses. The interpreter may still run such text — a line it
rejects is a fatal error only when it reaches it — so every pass that asks what the text
references reads it here: one lexer pass yields the raw facts, and each consumer applies its own
table to them, because they ask different questions. The facts are raw on purpose: names are
spelled the way AutoIt looks them up — case-folded, without a leading `$` — and no fact here
decides what a name means; which identifier names a channel builtin is the existence census's
table, which spelling a call or a binding reads is the usage model's. The keyword facts — a
declaration, a block keyword — derive from the parser's own kind sets, so the grammar stays their
one home. Every fact points only in a conservative direction — poison, keep, impure. The
parser's record list is not an input to anything here: its texts also live in the tree — an error
node is its own record, and a repair record names a token of a line the parser went on to read —
while the list outlives the edits that remove those lines, so a pass over it would refuse a tree
its own transforms had cleaned.
"""
from __future__ import annotations

import re

from dataclasses import dataclass

from refinery.lib.scripts.au3.lexer import Au3Lexer, decode_au3_string
from refinery.lib.scripts.au3.parser import BLOCK_OPENERS, STRAY_TERMINATORS
from refinery.lib.scripts.au3.token import Au3Token, Au3TokenKind, KEYWORD_SPELLINGS

#: The block keywords whose presence in unread text could shift where the real parser's block
#: boundaries fall, and with it which code is dead at all — the spellings of the parser's own
#: block opener and terminator kinds. The check runs over the raw text, so a string literal
#: holding the word counts too — a superset that only refuses more.
_BLOCK_KEYWORDS = re.compile(
    r'\b(?:'
    + '|'.join(
        KEYWORD_SPELLINGS[kind].lower()
        for kind in BLOCK_OPENERS | STRAY_TERMINATORS
    )
    + r')\b',
    re.IGNORECASE,
)

#: The tokens after which an opening parenthesis calls a computed callee rather than a name.
_COMPUTED_CALLEE_ENDS = frozenset({
    Au3TokenKind.VARIABLE,
    Au3TokenKind.RPAREN,
    Au3TokenKind.RBRACKET,
})

#: The keywords whose `ByRef` positions only a parsed declaration shows.
_DECLARATION_KEYWORDS = frozenset({
    Au3TokenKind.FUNC,
    Au3TokenKind.BYREF,
})


def spelled_name(text: str) -> str:
    """
    The name *text* spells where AutoIt looks a variable, a function, or an option up by a
    string: without a leading `$`, case-folded, and cut at the first NUL. Whether AutoIt reads
    past a NUL there is unpinned; no name holds one, so the cut is the one reading under which
    such a string names anything.
    """
    return text.partition('\0')[0].lstrip('$').lower()


@dataclass(frozen=True)
class Au3UnparsedText:
    """
    What one piece of unread source text spells: the variable and macro names, the bare
    identifiers — each a possible function or builtin call — the decoded string literals, the raw
    directive lines — each load-time source the real interpreter may still honor — whether a call
    opens on a computed callee, whether a function is declared, and whether a block keyword
    appears as a word anywhere in the raw text.
    """

    variables: frozenset[str]
    identifiers: frozenset[str]
    strings: tuple[str, ...]
    directives: tuple[str, ...]
    macros: frozenset[str]
    computed_callee: bool
    declares_function: bool
    block_keyword: bool


def read_unparsed(text: str) -> Au3UnparsedText:
    """
    Read every fact *text* spells in one pass of the lexer.
    """
    variables: set[str] = set()
    identifiers: set[str] = set()
    strings: list[str] = []
    directives: list[str] = []
    macros: set[str] = set()
    computed_callee = False
    declares_function = False
    previous: Au3Token | None = None
    for token in Au3Lexer(source=text).tokenize():
        kind = token.kind
        if kind is Au3TokenKind.VARIABLE:
            variables.add(spelled_name(token.value))
        elif kind is Au3TokenKind.IDENTIFIER:
            identifiers.add(token.value.lower())
        elif kind is Au3TokenKind.STRING:
            strings.append(decode_au3_string(token.value))
        elif kind is Au3TokenKind.DIRECTIVE:
            directives.append(token.value)
        elif kind is Au3TokenKind.MACRO:
            macros.add(token.value[1:].lower())
        elif kind is Au3TokenKind.LPAREN:
            if previous is not None and previous.kind in _COMPUTED_CALLEE_ENDS:
                computed_callee = True
        elif kind in _DECLARATION_KEYWORDS:
            declares_function = True
        previous = token
    return Au3UnparsedText(
        variables=frozenset(variables),
        identifiers=frozenset(identifiers),
        strings=tuple(strings),
        directives=tuple(directives),
        macros=frozenset(macros),
        computed_callee=computed_callee,
        declares_function=declares_function,
        block_keyword=_BLOCK_KEYWORDS.search(text) is not None,
    )
