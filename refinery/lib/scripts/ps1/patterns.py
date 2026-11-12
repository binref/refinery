"""
The wildcard patterns of PowerShell, read the way Windows PowerShell 5.1's `WildcardPattern` reads
them. Every layer that matches a name against a pattern a script spells — the emulator evaluating
`-like`, the listing folds replacing a lookup of the session with the one name it yields, the
world model deciding which takeovers a lookup can see — reads it through this module, so that two
readings of one pattern cannot disagree about what it matches.

The rules, measured on 5.1:

- `*` is any run of characters and `?` is one character.
- A backtick escapes the character behind it, so `` wr`?te `` is the literal name `wr?te` and
  `` w`rite `` is `write`.
- A `[...]` set holds literal characters and `a-z` ranges, and inside it `^`, `[` and `!` are
  literal: `[!x]rite` is the set of `!` and `x` followed by `rite`, not a negation, and matches
  neither `write` nor anything else a session lists.
- An unterminated set (`wr[ite`, `[zz`) or a reversed range is a pattern 5.1 rejects with a
  `WildcardPatternException`.
- A lone `]` is a literal character, but its presence still makes the text a pattern, as does any
  unescaped `*`, `?` or `[`: `Get-Command 'zz]x'` lists nothing and raises nothing, where the
  literal `Get-Command 'zzx'` raises.
"""
from __future__ import annotations

import functools
import re

from typing import NamedTuple

#: The characters whose presence, unescaped, makes a name a wildcard pattern.
_WILDCARD_CHARACTERS = frozenset('*?[]')

_ESCAPE = '`'


class _Token(NamedTuple):
    """
    One unit of a pattern: a run of any characters for `*`, one character of any kind for `?`, or
    one character of `members` — a literal is a set of one character.
    """
    star: bool
    members: str | None
    ranges: tuple[tuple[str, str], ...] = ()

    def admits(self, character: str) -> bool:
        if self.members is None:
            return True
        folded = character.casefold()
        if any(member.casefold() == folded for member in self.members):
            return True
        return any(
            lower <= character <= upper or lower.casefold() <= folded <= upper.casefold()
            for lower, upper in self.ranges
        )


class _MalformedPattern(Exception):
    pass


def _tokens(pattern: str) -> list[_Token]:
    """
    The pattern split into its tokens, or `_MalformedPattern` where 5.1 rejects it.
    """
    tokens: list[_Token] = []
    escaped = False
    inside = False
    opened = False
    members: list[str] = []
    ranges: list[bool] = []
    for character in pattern:
        if inside:
            if character == ']' and not opened and not escaped:
                inside = False
                tokens.append(_set_token(members, ranges))
                members, ranges = [], []
            elif character != _ESCAPE or escaped:
                members.append(character)
                ranges.append(character == '-' and not escaped)
            opened = False
        elif character == '*' and not escaped:
            tokens.append(_Token(True, None))
        elif character == '?' and not escaped:
            tokens.append(_Token(False, None))
        elif character == '[' and not escaped:
            inside = True
            opened = True
            members, ranges = [], []
        elif character != _ESCAPE or escaped:
            tokens.append(_Token(False, character))
        escaped = character == _ESCAPE and not escaped
    if inside:
        raise _MalformedPattern
    if escaped and pattern != _ESCAPE:
        tokens.append(_Token(False, _ESCAPE))
    return tokens


def _set_token(members: list[str], ranges: list[bool]) -> _Token:
    singles: list[str] = []
    spans: list[tuple[str, str]] = []
    index = 0
    count = len(members)
    while index < count:
        if index + 2 < count and ranges[index + 1]:
            lower, upper = members[index], members[index + 2]
            if lower > upper:
                raise _MalformedPattern
            spans.append((lower, upper))
            index += 3
        else:
            singles.append(members[index])
            index += 1
    return _Token(False, ''.join(singles), tuple(spans))


def _token_regex(token: _Token) -> str:
    if token.members is None:
        return '.'
    if not token.ranges and len(token.members) == 1:
        return re.escape(token.members)
    body = ''.join(re.escape(character) for character in token.members)
    body += ''.join(F'{re.escape(lower)}-{re.escape(upper)}' for lower, upper in token.ranges)
    return F'[{body}]'


def _segments(tokens: list[_Token]) -> list[str]:
    """
    The regular expressions of the runs of tokens the stars of a pattern separate, one more than
    there are stars.
    """
    segments: list[list[_Token]] = [[]]
    for token in tokens:
        if token.star:
            segments.append([])
        else:
            segments[-1].append(token)
    return [''.join(_token_regex(token) for token in segment) for segment in segments]


@functools.lru_cache(maxsize=4096)
def wildcard_regex(pattern: str, case_sensitive: bool = False) -> re.Pattern | None:
    """
    The regular expression 5.1 compiles *pattern* to, matched against a whole name and ignoring
    case unless *case_sensitive* asks for the `-clike` reading, or `None` for a pattern 5.1
    rejects. A caller evaluating the pattern raises where this answers `None`; a caller folding a
    lookup refuses.

    Every run between two stars matches a fixed number of characters, so the earliest place it
    matches after the run before it leaves the most room to the runs behind it, and is where the
    expression commits it: the cost of a match is linear in the name for each run. A plain `.*`
    per star retries every split of the name between the stars, which grows with the name to the
    power of their number, and both the patterns and the names come from the script.
    """
    try:
        tokens = _tokens(pattern)
    except _MalformedPattern:
        return None
    head, *rest = _segments(tokens)
    body = head
    if rest:
        *middle, tail = rest
        body += ''.join(F'(?>.*?{segment})' for segment in middle if segment)
        body += F'.*{tail}'
    flags = re.DOTALL | (0 if case_sensitive else re.IGNORECASE)
    return re.compile(F'^{body}\\Z', flags)


def is_wildcard_pattern(text: str) -> bool:
    """
    Whether *text* is read as a pattern rather than as one name: it holds an unescaped `*`, `?`,
    `[` or `]`.
    """
    escaped = False
    for character in text:
        if not escaped and character in _WILDCARD_CHARACTERS:
            return True
        escaped = character == _ESCAPE and not escaped
    return False


def literal_name(text: str) -> str | None:
    """
    The one name *text* denotes when it is no pattern, every escape removed, or `None` for a
    pattern.
    """
    if is_wildcard_pattern(text):
        return None
    tokens = _tokens(text)
    return ''.join(token.members or '' for token in tokens)


def wildcard_may_end_with(pattern: str, suffix: str) -> bool:
    """
    Whether some name *pattern* matches ends in *suffix*, ignoring case: the question a lookup of a
    pattern asks before it may claim that no program on `PATH` is among what it lists, since a
    program is listed under its full file name. Decided exactly over the tokens from the right; a
    pattern 5.1 rejects matches nothing and ends in nothing.
    """
    try:
        tokens = _tokens(pattern)
    except _MalformedPattern:
        return False

    def ends_with(token_count: int, suffix_count: int) -> bool:
        if suffix_count == 0:
            return True
        if token_count == 0:
            return False
        token = tokens[token_count - 1]
        if token.star:
            return True
        if not token.admits(suffix[suffix_count - 1]):
            return False
        return ends_with(token_count - 1, suffix_count - 1)

    return ends_with(len(tokens), len(suffix))
