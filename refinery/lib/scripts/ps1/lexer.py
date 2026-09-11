from __future__ import annotations

import enum
import re

from dataclasses import dataclass
from typing import Generator

from refinery.lib.scripts.ps1.token import (
    _KEYWORDS,
    _VARIABLE_PATTERN_CORE,
    DASHES,
    DOUBLE_QUOTES,
    SINGLE_QUOTES,
    Ps1Token,
    Ps1TokenKind,
    forces_new_token,
    forces_new_token_after_number,
    is_whitespace,
)


class Ps1LexerMode(enum.Enum):
    EXPRESSION = 'expression'
    ARGUMENT = 'argument'


_TWO_CHAR_OPS: dict[str, Ps1TokenKind] = {
    '+=' : Ps1TokenKind.PLUS_ASSIGN,
    '-=' : Ps1TokenKind.DASH_ASSIGN,
    '*=' : Ps1TokenKind.STAR_ASSIGN,
    '/=' : Ps1TokenKind.SLASH_ASSIGN,
    '%=' : Ps1TokenKind.PERCENT_ASSIGN,
    '++' : Ps1TokenKind.INCREMENT,
    '--' : Ps1TokenKind.DECREMENT,
    '..' : Ps1TokenKind.DOTDOT,
    '::' : Ps1TokenKind.DOUBLE_COLON,
    '&&' : Ps1TokenKind.DOUBLE_AMPERSAND,
    '||' : Ps1TokenKind.DOUBLE_PIPE,
    '@(' : Ps1TokenKind.AT_LPAREN,
    '@{' : Ps1TokenKind.AT_LBRACE,
    '$(' : Ps1TokenKind.DOLLAR_LPAREN,
}

_ONE_CHAR_OPS: dict[str, Ps1TokenKind] = {
    '+' : Ps1TokenKind.PLUS,
    '-' : Ps1TokenKind.DASH,
    '*' : Ps1TokenKind.STAR,
    '/' : Ps1TokenKind.SLASH,
    '%' : Ps1TokenKind.PERCENT,
    '.' : Ps1TokenKind.DOT,
    ',' : Ps1TokenKind.COMMA,
    ';' : Ps1TokenKind.SEMICOLON,
    '!' : Ps1TokenKind.EXCLAIM,
    '(' : Ps1TokenKind.LPAREN,
    ')' : Ps1TokenKind.RPAREN,
    '{' : Ps1TokenKind.LBRACE,
    '}' : Ps1TokenKind.RBRACE,
    '[' : Ps1TokenKind.LBRACKET,
    ']' : Ps1TokenKind.RBRACKET,
    '|' : Ps1TokenKind.PIPE,
    '&' : Ps1TokenKind.AMPERSAND,
    '=' : Ps1TokenKind.EQUALS,
    '<' : Ps1TokenKind.REDIRECT_IN,
}

_DASH_OPERATORS: dict[str, str] = {
    _name: F'-{_name}' for _name in (
        'and',
        'as',
        'band',
        'bnot',
        'bor',
        'bxor',
        'ccontains',
        'ceq',
        'cge',
        'cgt',
        'cin',
        'cle',
        'clike',
        'clt',
        'cmatch',
        'cne',
        'cnotcontains',
        'cnotin',
        'cnotlike',
        'cnotmatch',
        'contains',
        'creplace',
        'csplit',
        'eq',
        'f',
        'ge',
        'gt',
        'icontains',
        'ieq',
        'ige',
        'igt',
        'iin',
        'ile',
        'ilike',
        'ilt',
        'imatch',
        'in',
        'ine',
        'inotcontains',
        'inotin',
        'inotlike',
        'inotmatch',
        'ireplace',
        'is',
        'isnot',
        'isplit',
        'join',
        'le',
        'like',
        'lt',
        'match',
        'ne',
        'not',
        'notcontains',
        'notin',
        'notlike',
        'notmatch',
        'or',
        'replace',
        'shl',
        'shr',
        'split',
        'xor',
    )
}

_VARIABLE_STOPS_NO_RESCAN = frozenset('.[=')

_MEMBER_ACCESS_KINDS: dict[str, Ps1TokenKind] = {
    '.'  : Ps1TokenKind.DOT,
    '::' : Ps1TokenKind.DOUBLE_COLON,
    '['  : Ps1TokenKind.LBRACKET,
}

_REDIRECTION_PATTERN = re.compile(
    r'[1-6*](?:>>|>&[12]|>)'  # explicit stream: 2>&1, 2>>, 2>
    r'|>>|>&1|>',             # bare: >>, >&1, >
)

_DECIMAL_DIGITS = frozenset('0123456789')
_HEX_DIGITS = frozenset('0123456789abcdefABCDEF')
_HEX_MARKER = frozenset('xX')
_EXPONENT_MARKER = frozenset('eE')

#: The letters that name the type a numeral is read as. There are exactly two on 5.1 — an Int64 and
#: a Decimal — which is why every other width has to be spelled with a cast. The rest of the set
#: (`y`, `uy`, `s`, `us`, `u`, `ul`) arrived in 6.2 and `n` in 7.0, and none of them may be read
#: here: `1uy` is the word `1uy` on 5.1, not the byte one.
_TYPE_SUFFIX = frozenset('lLdD')
_DECIMAL_SUFFIX = frozenset('dD')

#: The letters that begin a binary multiplier. Each is a prefix and not the whole of one: the `b`
#: behind it is required, so `1kb` is a number where `1k` is a word.
_MULTIPLIER_START = frozenset('kKmMgGtTpP')
_MULTIPLIER_END = frozenset('bB')

_VARIABLE_PATTERN = re.compile(_VARIABLE_PATTERN_CORE, re.IGNORECASE)

_DASH_WORD = re.compile(r'[a-zA-Z]+')

_PARAMETER_TERMINATORS = frozenset(' \t\r\n{}();,|&.[')

_VARIABLE_START_CHARS = '_?{$^'


@dataclass
class Ps1Lexer:
    source: str
    pos: int = 0
    mode: Ps1LexerMode = Ps1LexerMode.ARGUMENT

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _peek(self, ahead: int = 0) -> str:
        """
        The character `ahead` positions past `Ps1Lexer.pos`, or the empty string where the source
        has ended. Every rule that asks what comes next has to answer for the end of the source
        too, and this is the one place that answer is given: the character classes in
        `refinery.lib.scripts.ps1.token` read the empty string as the end and judge it accordingly.
        """
        return self.source[self.pos + ahead:self.pos + ahead + 1]

    def _skip_whitespace(self) -> bool:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length:
            c = src[self.pos]
            if is_whitespace(c):
                self.pos += 1
            elif c == '`' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                self.pos += 2
            elif c == '`' and self.pos + 2 < length and src[self.pos + 1:self.pos + 3] == '\r\n':
                self.pos += 3
            else:
                break
        return self.pos > start

    def _read_line_comment(self) -> None:
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] != '\n':
            self.pos += 1

    def _read_block_comment(self) -> None:
        src = self.source
        length = len(src)
        self.pos += 2
        while self.pos < length - 1:
            if src[self.pos] == '#' and src[self.pos + 1] == '>':
                self.pos += 2
                return
            self.pos += 1
        self.pos = length

    def _try_skip_expandable(self) -> bool:
        src = self.source
        length = len(src)
        c = src[self.pos]
        if c == '`' and self.pos + 1 < length:
            self.pos += 2
            return True
        if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '(':
            self.pos += 2
            self._skip_subexpression_content()
            return True
        return False

    def _read_string(self, quote_set: frozenset[str], expandable: bool = False) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if expandable and self._try_skip_expandable():
                continue
            if c in quote_set:
                self.pos += 1
                if self.pos < length and src[self.pos] in quote_set:
                    self.pos += 1
                    continue
                return src[start:self.pos]
            self.pos += 1
        return src[start:self.pos]

    def _skip_subexpression_content(self):
        src = self.source
        length = len(src)
        depth = 1
        while self.pos < length:
            c = src[self.pos]
            if c == '`' and self.pos + 1 < length:
                self.pos += 2
                continue
            if c == '(':
                depth += 1
                self.pos += 1
                continue
            if c == ')':
                depth -= 1
                self.pos += 1
                if depth == 0:
                    return
                continue
            if c == '@' and self.pos + 1 < length:
                nc = src[self.pos + 1]
                if self.pos + 2 < length and src[self.pos + 2] in '\r\n':
                    if nc in SINGLE_QUOTES:
                        self._read_here_string(SINGLE_QUOTES)
                        continue
                    if nc in DOUBLE_QUOTES:
                        self._read_here_string(DOUBLE_QUOTES, expandable=True)
                        continue
            if c in SINGLE_QUOTES:
                self._read_string(SINGLE_QUOTES)
                continue
            if c in DOUBLE_QUOTES:
                self._read_string(DOUBLE_QUOTES, expandable=True)
                continue
            self.pos += 1

    def _skip_here_string_header(self):
        src = self.source
        length = len(src)
        self.pos += 2
        if self.pos < length and src[self.pos] == '\r':
            self.pos += 1
        if self.pos < length and src[self.pos] == '\n':
            self.pos += 1

    def _check_here_string_terminator(self, quote_set: frozenset[str]) -> bool:
        src = self.source
        length = len(src)
        if src[self.pos] == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
            nl_end = self.pos + 2
        else:
            nl_end = self.pos + 1
        if nl_end + 1 < length and src[nl_end] in quote_set and src[nl_end + 1] == '@':
            self.pos = nl_end + 2
            return True
        return False

    def _read_here_string(self, quote_set: frozenset[str], expandable: bool = False) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self._skip_here_string_header()
        while self.pos < length:
            c = src[self.pos]
            if c in '\r\n':
                if self._check_here_string_terminator(quote_set):
                    return src[start:self.pos]
            if expandable and self._try_skip_expandable():
                continue
            self.pos += 1
        return src[start:self.pos]

    def _read_variable(self, prefix: str) -> Ps1Token:
        start = self.pos
        self.pos += len(prefix)
        m = _VARIABLE_PATTERN.match(self.source, self.pos)
        if m:
            self.pos = m.end()
        kind = Ps1TokenKind.SPLAT_VARIABLE if prefix == '@' else Ps1TokenKind.VARIABLE
        return Ps1Token(kind, self.source[start:self.pos], start)

    def _read_digits(self, digits: frozenset[str]) -> int:
        start = self.pos
        while self._peek() in digits:
            self.pos += 1
        return self.pos - start

    def _read_exponent(self) -> bool:
        """
        Read the power an `e` was written for, and say whether one was there. A sign may stand
        between the two, and digits must: `1e3` is a thousand and `1e` is the word `1e`.
        """
        if self._peek() in ('+', '-'):
            self.pos += 1
        return self._read_digits(_DECIMAL_DIGITS) > 0

    def _read_fraction(self) -> bool:
        """
        Read what follows a numeral's dot: the digits after it, and the power they may be raised to.
        No digit is required — `1.` is the number one and `1.e1` is ten — because the dot has
        already settled that a numeral is being read.
        """
        self._read_digits(_DECIMAL_DIGITS)
        if self._peek() not in _EXPONENT_MARKER:
            return True
        self.pos += 1
        return self._read_exponent()

    def _read_number(self) -> Ps1Token | None:
        """
        The numeral written at `Ps1Lexer.pos`, or `None` where what stands there only looks like one.

        The parts come in 5.1's order and are not alternatives: a base, then a fraction or a power,
        then a type suffix, then a multiplier. Reading a suffix *or* a multiplier loses `1dkb`, a
        Decimal kilobyte, and `1.5L`, an Int64. A trailing dot belongs to the numeral — `3.` is
        three, given back only to the range operator so `3..5` counts from three — but a dot after a
        power does not, so `1e3` ends where the dot begins and 5.1 reads what follows as a member.

        Three spellings return `None` because the numeral itself cannot be one: `0x` names no digits,
        `1e` raises nothing to a power, and a multiplier with no `b` behind it is part of the word
        around it, so `1k` is a word where `1kb` is a number.

        The reported kind is which literal the parser builds, not what the numeral is worth: `1kb` is
        a real to spell and an `Int32` to read, which `refinery.lib.scripts.ps1.analysis.values.read`
        decides.
        """
        start = self.pos
        real = False
        if self._peek() == '.':
            self.pos += 1
            if not self._read_fraction():
                self.pos = start
                return None
            real = True
        elif self._peek() == '0' and self._peek(1) in _HEX_MARKER:
            self.pos += 2
            if not self._read_digits(_HEX_DIGITS):
                self.pos = start
                return None
        else:
            self._read_digits(_DECIMAL_DIGITS)
            if self._peek() == '.' and self._peek(1) != '.':
                self.pos += 1
                if not self._read_fraction():
                    self.pos = start
                    return None
                real = True
            elif self._peek() in _EXPONENT_MARKER:
                self.pos += 1
                if not self._read_exponent():
                    self.pos = start
                    return None
                real = True
        suffix = self._peek()
        if suffix in _TYPE_SUFFIX:
            self.pos += 1
            real = real or suffix in _DECIMAL_SUFFIX
        if self._peek() in _MULTIPLIER_START:
            self.pos += 1
            if self._peek() not in _MULTIPLIER_END:
                self.pos = start
                return None
            self.pos += 1
            real = True
        kind = Ps1TokenKind.REAL if real else Ps1TokenKind.INTEGER
        return Ps1Token(kind, self.source[start:self.pos], start)

    def _numeral_ends_here(self) -> bool:
        """
        Whether the numeral just read really ends where it stopped. Which characters can end one
        depends on the slot: where an expression is read a numeral ends on an operator too, so `1+2`
        is three tokens, and where a bare word is a value only a token terminator will do, so `f 1+2`
        passes the single word `1+2`.
        """
        c = self._peek()
        if forces_new_token(c):
            return True
        return self.mode is Ps1LexerMode.EXPRESSION and forces_new_token_after_number(c)

    def _try_dash_operator(self) -> Ps1Token | None:
        src = self.source
        start = self.pos
        self.pos += 1
        m = _DASH_WORD.match(src, self.pos)
        if not m:
            self.pos = start
            return None
        word = m.group().lower()
        if word in _DASH_OPERATORS:
            self.pos = m.end()
            return Ps1Token(Ps1TokenKind.OPERATOR, _DASH_OPERATORS[word], start)
        self.pos = start
        return None

    def _try_parameter(self) -> Ps1Token | None:
        src = self.source
        length = len(src)
        start = self.pos
        self.pos += 1
        if self.pos >= length:
            self.pos = start
            return None
        c = src[self.pos]
        if not (c.isalpha() or c == '_' or c == '?'):
            self.pos = start
            return None
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c in _PARAMETER_TERMINATORS or c.isspace():
                break
            if c in SINGLE_QUOTES or c in DOUBLE_QUOTES:
                self.pos = start
                return self._read_generic_token()
            if c == ':':
                self.pos += 1
                break
            self.pos += 1
        return Ps1Token(Ps1TokenKind.PARAMETER, src[start:self.pos], start)

    def _read_argument_dash(self) -> Ps1Token:
        """
        The token a dash begins in argument mode. A dash touching a letter, `_` or `?` names a
        parameter; a dash touching anything else is part of the word around it, so `f -1` passes the
        string `-1` rather than the number, and `f -` passes the word `-`.

        No binder is consulted: 5.1 lets a sign join a numeral only where its expression rule asked
        for one, which it never does for an argument, so the dash falls to the same generic scan
        every other unrecognized character does.
        """
        return self._try_parameter() or self._read_generic_token()

    def _try_redirection(self) -> Ps1Token | None:
        m = _REDIRECTION_PATTERN.match(self.source, self.pos)
        if m:
            start = self.pos
            self.pos = m.end()
            return Ps1Token(Ps1TokenKind.REDIRECTION, m.group(), start)
        return None

    def _read_identifier(self) -> Ps1Token:
        src = self.source
        length = len(src)
        start = self.pos
        c = src[self.pos]
        if c == '`' and self.pos + 1 < length:
            self.pos += 2
        else:
            self.pos += 1
        while self.pos < length:
            ch = src[self.pos]
            if ch == '`' and self.pos + 1 < length:
                self.pos += 2
            elif ch.isalnum() or ch == '_':
                self.pos += 1
            elif ch in DASHES and self.mode != Ps1LexerMode.EXPRESSION:
                self.pos += 1
            else:
                break
        return Ps1Token(Ps1TokenKind.GENERIC_TOKEN, src[start:self.pos], start)

    def _read_generic_token(self) -> Ps1Token:
        start = self.pos
        src = self.source
        length = len(src)
        has_expansion = False
        while self.pos < length:
            c = src[self.pos]
            if c == '`' and self.pos + 1 < length:
                self.pos += 2
                continue
            if c in SINGLE_QUOTES:
                self._read_string(SINGLE_QUOTES)
                continue
            if c in DOUBLE_QUOTES:
                self._read_string(DOUBLE_QUOTES, expandable=True)
                continue
            if c == '$' and self.pos + 1 < length:
                nc = src[self.pos + 1]
                if nc == '(':
                    has_expansion = True
                    self.pos += 2
                    self._skip_subexpression_content()
                    continue
                if nc.isalnum() or nc in _VARIABLE_START_CHARS:
                    m = _VARIABLE_PATTERN.match(src, self.pos + 1)
                    if m:
                        has_expansion = True
                        self.pos = m.end()
                        continue
                self.pos += 1
                continue
            if forces_new_token(c):
                break
            self.pos += 1
        kind = Ps1TokenKind.GENERIC_EXPAND if has_expansion else Ps1TokenKind.GENERIC_TOKEN
        return Ps1Token(kind, src[start:self.pos], start)

    def scan_member_access(self) -> Ps1Token | None:
        """
        The member access operator written at `Ps1Lexer.pos`, or `None` where none is. A reader that
        has just taken a value asks this instead of asking for a token, because one character has two
        answers: a `.` before a digit begins a number where a value may start and names a member
        where one has just ended, so `$x.5` reads the property `5` and `$x = .5` reads a half.

        Whether anything binds here at all is the caller's question: nothing is passed over, so an
        operator that does not touch what precedes it is simply read at the wrong position.

        Two spellings are refused rather than read. A second dot is the range operator, so `1..5`
        counts from one rather than reading a member of it. And where a bare word is a value, an
        access with nothing behind it belongs to the word: `f $x.` passes `$x.` and asks for no
        member.
        """
        spelling = self._member_access_spelling()
        if spelling is None:
            return None
        offset = self.pos
        self.pos += len(spelling)
        if spelling != '[' and self.mode is Ps1LexerMode.ARGUMENT and self._nothing_to_reach():
            self.pos = offset
            return None
        return Ps1Token(_MEMBER_ACCESS_KINDS[spelling], spelling, offset)

    def _nothing_to_reach(self) -> bool:
        """
        Whether the source at `Ps1Lexer.pos` holds nothing an access could reach. A line ends the
        statement rather than the token, so it is named here beside the whitespace and the end of
        the source that `forces_new_token` already answers for.
        """
        c = self._peek()
        return not c or c in '\r\n' or is_whitespace(c)

    def _member_access_spelling(self) -> str | None:
        if self._peek() == '[':
            return '['
        if self._peek() == ':' and self._peek(1) == ':':
            return '::'
        if self._peek() == '.' and self._peek(1) != '.':
            return '.'
        return None

    def _keyword_or_token(self, token: Ps1Token) -> Ps1Token:
        kw = _KEYWORDS.get(token.value.lower())
        if kw is None:
            return token
        return Ps1Token(kw, token.value, token.offset)

    def tokenize(self) -> Generator[Ps1Token, None, None]:
        while True:
            token = self.scan()
            yield token
            if token.kind == Ps1TokenKind.EOF:
                return

    def scan(self) -> Ps1Token:
        """
        Read one token at `Ps1Lexer.pos` in the current `Ps1Lexer.mode` and advance past it. The
        result depends on nothing but the source, the position and the mode, so restoring a position
        and scanning again re-reads the same text faithfully. That is what allows a caller to hold a
        single token of lookahead and discard it when the mode changes.
        """
        src = self.source
        length = len(src)

        while True:
            self._skip_whitespace()
            if self._at_end():
                return Ps1Token(Ps1TokenKind.EOF, '', self.pos)

            start = self.pos
            c = src[self.pos]

            if c == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                self.pos += 2
                return Ps1Token(Ps1TokenKind.NEWLINE, '\r\n', start)
            if c == '\n':
                self.pos += 1
                return Ps1Token(Ps1TokenKind.NEWLINE, '\n', start)

            c2 = src[self.pos:self.pos + 2]
            if len(c2) == 2:
                d0 = '-' if c2[0] in DASHES else c2[0]
                d1 = '-' if c2[1] in DASHES else c2[1]
                c2 = d0 + d1

            if c2 == '<#':
                self._read_block_comment()
                continue
            if c == '#':
                self._read_line_comment()
                continue

            if c == '@' and self.pos + 1 < length:
                nc = src[self.pos + 1]
                if nc in SINGLE_QUOTES:
                    text = self._read_here_string(SINGLE_QUOTES)
                    return Ps1Token(Ps1TokenKind.HSTRING_VERBATIM, text, start)
                if nc in DOUBLE_QUOTES:
                    text = self._read_here_string(DOUBLE_QUOTES, expandable=True)
                    return Ps1Token(Ps1TokenKind.HSTRING_EXPAND, text, start)

            if c2 in ('..', '--', '++', '::', '+=', '-=', '*=', '/=', '%=') and self.mode == Ps1LexerMode.ARGUMENT:
                if not forces_new_token(self._peek(2)):
                    token = self._read_generic_token()
                    if token.value:
                        return token

            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                kind = _TWO_CHAR_OPS[c2]
                return Ps1Token(kind, c2, start)

            if c == ':' and self.pos + 1 < length and (src[self.pos + 1].isalpha() or src[self.pos + 1] == '_'):
                self.pos += 1
                while self.pos < length and (src[self.pos].isalnum() or src[self.pos] == '_'):
                    self.pos += 1
                return Ps1Token(Ps1TokenKind.LABEL, src[start:self.pos], start)

            if c == '$' or (c == '@' and self.pos + 1 < length and src[self.pos + 1] not in '({'):
                nc = src[self.pos + 1] if self.pos + 1 < length else ''
                if nc and (nc.isalnum() or nc in _VARIABLE_START_CHARS):
                    token = self._read_variable(c)
                    if self.mode == Ps1LexerMode.ARGUMENT:
                        fc = self._peek()
                        if not forces_new_token(fc) and fc not in _VARIABLE_STOPS_NO_RESCAN:
                            self.pos = start
                            token = self._read_generic_token()
                    return token

            if c in SINGLE_QUOTES:
                text = self._read_string(SINGLE_QUOTES)
                return Ps1Token(Ps1TokenKind.STRING_VERBATIM, text, start)
            if c in DOUBLE_QUOTES:
                text = self._read_string(DOUBLE_QUOTES, expandable=True)
                return Ps1Token(Ps1TokenKind.STRING_EXPAND, text, start)

            if c in '123456' and self.pos + 1 < length and src[self.pos + 1] == '>':
                if self.mode == Ps1LexerMode.ARGUMENT:
                    redir = self._try_redirection()
                    if redir:
                        return redir

            if c in _DECIMAL_DIGITS or (c == '.' and self._peek(1) in _DECIMAL_DIGITS):
                token = self._read_number()
                if token is not None and self._numeral_ends_here():
                    return token
                self.pos = start
                return self._read_generic_token()

            if c in DASHES:
                if self.mode == Ps1LexerMode.EXPRESSION:
                    op = self._try_dash_operator()
                    if op:
                        return op
                elif self.mode == Ps1LexerMode.ARGUMENT:
                    return self._read_argument_dash()

            redir = self._try_redirection()
            if redir:
                return redir

            if self.mode == Ps1LexerMode.ARGUMENT:
                if c == '.':
                    nc = self._peek(1)
                    if (
                        not forces_new_token(nc)
                        and nc != '$'
                        and nc not in SINGLE_QUOTES
                        and nc not in DOUBLE_QUOTES
                    ):
                        token = self._read_generic_token()
                        if token.value:
                            return token

            if self.mode == Ps1LexerMode.ARGUMENT and c in '*/%=!+?[':
                if not forces_new_token(self._peek(1)):
                    token = self._read_generic_token()
                    if token.value:
                        return token

            if c in _ONE_CHAR_OPS or c in DASHES:
                self.pos += 1
                kind = _ONE_CHAR_OPS.get(c) or Ps1TokenKind.DASH
                return Ps1Token(kind, c, start)

            if self.mode == Ps1LexerMode.ARGUMENT:
                if c.isalpha() or c == '_' or c == '\\' or c == '`':
                    token = self._read_generic_token()
                    if token.value:
                        return self._keyword_or_token(token)

            if c.isalpha() or c == '_' or c == '`':
                token = self._read_identifier()
                if not forces_new_token(self._peek()):
                    if self.mode == Ps1LexerMode.ARGUMENT or (
                        src[self.pos] in SINGLE_QUOTES
                        or src[self.pos] in DOUBLE_QUOTES
                        or src[self.pos] == '$'
                    ):
                        self.pos = start
                        token = self._read_generic_token()
                if token.value:
                    return self._keyword_or_token(token)

            self.pos += 1
            return Ps1Token(Ps1TokenKind.GENERIC_TOKEN, c, start)


def reads_as_one_numeral(spelling: str, following: str, mode: Ps1LexerMode) -> bool:
    """
    Whether a numeral written as `spelling` is still read as that numeral once `following` is
    written straight against it. A numeral ends where the character after it says it does, so the
    same digits are a number in one place and part of a word in another: `3` before `.ToString` is
    the word `3.ToString`, `0xFF` before it is the number and a member read, and `3` before `[0]`
    or `::MaxValue` is a word again because neither bracket nor colon ends a numeral.

    The question is put to the lexer rather than restated here, so the slot deciding whether its
    value needs a bracket and the reader that would read it back cannot come apart.

    A sign is the one thing asked around the lexer rather than of it. Where an expression is read, a
    `+` or `-` written straight against a numeral is part of it, and the rest of the rule then
    applies to the whole: measured, `-1kb.GetType()` reads the member of minus one kilobyte while
    `-1.GetType` is one word. Where a bare word is a value no sign is ever taken, so the spelling is
    asked about as it was written.
    """
    signed = mode is Ps1LexerMode.EXPRESSION and spelling[:1] in ('+', '-')
    numeral = spelling[1:] if signed else spelling
    lexer = Ps1Lexer(F'{numeral}{following}', mode=mode)
    token = lexer.scan()
    if token.kind not in (Ps1TokenKind.INTEGER, Ps1TokenKind.REAL):
        return False
    return lexer.pos == len(numeral)
