from __future__ import annotations

import enum
import re

from dataclasses import dataclass, field
from typing import Generator

from refinery.lib.scripts.ps1.token import _KEYWORDS, Ps1Token, Ps1TokenKind


class Ps1LexerMode(enum.Enum):
    EXPRESSION = 'expression'
    ARGUMENT = 'argument'


BACKTICK_ESCAPE = {
    '0' : '\0',
    'a' : '\a',
    'b' : '\b',
    'e' : '\x1b',
    'f' : '\f',
    'n' : '\n',
    'r' : '\r',
    't' : '\t',
    'v' : '\v',
}

SINGLE_QUOTES = frozenset("'\u2018\u2019\u201A\u201B")
DOUBLE_QUOTES = frozenset('"\u201C\u201D\u201E')
DASHES = frozenset('-\u2013\u2014\u2015')
WHITESPACE = frozenset(' \t\u00A0\u0085')

NORMALIZE_QUOTES = str.maketrans({
    '\u2018': "'",
    '\u2019': "'",
    '\u201A': "'",
    '\u201B': "'",
    '\u201C': '"',
    '\u201D': '"',
    '\u201E': '"',
})

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

_FORCE_START_NEW_TOKEN = frozenset(' \t\r\n|&;,{}()')
_FORCE_NEW_TOKEN_AFTER_NUMBER = frozenset('!#%*+-./<=>]')

_VARIABLE_STOPS_NO_RESCAN = frozenset('.[=')

_REDIRECTION_PATTERN = re.compile(
    r'[1-6*](?:>>|>&[12]|>)'  # explicit stream: 2>&1, 2>>, 2>
    r'|>>|>&1|>'              # bare: >>, >&1, >
    r'|<',                    # input
)

_INTEGER_PATTERN = re.compile(
    r'0[xX][0-9a-fA-F][0-9a-fA-F_]*(?:l|L)?'
    r'|0[bB][01][01_]*(?:l|L)?'
    r'|[0-9][0-9_]*(?:l|L)?',
)

_REAL_PATTERN = re.compile(
    r'(?:'
    r'(?:[0-9]*\.[0-9]+|[0-9]+\.)(?:[eE][+-]?[0-9]+)?'
    r'|[0-9]+[eE][+-]?[0-9]+'
    r')(?:[dD]|[kKmMgGtTpP][bB])?'
    r'|[0-9]+(?:\.[0-9]+)?(?:[dD]|[kKmMgGtTpP][bB])',
)

_VARIABLE_PATTERN = re.compile(
    r'(?:[a-zA-Z0-9_]+:(?!:))?'
    r'(?:\{[^}]+\}|[a-zA-Z0-9_][a-zA-Z0-9_?]*)'
    r'|[$?^]',
    re.IGNORECASE,
)

_PARAMETER_TERMINATORS = frozenset(' \t\r\n{}();,|&.[')


@dataclass
class Ps1Lexer:
    source: str
    pos: int = 0
    mode_stack: list[Ps1LexerMode] = field(default_factory=lambda: [Ps1LexerMode.EXPRESSION])

    @property
    def mode(self) -> Ps1LexerMode:
        return self.mode_stack[-1]

    @mode.setter
    def mode(self, value: Ps1LexerMode):
        self.mode_stack[-1] = value

    def push_mode(self, mode: Ps1LexerMode):
        self.mode_stack.append(mode)

    def pop_mode(self):
        if len(self.mode_stack) > 1:
            self.mode_stack.pop()

    def _peek(self, count: int = 1) -> str:
        return self.source[self.pos:self.pos + count]

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _skip_whitespace(self) -> bool:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length:
            c = src[self.pos]
            if c in WHITESPACE:
                self.pos += 1
            elif c == '`' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                self.pos += 2
            elif c == '`' and self.pos + 2 < length and src[self.pos + 1:self.pos + 3] == '\r\n':
                self.pos += 3
            else:
                break
        return self.pos > start

    def _read_line_comment(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] != '\n':
            self.pos += 1
        return src[start:self.pos]

    def _read_block_comment(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 2
        while self.pos < length - 1:
            if src[self.pos] == '#' and src[self.pos + 1] == '>':
                self.pos += 2
                return src[start:self.pos]
            self.pos += 1
        self.pos = length
        return src[start:self.pos]

    def _read_verbatim_string(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c in SINGLE_QUOTES:
                self.pos += 1
                if self.pos < length and src[self.pos] in SINGLE_QUOTES:
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
                if (nc in SINGLE_QUOTES or nc in DOUBLE_QUOTES) and self.pos + 2 < length and src[self.pos + 2] in '\r\n':
                    quote_set = SINGLE_QUOTES if nc in SINGLE_QUOTES else DOUBLE_QUOTES
                    self.pos += 2
                    if self.pos < length and src[self.pos] == '\r':
                        self.pos += 1
                    if self.pos < length and src[self.pos] == '\n':
                        self.pos += 1
                    while self.pos < length:
                        if src[self.pos] in '\r\n':
                            if src[self.pos] == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                                self.pos += 2
                            else:
                                self.pos += 1
                            if self.pos + 1 < length and src[self.pos] in quote_set and src[self.pos + 1] == '@':
                                self.pos += 2
                                break
                        else:
                            self.pos += 1
                    continue
            if c in SINGLE_QUOTES:
                self.pos += 1
                while self.pos < length:
                    if src[self.pos] in SINGLE_QUOTES:
                        self.pos += 1
                        if self.pos < length and src[self.pos] in SINGLE_QUOTES:
                            self.pos += 1
                            continue
                        break
                    self.pos += 1
                continue
            if c in DOUBLE_QUOTES:
                self.pos += 1
                while self.pos < length:
                    sc = src[self.pos]
                    if sc == '`' and self.pos + 1 < length:
                        self.pos += 2
                        continue
                    if sc == '$' and self.pos + 1 < length and src[self.pos + 1] == '(':
                        self.pos += 2
                        self._skip_subexpression_content()
                        continue
                    if sc in DOUBLE_QUOTES:
                        self.pos += 1
                        if self.pos < length and src[self.pos] in DOUBLE_QUOTES:
                            self.pos += 1
                            continue
                        break
                    self.pos += 1
                continue
            self.pos += 1

    def _read_expandable_string(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '`' and self.pos + 1 < length:
                self.pos += 2
                continue
            if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '(':
                self.pos += 2
                self._skip_subexpression_content()
                continue
            if c in DOUBLE_QUOTES:
                self.pos += 1
                if self.pos < length and src[self.pos] in DOUBLE_QUOTES:
                    self.pos += 1
                    continue
                return src[start:self.pos]
            self.pos += 1
        return src[start:self.pos]

    def _read_verbatim_here_string(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 2
        if self.pos < length and src[self.pos] == '\r':
            self.pos += 1
        if self.pos < length and src[self.pos] == '\n':
            self.pos += 1
        while self.pos < length:
            if src[self.pos] in '\r\n':
                if src[self.pos] == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                    nl_end = self.pos + 2
                else:
                    nl_end = self.pos + 1
                if nl_end + 1 < length and src[nl_end] in SINGLE_QUOTES and src[nl_end + 1] == '@':
                    self.pos = nl_end + 2
                    return src[start:self.pos]
            self.pos += 1
        return src[start:self.pos]

    def _read_expandable_here_string(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 2
        if self.pos < length and src[self.pos] == '\r':
            self.pos += 1
        if self.pos < length and src[self.pos] == '\n':
            self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c in '\r\n':
                if c == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                    nl_end = self.pos + 2
                else:
                    nl_end = self.pos + 1
                if nl_end + 1 < length and src[nl_end] in DOUBLE_QUOTES and src[nl_end + 1] == '@':
                    self.pos = nl_end + 2
                    return src[start:self.pos]
            if c == '`' and self.pos + 1 < length:
                self.pos += 2
                continue
            if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '(':
                self.pos += 2
                self._skip_subexpression_content()
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

    def _read_number(self) -> Ps1Token | None:
        src = self.source
        m = _REAL_PATTERN.match(src, self.pos)
        if m:
            text = m.group()
            end = m.end()
            if text.endswith('.') and end < len(src):
                nc = src[end]
                if nc == '.' or nc.isalpha() or nc in '_$@{':
                    text = text[:-1]
                    end -= 1
                    if text and text.replace('_', '').isdigit():
                        start = self.pos
                        self.pos = end
                        return Ps1Token(Ps1TokenKind.INTEGER, text, start)
            start = self.pos
            self.pos = end
            return Ps1Token(Ps1TokenKind.REAL, text, start)
        m = _INTEGER_PATTERN.match(src, self.pos)
        if m:
            start = self.pos
            self.pos = m.end()
            if (
                self.pos + 1 < len(src)
                and src[self.pos].lower() in 'kmgtp'
                and src[self.pos + 1].lower() == 'b'
            ):
                text = src[start:self.pos + 2]
                self.pos += 2
                return Ps1Token(Ps1TokenKind.REAL, text, start)
            return Ps1Token(Ps1TokenKind.INTEGER, m.group(), start)
        return None

    def _try_dash_operator(self) -> Ps1Token | None:
        src = self.source
        start = self.pos
        self.pos += 1
        m = re.match(r'[a-zA-Z]+', src[self.pos:])
        if not m:
            self.pos = start
            return None
        word = m.group().lower()
        if word in _DASH_OPERATORS:
            self.pos += m.end()
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

    def _try_redirection(self) -> Ps1Token | None:
        m = _REDIRECTION_PATTERN.match(self.source, self.pos)
        if m:
            start = self.pos
            self.pos = m.end()
            return Ps1Token(Ps1TokenKind.REDIRECTION, m.group(), start)
        return None

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
                self._read_verbatim_string()
                continue
            if c in DOUBLE_QUOTES:
                self._read_expandable_string()
                continue
            if c == '$' and self.pos + 1 < length:
                nc = src[self.pos + 1]
                if nc == '(':
                    has_expansion = True
                    self.pos += 2
                    self._skip_subexpression_content()
                    continue
                if nc.isalnum() or nc in '_?{$^':
                    m = _VARIABLE_PATTERN.match(src, self.pos + 1)
                    if m:
                        has_expansion = True
                        self.pos = m.end()
                        continue
                self.pos += 1
                continue
            if c in _FORCE_START_NEW_TOKEN:
                break
            self.pos += 1
        kind = Ps1TokenKind.GENERIC_EXPAND if has_expansion else Ps1TokenKind.GENERIC_TOKEN
        return Ps1Token(kind, src[start:self.pos], start)

    def _emit(self, token: Ps1Token) -> Generator[Ps1Token, Ps1LexerMode | None, None]:
        mode_hint = yield token
        if mode_hint is not None:
            self.mode = mode_hint

    def tokenize(self) -> Generator[Ps1Token, Ps1LexerMode | None, None]:
        src = self.source
        length = len(src)

        while True:
            self._skip_whitespace()
            if self._at_end():
                yield Ps1Token(Ps1TokenKind.EOF, '', self.pos)
                return

            start = self.pos
            c = src[self.pos]
            c2 = src[self.pos:self.pos + 2]
            if len(c2) == 2:
                d0 = '-' if c2[0] in DASHES else c2[0]
                d1 = '-' if c2[1] in DASHES else c2[1]
                c2 = d0 + d1

            if c == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                self.pos += 2
                yield from self._emit(Ps1Token(Ps1TokenKind.NEWLINE, '\r\n', start))
                continue
            if c == '\n':
                self.pos += 1
                yield from self._emit(Ps1Token(Ps1TokenKind.NEWLINE, '\n', start))
                continue

            if c2 == '<#':
                self._read_block_comment()
                continue
            if c == '#':
                self._read_line_comment()
                continue

            if c == '@' and self.pos + 1 < length:
                nc = src[self.pos + 1]
                if nc in SINGLE_QUOTES:
                    text = self._read_verbatim_here_string()
                    yield from self._emit(Ps1Token(Ps1TokenKind.HSTRING_VERBATIM, text, start))
                    continue
                if nc in DOUBLE_QUOTES:
                    text = self._read_expandable_here_string()
                    yield from self._emit(Ps1Token(Ps1TokenKind.HSTRING_EXPAND, text, start))
                    continue

            if c2 in ('..', '--', '++', '::', '+=', '-=', '*=', '/=', '%=') and self.mode == Ps1LexerMode.ARGUMENT:
                after = self.pos + 2
                if after < length and src[after] not in ' \t\r\n|&;,{}()':
                    token = self._read_generic_token()
                    if token.value:
                        yield from self._emit(token)
                        continue

            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                kind = _TWO_CHAR_OPS[c2]
                yield from self._emit(Ps1Token(kind, c2, start))
                continue

            if c == ':' and self.pos + 1 < length and (src[self.pos + 1].isalpha() or src[self.pos + 1] == '_'):
                self.pos += 1
                while self.pos < length and (src[self.pos].isalnum() or src[self.pos] == '_'):
                    self.pos += 1
                yield from self._emit(Ps1Token(Ps1TokenKind.LABEL, src[start:self.pos], start))
                continue

            if c == '$' or (c == '@' and self.pos + 1 < length and src[self.pos + 1] not in '({'):
                nc = src[self.pos + 1] if self.pos + 1 < length else ''
                if c == '$' and nc == '(':
                    pass
                elif nc and (nc.isalnum() or nc in '_?{$^'):
                    token = self._read_variable(c)
                    if self.mode == Ps1LexerMode.ARGUMENT and self.pos < length:
                        fc = src[self.pos]
                        if fc not in _FORCE_START_NEW_TOKEN and fc not in _VARIABLE_STOPS_NO_RESCAN:
                            self.pos = start
                            token = self._read_generic_token()
                    yield from self._emit(token)
                    continue

            if c in SINGLE_QUOTES:
                text = self._read_verbatim_string()
                yield from self._emit(Ps1Token(Ps1TokenKind.STRING_VERBATIM, text, start))
                continue
            if c in DOUBLE_QUOTES:
                text = self._read_expandable_string()
                yield from self._emit(Ps1Token(Ps1TokenKind.STRING_EXPAND, text, start))
                continue

            if c in '123456' and self.pos + 1 < length and src[self.pos + 1] == '>':
                if self.mode != Ps1LexerMode.EXPRESSION:
                    redir = self._try_redirection()
                    if redir:
                        yield from self._emit(redir)
                        continue

            if c.isdigit() or (c == '.' and self.pos + 1 < length and src[self.pos + 1].isdigit()):
                token = self._read_number()
                if token:
                    nc = src[self.pos] if self.pos < length else None
                    if nc is not None and nc not in _FORCE_START_NEW_TOKEN and not nc.isspace():
                        if self.mode == Ps1LexerMode.ARGUMENT or (
                            nc not in _FORCE_NEW_TOKEN_AFTER_NUMBER
                        ):
                            self.pos = start
                            token = self._read_generic_token()
                    yield from self._emit(token)
                    continue

            if c in DASHES:
                if self.mode == Ps1LexerMode.EXPRESSION:
                    op = self._try_dash_operator()
                    if op:
                        yield from self._emit(op)
                        continue
                elif self.mode == Ps1LexerMode.ARGUMENT:
                    param = self._try_parameter()
                    if param:
                        yield from self._emit(param)
                        continue

            redir = self._try_redirection()
            if redir:
                yield from self._emit(redir)
                continue

            if self.mode == Ps1LexerMode.ARGUMENT:
                if c == '.' and self.pos + 1 < length:
                    nc = src[self.pos + 1]
                    if nc not in ' \t\r\n|&;,{}()$' and nc not in SINGLE_QUOTES and nc not in DOUBLE_QUOTES:
                        token = self._read_generic_token()
                        if token.value:
                            yield from self._emit(token)
                            continue

            if self.mode == Ps1LexerMode.ARGUMENT and c in '*/%=!+':
                if self.pos + 1 < length and src[self.pos + 1] not in ' \t\r\n|&;,{}()':
                    token = self._read_generic_token()
                    if token.value:
                        yield from self._emit(token)
                        continue

            if c in _ONE_CHAR_OPS or c in DASHES:
                self.pos += 1
                kind = _ONE_CHAR_OPS.get(c) or Ps1TokenKind.DASH
                yield from self._emit(Ps1Token(kind, c, start))
                continue

            if self.mode == Ps1LexerMode.ARGUMENT:
                if c.isalpha() or c == '_' or c == '\\' or c == '`':
                    token = self._read_generic_token()
                    if token.value:
                        word = token.value.lower()
                        kw = _KEYWORDS.get(word)
                        if kw is not None:
                            yield from self._emit(Ps1Token(kw, token.value, token.offset))
                        else:
                            yield from self._emit(token)
                        continue

            if c.isalpha() or c == '_' or c == '`':
                word = []
                if c == '`' and self.pos + 1 < length:
                    self.pos += 1
                    word.append(src[self.pos])
                    self.pos += 1
                else:
                    word.append(c)
                    self.pos += 1
                while self.pos < length:
                    ch = src[self.pos]
                    if ch == '`' and self.pos + 1 < length:
                        self.pos += 1
                        word.append(src[self.pos])
                        self.pos += 1
                    elif ch.isalnum() or ch == '_':
                        word.append(ch)
                        self.pos += 1
                    elif ch in DASHES and self.mode != Ps1LexerMode.EXPRESSION:
                        word.append(ch)
                        self.pos += 1
                    else:
                        break
                if self.pos < length and src[self.pos] not in _FORCE_START_NEW_TOKEN:
                    if self.mode == Ps1LexerMode.ARGUMENT or (
                        src[self.pos] in SINGLE_QUOTES
                        or src[self.pos] in DOUBLE_QUOTES
                        or src[self.pos] == '$'
                    ):
                        self.pos = start
                        token = self._read_generic_token()
                        if token.value:
                            yield from self._emit(token)
                            continue
                identifier = ''.join(word)
                if identifier:
                    kw = _KEYWORDS.get(identifier.lower())
                    if kw is not None:
                        yield from self._emit(Ps1Token(kw, identifier, start))
                    else:
                        yield from self._emit(Ps1Token(Ps1TokenKind.GENERIC_TOKEN, identifier, start))
                    continue

            self.pos += 1
            yield from self._emit(Ps1Token(Ps1TokenKind.GENERIC_TOKEN, c, start))
