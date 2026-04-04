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

_REDIRECTION_PATTERN = re.compile(
    r'(?:[1-6*])?(?:>>|>&[12]|>)',
)

_INTEGER_PATTERN = re.compile(
    r'0[xX][0-9a-fA-F][0-9a-fA-F_]*(?:l|L)?'
    r'|0[bB][01][01_]*(?:l|L)?'
    r'|[0-9][0-9_]*(?:l|L)?',
)

_REAL_PATTERN = re.compile(
    r'(?:[0-9]*\.[0-9]+|[0-9]+\.)(?:[eE][+-]?[0-9]+)?'
    r'|[0-9]+[eE][+-]?[0-9]+'
    r'|[0-9]+(?:\.[0-9]+)?[dDkKmMgGtTpP][bB]?',
)

_VARIABLE_PATTERN = re.compile(
    r'(?:(?:global|local|script|private|using|env|variable|function|alias|drive)'
    r':)?'
    r'(?:\{[^}]+\}|[a-zA-Z0-9_?$^][a-zA-Z0-9_?]*)',
    re.IGNORECASE,
)


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
            if c in ' \t':
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
            if c == "'":
                self.pos += 1
                if self.pos < length and src[self.pos] == "'":
                    self.pos += 1
                    continue
                return src[start:self.pos]
            self.pos += 1
        return src[start:self.pos]

    def _read_expandable_string(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        depth = 0
        while self.pos < length:
            c = src[self.pos]
            if c == '`' and self.pos + 1 < length:
                self.pos += 2
                continue
            if depth > 0:
                if c == '(':
                    depth += 1
                    self.pos += 1
                    continue
                if c == ')':
                    depth -= 1
                    self.pos += 1
                    continue
                if c == "'":
                    self.pos += 1
                    while self.pos < length:
                        if src[self.pos] == "'":
                            self.pos += 1
                            if self.pos < length and src[self.pos] == "'":
                                self.pos += 1
                                continue
                            break
                        self.pos += 1
                    continue
                if c == '"':
                    self.pos += 1
                    while self.pos < length:
                        sc = src[self.pos]
                        if sc == '`' and self.pos + 1 < length:
                            self.pos += 2
                            continue
                        if sc == '"':
                            self.pos += 1
                            if self.pos < length and src[self.pos] == '"':
                                self.pos += 1
                                continue
                            break
                        self.pos += 1
                    continue
                self.pos += 1
                continue
            if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '(':
                depth += 1
                self.pos += 2
                continue
            if c == '"':
                self.pos += 1
                if self.pos < length and src[self.pos] == '"':
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
            if src[self.pos] == '\n' or (
                src[self.pos] == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n'
            ):
                nl_end = self.pos + 1 if src[self.pos] == '\n' else self.pos + 2
                if nl_end < length and src[nl_end:nl_end + 2] == "'@":
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
            if src[self.pos] == '\n' or (
                src[self.pos] == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n'
            ):
                nl_end = self.pos + 1 if src[self.pos] == '\n' else self.pos + 2
                if nl_end < length and src[nl_end:nl_end + 2] == '"@':
                    self.pos = nl_end + 2
                    return src[start:self.pos]
            if src[self.pos] == '`' and self.pos + 1 < length:
                self.pos += 2
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
            if text.endswith('.') and end < len(src) and src[end] == '.':
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
        start = self.pos
        self.pos += 1
        m = re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', src[self.pos:])
        if not m:
            self.pos = start
            return None
        self.pos += m.end()
        after = src[self.pos:self.pos + 1]
        if after == ':':
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
        while self.pos < length:
            c = src[self.pos]
            if c == '`' and self.pos + 1 < length:
                self.pos += 2
                continue
            if c in ' \t\r\n|&;,{}()' or (c == '"') or (c == "'"):
                break
            if c == '$' or c == '@':
                break
            self.pos += 1
        return Ps1Token(Ps1TokenKind.GENERIC_TOKEN, src[start:self.pos], start)

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

            if c == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                self.pos += 2
                mode_hint = yield Ps1Token(Ps1TokenKind.NEWLINE, '\r\n', start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue
            if c == '\n':
                self.pos += 1
                mode_hint = yield Ps1Token(Ps1TokenKind.NEWLINE, '\n', start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue

            if c2 == '<#':
                text = self._read_block_comment()
                mode_hint = yield Ps1Token(Ps1TokenKind.COMMENT, text, start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue
            if c == '#':
                text = self._read_line_comment()
                mode_hint = yield Ps1Token(Ps1TokenKind.COMMENT, text, start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue

            if c == '@' and self.pos + 1 < length:
                nc = src[self.pos + 1]
                if nc == "'":
                    text = self._read_verbatim_here_string()
                    mode_hint = yield Ps1Token(Ps1TokenKind.HSTRING_VERBATIM, text, start)
                    if mode_hint is not None:
                        self.mode = mode_hint
                    continue
                if nc == '"':
                    text = self._read_expandable_here_string()
                    mode_hint = yield Ps1Token(Ps1TokenKind.HSTRING_EXPAND, text, start)
                    if mode_hint is not None:
                        self.mode = mode_hint
                    continue

            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                kind = _TWO_CHAR_OPS[c2]
                mode_hint = yield Ps1Token(kind, c2, start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue

            if c == '$' or (c == '@' and self.pos + 1 < length and src[self.pos + 1] not in '({'):
                nc = src[self.pos + 1] if self.pos + 1 < length else ''
                if c == '$' and nc == '(':
                    pass
                elif nc and (nc.isalnum() or nc in '_?{$^'):
                    token = self._read_variable(c)
                    mode_hint = yield token
                    if mode_hint is not None:
                        self.mode = mode_hint
                    continue

            if c == "'":
                text = self._read_verbatim_string()
                mode_hint = yield Ps1Token(Ps1TokenKind.STRING_VERBATIM, text, start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue
            if c == '"':
                text = self._read_expandable_string()
                mode_hint = yield Ps1Token(Ps1TokenKind.STRING_EXPAND, text, start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue

            if c.isdigit() or (c == '.' and self.pos + 1 < length and src[self.pos + 1].isdigit()):
                token = self._read_number()
                if token:
                    mode_hint = yield token
                    if mode_hint is not None:
                        self.mode = mode_hint
                    continue

            if c == '-':
                if self.mode == Ps1LexerMode.EXPRESSION:
                    op = self._try_dash_operator()
                    if op:
                        mode_hint = yield op
                        if mode_hint is not None:
                            self.mode = mode_hint
                        continue
                elif self.mode == Ps1LexerMode.ARGUMENT:
                    param = self._try_parameter()
                    if param:
                        mode_hint = yield param
                        if mode_hint is not None:
                            self.mode = mode_hint
                        continue

            redir = self._try_redirection()
            if redir:
                mode_hint = yield redir
                if mode_hint is not None:
                    self.mode = mode_hint
                continue

            if c in _ONE_CHAR_OPS:
                self.pos += 1
                kind = _ONE_CHAR_OPS[c]
                mode_hint = yield Ps1Token(kind, c, start)
                if mode_hint is not None:
                    self.mode = mode_hint
                continue

            if self.mode == Ps1LexerMode.ARGUMENT:
                if c.isalpha() or c == '_' or c == '\\' or c == '`':
                    token = self._read_generic_token()
                    if token.value:
                        word = token.value.lower()
                        kw = _KEYWORDS.get(word)
                        if kw is not None:
                            mode_hint = yield Ps1Token(kw, token.value, token.offset)
                        else:
                            mode_hint = yield token
                        if mode_hint is not None:
                            self.mode = mode_hint
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
                    elif ch.isalnum() or ch in '_-':
                        word.append(ch)
                        self.pos += 1
                    else:
                        break
                identifier = ''.join(word)
                if identifier:
                    kw = _KEYWORDS.get(identifier.lower())
                    if kw is not None:
                        mode_hint = yield Ps1Token(kw, identifier, start)
                    else:
                        mode_hint = yield Ps1Token(Ps1TokenKind.GENERIC_TOKEN, identifier, start)
                    if mode_hint is not None:
                        self.mode = mode_hint
                    continue

            self.pos += 1
            mode_hint = yield Ps1Token(Ps1TokenKind.GENERIC_TOKEN, c, start)
            if mode_hint is not None:
                self.mode = mode_hint
