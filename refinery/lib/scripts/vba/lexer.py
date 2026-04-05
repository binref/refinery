from __future__ import annotations

from dataclasses import dataclass
from typing import Generator

from refinery.lib.scripts.vba.token import _KEYWORDS, VbaToken, VbaTokenKind


@dataclass
class VbaLexer:
    source: str
    pos: int = 0

    def _peek(self, count: int = 1) -> str:
        return self.source[self.pos:self.pos + count]

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _skip_whitespace(self) -> bool:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] in ' \t':
            self.pos += 1
        return self.pos > start

    def _read_string(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '"':
                self.pos += 1
                if self.pos < length and src[self.pos] == '"':
                    self.pos += 1
                    continue
                return src[start:self.pos]
            if c in '\r\n':
                return src[start:self.pos]
            self.pos += 1
        return src[start:self.pos]

    def _read_date_literal(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '#':
                self.pos += 1
                return src[start:self.pos]
            if c in '\r\n':
                return src[start:self.pos]
            self.pos += 1
        return src[start:self.pos]

    def _read_number(self) -> VbaToken:
        start = self.pos
        src = self.source
        length = len(src)

        if src[self.pos] == '&' and self.pos + 1 < length:
            nc = src[self.pos + 1].lower()
            if nc == 'h':
                self.pos += 2
                while self.pos < length and src[self.pos] in '0123456789abcdefABCDEF':
                    self.pos += 1
                if self.pos < length and src[self.pos] in '&%':
                    self.pos += 1
                return VbaToken(VbaTokenKind.INTEGER, src[start:self.pos], start)
            if nc == 'o':
                self.pos += 2
                while self.pos < length and src[self.pos] in '01234567':
                    self.pos += 1
                if self.pos < length and src[self.pos] in '&%':
                    self.pos += 1
                return VbaToken(VbaTokenKind.INTEGER, src[start:self.pos], start)

        while self.pos < length and src[self.pos].isdigit():
            self.pos += 1

        is_float = False
        if self.pos < length and src[self.pos] == '.':
            next_pos = self.pos + 1
            if next_pos < length and src[next_pos].isdigit():
                is_float = True
                self.pos += 1
                while self.pos < length and src[self.pos].isdigit():
                    self.pos += 1

        if self.pos < length and src[self.pos] in 'eEdD':
            is_float = True
            self.pos += 1
            if self.pos < length and src[self.pos] in '+-':
                self.pos += 1
            while self.pos < length and src[self.pos].isdigit():
                self.pos += 1

        if self.pos < length and src[self.pos] in '%&!#@':
            self.pos += 1

        kind = VbaTokenKind.FLOAT if is_float else VbaTokenKind.INTEGER
        return VbaToken(kind, src[start:self.pos], start)

    def _read_identifier_or_keyword(self) -> VbaToken:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length:
            c = src[self.pos]
            if c.isalnum() or c == '_':
                self.pos += 1
            else:
                break
        word = src[start:self.pos]
        suffix = ''
        if self.pos < length and src[self.pos] in '%&!#@$':
            c_suffix = src[self.pos]
            consume = True
            if c_suffix == '&' and not (
                self.pos + 1 >= length
                or src[self.pos + 1] in ' \t\r\n)],;:\x00(.!'
            ):
                consume = False
            elif c_suffix == '!' and (
                self.pos + 1 < length
                and (src[self.pos + 1].isalpha() or src[self.pos + 1] == '_')
            ):
                consume = False
            if consume:
                suffix = c_suffix
                self.pos += 1
        kw = _KEYWORDS.get(word.lower())
        if kw is not None and not suffix:
            return VbaToken(kw, word, start)
        return VbaToken(VbaTokenKind.IDENTIFIER, word + suffix, start)

    def _read_comment(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] not in '\r\n':
            self.pos += 1
        return src[start:self.pos]

    def tokenize(self) -> Generator[VbaToken, None, None]:
        src = self.source
        length = len(src)
        last_was_newline = True

        while True:
            self._skip_whitespace()
            if self._at_end():
                yield VbaToken(VbaTokenKind.EOF, '', self.pos)
                return

            start = self.pos
            c = src[self.pos]

            if c == '_':
                p = self.pos + 1
                while p < length and src[p] in ' \t':
                    p += 1
                if p >= length or src[p] in '\r\n':
                    self.pos = p
                    if self.pos < length and src[self.pos] == '\r':
                        self.pos += 1
                    if self.pos < length and src[self.pos] == '\n':
                        self.pos += 1
                    continue

            if c == '\r' or c == '\n':
                if c == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                    self.pos += 2
                else:
                    self.pos += 1
                if not last_was_newline:
                    yield VbaToken(VbaTokenKind.NEWLINE, '\n', start)
                    last_was_newline = True
                continue

            if c == "'":
                text = self._read_comment()
                yield VbaToken(VbaTokenKind.COMMENT, text, start)
                continue

            if c == '"':
                text = self._read_string()
                last_was_newline = False
                yield VbaToken(VbaTokenKind.STRING, text, start)
                continue

            if c == '#':
                if last_was_newline and self.pos + 1 < length and src[self.pos + 1].isalpha():
                    peek = self.pos + 1
                    while peek < length and src[peek].isalpha():
                        peek += 1
                    word = src[self.pos + 1:peek].lower()
                    if word in ('if', 'elseif', 'else', 'end', 'const'):
                        while self.pos < length and src[self.pos] not in '\r\n':
                            self.pos += 1
                        continue
                if self.pos + 1 < length and not src[self.pos + 1].isspace():
                    text = self._read_date_literal()
                    last_was_newline = False
                    yield VbaToken(VbaTokenKind.DATE_LITERAL, text, start)
                    continue
                self.pos += 1
                last_was_newline = False
                yield VbaToken(VbaTokenKind.IDENTIFIER, '#', start)
                continue

            if c == '&' and self.pos + 1 < length and src[self.pos + 1].lower() in 'ho':
                tok = self._read_number()
                last_was_newline = False
                yield tok
                continue

            if c.isdigit() or (c == '.' and self.pos + 1 < length and src[self.pos + 1].isdigit()):
                tok = self._read_number()
                last_was_newline = False
                yield tok
                continue

            if c.isalpha() or c == '_':
                tok = self._read_identifier_or_keyword()
                if tok.kind in (
                    VbaTokenKind.BOOLEAN_TRUE,
                    VbaTokenKind.BOOLEAN_FALSE,
                ):
                    last_was_newline = False
                    yield tok
                    continue
                if tok.value.lower() == 'rem':
                    text = self._read_comment()
                    yield VbaToken(VbaTokenKind.COMMENT, tok.value + text, start)
                    continue
                last_was_newline = False
                yield tok
                continue

            c2 = src[self.pos:self.pos + 2]
            if c2 == '<>':
                self.pos += 2
                last_was_newline = False
                yield VbaToken(VbaTokenKind.NEQ, '<>', start)
                continue
            if c2 == '<=':
                self.pos += 2
                last_was_newline = False
                yield VbaToken(VbaTokenKind.LTE, '<=', start)
                continue
            if c2 == '>=':
                self.pos += 2
                last_was_newline = False
                yield VbaToken(VbaTokenKind.GTE, '>=', start)
                continue
            if c2 == ':=':
                self.pos += 2
                last_was_newline = False
                yield VbaToken(VbaTokenKind.ASSIGN, ':=', start)
                continue

            _ONE_CHAR_OPS: dict[str, VbaTokenKind] = {
                '+' : VbaTokenKind.PLUS,
                '-' : VbaTokenKind.MINUS,
                '*' : VbaTokenKind.STAR,
                '/' : VbaTokenKind.SLASH,
                '\\': VbaTokenKind.BACKSLASH,
                '^' : VbaTokenKind.CARET,
                '&' : VbaTokenKind.AMPERSAND,
                '=' : VbaTokenKind.EQ,
                '<' : VbaTokenKind.LT,
                '>' : VbaTokenKind.GT,
                '.' : VbaTokenKind.DOT,
                '!' : VbaTokenKind.BANG,
                '(' : VbaTokenKind.LPAREN,
                ')' : VbaTokenKind.RPAREN,
                ',' : VbaTokenKind.COMMA,
                ';' : VbaTokenKind.SEMICOLON,
                ':' : VbaTokenKind.COLON,
            }

            op_kind = _ONE_CHAR_OPS.get(c)
            if op_kind is not None:
                self.pos += 1
                last_was_newline = False
                if op_kind == VbaTokenKind.COLON:
                    yield VbaToken(VbaTokenKind.COLON, ':', start)
                else:
                    yield VbaToken(op_kind, c, start)
                continue

            self.pos += 1
            last_was_newline = False
            yield VbaToken(VbaTokenKind.IDENTIFIER, c, start)
