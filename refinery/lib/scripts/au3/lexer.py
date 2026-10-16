from __future__ import annotations

import string

from dataclasses import dataclass
from typing import Generator

from refinery.lib.scripts.au3.token import KEYWORDS, Au3Token, Au3TokenKind

_HEX = frozenset('0123456789abcdefABCDEF')

_TWO_CHAR_OPS: dict[str, Au3TokenKind] = {
    '==' : Au3TokenKind.EQ_STRICT,
    '<>' : Au3TokenKind.NE,
    '<=' : Au3TokenKind.LE,
    '>=' : Au3TokenKind.GE,
    '+=' : Au3TokenKind.PLUS_ASSIGN,
    '-=' : Au3TokenKind.MINUS_ASSIGN,
    '*=' : Au3TokenKind.MUL_ASSIGN,
    '/=' : Au3TokenKind.DIV_ASSIGN,
    '&=' : Au3TokenKind.CONCAT_ASSIGN,
}

_ONE_CHAR_OPS: dict[str, Au3TokenKind] = {
    '='  : Au3TokenKind.ASSIGN_OR_EQ,
    '+'  : Au3TokenKind.PLUS,
    '-'  : Au3TokenKind.MINUS,
    '*'  : Au3TokenKind.STAR,
    '/'  : Au3TokenKind.SLASH,
    '^'  : Au3TokenKind.CARET,
    '&'  : Au3TokenKind.AMP,
    '<'  : Au3TokenKind.LT,
    '>'  : Au3TokenKind.GT,
    '?'  : Au3TokenKind.QUESTION,
    ':'  : Au3TokenKind.COLON,
    '('  : Au3TokenKind.LPAREN,
    ')'  : Au3TokenKind.RPAREN,
    '['  : Au3TokenKind.LBRACKET,
    ']'  : Au3TokenKind.RBRACKET,
    ','  : Au3TokenKind.COMMA,
    '.'  : Au3TokenKind.DOT,
}

#: Every character the lexer ends a line on, and with it a comment, a directive, or a string
#: literal: `refinery.lib.scripts.au3.analysis.values` reads the set to refuse a value no
#: literal can spell.
LINE_BREAKS = frozenset('\r\n\u2028\u2029')

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

_BLOCK_COMMENT_START = ('#cs', '#comments-start')
_BLOCK_COMMENT_END = ('#ce', '#comments-end')


def _is_ident_start(c: str) -> bool:
    return c.isalpha() or c == '_' or ord(c) >= 0x80


def _is_ident_part(c: str) -> bool:
    return c.isalnum() or c == '_' or ord(c) >= 0x80


def is_au3_identifier(text: str) -> bool:
    """
    Whether *text* is a shape the lexer reads as exactly one name: a first character a name
    starts with and only characters a name continues with, so a caller that prints it back can
    rely on the lexer reading the same name again.
    """
    return bool(text) and _is_ident_start(text[0]) and all(
        _is_ident_part(c) for c in text[1:]
    )


def ascii_lower(text: str) -> str:
    """
    The lowercase spelling of *text* with ASCII letters only. Python's `str.lower` also folds
    characters outside ASCII into ASCII letters — U+212A KELVIN SIGN becomes `k` — and whether
    AutoIt folds them too is unpinned, so a caller that may only rewrite a name it knows the
    engine matches compares through this instead.
    """
    return text.translate(_ASCII_LOWER)


def decode_au3_string(text: str) -> str:
    """
    Decode an AutoIt string literal, including its delimiting quotes. A doubled quote is the
    only escape sequence; both quote styles delimit strings. An unterminated literal decodes
    to its body.
    """
    quote = text[0]
    body = text[1:-1] if len(text) > 1 and text[-1] == quote else text[1:]
    return body.replace(quote * 2, quote)


def encode_au3_string(value: str, quote: str = '"') -> str:
    """
    Encode a string as an AutoIt string literal with the given quote character.
    """
    return quote + value.replace(quote, quote * 2) + quote


@dataclass
class Au3Lexer:
    source: str
    pos: int = 0

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _read_line_comment(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length and src[self.pos] not in LINE_BREAKS:
            self.pos += 1
        return Au3Token(Au3TokenKind.COMMENT, src[start:self.pos], start)

    def _match_word(self, words: tuple[str, ...]) -> int | None:
        """
        Return the length of the first of `words` that starts at the cursor and is not the
        prefix of a longer identifier, or `None`. Matching is case-insensitive.
        """
        src = self.source
        for word in words:
            end = self.pos + len(word)
            if src[self.pos:end].lower() == word:
                after = src[end:end + 1]
                if not after or not _is_ident_part(after):
                    return len(word)
        return None

    def _read_block_comment(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        depth = 0
        while self.pos < length:
            if (n := self._match_word(_BLOCK_COMMENT_END)) is not None:
                self.pos += n
                depth -= 1
            elif (n := self._match_word(_BLOCK_COMMENT_START)) is not None:
                self.pos += n
                depth += 1
            else:
                self.pos += 1
                continue
            if depth == 0:
                break
        end = self.pos
        if depth != 0 and end > start and src[end - 1] in LINE_BREAKS:
            # A comment the file never closes runs to its end, and the break that ends that last
            # line is the one the synthesizer writes after every statement: leaving it out of the
            # comment is what makes printing one read back as itself. A terminated comment already
            # stops at its closing word, so only the unterminated one needs this.
            if end - 1 > start and src[end - 1] == '\n' and src[end - 2] == '\r':
                end -= 2
            else:
                end -= 1
            self.pos = end
        return Au3Token(Au3TokenKind.COMMENT, src[start:end], start)

    def _read_directive(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length and src[self.pos] not in LINE_BREAKS:
            self.pos += 1
        return Au3Token(Au3TokenKind.DIRECTIVE, src[start:self.pos], start)

    def _read_string(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        quote = src[self.pos]
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c in LINE_BREAKS:
                break
            if c == quote:
                self.pos += 1
                if self.pos < length and src[self.pos] == quote:
                    self.pos += 1
                    continue
                break
            self.pos += 1
        return Au3Token(Au3TokenKind.STRING, src[start:self.pos], start)

    def _read_number(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        if src[self.pos] == '0' and src[self.pos + 1:self.pos + 2] in ('x', 'X'):
            if src[self.pos + 2:self.pos + 3] and src[self.pos + 2] in _HEX:
                self.pos += 2
                while self.pos < length and src[self.pos] in _HEX:
                    self.pos += 1
                return Au3Token(Au3TokenKind.INTEGER, src[start:self.pos], start)
        is_float = False
        while self.pos < length and src[self.pos].isdigit():
            self.pos += 1
        if (
            self.pos < length
            and src[self.pos] == '.'
            and self.pos + 1 < length
            and src[self.pos + 1].isdigit()
        ):
            is_float = True
            self.pos += 1
            while self.pos < length and src[self.pos].isdigit():
                self.pos += 1
        if self.pos < length and src[self.pos] in 'eE':
            peek = self.pos + 1
            if peek < length and src[peek] in '+-':
                peek += 1
            if peek < length and src[peek].isdigit():
                is_float = True
                self.pos = peek
                while self.pos < length and src[self.pos].isdigit():
                    self.pos += 1
        kind = Au3TokenKind.FLOAT if is_float else Au3TokenKind.INTEGER
        return Au3Token(kind, src[start:self.pos], start)

    def _read_prefixed_name(self, kind: Au3TokenKind) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        self.pos += 1
        while self.pos < length and _is_ident_part(src[self.pos]):
            self.pos += 1
        return Au3Token(kind, src[start:self.pos], start)

    def _read_identifier(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length and _is_ident_part(src[self.pos]):
            self.pos += 1
        word = src[start:self.pos]
        kind = KEYWORDS.get(word.lower())
        if kind is not None:
            return Au3Token(kind, word, start)
        return Au3Token(Au3TokenKind.IDENTIFIER, word, start)

    def _consume_continuation(self):
        """
        The cursor is on a line-continuation underscore: consume it, the rest of its line, and
        the line break itself, so the logical line continues on the next physical one. Blank
        lines after the break are consumed as well.
        """
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] not in LINE_BREAKS:
            self.pos += 1
        while self.pos < length and src[self.pos] in LINE_BREAKS:
            self.pos += 1
            while self.pos < length and src[self.pos] in ' \t':
                self.pos += 1
            if self.pos < length and src[self.pos] not in LINE_BREAKS:
                return

    def _is_blank_rest_of_line(self) -> bool:
        """
        Check whether everything from just after the cursor's underscore to the end of the
        line is whitespace or a comment.
        """
        src = self.source
        length = len(src)
        pos = self.pos + 1
        while pos < length and src[pos] in ' \t':
            pos += 1
        if pos < length and src[pos] == ';':
            while pos < length and src[pos] not in LINE_BREAKS:
                pos += 1
        return pos >= length or src[pos] in LINE_BREAKS

    def _read_newline(self) -> Au3Token:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length:
            c = src[self.pos]
            if c in LINE_BREAKS:
                self.pos += 1
            elif c in ' \t':
                self.pos += 1
            else:
                break
        return Au3Token(Au3TokenKind.NEWLINE, '', start)

    def tokenize(self) -> Generator[Au3Token, None, None]:
        src = self.source
        length = len(src)
        while True:
            while self.pos < length and src[self.pos] in ' \t\f\v':
                self.pos += 1
            if self._at_end():
                yield Au3Token(Au3TokenKind.EOF, '', self.pos)
                return
            start = self.pos
            c = src[self.pos]
            c2 = src[self.pos:self.pos + 2]
            if c in LINE_BREAKS:
                yield self._read_newline()
                continue
            if c == ';':
                yield self._read_line_comment()
                continue
            if c == '#':
                if self._match_word(_BLOCK_COMMENT_START) is not None:
                    yield self._read_block_comment()
                    continue
                yield self._read_directive()
                continue
            if c in '"\'':
                yield self._read_string()
                continue
            if c == '$' and self.pos + 1 < length and _is_ident_start(src[self.pos + 1]):
                yield self._read_prefixed_name(Au3TokenKind.VARIABLE)
                continue
            if c == '@' and self.pos + 1 < length and _is_ident_start(src[self.pos + 1]):
                yield self._read_prefixed_name(Au3TokenKind.MACRO)
                continue
            if c.isdigit() or c == '.' and self.pos + 1 < length and src[self.pos + 1].isdigit():
                yield self._read_number()
                continue
            if c == '_' and (self.pos + 1 >= length or not _is_ident_part(src[self.pos + 1])):
                if self._is_blank_rest_of_line():
                    self._consume_continuation()
                    continue
                self.pos += 1
                yield Au3Token(Au3TokenKind.ERROR, '_', start)
                continue
            if _is_ident_start(c):
                yield self._read_identifier()
                continue
            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                yield Au3Token(_TWO_CHAR_OPS[c2], c2, start)
                continue
            if c in _ONE_CHAR_OPS:
                self.pos += 1
                yield Au3Token(_ONE_CHAR_OPS[c], c, start)
                continue
            self.pos += 1
            yield Au3Token(Au3TokenKind.ERROR, c, start)
