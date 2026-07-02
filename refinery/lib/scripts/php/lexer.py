from __future__ import annotations

import enum

from dataclasses import dataclass, field
from typing import Generator

from refinery.lib.scripts.php.token import (
    CAST_KEYWORDS,
    KEYWORDS,
    PhpToken,
    PhpTokenKind,
)

_ESCAPE_MAP: dict[str, str] = {
    'n'  : '\n',
    'r'  : '\r',
    't'  : '\t',
    'v'  : '\v',
    'f'  : '\f',
    'e'  : '\x1b',
    '\\' : '\\',
    '$'  : '$',
    '"'  : '"',
}

_HEX = frozenset('0123456789abcdefABCDEF')

_THREE_CHAR_OPS: dict[str, PhpTokenKind] = {
    '===' : PhpTokenKind.IS_IDENTICAL,
    '!==' : PhpTokenKind.IS_NOT_IDENTICAL,
    '<=>' : PhpTokenKind.SPACESHIP,
    '**=' : PhpTokenKind.POW_EQUAL,
    '<<=' : PhpTokenKind.SL_EQUAL,
    '>>=' : PhpTokenKind.SR_EQUAL,
    '??=' : PhpTokenKind.COALESCE_EQUAL,
    '?->' : PhpTokenKind.NULLSAFE_OPERATOR,
    '...' : PhpTokenKind.ELLIPSIS,
}

_TWO_CHAR_OPS: dict[str, PhpTokenKind] = {
    '**' : PhpTokenKind.POW,
    '++' : PhpTokenKind.INC,
    '--' : PhpTokenKind.DEC,
    '->' : PhpTokenKind.OBJECT_OPERATOR,
    '=>' : PhpTokenKind.DOUBLE_ARROW,
    '::' : PhpTokenKind.DOUBLE_COLON,
    '==' : PhpTokenKind.IS_EQUAL,
    '!=' : PhpTokenKind.IS_NOT_EQUAL,
    '<>' : PhpTokenKind.IS_NOT_EQUAL,
    '<=' : PhpTokenKind.IS_SMALLER_OR_EQUAL,
    '>=' : PhpTokenKind.IS_GREATER_OR_EQUAL,
    '+=' : PhpTokenKind.PLUS_EQUAL,
    '-=' : PhpTokenKind.MINUS_EQUAL,
    '*=' : PhpTokenKind.MUL_EQUAL,
    '/=' : PhpTokenKind.DIV_EQUAL,
    '%=' : PhpTokenKind.MOD_EQUAL,
    '.=' : PhpTokenKind.CONCAT_EQUAL,
    '&=' : PhpTokenKind.AND_EQUAL,
    '|=' : PhpTokenKind.OR_EQUAL,
    '^=' : PhpTokenKind.XOR_EQUAL,
    '&&' : PhpTokenKind.BOOLEAN_AND,
    '||' : PhpTokenKind.BOOLEAN_OR,
    '??' : PhpTokenKind.COALESCE,
    '<<' : PhpTokenKind.SL,
    '>>' : PhpTokenKind.SR,
}

_ONE_CHAR_OPS: dict[str, PhpTokenKind] = {
    '+' : PhpTokenKind.PLUS,
    '-' : PhpTokenKind.MINUS,
    '*' : PhpTokenKind.STAR,
    '/' : PhpTokenKind.SLASH,
    '%' : PhpTokenKind.PERCENT,
    '.' : PhpTokenKind.DOT,
    '=' : PhpTokenKind.EQUALS,
    '<' : PhpTokenKind.LT,
    '>' : PhpTokenKind.GT,
    '&' : PhpTokenKind.AMP,
    '|' : PhpTokenKind.PIPE,
    '^' : PhpTokenKind.CARET,
    '~' : PhpTokenKind.TILDE,
    '!' : PhpTokenKind.BANG,
    '@' : PhpTokenKind.AT,
    '?' : PhpTokenKind.QUESTION,
    ':' : PhpTokenKind.COLON,
    '(' : PhpTokenKind.LPAREN,
    ')' : PhpTokenKind.RPAREN,
    '{' : PhpTokenKind.LBRACE,
    '}' : PhpTokenKind.RBRACE,
    '[' : PhpTokenKind.LBRACKET,
    ']' : PhpTokenKind.RBRACKET,
    ';' : PhpTokenKind.SEMICOLON,
    ',' : PhpTokenKind.COMMA,
    '$' : PhpTokenKind.DOLLAR,
    '\\': PhpTokenKind.NS_SEPARATOR,
}


class PhpLexerMode(enum.Enum):
    INLINE_HTML = 'inline-html'
    SCRIPTING = 'scripting'


def _is_ident_start(c: str) -> bool:
    return c.isalpha() or c == '_' or ord(c) >= 0x80


def _is_ident_part(c: str) -> bool:
    return c.isalnum() or c == '_' or ord(c) >= 0x80


@dataclass
class PhpLexer:
    source: str
    pos: int = 0
    mode_stack: list[PhpLexerMode] = field(
        default_factory=lambda: [PhpLexerMode.INLINE_HTML])

    @property
    def mode(self) -> PhpLexerMode:
        return self.mode_stack[-1]

    @mode.setter
    def mode(self, value: PhpLexerMode):
        self.mode_stack[-1] = value

    def push_mode(self, mode: PhpLexerMode):
        self.mode_stack.append(mode)

    def pop_mode(self):
        if len(self.mode_stack) > 1:
            self.mode_stack.pop()

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _read_inline_html(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length:
            if src[self.pos] == '<' and src[self.pos + 1:self.pos + 2] == '?':
                break
            self.pos += 1
        return PhpToken(PhpTokenKind.INLINE_HTML, src[start:self.pos], start)

    def _read_open_tag(self) -> PhpToken:
        src = self.source
        start = self.pos
        if src[self.pos:self.pos + 3] == '<?=':
            self.pos += 3
            return PhpToken(PhpTokenKind.OPEN_TAG_ECHO, '<?=', start)
        if src[self.pos:self.pos + 5].lower() == '<?php':
            after = src[self.pos + 5:self.pos + 6]
            if after == '' or after.isspace():
                self.pos += 5
                return PhpToken(PhpTokenKind.OPEN_TAG, src[start:self.pos], start)
        self.pos += 2
        return PhpToken(PhpTokenKind.OPEN_TAG, '<?', start)

    def _read_line_comment(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length and src[self.pos] not in '\r\n':
            if src[self.pos] == '?' and src[self.pos + 1:self.pos + 2] == '>':
                break
            self.pos += 1
        return PhpToken(PhpTokenKind.COMMENT, src[start:self.pos], start)

    def _read_block_comment(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        kind = PhpTokenKind.COMMENT
        if src[self.pos:self.pos + 3] == '/**' and src[self.pos + 3:self.pos + 4] != '/':
            kind = PhpTokenKind.DOC_COMMENT
        self.pos += 2
        while self.pos < length - 1:
            if src[self.pos] == '*' and src[self.pos + 1] == '/':
                self.pos += 2
                return PhpToken(kind, src[start:self.pos], start)
            self.pos += 1
        self.pos = length
        return PhpToken(kind, src[start:self.pos], start)

    def _skip_string_interpolation(self):
        """
        Advance the cursor over a balanced `{ ... }` interpolation region inside a double-quoted
        string or heredoc body. The cursor must point at the opening brace. Nested braces and nested
        quoted strings are skipped as units so that a closing brace or quote appearing inside the
        interpolation does not terminate the enclosing string prematurely.
        """
        src = self.source
        length = len(src)
        depth = 0
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self.pos += 2
                continue
            if c in '\'"':
                self._skip_nested_string(c)
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                self.pos += 1
                if depth == 0:
                    return
                continue
            self.pos += 1

    def _skip_nested_string(self, quote: str):
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self.pos += 2
                continue
            self.pos += 1
            if c == quote:
                return

    def _read_single_quoted(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self.pos += 2
                continue
            self.pos += 1
            if c == '\'':
                break
        return PhpToken(PhpTokenKind.STRING_SINGLE, src[start:self.pos], start)

    def _read_interpolated(self, quote: str, kind: PhpTokenKind) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self.pos += 2
                continue
            if c == quote:
                self.pos += 1
                break
            if c == '{' and src[self.pos + 1:self.pos + 2] == '$':
                self._skip_string_interpolation()
                continue
            if c == '$' and src[self.pos + 1:self.pos + 2] == '{':
                self.pos += 1
                self._skip_string_interpolation()
                continue
            self.pos += 1
        return PhpToken(kind, src[start:self.pos], start)

    def _read_heredoc(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        self.pos += 3
        while self.pos < length and src[self.pos] in ' \t':
            self.pos += 1
        nowdoc = False
        quote = ''
        if self.pos < length and src[self.pos] in '\'"':
            quote = src[self.pos]
            nowdoc = quote == '\''
            self.pos += 1
        label_start = self.pos
        while self.pos < length and _is_ident_part(src[self.pos]):
            self.pos += 1
        label = src[label_start:self.pos]
        if quote:
            self.pos += 1
        while self.pos < length and src[self.pos] not in '\r\n':
            self.pos += 1
        kind = PhpTokenKind.NOWDOC if nowdoc else PhpTokenKind.HEREDOC
        if not label:
            return PhpToken(PhpTokenKind.ERROR, src[start:self.pos], start)
        while self.pos < length:
            line_start = self.pos
            while self.pos < length and src[self.pos] in '\r\n':
                self.pos += 1
            content_start = self.pos
            while self.pos < length and src[self.pos] in ' \t':
                self.pos += 1
            if src[self.pos:self.pos + len(label)] == label:
                after = src[self.pos + len(label):self.pos + len(label) + 1]
                if not after or not _is_ident_part(after):
                    self.pos += len(label)
                    return PhpToken(kind, src[start:self.pos], start)
            self.pos = content_start
            if self.pos == line_start:
                self.pos += 1
            while self.pos < length and src[self.pos] not in '\r\n':
                if (
                    not nowdoc
                    and src[self.pos] == '\\'
                ):
                    self.pos += 2
                    continue
                self.pos += 1
        return PhpToken(kind, src[start:self.pos], start)

    def _read_number(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        if src[self.pos] == '0' and self.pos + 1 < length:
            nc = src[self.pos + 1]
            if nc in 'xX':
                self.pos += 2
                return self._read_prefixed_int('0123456789abcdefABCDEF_', start)
            if nc in 'oO':
                self.pos += 2
                return self._read_prefixed_int('01234567_', start)
            if nc in 'bB':
                self.pos += 2
                return self._read_prefixed_int('01_', start)
        while self.pos < length and (src[self.pos].isdigit() or src[self.pos] == '_'):
            self.pos += 1
        is_float = False
        if self.pos < length and src[self.pos] == '.' and src[self.pos + 1:self.pos + 2] != '.':
            is_float = True
            self.pos += 1
            while self.pos < length and (src[self.pos].isdigit() or src[self.pos] == '_'):
                self.pos += 1
        if self.pos < length and src[self.pos] in 'eE':
            peek = self.pos + 1
            if peek < length and src[peek] in '+-':
                peek += 1
            if peek < length and src[peek].isdigit():
                is_float = True
                self.pos = peek
                while self.pos < length and (src[self.pos].isdigit() or src[self.pos] == '_'):
                    self.pos += 1
        kind = PhpTokenKind.FLOAT if is_float else PhpTokenKind.INTEGER
        return PhpToken(kind, src[start:self.pos], start)

    def _read_prefixed_int(self, valid_digits: str, start: int) -> PhpToken:
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] in valid_digits:
            self.pos += 1
        return PhpToken(PhpTokenKind.INTEGER, src[start:self.pos], start)

    def _read_variable(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        self.pos += 1
        while self.pos < length and _is_ident_part(src[self.pos]):
            self.pos += 1
        return PhpToken(PhpTokenKind.VARIABLE, src[start:self.pos], start)

    def _read_identifier(self) -> PhpToken:
        src = self.source
        length = len(src)
        start = self.pos
        while self.pos < length and _is_ident_part(src[self.pos]):
            self.pos += 1
        word = src[start:self.pos]
        kind = KEYWORDS.get(word.lower())
        if kind is not None:
            return PhpToken(kind, word, start)
        return PhpToken(PhpTokenKind.IDENTIFIER, word, start)

    def _try_read_cast(self) -> PhpToken | None:
        src = self.source
        length = len(src)
        start = self.pos
        pos = self.pos + 1
        while pos < length and src[pos] in ' \t':
            pos += 1
        word_start = pos
        while pos < length and src[pos].isalpha():
            pos += 1
        word = src[word_start:pos]
        if not word:
            return None
        while pos < length and src[pos] in ' \t':
            pos += 1
        if pos >= length or src[pos] != ')':
            return None
        kind = CAST_KEYWORDS.get(word.lower())
        if kind is None:
            return None
        self.pos = pos + 1
        return PhpToken(kind, src[start:self.pos], start)

    def tokenize(self) -> Generator[PhpToken, None, None]:
        src = self.source
        length = len(src)
        while True:
            if self.mode is PhpLexerMode.INLINE_HTML:
                if self._at_end():
                    yield PhpToken(PhpTokenKind.EOF, '', self.pos)
                    return
                if src[self.pos] == '<' and src[self.pos + 1:self.pos + 2] == '?':
                    tok = self._read_open_tag()
                    self.mode = PhpLexerMode.SCRIPTING
                    yield tok
                    continue
                html = self._read_inline_html()
                if html.value:
                    yield html
                continue

            while self.pos < length and src[self.pos] in ' \t\r\n\f\v':
                self.pos += 1
            if self._at_end():
                yield PhpToken(PhpTokenKind.EOF, '', self.pos)
                return

            start = self.pos
            c = src[self.pos]
            c2 = src[self.pos:self.pos + 2]

            if c2 == '?>':
                self.pos += 2
                if self.pos < length and src[self.pos] == '\n':
                    self.pos += 1
                elif src[self.pos:self.pos + 2] == '\r\n':
                    self.pos += 2
                self.mode = PhpLexerMode.INLINE_HTML
                yield PhpToken(PhpTokenKind.CLOSE_TAG, '?>', start)
                continue

            if c2 == '//' or c == '#' and c2 != '#[':
                yield self._read_line_comment()
                continue
            if c2 == '/*':
                yield self._read_block_comment()
                continue
            if c2 == '#[':
                self.pos += 2
                yield PhpToken(PhpTokenKind.ATTRIBUTE, '#[', start)
                continue

            if c == '\'':
                yield self._read_single_quoted()
                continue
            if c == '"':
                yield self._read_interpolated('"', PhpTokenKind.STRING_DOUBLE)
                continue
            if c == '`':
                yield self._read_interpolated('`', PhpTokenKind.SHELL_EXEC)
                continue
            if c2 == '<<' and src[self.pos:self.pos + 3] == '<<<':
                yield self._read_heredoc()
                continue

            if c == '$' and self.pos + 1 < length and _is_ident_start(src[self.pos + 1]):
                yield self._read_variable()
                continue

            if c.isdigit() or (
                c == '.' and self.pos + 1 < length and src[self.pos + 1].isdigit()
            ):
                yield self._read_number()
                continue

            if _is_ident_start(c):
                yield self._read_identifier()
                continue

            if c == '(':
                cast = self._try_read_cast()
                if cast is not None:
                    yield cast
                    continue

            c3 = src[self.pos:self.pos + 3]
            if c3 in _THREE_CHAR_OPS:
                self.pos += 3
                yield PhpToken(_THREE_CHAR_OPS[c3], c3, start)
                continue
            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                yield PhpToken(_TWO_CHAR_OPS[c2], c2, start)
                continue
            if c in _ONE_CHAR_OPS:
                self.pos += 1
                yield PhpToken(_ONE_CHAR_OPS[c], c, start)
                continue

            self.pos += 1
            yield PhpToken(PhpTokenKind.ERROR, c, start)


def decode_php_single_quoted(text: str) -> str:
    """
    Decode the body of a single-quoted PHP string literal. Only `\\'` and `\\\\` are recognized as
    escape sequences; every other backslash is literal.
    """
    if '\\' not in text:
        return text
    parts: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        c = text[i]
        if c == '\\' and i + 1 < length and text[i + 1] in '\\\'':
            parts.append(text[i + 1])
            i += 2
            continue
        parts.append(c)
        i += 1
    return ''.join(parts)


def decode_php_double_quoted(text: str) -> str:
    """
    Decode the escape sequences of a double-quoted PHP string body. Interpolation is not resolved;
    embedded variable references are left verbatim. Recognizes the standard C-style escapes as well
    as `\\xHH`, `\\u{...}`, and octal `\\NNN`.
    """
    if '\\' not in text:
        return text
    parts: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        c = text[i]
        if c != '\\' or i + 1 >= length:
            parts.append(c)
            i += 1
            continue
        n = text[i + 1]
        mapped = _ESCAPE_MAP.get(n)
        if mapped is not None:
            parts.append(mapped)
            i += 2
            continue
        if n == 'x' and i + 2 < length and text[i + 2] in _HEX:
            j = i + 2
            while j < length and j < i + 4 and text[j] in _HEX:
                j += 1
            parts.append(chr(int(text[i + 2:j], 16)))
            i = j
            continue
        if n == 'u' and text[i + 2:i + 3] == '{':
            end = text.find('}', i + 3)
            if end != -1 and all(h in _HEX for h in text[i + 3:end]) and end > i + 3:
                code_point = int(text[i + 3:end], 16)
                if code_point <= 0x10FFFF:
                    parts.append(chr(code_point))
                    i = end + 1
                    continue
                parts.append(text[i:end + 1])
                i = end + 1
                continue
        if n in '01234567':
            j = i + 1
            while j < length and j < i + 4 and text[j] in '01234567':
                j += 1
            parts.append(chr(int(text[i + 1:j], 8) & 0xFF))
            i = j
            continue
        parts.append(c)
        i += 1
    return ''.join(parts)
