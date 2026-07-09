from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generator

from refinery.lib.scripts.js.token import KEYWORDS, JsToken, JsTokenKind

_ESCAPE_MAP: dict[str, str] = {
    'b'  : '\b',
    'f'  : '\f',
    'n'  : '\n',
    'r'  : '\r',
    't'  : '\t',
    'v'  : '\v',
    '0'  : '\0',
    '\\' : '\\',
    "'"  : "'",
    '"'  : '"',
    '`'  : '`',
}

_HEX = frozenset('0123456789abcdefABCDEF')


def _decode_one_escape(src: str, pos: int, length: int) -> tuple[str, int]:
    if pos >= length:
        return '', pos
    c = src[pos]
    pos += 1
    mapped = _ESCAPE_MAP.get(c)
    if mapped is not None:
        return mapped, pos
    if c == 'x' and pos + 1 < length:
        hexstr = src[pos:pos + 2]
        if len(hexstr) == 2 and _HEX.issuperset(hexstr):
            return chr(int(hexstr, 16)), pos + 2
        return 'x', pos
    if c == 'u':
        if pos < length and src[pos] == '{':
            end = src.find('}', pos + 1)
            if end != -1:
                hexstr = src[pos + 1:end]
                if hexstr and _HEX.issuperset(hexstr):
                    return chr(int(hexstr, 16)), end + 1
                return 'u', end + 1
        elif pos + 3 < length:
            hexstr = src[pos:pos + 4]
            if len(hexstr) == 4 and _HEX.issuperset(hexstr):
                return chr(int(hexstr, 16)), pos + 4
        return 'u', pos
    if c in '\r\n':
        if c == '\r' and pos < length and src[pos] == '\n':
            pos += 1
        return '', pos
    return c, pos


_FOUR_CHAR_OPS: dict[str, JsTokenKind] = {
    '>>>=' : JsTokenKind.GT3_ASSIGN,
}

_THREE_CHAR_OPS: dict[str, JsTokenKind] = {
    '===' : JsTokenKind.EQ3,
    '!==' : JsTokenKind.BANG_EQ2,
    '>>>' : JsTokenKind.GT3,
    '**=' : JsTokenKind.STAR2_ASSIGN,
    '<<=' : JsTokenKind.LT2_ASSIGN,
    '>>=' : JsTokenKind.GT2_ASSIGN,
    '&&=' : JsTokenKind.AND_ASSIGN,
    '||=' : JsTokenKind.OR_ASSIGN,
    '??=' : JsTokenKind.NULLISH_ASSIGN,
    '...' : JsTokenKind.ELLIPSIS,
}

_TWO_CHAR_OPS: dict[str, JsTokenKind] = {
    '==' : JsTokenKind.EQ2,
    '!=' : JsTokenKind.BANG_EQ,
    '<=' : JsTokenKind.LT_EQ,
    '>=' : JsTokenKind.GT_EQ,
    '+=' : JsTokenKind.PLUS_ASSIGN,
    '-=' : JsTokenKind.MINUS_ASSIGN,
    '*=' : JsTokenKind.STAR_ASSIGN,
    '/=' : JsTokenKind.SLASH_ASSIGN,
    '%=' : JsTokenKind.PERCENT_ASSIGN,
    '&=' : JsTokenKind.AMP_ASSIGN,
    '|=' : JsTokenKind.PIPE_ASSIGN,
    '^=' : JsTokenKind.CARET_ASSIGN,
    '**' : JsTokenKind.STAR2,
    '++' : JsTokenKind.INC,
    '--' : JsTokenKind.DEC,
    '&&' : JsTokenKind.AND,
    '||' : JsTokenKind.OR,
    '??' : JsTokenKind.QQ,
    '?.' : JsTokenKind.QUESTION_DOT,
    '=>' : JsTokenKind.ARROW,
    '<<' : JsTokenKind.LT2,
    '>>' : JsTokenKind.GT2,
}

_ONE_CHAR_OPS: dict[str, JsTokenKind] = {
    '+' : JsTokenKind.PLUS,
    '-' : JsTokenKind.MINUS,
    '*' : JsTokenKind.STAR,
    '%' : JsTokenKind.PERCENT,
    '=' : JsTokenKind.EQUALS,
    '!' : JsTokenKind.BANG,
    '<' : JsTokenKind.LT,
    '>' : JsTokenKind.GT,
    '&' : JsTokenKind.AMP,
    '|' : JsTokenKind.PIPE,
    '^' : JsTokenKind.CARET,
    '~' : JsTokenKind.TILDE,
    '.' : JsTokenKind.DOT,
    '?' : JsTokenKind.QUESTION,
    ':' : JsTokenKind.COLON,
    '(' : JsTokenKind.LPAREN,
    ')' : JsTokenKind.RPAREN,
    '{' : JsTokenKind.LBRACE,
    '}' : JsTokenKind.RBRACE,
    '[' : JsTokenKind.LBRACKET,
    ']' : JsTokenKind.RBRACKET,
    ';' : JsTokenKind.SEMICOLON,
    ',' : JsTokenKind.COMMA,
}

_EXPR_END_KINDS = frozenset({
    JsTokenKind.IDENTIFIER,
    JsTokenKind.INTEGER,
    JsTokenKind.FLOAT,
    JsTokenKind.BIGINT,
    JsTokenKind.STRING_SINGLE,
    JsTokenKind.STRING_DOUBLE,
    JsTokenKind.TEMPLATE_FULL,
    JsTokenKind.TEMPLATE_TAIL,
    JsTokenKind.REGEXP,
    JsTokenKind.RPAREN,
    JsTokenKind.RBRACKET,
    JsTokenKind.INC,
    JsTokenKind.DEC,
    JsTokenKind.TRUE,
    JsTokenKind.FALSE,
    JsTokenKind.NULL,
    JsTokenKind.THIS,
    JsTokenKind.SUPER,
})


@dataclass
class JsLexer:
    source: str
    pos: int = 0
    _template_depth: int = 0
    _brace_stack: list[int] = field(default_factory=list)

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

    def _read_line_comment(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 2
        while self.pos < length and src[self.pos] != '\n':
            self.pos += 1
        return src[start:self.pos]

    def _read_block_comment(self) -> tuple[str, bool]:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 2
        has_newline = False
        while self.pos < length - 1:
            if src[self.pos] == '*' and src[self.pos + 1] == '/':
                self.pos += 2
                return src[start:self.pos], has_newline
            if src[self.pos] in '\r\n':
                has_newline = True
            self.pos += 1
        self.pos = length
        return src[start:self.pos], has_newline

    def _read_string_escape(self) -> str:
        self.pos += 1
        result, self.pos = _decode_one_escape(
            self.source, self.pos, len(self.source))
        return result

    def _read_string(self, quote: str) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self._read_string_escape()
                continue
            self.pos += 1
            if c == quote:
                return src[start:self.pos]
            if c in '\r\n':
                return src[start:self.pos]
        return src[start:self.pos]

    def _scan_template_content(
        self,
        start: int,
        close_kind: JsTokenKind,
        interp_kind: JsTokenKind,
        depth_delta: int,
    ) -> JsToken:
        src = self.source
        length = len(src)
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self._read_string_escape()
                continue
            if c == '`':
                self.pos += 1
                self._template_depth += depth_delta
                return JsToken(close_kind, src[start:self.pos], start)
            if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '{':
                self.pos += 2
                if depth_delta == 0:
                    self._template_depth += 1
                self._brace_stack.append(0)
                return JsToken(interp_kind, src[start:self.pos], start)
            self.pos += 1
        self._template_depth += depth_delta
        return JsToken(close_kind, src[start:self.pos], start)

    def _read_template(self) -> JsToken:
        start = self.pos
        self.pos += 1
        return self._scan_template_content(
            start, JsTokenKind.TEMPLATE_FULL, JsTokenKind.TEMPLATE_HEAD, 0)

    def _resume_template(self) -> JsToken:
        start = self.pos
        self.pos += 1
        return self._scan_template_content(
            start, JsTokenKind.TEMPLATE_TAIL, JsTokenKind.TEMPLATE_MIDDLE, -1)

    def _read_regexp(self) -> str:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        in_class = False
        while self.pos < length:
            c = src[self.pos]
            if c == '\\' and self.pos + 1 < length:
                self.pos += 2
                continue
            if c == '[':
                in_class = True
                self.pos += 1
                continue
            if c == ']' and in_class:
                in_class = False
                self.pos += 1
                continue
            if c == '/' and not in_class:
                self.pos += 1
                while self.pos < length and src[self.pos].isalpha():
                    self.pos += 1
                return src[start:self.pos]
            if c in '\r\n':
                break
            self.pos += 1
        return src[start:self.pos]

    def _read_prefixed_int(self, start: int, valid_digits: str) -> JsToken:
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] in valid_digits:
            self.pos += 1
        if self.pos < length and src[self.pos] == 'n':
            self.pos += 1
            return JsToken(JsTokenKind.BIGINT, src[start:self.pos], start)
        return JsToken(JsTokenKind.INTEGER, src[start:self.pos], start)

    def _read_number(self) -> JsToken:
        start = self.pos
        src = self.source
        length = len(src)

        if src[self.pos] == '0' and self.pos + 1 < length:
            nc = src[self.pos + 1]
            if nc in 'xX':
                self.pos += 2
                return self._read_prefixed_int(start, '0123456789abcdefABCDEF_')
            if nc in 'oO':
                self.pos += 2
                return self._read_prefixed_int(start, '01234567_')
            if nc in 'bB':
                self.pos += 2
                return self._read_prefixed_int(start, '01_')

        while self.pos < length and (src[self.pos].isdigit() or src[self.pos] == '_'):
            self.pos += 1

        is_float = False
        if self.pos < length and src[self.pos] == '.':
            next_pos = self.pos + 1
            if next_pos < length and src[next_pos].isdigit():
                is_float = True
                self.pos += 1
                while self.pos < length and (
                    src[self.pos].isdigit() or src[self.pos] == '_'
                ):
                    self.pos += 1

        if self.pos < length and src[self.pos] in 'eE':
            is_float = True
            self.pos += 1
            if self.pos < length and src[self.pos] in '+-':
                self.pos += 1
            while self.pos < length and (
                src[self.pos].isdigit() or src[self.pos] == '_'
            ):
                self.pos += 1

        if not is_float and self.pos < length and src[self.pos] == 'n':
            self.pos += 1
            return JsToken(JsTokenKind.BIGINT, src[start:self.pos], start)

        kind = JsTokenKind.FLOAT if is_float else JsTokenKind.INTEGER
        return JsToken(kind, src[start:self.pos], start)

    def _read_identifier_or_keyword(self) -> JsToken:
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length:
            c = src[self.pos]
            if c.isalnum() or c == '_' or c == '$':
                self.pos += 1
            elif c == '\\' and self.pos + 1 < length and src[self.pos + 1] == 'u':
                self._read_string_escape()
            else:
                break
        word = src[start:self.pos]
        kw = KEYWORDS.get(word)
        if kw is not None:
            return JsToken(kw, word, start)
        return JsToken(JsTokenKind.IDENTIFIER, word, start)

    def tokenize(self) -> Generator[JsToken, None, None]:
        src = self.source
        length = len(src)
        prev_allows_regex = True

        if src.startswith('#!'):
            end = src.find('\n')
            self.pos = end if end >= 0 else length

        while True:
            self._skip_whitespace()
            if self._at_end():
                yield JsToken(JsTokenKind.EOF, '', self.pos)
                return

            start = self.pos
            c = src[self.pos]
            c2 = src[self.pos:self.pos + 2]

            if c == '\r' and self.pos + 1 < length and src[self.pos + 1] == '\n':
                self.pos += 2
                yield JsToken(JsTokenKind.NEWLINE, '\r\n', start)
                continue
            if c in '\r\n':
                self.pos += 1
                yield JsToken(JsTokenKind.NEWLINE, c, start)
                continue

            if c2 == '//':
                text = self._read_line_comment()
                yield JsToken(JsTokenKind.COMMENT, text, start)
                continue
            if c2 == '/*':
                text, has_newline = self._read_block_comment()
                yield JsToken(JsTokenKind.COMMENT, text, start)
                if has_newline:
                    yield JsToken(JsTokenKind.NEWLINE, '', self.pos)
                continue

            if c == "'":
                text = self._read_string("'")
                prev_allows_regex = False
                yield JsToken(JsTokenKind.STRING_SINGLE, text, start)
                continue
            if c == '"':
                text = self._read_string('"')
                prev_allows_regex = False
                yield JsToken(JsTokenKind.STRING_DOUBLE, text, start)
                continue
            if c == '`':
                tok = self._read_template()
                prev_allows_regex = False
                yield tok
                continue

            if c == '}' and self._template_depth > 0 and self._brace_stack:
                if self._brace_stack[-1] == 0:
                    self._brace_stack.pop()
                    tok = self._resume_template()
                    prev_allows_regex = False
                    yield tok
                    continue
                else:
                    self._brace_stack[-1] -= 1

            if c.isdigit() or (
                c == '.' and self.pos + 1 < length and src[self.pos + 1].isdigit()
            ):
                tok = self._read_number()
                prev_allows_regex = False
                yield tok
                continue

            if c.isalpha() or c == '_' or c == '$' or c == '\\':
                tok = self._read_identifier_or_keyword()
                prev_allows_regex = tok.kind not in _EXPR_END_KINDS
                yield tok
                continue

            if c == '#':
                nxt = src[self.pos + 1] if self.pos + 1 < length else ''
                if nxt.isalpha() or nxt == '_' or nxt == '$' or nxt == '\\':
                    self.pos += 1
                    name = self._read_identifier_or_keyword()
                    prev_allows_regex = False
                    yield JsToken(JsTokenKind.PRIVATE_IDENTIFIER, '#' + name.value, start)
                    continue

            if c == '/':
                if prev_allows_regex:
                    text = self._read_regexp()
                    prev_allows_regex = False
                    yield JsToken(JsTokenKind.REGEXP, text, start)
                    continue
                c2_slash = src[self.pos:self.pos + 2]
                if c2_slash == '/=':
                    self.pos += 2
                    prev_allows_regex = True
                    yield JsToken(JsTokenKind.SLASH_ASSIGN, '/=', start)
                    continue
                self.pos += 1
                prev_allows_regex = True
                yield JsToken(JsTokenKind.SLASH, '/', start)
                continue

            c4 = src[self.pos:self.pos + 4]
            if c4 in _FOUR_CHAR_OPS:
                self.pos += 4
                kind = _FOUR_CHAR_OPS[c4]
                prev_allows_regex = True
                yield JsToken(kind, c4, start)
                continue

            c3 = src[self.pos:self.pos + 3]
            if c3 in _THREE_CHAR_OPS:
                self.pos += 3
                kind = _THREE_CHAR_OPS[c3]
                prev_allows_regex = True
                yield JsToken(kind, c3, start)
                continue

            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                kind = _TWO_CHAR_OPS[c2]
                if kind in (JsTokenKind.INC, JsTokenKind.DEC):
                    pass
                else:
                    prev_allows_regex = True
                yield JsToken(kind, c2, start)
                continue

            if c in _ONE_CHAR_OPS:
                self.pos += 1
                kind = _ONE_CHAR_OPS[c]
                if kind in (
                    JsTokenKind.RPAREN,
                    JsTokenKind.RBRACKET,
                ):
                    prev_allows_regex = False
                elif kind == JsTokenKind.RBRACE:
                    prev_allows_regex = True
                else:
                    prev_allows_regex = kind not in _EXPR_END_KINDS
                if kind == JsTokenKind.LBRACE and self._brace_stack:
                    self._brace_stack[-1] += 1
                yield JsToken(kind, c, start)
                continue

            self.pos += 1
            prev_allows_regex = True
            yield JsToken(JsTokenKind.ERROR, c, start)


def decode_js_string_body(text: str) -> str:
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
        decoded, i = _decode_one_escape(text, i + 1, length)
        if decoded:
            parts.append(decoded)
    return ''.join(parts)
