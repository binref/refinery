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
        src = self.source
        length = len(src)
        self.pos += 1
        if self.pos >= length:
            return ''
        c = src[self.pos]
        self.pos += 1
        mapped = _ESCAPE_MAP.get(c)
        if mapped is not None:
            return mapped
        if c == 'x' and self.pos + 1 < length:
            hexstr = src[self.pos:self.pos + 2]
            if len(hexstr) == 2 and all(
                h in '0123456789abcdefABCDEF' for h in hexstr
            ):
                self.pos += 2
                return chr(int(hexstr, 16))
            return 'x'
        if c == 'u':
            if self.pos < length and src[self.pos] == '{':
                end = src.find('}', self.pos + 1)
                if end != -1:
                    hexstr = src[self.pos + 1:end]
                    if hexstr and all(
                        h in '0123456789abcdefABCDEF' for h in hexstr
                    ):
                        self.pos = end + 1
                        return chr(int(hexstr, 16))
                    self.pos = end + 1
                    return 'u'
            elif self.pos + 3 < length:
                hexstr = src[self.pos:self.pos + 4]
                if len(hexstr) == 4 and all(
                    h in '0123456789abcdefABCDEF' for h in hexstr
                ):
                    self.pos += 4
                    return chr(int(hexstr, 16))
            return 'u'
        if c in '\r\n':
            if c == '\r' and self.pos < length and src[self.pos] == '\n':
                self.pos += 1
            return ''
        return c

    def _read_single_string(self) -> str:
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
            if c == "'":
                return src[start:self.pos]
            if c in '\r\n':
                return src[start:self.pos]
        return src[start:self.pos]

    def _read_double_string(self) -> str:
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
            if c == '"':
                return src[start:self.pos]
            if c in '\r\n':
                return src[start:self.pos]
        return src[start:self.pos]

    def _read_template(self) -> JsToken:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self._read_string_escape()
                continue
            if c == '`':
                self.pos += 1
                return JsToken(JsTokenKind.TEMPLATE_FULL, src[start:self.pos], start)
            if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '{':
                self.pos += 2
                self._template_depth += 1
                self._brace_stack.append(0)
                return JsToken(JsTokenKind.TEMPLATE_HEAD, src[start:self.pos], start)
            self.pos += 1
        return JsToken(JsTokenKind.TEMPLATE_FULL, src[start:self.pos], start)

    def _resume_template(self) -> JsToken:
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self._read_string_escape()
                continue
            if c == '`':
                self.pos += 1
                self._template_depth -= 1
                return JsToken(JsTokenKind.TEMPLATE_TAIL, src[start:self.pos], start)
            if c == '$' and self.pos + 1 < length and src[self.pos + 1] == '{':
                self.pos += 2
                self._brace_stack.append(0)
                return JsToken(JsTokenKind.TEMPLATE_MIDDLE, src[start:self.pos], start)
            self.pos += 1
        self._template_depth -= 1
        return JsToken(JsTokenKind.TEMPLATE_TAIL, src[start:self.pos], start)

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

    def _read_number(self) -> JsToken:
        start = self.pos
        src = self.source
        length = len(src)

        if src[self.pos] == '0' and self.pos + 1 < length:
            nc = src[self.pos + 1]
            if nc in 'xX':
                self.pos += 2
                while self.pos < length and (
                    src[self.pos] in '0123456789abcdefABCDEF_'
                ):
                    self.pos += 1
                if self.pos < length and src[self.pos] == 'n':
                    self.pos += 1
                    return JsToken(JsTokenKind.BIGINT, src[start:self.pos], start)
                return JsToken(JsTokenKind.INTEGER, src[start:self.pos], start)
            if nc in 'oO':
                self.pos += 2
                while self.pos < length and (
                    src[self.pos] in '01234567_'
                ):
                    self.pos += 1
                if self.pos < length and src[self.pos] == 'n':
                    self.pos += 1
                    return JsToken(JsTokenKind.BIGINT, src[start:self.pos], start)
                return JsToken(JsTokenKind.INTEGER, src[start:self.pos], start)
            if nc in 'bB':
                self.pos += 2
                while self.pos < length and src[self.pos] in '01_':
                    self.pos += 1
                if self.pos < length and src[self.pos] == 'n':
                    self.pos += 1
                    return JsToken(JsTokenKind.BIGINT, src[start:self.pos], start)
                return JsToken(JsTokenKind.INTEGER, src[start:self.pos], start)

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
                text = self._read_single_string()
                prev_allows_regex = False
                yield JsToken(JsTokenKind.STRING_SINGLE, text, start)
                continue
            if c == '"':
                text = self._read_double_string()
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
            yield JsToken(JsTokenKind.IDENTIFIER, c, start)
