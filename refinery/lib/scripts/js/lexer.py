from __future__ import annotations

import enum
import re
import unicodedata

from dataclasses import dataclass, field
from typing import Generator

from refinery.lib.scripts.js.token import (
    KEYWORDS,
    LINE_TERMINATORS,
    WHITESPACE,
    JsToken,
    JsTokenKind,
)
from refinery.lib.scripts.js.utf16 import (
    code_units,
    to_code_units,
)

_ESCAPE_MAP: dict[str, str] = {
    'b'  : '\b',
    'f'  : '\f',
    'n'  : '\n',
    'r'  : '\r',
    't'  : '\t',
    'v'  : '\v',
    '\\' : '\\',
    "'"  : "'",
    '"'  : '"',
    '`'  : '`',
}

_HEX = frozenset('0123456789abcdefABCDEF')
_OCTAL = frozenset('01234567')
_DECIMAL = frozenset('0123456789')

_WHITESPACE = frozenset(WHITESPACE)
_LINE_TERMINATOR = re.compile(F'[{re.escape(LINE_TERMINATORS)}]')
"""
The two productions `refinery.lib.scripts.js.token` spells, in the shapes this scan reads them. The
spelling stays a string there because `refinery.lib.scripts.js.numbers.TRIMMABLE_WHITESPACE` is the
concatenation of the two, and neither shape here is the right one for the other: whitespace is asked
about one character at a time, where a comment asks only where the next terminator is.
"""

_MAX_CODE_POINT = 0x10FFFF
"""
The largest code point a `\\u{...}` escape may name. A larger one is no escape at all, and it is
asked about here rather than left to `chr`, which raises: the scan runs inside a generator that the
parser reads statement by statement, so an exception raised in it is not a diagnostic but the end
of the token stream, and every statement behind the escape disappears with it.
"""

_IDENTIFIER_JOINERS = frozenset('\u200c\u200d')
"""
The zero width non-joiner and the zero width joiner, which are IdentifierPart and nothing else: they
may stand inside a name but not open one. They carry no width, so a name written with one reads as
the same name, which is exactly what makes them worth writing in an obfuscated file.
"""


def _begins_unicode_escape(src: str, pos: int) -> bool:
    return src[pos:pos + 2] == '\\u'


_ASCII_NAME_START = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$')
_ASCII_NAME_PART = _ASCII_NAME_START | _DECIMAL
"""
The characters almost every name is written with, asked first because asking the Unicode database
per character is what the scan spends its time on otherwise. These two are the whole of ASCII that
a name may hold — `_` is the one Pc below the eighth bit and `$` is in no category IdentifierStart
names at all — so an ASCII character that is in neither is in no name, and the character that ends
a name is the one the scan asks about most.
"""

_ID_START_CATEGORIES = frozenset({'Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nl'})
_ID_CONTINUE_CATEGORIES = _ID_START_CATEGORIES | frozenset({'Mn', 'Mc', 'Nd', 'Pc'})
_OTHER_ID_START = frozenset('\u1885\u1886\u2118\u212e\u309b\u309c')
_OTHER_ID_CONTINUE = frozenset(
    '\u00b7\u0387\u1369\u136a\u136b\u136c\u136d\u136e\u136f\u1370\u1371\u19da\u30fb\uff65'
)
"""
ID_Start and ID_Continue as UAX #31 defines them and ECMA-262 11.6 adopts them, with the two lists
of characters those properties name outright because their category alone would leave them out. A
name is written with these and not with what a locale calls a letter: an accent written as its own
combining character, the middle dot of a Catalan `l·l`, the katakana middle dot, and an undertie
are all IdentifierPart, and reading a name as though they were not ends it early and reads what
follows as an operator.

Other_ID_Continue is a list Unicode extends, and the two lists here are the ones Unicode 15.1
names, which is what `unicodedata` on this interpreter answers the categories from. A database
holding a different revision than these lists were written against disagrees with the categories
beside them rather than with anything stated here.
"""

_EXTRA_NAME_PART = _IDENTIFIER_JOINERS | _OTHER_ID_START | _OTHER_ID_CONTINUE
"""
Every character IdentifierPart takes beyond what its categories give it, asked as one membership
so that the tail of the scan's per-character question is a single lookup.
"""


def _opens_a_name(c: str) -> bool:
    if c in _ASCII_NAME_START:
        return True
    if c.isascii():
        return False
    return unicodedata.category(c) in _ID_START_CATEGORIES or c in _OTHER_ID_START


def _continues_a_name(c: str) -> bool:
    if c in _ASCII_NAME_PART:
        return True
    if c.isascii():
        return False
    return unicodedata.category(c) in _ID_CONTINUE_CATEGORIES or c in _EXTRA_NAME_PART


def _at_identifier_start(src: str, pos: int) -> bool:
    """
    Whether an IdentifierName begins at *pos*. A backslash opens one only where it opens a
    unicode escape; one that begins no escape is a character no name may hold, and reading it as
    the start of a name is how a scan that consumed nothing yielded empty identifiers for as long
    as anything read them.
    """
    c = src[pos:pos + 1]
    if not c:
        return False
    return _opens_a_name(c) or _begins_unicode_escape(src, pos)


class _EscapeUse(enum.Enum):
    """
    Which literals accept an escape. Every escape a template accepts a string accepts too, so the
    three are ordered: one a template has, one only a string keeps, and one no literal has at all. A
    literal carrying an escape it does not accept denotes nothing.

    `STRING` is the legacy octal escape and `\\8`/`\\9` Annex B holds open for sloppy code, which a
    template refuses and a string reads as the character it names. `NEITHER` is a `\\x` or `\\u`
    naming no character, which neither literal has: the reading that answers with the letters behind
    the backslash reports a value for a file that has none.
    """
    EITHER = enum.auto()
    STRING = enum.auto()
    NEITHER = enum.auto()


def _decode_one_escape(src: str, pos: int, length: int) -> tuple[str, int, _EscapeUse]:
    """
    What the escape opened at *pos* denotes, where it ends, and which literals accept it. The third
    answer is what the two literals disagree about: a string keeps the escapes Annex B holds open
    for sloppy code and reads anything else as the character behind the backslash, while a template
    admits neither; and an escape naming no character is one no literal has.

    Refusal is reported here rather than scanned for again, because the classification is this
    decode: which spellings of `\\x` and `\\u` are malformed is a fact about the escape grammar, and
    a second reader of the same text would be a second statement of it.
    """
    if pos >= length:
        return '', pos, _EscapeUse.NEITHER
    c = src[pos]
    pos += 1
    mapped = _ESCAPE_MAP.get(c)
    if mapped is not None:
        return mapped, pos, _EscapeUse.EITHER
    if c in _OCTAL:
        value = int(c, 8)
        remaining = 2 if c in '0123' else 1
        legacy = c != '0'
        while remaining > 0 and pos < length and src[pos] in _OCTAL:
            value = value * 8 + int(src[pos], 8)
            pos += 1
            remaining -= 1
            legacy = True
        if not legacy and pos < length and src[pos] in _DECIMAL:
            legacy = True
        return chr(value), pos, _EscapeUse.STRING if legacy else _EscapeUse.EITHER
    if c in '89':
        return c, pos, _EscapeUse.STRING
    if c == 'x':
        hexstr = src[pos:pos + 2]
        if len(hexstr) == 2 and _HEX.issuperset(hexstr):
            return chr(int(hexstr, 16)), pos + 2, _EscapeUse.EITHER
        return 'x', pos, _EscapeUse.NEITHER
    if c == 'u':
        if pos < length and src[pos] == '{':
            end = pos + 1
            while end < length and src[end] in _HEX:
                end += 1
            if end > pos + 1 and end < length and src[end] == '}':
                value = int(src[pos + 1:end], 16)
                if value <= _MAX_CODE_POINT:
                    return code_units(value), end + 1, _EscapeUse.EITHER
                return 'u', end + 1, _EscapeUse.NEITHER
        else:
            hexstr = src[pos:pos + 4]
            if len(hexstr) == 4 and _HEX.issuperset(hexstr):
                return chr(int(hexstr, 16)), pos + 4, _EscapeUse.EITHER
        return 'u', pos, _EscapeUse.NEITHER
    if c in LINE_TERMINATORS:
        if c == '\r' and pos < length and src[pos] == '\n':
            pos += 1
        return '', pos, _EscapeUse.EITHER
    return c, pos, _EscapeUse.EITHER


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
    '/' : JsTokenKind.SLASH,
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
    '@' : JsTokenKind.AT,
}


HTML_OPEN_COMMENT = '<!--'
HTML_CLOSE_COMMENT = '-->'


@dataclass(frozen=True)
class JsLexerState:
    """
    What a rewind has to put back. The position is not part of it, because a rewind always goes to
    the start of a token the parser is already holding; what no longer follows from that offset
    once scanning has moved past it is the template nesting, whether the scan stands at the head of
    its line, and whether it has read an HTML-like comment yet.
    """
    template_depth: int
    brace_stack: tuple[int, ...]
    line_head: bool
    html_comment: int | None


@dataclass
class JsLexer:
    source: str
    pos: int = 0
    html_comment: int | None = None
    """
    The offset of the first HTML-like comment delimiter the scan has read (§B.1.1): a `<!--`
    anywhere, or a `-->` at the head of its line. Module code refuses both, and the parser carries
    the fact onto the script it builds, since the comment such a delimiter opens may stand where no
    statement of the tree carries it.
    """
    _template_depth: int = 0
    _brace_stack: list[int] = field(default_factory=list)
    _line_head: bool = True
    """
    Whether nothing but whitespace and comments stands between the last line terminator and the
    scan position, which is the one place `-->` opens a comment rather than spelling a decrement
    and a `>` (§B.1.1).
    """

    def capture(self) -> JsLexerState:
        return JsLexerState(
            self._template_depth,
            tuple(self._brace_stack),
            self._line_head,
            self.html_comment,
        )

    def rewind(self, pos: int, state: JsLexerState) -> None:
        self.pos = pos
        self._template_depth = state.template_depth
        self._brace_stack = list(state.brace_stack)
        self._line_head = state.line_head
        self.html_comment = state.html_comment

    def scan_regexp(self) -> JsToken | None:
        """
        Read a regular expression literal where scanning currently stands. ECMA-262 clause 12 picks
        the lexical goal symbol from the syntactic grammar context, which only the parser knows, so
        no path through `JsLexer.tokenize` reaches this scan: a slash is spelled as the operator it
        looks like until someone who is expecting an expression asks for it again.

        The answer is `None` where no literal stands here, which is what makes asking affordable:
        a RegularExpressionLiteral holds no line terminator, so a scan that reaches the end of its
        line has read something that is not one, and the position it started from is given back
        untouched for the caller to read as the operator it already looked like.
        """
        start = self.pos
        if self._peek() != '/':
            return None
        text = self._read_regexp()
        if text is None:
            return None
        self._line_head = False
        return JsToken(JsTokenKind.REGEXP, text, start)

    def _peek(self, count: int = 1) -> str:
        return self.source[self.pos:self.pos + count]

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _skip_whitespace(self) -> bool:
        """
        Consume the ECMA-262 WhiteSpace between two tokens. It is the whole production and not the
        space and the tab alone, because every other character in it separates tokens just as they
        do: a file that opens with a byte order mark is ordinary, and reading that mark as a token
        of its own splits one program into two statements.

        Line terminators are deliberately not consumed here. They separate tokens too, but they also
        end a line, and the parser reads the end of a line as a place a semicolon may be inserted.
        """
        start = self.pos
        src = self.source
        length = len(src)
        while self.pos < length and src[self.pos] in _WHITESPACE:
            self.pos += 1
        return self.pos > start

    def _read_line_comment(self) -> str:
        """
        Consume a comment that runs to the end of its line: one opened by `//`, one opened by
        either HTML-like delimiter, and the `#!` line, which is one. The end is looked for at once
        rather than one character at a time, because a comment is the longest run of characters
        this scan ever walks and the run is over as soon as a terminator is anywhere in it.
        """
        start = self.pos
        src = self.source
        end = _LINE_TERMINATOR.search(src, start)
        self.pos = end.start() if end else len(src)
        return src[start:self.pos]

    def _read_html_comment(self) -> JsToken:
        start = self.pos
        if self.html_comment is None:
            self.html_comment = start
        return JsToken(JsTokenKind.COMMENT, self._read_line_comment(), start)

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
            if src[self.pos] in LINE_TERMINATORS:
                has_newline = True
            self.pos += 1
        self.pos = length
        return src[start:self.pos], has_newline

    def _read_string_escape(self) -> str:
        self.pos += 1
        result, self.pos, _ = _decode_one_escape(
            self.source, self.pos, len(self.source))
        return result

    def _read_string(self, quote: str) -> tuple[str, bool]:
        """
        The string literal that begins here, and whether the closing quote was there. A literal ends
        at a line feed or a carriage return and at no other line terminator — `U+2028` and `U+2029`
        stand inside one since ES2019 — and the terminator that ends it is left unread, so the line
        still ends where the source ended it and a semicolon may be inserted there.

        The escape is consumed before that check rather than after it, which is what lets a
        backslash continue a literal onto the next line.
        """
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        while self.pos < length:
            c = src[self.pos]
            if c == '\\':
                self._read_string_escape()
                continue
            if c in '\r\n':
                break
            self.pos += 1
            if c == quote:
                return src[start:self.pos], True
        return src[start:self.pos], False

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
        return JsToken(close_kind, src[start:self.pos], start, False)

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

    def _read_regexp(self) -> str | None:
        """
        The RegularExpressionLiteral that begins here, or `None` where the text spells none. A
        backslash escapes the character after it but never a line terminator, so a literal that
        reaches the end of its line is unterminated rather than continued, and the position is
        restored so that the same text can be read again as whatever else it may be.

        RegularExpressionFirstChar admits neither a slash nor a star, which is what leaves `//` and
        `/*` to spell the two comments and nothing else.
        """
        start = self.pos
        src = self.source
        length = len(src)
        self.pos += 1
        if self._peek() in ('*', '/'):
            self.pos = start
            return None
        in_class = False
        while self.pos < length:
            c = src[self.pos]
            if c == '\\' and self.pos + 1 < length and src[self.pos + 1] not in LINE_TERMINATORS:
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
            if c in LINE_TERMINATORS:
                break
            self.pos += 1
        self.pos = start
        return None

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
        """
        The numeric literal that begins here. The digits after the point are optional where there
        are digits in front of it — `3.` is the number three — which is what makes `1..toString()`
        a call on a numeral rather than a member of a member. The point belongs to the numeral
        whenever it can, so `1.toString()` is a numeral with a name behind it and no program at all.

        A literal that opens with the point has no such option: `.5` needs its digits, and the
        point that would follow them belongs to whatever comes next. Neither has a prefixed literal,
        which ends at its digits.
        """
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

        while self.pos < length and (src[self.pos] in _DECIMAL or src[self.pos] == '_'):
            self.pos += 1
        has_integer_part = self.pos > start

        is_float = False
        if self.pos < length and src[self.pos] == '.':
            next_pos = self.pos + 1
            if next_pos < length and src[next_pos] in _DECIMAL:
                is_float = True
                self.pos += 1
                while self.pos < length and (
                    src[self.pos] in _DECIMAL or src[self.pos] == '_'
                ):
                    self.pos += 1
            elif has_integer_part:
                is_float = True
                self.pos += 1

        if self.pos < length and src[self.pos] in 'eE':
            is_float = True
            self.pos += 1
            if self.pos < length and src[self.pos] in '+-':
                self.pos += 1
            while self.pos < length and (
                src[self.pos] in _DECIMAL or src[self.pos] == '_'
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
            if _continues_a_name(c):
                self.pos += 1
            elif _begins_unicode_escape(src, self.pos):
                self._read_string_escape()
            else:
                break
        word = src[start:self.pos]
        kw = KEYWORDS.get(word)
        if kw is not None:
            return JsToken(kw, word, start)
        return JsToken(JsTokenKind.IDENTIFIER, word, start)

    def tokenize(self) -> Generator[JsToken, None, None]:
        """
        Every token of the source in order, ending in `EOF`. A line terminator puts the scan at the
        head of a line and every token but a comment moves it off again, which is what decides
        whether a `-->` opens a comment.
        """
        src = self.source
        length = len(src)

        if self.pos == 0 and src.startswith('#!'):
            self._read_line_comment()

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
                self._line_head = True
                yield JsToken(JsTokenKind.NEWLINE, '\r\n', start)
                continue
            if c in LINE_TERMINATORS:
                self.pos += 1
                self._line_head = True
                yield JsToken(JsTokenKind.NEWLINE, c, start)
                continue

            if c2 == '//':
                text = self._read_line_comment()
                yield JsToken(JsTokenKind.COMMENT, text, start)
                continue
            if c2 == '<!' and src.startswith(HTML_OPEN_COMMENT, start):
                yield self._read_html_comment()
                continue
            if c2 == '--' and self._line_head and src.startswith(HTML_CLOSE_COMMENT, start):
                yield self._read_html_comment()
                continue
            if c2 == '/*':
                text, has_newline = self._read_block_comment()
                yield JsToken(JsTokenKind.COMMENT, text, start)
                if has_newline:
                    self._line_head = True
                    yield JsToken(JsTokenKind.NEWLINE, '', self.pos)
                continue

            self._line_head = False

            if c == "'":
                text, terminated = self._read_string("'")
                yield JsToken(JsTokenKind.STRING_SINGLE, text, start, terminated)
                continue
            if c == '"':
                text, terminated = self._read_string('"')
                yield JsToken(JsTokenKind.STRING_DOUBLE, text, start, terminated)
                continue
            if c == '`':
                yield self._read_template()
                continue

            if c == '}' and self._template_depth > 0 and self._brace_stack:
                if self._brace_stack[-1] == 0:
                    self._brace_stack.pop()
                    yield self._resume_template()
                    continue
                else:
                    self._brace_stack[-1] -= 1

            if c in _DECIMAL or (
                c == '.' and src[self.pos + 1:self.pos + 2] in _DECIMAL
            ):
                yield self._read_number()
                continue

            if _at_identifier_start(src, self.pos):
                yield self._read_identifier_or_keyword()
                continue

            if c == '#':
                if _at_identifier_start(src, self.pos + 1):
                    self.pos += 1
                    name = self._read_identifier_or_keyword()
                    yield JsToken(JsTokenKind.PRIVATE_IDENTIFIER, '#' + name.value, start)
                    continue

            c4 = src[self.pos:self.pos + 4]
            if c4 in _FOUR_CHAR_OPS:
                self.pos += 4
                yield JsToken(_FOUR_CHAR_OPS[c4], c4, start)
                continue

            c3 = src[self.pos:self.pos + 3]
            if c3 in _THREE_CHAR_OPS:
                self.pos += 3
                yield JsToken(_THREE_CHAR_OPS[c3], c3, start)
                continue

            if c2 in _TWO_CHAR_OPS:
                self.pos += 2
                yield JsToken(_TWO_CHAR_OPS[c2], c2, start)
                continue

            if c in _ONE_CHAR_OPS:
                self.pos += 1
                kind = _ONE_CHAR_OPS[c]
                if kind == JsTokenKind.LBRACE and self._brace_stack:
                    self._brace_stack[-1] += 1
                yield JsToken(kind, c, start)
                continue

            self.pos += 1
            yield JsToken(JsTokenKind.ERROR, c, start)


def _decode_body(text: str) -> tuple[str, bool, bool]:
    """
    The text a literal body denotes, whether a string may carry it, and whether a template may. A
    string may carry every escape but the ones naming no character; a template may carry only the
    escapes a string and a template share, so its answer implies the other.

    The text is the code units the string is made of. A character above the basic plane is two of
    them however it was written — as itself, as one `\\u{...}` escape, or as the two `\\uXXXX`
    escapes naming its surrogates — so the three spellings denote one string here as they do in an
    engine, and a program asking how long that string is, what stands at either half of it, or
    whether it equals a string written the other way, is answered with what it would be answered.

    A lone surrogate is left standing, because JavaScript admits one in a string and no pairing rule
    may invent the partner it lacks.
    """
    if '\\' not in text:
        return to_code_units(text), True, True
    parts: list[str] = []
    string_valid = True
    template_valid = True
    i = 0
    length = len(text)
    while i < length:
        c = text[i]
        if c != '\\' or i + 1 >= length:
            parts.append(c)
            i += 1
            continue
        decoded, i, use = _decode_one_escape(text, i + 1, length)
        string_valid = string_valid and use is not _EscapeUse.NEITHER
        template_valid = template_valid and use is _EscapeUse.EITHER
        if decoded:
            parts.append(decoded)
    return to_code_units(''.join(parts)), string_valid, template_valid


def _read_unicode_escape(text: str, pos: int) -> tuple[int, int] | None:
    """
    The code point the escape at *pos* names and where it ends, or `None` where the text at *pos*
    is no unicode escape at all. A name admits this escape and no other, so this reads for it alone
    rather than through `_decode_one_escape`, which answers for every escape a string has and
    reports a malformed one as the character behind the backslash. That reading is the right one
    inside a literal and the wrong one here: `\\u061` is a string holding `u061` and is no name.

    What comes back is the code point rather than the units that spell it, because the rule the
    caller applies is about the code point: `\\ud801\\udc00` names two of them, each half of a pair
    and neither a character any name may hold, where `\\u{10400}` names the one they would have
    spelled together.
    """
    if text[pos:pos + 1] != 'u':
        return None
    pos += 1
    if text[pos:pos + 1] == '{':
        end = pos + 1
        while end < len(text) and text[end] in _HEX:
            end += 1
        if end == pos + 1 or text[end:end + 1] != '}':
            return None
        value = int(text[pos + 1:end], 16)
        return None if value > _MAX_CODE_POINT else (value, end + 1)
    digits = text[pos:pos + 4]
    if len(digits) != 4 or not _HEX.issuperset(digits):
        return None
    return int(digits, 16), pos + 4


def identifier_string_value(text: str) -> str | None:
    """
    The name *text* spells, or `None` where it spells no name at all. An escape and the character it
    names are one name written two ways, so this is what says that `\\u0061bc` and `abc` are the
    same binding, and it is the only reading of an identifier that any question about names may be
    asked of.

    The answer is code units, like every other string this package holds, so that a name written
    with a `\\u{...}` escape and the same name written with the character itself compare equal.
    Validity is decided one escape at a time and before that joining happens, which is the whole of
    the difference between the two spellings of an astral character: the pair `\\ud801\\udc00`
    names two lone surrogates, neither of which any name may hold, while `\\u{10400}` names the
    character they encode.

    Text holding no escape is answered as itself. What the scan read as a name is a name, and
    this is asked only of what it read: a text no scan produced, `0a`, would come back as
    itself here and as nothing at all written `\\u0030a`.
    """
    if '\\' not in text:
        return to_code_units(text) or None
    parts: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        c = text[i]
        if c == '\\':
            escape = _read_unicode_escape(text, i + 1)
            if escape is None:
                return None
            value, i = escape
            c = chr(value)
        else:
            i += 1
        if not (_opens_a_name(c) if not parts else _continues_a_name(c)):
            return None
        parts.append(code_units(ord(c)))
    return ''.join(parts) or None


def decode_js_string_body(text: str) -> str | None:
    """
    The text a string literal body denotes, or `None` where it denotes nothing. A string keeps the
    legacy escapes Annex B holds open for sloppy code, reading each as the character it names, so
    the one spelling it has no rule for is a `\\x` or `\\u` naming no character; the reading a
    template gives the same text is `decode_js_template_body`.
    """
    text_value, string_valid, _ = _decode_body(text)
    return text_value if string_valid else None


def has_legacy_numeric_escape(text: str) -> bool:
    """
    Whether the body of a literal was written with a legacy octal or non-octal-decimal escape: a
    backslash followed by `1` through `9`, or by `0` with another decimal digit behind it. A plain
    `\\0` is the NUL escape and is none of these, and a backslash that escapes a backslash opens no
    escape at all, so the scan steps over both rather than counting them.

    Strict code rejects such an escape, which is what reads this. A template refuses it too, but
    refuses more besides, so that rule asks the decode rather than this scan: an escape naming no
    character is a syntax error in either mode and no strict violation at all.
    """
    i = 0
    n = len(text)
    while i < n:
        if text[i] != '\\':
            i += 1
            continue
        if i + 1 >= n:
            return False
        nxt = text[i + 1]
        if nxt in '123456789':
            return True
        if nxt == '0':
            if i + 2 < n and text[i + 2] in '0123456789':
                return True
        i += 2
    return False


def decode_js_template_body(text: str) -> str | None:
    """
    What a run of template text denotes, or `None` where it denotes nothing. It is the body of a
    string literal with two rules more.

    A template is the one literal that may span lines, and every line terminator sequence in it
    denotes a line feed, so a file saved with CRLF endings holds the same template as one saved
    with LF. Normalizing before the escapes are read is what keeps a backslash at the end of a line
    a continuation in either file.

    The escapes a template admits are those of a string minus the ones Annex B keeps alive for
    sloppy code, and minus every spelling of `\\x` and `\\u` that names no character. A template
    carrying one of those is not a template at all: untagged it is a syntax error, and tagged it is
    a run whose cooked value the language states is `undefined`. There is no text it denotes, and
    answering with the text the same spelling would denote in a string is how a script no engine
    will run gets a value computed for it anyway.
    """
    if '\r' in text:
        text = text.replace('\r\n', '\n').replace('\r', '\n')
    decoded, _, template_valid = _decode_body(text)
    return decoded if template_valid else None
