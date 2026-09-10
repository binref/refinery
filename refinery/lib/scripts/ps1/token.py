from __future__ import annotations

import enum
import unicodedata

from dataclasses import dataclass

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

#: The inverse of `BACKTICK_ESCAPE`: how a character that cannot stand for itself inside a
#: double-quoted string is written. It belongs beside the table it inverts, and beside the lexer
#: that reads what it writes, so that reading and writing an escape stay one fact.
BACKTICK_ENCODE = {v: F'`{k}' for k, v in BACKTICK_ESCAPE.items()}

SINGLE_QUOTES = frozenset("'\u2018\u2019\u201A\u201B")
DOUBLE_QUOTES = frozenset('"\u201C\u201D\u201E')
DASHES = frozenset('-\u2013\u2014\u2015')

#: The Unicode general categories a space, a line separator and a paragraph separator carry. Above
#: Latin-1 these are the whole of PowerShell's whitespace rule, which asks `char.IsSeparator` and
#: nothing of its own.
_SEPARATOR_CATEGORIES = frozenset(('Zl', 'Zp', 'Zs'))

#: The ASCII characters PowerShell passes over between two tokens. A newline is deliberately not one
#: of them: it ends a statement, so it is a token rather than the space around one.
_ASCII_WHITESPACE = frozenset(' \t\v\f')

#: The two characters above ASCII and below `_SEPARATOR_CATEGORIES`' reach that PowerShell names one
#: at a time. Neither is settled by category: a no-break space is a separator and would be found
#: anyway, and a next-line control is not one and would not.
_LATIN1_WHITESPACE = frozenset('\u00A0\u0085')

#: The ASCII characters that end the token being read, whatever that token began with. This is what
#: makes `a#b` one word where `a{` is two.
_ASCII_FORCE_NEW_TOKEN = frozenset(' \t\n\v\f\r&(),;{|}')

#: The ASCII characters that end a token only where it began with a digit, which is the whole of the
#: difference between `7z` and `7+`. A `?` and a `:` are not among them: they end a numeral from 7.0
#: onwards, where a ternary operator may follow one, and on 5.1 `1?` is a single word.
_ASCII_FORCE_NEW_TOKEN_AFTER_NUMBER = frozenset('!#%*+-./<=>]')


def is_whitespace(c: str) -> bool:
    """
    Whether `c` stands between two tokens without being one. Above Latin-1 the question is Unicode's
    rather than PowerShell's — every separator counts, so an em space and a line separator part two
    words exactly as a space does — and below it the answer is a table, which is why a vertical tab
    and a form feed are whitespace while a carriage return is not.
    """
    if c < '\x80':
        return c in _ASCII_WHITESPACE
    if c <= '\u0100':
        return c in _LATIN1_WHITESPACE
    return unicodedata.category(c) in _SEPARATOR_CATEGORIES


def forces_new_token(c: str) -> bool:
    """
    Whether `c` ends the token being read, whatever that token began with. Above ASCII that is
    exactly whitespace; below it there are a handful more.

    The empty string stands for the end of the source, and it ends every token. PowerShell says the
    same thing by reading a NUL past the last character and listing the NUL in the table, which is
    a spelling this cannot borrow: the reader here asks about its own first character, where
    PowerShell's has already taken one, so a NUL in the set would part a word beginning with one
    that PowerShell keeps whole.
    """
    if not c:
        return True
    if c < '\x80':
        return c in _ASCII_FORCE_NEW_TOKEN
    return is_whitespace(c)


def forces_new_token_after_number(c: str) -> bool:
    """
    Whether `c` ends a token that began with a digit. A numeral ends on more characters than a word
    does, which is the whole of why `7z` is one token and `7+` is two. Above ASCII a dash is the
    only one, in each of the spellings `DASHES` accepts.

    The end of the source is not among them and is not meant to be: it is `forces_new_token` that
    answers for it, and a reader has to ask that one first anyway, because what ends every token
    ends a numeral too.
    """
    if c < '\x80':
        return c in _ASCII_FORCE_NEW_TOKEN_AFTER_NUMBER
    return c in DASHES


NORMALIZE_QUOTES = str.maketrans({
    '\u2018': "'",
    '\u2019': "'",
    '\u201A': "'",
    '\u201B': "'",
    '\u201C': '"',
    '\u201D': '"',
    '\u201E': '"',
})

_VARIABLE_PATTERN_CORE = (
    r'(?:[a-zA-Z0-9_]+:(?!:))?'
    r'(?:\{[^}]+\}|[a-zA-Z0-9_][a-zA-Z0-9_?]*)'
    r'|[$?^]'
)


def _strip_backtick_noop(name: str) -> str:
    result: list[str] = []
    i = 0
    while i < len(name):
        if name[i] == '`' and i + 1 < len(name):
            result.append(name[i + 1])
            i += 2
            continue
        result.append(name[i])
        i += 1
    return ''.join(result)


class Ps1TokenKind(enum.Enum):
    INTEGER          = 'integer'         # noqa
    REAL             = 'real'            # noqa
    STRING_VERBATIM  = 'sq-string'       # noqa
    STRING_EXPAND    = 'dq-string'       # noqa
    HSTRING_VERBATIM = 'sq-hstring'      # noqa
    HSTRING_EXPAND   = 'dq-hstring'      # noqa

    VARIABLE         = 'variable'        # noqa
    SPLAT_VARIABLE   = 'splat-variable'  # noqa
    LABEL            = 'label'           # noqa

    PLUS             = '+'               # noqa
    DASH             = '-'               # noqa
    STAR             = '*'               # noqa
    SLASH            = '/'               # noqa
    PERCENT          = '%'               # noqa
    DOT              = '.'               # noqa
    DOTDOT           = '..'              # noqa
    COMMA            = ','               # noqa
    SEMICOLON        = ';'               # noqa
    INCREMENT        = '++'              # noqa
    DECREMENT        = '--'              # noqa
    EXCLAIM          = '!'               # noqa
    DOUBLE_COLON     = '::'              # noqa
    DOUBLE_AMPERSAND = '&&'              # noqa
    DOUBLE_PIPE      = '||'              # noqa

    EQUALS           = '='               # noqa
    PLUS_ASSIGN      = '+='              # noqa
    DASH_ASSIGN      = '-='              # noqa
    STAR_ASSIGN      = '*='              # noqa
    SLASH_ASSIGN     = '/='              # noqa
    PERCENT_ASSIGN   = '%='              # noqa

    OPERATOR         = 'operator'        # noqa
    PARAMETER        = 'parameter'       # noqa
    GENERIC_TOKEN    = 'generic-token'   # noqa
    GENERIC_EXPAND   = 'generic-expand'  # noqa

    LPAREN           = '('               # noqa
    RPAREN           = ')'               # noqa
    LBRACE           = '{'               # noqa
    RBRACE           = '}'               # noqa
    LBRACKET         = '['               # noqa
    RBRACKET         = ']'               # noqa
    AT_LPAREN        = '@('              # noqa
    AT_LBRACE        = '@{'              # noqa
    DOLLAR_LPAREN    = '$('              # noqa

    PIPE             = '|'               # noqa
    AMPERSAND        = '&'               # noqa
    REDIRECTION      = 'redirection'     # noqa
    REDIRECT_IN      = '<'               # noqa

    IF               = 'if'              # noqa
    ELSEIF           = 'elseif'          # noqa
    ELSE             = 'else'            # noqa
    SWITCH           = 'switch'          # noqa
    WHILE            = 'while'           # noqa
    FOR              = 'for'             # noqa
    FOREACH          = 'foreach'         # noqa
    DO               = 'do'              # noqa
    UNTIL            = 'until'           # noqa
    FUNCTION         = 'function'        # noqa
    FILTER           = 'filter'          # noqa
    RETURN           = 'return'          # noqa
    BREAK            = 'break'           # noqa
    CONTINUE         = 'continue'        # noqa
    THROW            = 'throw'           # noqa
    EXIT             = 'exit'            # noqa
    TRY              = 'try'             # noqa
    CATCH            = 'catch'           # noqa
    FINALLY          = 'finally'         # noqa
    TRAP             = 'trap'            # noqa
    DATA             = 'data'            # noqa
    BEGIN            = 'begin'           # noqa
    PROCESS          = 'process'         # noqa
    END              = 'end'             # noqa
    PARAM            = 'param'           # noqa
    IN               = 'in'              # noqa
    CLASS            = 'class'           # noqa
    USING            = 'using'           # noqa
    ENUM             = 'enum'            # noqa
    DYNAMICPARAM     = 'dynamicparam'    # noqa

    NEWLINE          = 'newline'         # noqa
    EOF              = 'eof'             # noqa

    @property
    def is_keyword(self):
        return self in _KEYWORDS_SET

    @property
    def is_assignment(self):
        return self in _ASSIGNMENT_SET

    @property
    def mode_invariant(self):
        """
        Whether the text of a token of this kind reads the same in every
        `refinery.lib.scripts.ps1.lexer.Ps1LexerMode`. A parser holding one as lookahead may keep it
        across a mode change, because scanning it again could not produce anything else. A kind
        earns membership only by being witnessed in the material the invariance test drives: an
        entry that test cannot reach is a claim nothing checks, and skipping the re-read is worth
        nothing next to that.
        """
        return self in _MODE_INVARIANT_SET


_KEYWORDS: dict[str, Ps1TokenKind] = {
    'if'           : Ps1TokenKind.IF,
    'elseif'       : Ps1TokenKind.ELSEIF,
    'else'         : Ps1TokenKind.ELSE,
    'switch'       : Ps1TokenKind.SWITCH,
    'while'        : Ps1TokenKind.WHILE,
    'for'          : Ps1TokenKind.FOR,
    'foreach'      : Ps1TokenKind.FOREACH,
    'do'           : Ps1TokenKind.DO,
    'until'        : Ps1TokenKind.UNTIL,
    'function'     : Ps1TokenKind.FUNCTION,
    'filter'       : Ps1TokenKind.FILTER,
    'return'       : Ps1TokenKind.RETURN,
    'break'        : Ps1TokenKind.BREAK,
    'continue'     : Ps1TokenKind.CONTINUE,
    'throw'        : Ps1TokenKind.THROW,
    'exit'         : Ps1TokenKind.EXIT,
    'try'          : Ps1TokenKind.TRY,
    'catch'        : Ps1TokenKind.CATCH,
    'finally'      : Ps1TokenKind.FINALLY,
    'trap'         : Ps1TokenKind.TRAP,
    'data'         : Ps1TokenKind.DATA,
    'begin'        : Ps1TokenKind.BEGIN,
    'process'      : Ps1TokenKind.PROCESS,
    'end'          : Ps1TokenKind.END,
    'param'        : Ps1TokenKind.PARAM,
    'in'           : Ps1TokenKind.IN,
    'class'        : Ps1TokenKind.CLASS,
    'using'        : Ps1TokenKind.USING,
    'enum'         : Ps1TokenKind.ENUM,
    'dynamicparam' : Ps1TokenKind.DYNAMICPARAM,
}

_KEYWORDS_SET = frozenset(_KEYWORDS.values())

_ASSIGNMENT_SET = frozenset((
    Ps1TokenKind.EQUALS,
    Ps1TokenKind.PLUS_ASSIGN,
    Ps1TokenKind.DASH_ASSIGN,
    Ps1TokenKind.STAR_ASSIGN,
    Ps1TokenKind.SLASH_ASSIGN,
    Ps1TokenKind.PERCENT_ASSIGN,
))

_MODE_INVARIANT_SET = frozenset((
    Ps1TokenKind.AMPERSAND,
    Ps1TokenKind.AT_LBRACE,
    Ps1TokenKind.AT_LPAREN,
    Ps1TokenKind.COMMA,
    Ps1TokenKind.DOLLAR_LPAREN,
    Ps1TokenKind.EOF,
    Ps1TokenKind.HSTRING_VERBATIM,
    Ps1TokenKind.LBRACE,
    Ps1TokenKind.LPAREN,
    Ps1TokenKind.NEWLINE,
    Ps1TokenKind.PIPE,
    Ps1TokenKind.RBRACE,
    Ps1TokenKind.RBRACKET,
    Ps1TokenKind.RPAREN,
    Ps1TokenKind.SEMICOLON,
    Ps1TokenKind.STRING_EXPAND,
    Ps1TokenKind.STRING_VERBATIM,
))

KEYWORD_SPELLING: dict[str, str] = {
    'param': 'Param',
}


@dataclass
class Ps1Token:
    kind: Ps1TokenKind
    value: str
    offset: int

    def __repr__(self):
        v = self.value
        if len(v) > 40:
            v = v[:37] + '...'
        return F'Token({self.kind.name}, {v!r}, @{self.offset})'
