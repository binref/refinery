from __future__ import annotations

import enum

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
    COMMENT          = 'comment'         # noqa
    EOF              = 'eof'             # noqa

    @property
    def is_keyword(self):
        return self in _KEYWORDS_SET

    @property
    def is_assignment(self):
        return self in (
            Ps1TokenKind.EQUALS,
            Ps1TokenKind.PLUS_ASSIGN,
            Ps1TokenKind.DASH_ASSIGN,
            Ps1TokenKind.STAR_ASSIGN,
            Ps1TokenKind.SLASH_ASSIGN,
            Ps1TokenKind.PERCENT_ASSIGN,
        )


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
