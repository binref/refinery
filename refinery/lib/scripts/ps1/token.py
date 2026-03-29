from __future__ import annotations

import enum

from dataclasses import dataclass


class Ps1TokenKind(enum.Enum):
    INTEGER          = 'integer'
    REAL             = 'real'
    STRING_VERBATIM  = 'sq-string'
    STRING_EXPAND    = 'dq-string'
    HSTRING_VERBATIM = 'sq-hstring'
    HSTRING_EXPAND   = 'dq-hstring'

    VARIABLE         = 'variable'
    SPLAT_VARIABLE   = 'splat-variable'
    LABEL            = 'label'

    PLUS             = '+'
    DASH             = '-'
    STAR             = '*'
    SLASH            = '/'
    PERCENT          = '%'
    DOT              = '.'
    DOTDOT           = '..'
    COMMA            = ','
    SEMICOLON        = ';'
    INCREMENT        = '++'
    DECREMENT        = '--'
    EXCLAIM          = '!'
    DOUBLE_COLON     = '::'
    DOUBLE_AMPERSAND = '&&'
    DOUBLE_PIPE      = '||'

    EQUALS           = '='
    PLUS_ASSIGN      = '+='
    DASH_ASSIGN      = '-='
    STAR_ASSIGN      = '*='
    SLASH_ASSIGN     = '/='
    PERCENT_ASSIGN   = '%='

    OPERATOR         = 'operator'
    PARAMETER        = 'parameter'
    GENERIC_TOKEN    = 'generic-token'

    LPAREN           = '('
    RPAREN           = ')'
    LBRACE           = '{'
    RBRACE           = '}'
    LBRACKET         = '['
    RBRACKET         = ']'
    AT_LPAREN        = '@('
    AT_LBRACE        = '@{'
    DOLLAR_LPAREN    = '$('

    PIPE             = '|'
    AMPERSAND        = '&'
    REDIRECTION      = 'redirection'

    IF               = 'if'
    ELSEIF           = 'elseif'
    ELSE             = 'else'
    SWITCH           = 'switch'
    WHILE            = 'while'
    FOR              = 'for'
    FOREACH          = 'foreach'
    DO               = 'do'
    UNTIL            = 'until'
    FUNCTION         = 'function'
    FILTER           = 'filter'
    RETURN           = 'return'
    BREAK            = 'break'
    CONTINUE         = 'continue'
    THROW            = 'throw'
    EXIT             = 'exit'
    TRY              = 'try'
    CATCH            = 'catch'
    FINALLY          = 'finally'
    TRAP             = 'trap'
    DATA             = 'data'
    BEGIN            = 'begin'
    PROCESS          = 'process'
    END              = 'end'
    PARAM            = 'param'
    IN               = 'in'
    CLASS            = 'class'
    USING            = 'using'
    ENUM             = 'enum'
    DYNAMICPARAM     = 'dynamicparam'

    NEWLINE          = 'newline'
    COMMENT          = 'comment'
    EOF              = 'eof'

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
