from __future__ import annotations

import enum

from dataclasses import dataclass


class VbaTokenKind(enum.Enum):
    INTEGER        = 'integer'
    FLOAT          = 'float'
    STRING         = 'string'
    DATE_LITERAL   = 'date'
    BOOLEAN_TRUE   = 'true'
    BOOLEAN_FALSE  = 'false'

    IDENTIFIER     = 'identifier'

    SUB            = 'sub'
    FUNCTION       = 'function'
    END            = 'end'
    IF             = 'if'
    THEN           = 'then'
    ELSE           = 'else'
    ELSEIF         = 'elseif'
    FOR            = 'for'
    TO             = 'to'
    STEP           = 'step'
    NEXT           = 'next'
    DO             = 'do'
    LOOP           = 'loop'
    WHILE          = 'while'
    WEND           = 'wend'
    UNTIL          = 'until'
    SELECT         = 'select'
    CASE           = 'case'
    WITH           = 'with'
    SET            = 'set'
    LET            = 'let'
    DIM            = 'dim'
    REDIM          = 'redim'
    PUBLIC         = 'public'
    PRIVATE        = 'private'
    STATIC         = 'static'
    CONST          = 'const'
    AS             = 'as'
    NEW            = 'new'
    BYVAL          = 'byval'
    BYREF          = 'byref'
    OPTIONAL       = 'optional'
    PARAMARRAY     = 'paramarray'
    CALL           = 'call'
    GOTO           = 'goto'
    GOSUB          = 'gosub'
    RETURN         = 'return'
    EXIT           = 'exit'
    ON             = 'on'
    ERROR          = 'error'
    RESUME         = 'resume'
    OPTION         = 'option'
    DECLARE        = 'declare'
    TYPE           = 'type'
    ENUM           = 'enum'
    CLASS          = 'class'
    MODULE         = 'module'
    PROPERTY       = 'property'
    GET            = 'get'
    NOTHING        = 'nothing'
    NULL           = 'null'
    EMPTY          = 'empty'
    ME             = 'me'
    AND            = 'and'
    OR             = 'or'
    NOT            = 'not'
    XOR            = 'xor'
    EQV            = 'eqv'
    IMP            = 'imp'
    MOD            = 'mod'
    LIKE           = 'like'
    IS             = 'is'
    EACH           = 'each'
    IN             = 'in'
    PRESERVE       = 'preserve'
    EXPLICIT       = 'explicit'
    COMPARE        = 'compare'
    BASE           = 'base'
    ERASE          = 'erase'
    STOP           = 'stop'
    DEBUG          = 'debug'
    PRINT          = 'print'
    EVENT          = 'event'
    RAISEEVENT     = 'raiseevent'
    IMPLEMENTS     = 'implements'
    LIB            = 'lib'
    ALIAS          = 'alias'
    WITHEVENTS     = 'withevents'
    TYPEOF         = 'typeof'

    PLUS           = '+'
    MINUS          = '-'
    STAR           = '*'
    SLASH          = '/'
    BACKSLASH      = '\\'
    CARET          = '^'
    AMPERSAND      = '&'
    EQ             = '='
    NEQ            = '<>'
    LT             = '<'
    GT             = '>'
    LTE            = '<='
    GTE            = '>='
    DOT            = '.'
    BANG           = '!'

    LPAREN         = '('
    RPAREN         = ')'
    COMMA          = ','
    SEMICOLON      = ';'
    COLON          = ':'

    NEWLINE        = 'newline'
    COMMENT        = 'comment'
    EOF            = 'eof'

    @property
    def is_keyword(self):
        return self in _KEYWORDS_SET

    @property
    def is_comparison(self):
        return self in _COMPARISON_SET

    @property
    def is_logical(self):
        return self in _LOGICAL_SET

    @property
    def is_end_of_statement(self):
        return self in (VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF)


_KEYWORDS: dict[str, VbaTokenKind] = {
    'sub'        : VbaTokenKind.SUB,
    'function'   : VbaTokenKind.FUNCTION,
    'end'        : VbaTokenKind.END,
    'if'         : VbaTokenKind.IF,
    'then'       : VbaTokenKind.THEN,
    'else'       : VbaTokenKind.ELSE,
    'elseif'     : VbaTokenKind.ELSEIF,
    'for'        : VbaTokenKind.FOR,
    'to'         : VbaTokenKind.TO,
    'step'       : VbaTokenKind.STEP,
    'next'       : VbaTokenKind.NEXT,
    'do'         : VbaTokenKind.DO,
    'loop'       : VbaTokenKind.LOOP,
    'while'      : VbaTokenKind.WHILE,
    'wend'       : VbaTokenKind.WEND,
    'until'      : VbaTokenKind.UNTIL,
    'select'     : VbaTokenKind.SELECT,
    'case'       : VbaTokenKind.CASE,
    'with'       : VbaTokenKind.WITH,
    'set'        : VbaTokenKind.SET,
    'let'        : VbaTokenKind.LET,
    'dim'        : VbaTokenKind.DIM,
    'redim'      : VbaTokenKind.REDIM,
    'public'     : VbaTokenKind.PUBLIC,
    'private'    : VbaTokenKind.PRIVATE,
    'static'     : VbaTokenKind.STATIC,
    'const'      : VbaTokenKind.CONST,
    'as'         : VbaTokenKind.AS,
    'new'        : VbaTokenKind.NEW,
    'byval'      : VbaTokenKind.BYVAL,
    'byref'      : VbaTokenKind.BYREF,
    'optional'   : VbaTokenKind.OPTIONAL,
    'paramarray' : VbaTokenKind.PARAMARRAY,
    'call'       : VbaTokenKind.CALL,
    'goto'       : VbaTokenKind.GOTO,
    'gosub'      : VbaTokenKind.GOSUB,
    'return'     : VbaTokenKind.RETURN,
    'exit'       : VbaTokenKind.EXIT,
    'on'         : VbaTokenKind.ON,
    'error'      : VbaTokenKind.ERROR,
    'resume'     : VbaTokenKind.RESUME,
    'option'     : VbaTokenKind.OPTION,
    'declare'    : VbaTokenKind.DECLARE,
    'type'       : VbaTokenKind.TYPE,
    'enum'       : VbaTokenKind.ENUM,
    'class'      : VbaTokenKind.CLASS,
    'module'     : VbaTokenKind.MODULE,
    'property'   : VbaTokenKind.PROPERTY,
    'get'        : VbaTokenKind.GET,
    'nothing'    : VbaTokenKind.NOTHING,
    'null'       : VbaTokenKind.NULL,
    'empty'      : VbaTokenKind.EMPTY,
    'me'         : VbaTokenKind.ME,
    'and'        : VbaTokenKind.AND,
    'or'         : VbaTokenKind.OR,
    'not'        : VbaTokenKind.NOT,
    'xor'        : VbaTokenKind.XOR,
    'eqv'        : VbaTokenKind.EQV,
    'imp'        : VbaTokenKind.IMP,
    'mod'        : VbaTokenKind.MOD,
    'like'       : VbaTokenKind.LIKE,
    'is'         : VbaTokenKind.IS,
    'each'       : VbaTokenKind.EACH,
    'in'         : VbaTokenKind.IN,
    'preserve'   : VbaTokenKind.PRESERVE,
    'explicit'   : VbaTokenKind.EXPLICIT,
    'compare'    : VbaTokenKind.COMPARE,
    'base'       : VbaTokenKind.BASE,
    'erase'      : VbaTokenKind.ERASE,
    'stop'       : VbaTokenKind.STOP,
    'debug'      : VbaTokenKind.DEBUG,
    'print'      : VbaTokenKind.PRINT,
    'true'       : VbaTokenKind.BOOLEAN_TRUE,
    'false'      : VbaTokenKind.BOOLEAN_FALSE,
    'event'      : VbaTokenKind.EVENT,
    'raiseevent' : VbaTokenKind.RAISEEVENT,
    'implements' : VbaTokenKind.IMPLEMENTS,
    'lib'        : VbaTokenKind.LIB,
    'alias'      : VbaTokenKind.ALIAS,
    'withevents' : VbaTokenKind.WITHEVENTS,
    'typeof'     : VbaTokenKind.TYPEOF,
}

_KEYWORDS_SET = frozenset(_KEYWORDS.values())

_COMPARISON_SET = frozenset({
    VbaTokenKind.EQ,
    VbaTokenKind.NEQ,
    VbaTokenKind.LT,
    VbaTokenKind.GT,
    VbaTokenKind.LTE,
    VbaTokenKind.GTE,
    VbaTokenKind.IS,
    VbaTokenKind.LIKE,
})

_LOGICAL_SET = frozenset({
    VbaTokenKind.AND,
    VbaTokenKind.OR,
    VbaTokenKind.XOR,
    VbaTokenKind.EQV,
    VbaTokenKind.IMP,
    VbaTokenKind.NOT,
})

_TYPE_SUFFIX_MAP: dict[str, str] = {
    '%' : 'Integer',
    '&' : 'Long',
    '!' : 'Single',
    '#' : 'Double',
    '@' : 'Currency',
    '$' : 'String',
}


@dataclass
class VbaToken:
    kind: VbaTokenKind
    value: str
    offset: int

    def __repr__(self):
        v = self.value
        if len(v) > 40:
            v = v[:37] + '...'
        return F'Token({self.kind.name}, {v!r}, @{self.offset})'
