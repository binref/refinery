from __future__ import annotations

import enum

from dataclasses import dataclass


class VbaTokenKind(enum.Enum):
    INTEGER        = 'integer'     # noqa
    FLOAT          = 'float'       # noqa
    STRING         = 'string'      # noqa
    DATE_LITERAL   = 'date'        # noqa
    BOOLEAN_TRUE   = 'true'        # noqa
    BOOLEAN_FALSE  = 'false'       # noqa

    IDENTIFIER     = 'identifier'  # noqa

    SUB            = 'sub'         # noqa
    FUNCTION       = 'function'    # noqa
    END            = 'end'         # noqa
    IF             = 'if'          # noqa
    THEN           = 'then'        # noqa
    ELSE           = 'else'        # noqa
    ELSEIF         = 'elseif'      # noqa
    FOR            = 'for'         # noqa
    TO             = 'to'          # noqa
    STEP           = 'step'        # noqa
    NEXT           = 'next'        # noqa
    DO             = 'do'          # noqa
    LOOP           = 'loop'        # noqa
    WHILE          = 'while'       # noqa
    WEND           = 'wend'        # noqa
    UNTIL          = 'until'       # noqa
    SELECT         = 'select'      # noqa
    CASE           = 'case'        # noqa
    WITH           = 'with'        # noqa
    SET            = 'set'         # noqa
    LET            = 'let'         # noqa
    DIM            = 'dim'         # noqa
    REDIM          = 'redim'       # noqa
    PUBLIC         = 'public'      # noqa
    PRIVATE        = 'private'     # noqa
    STATIC         = 'static'      # noqa
    CONST          = 'const'       # noqa
    AS             = 'as'          # noqa
    NEW            = 'new'         # noqa
    BYVAL          = 'byval'       # noqa
    BYREF          = 'byref'       # noqa
    OPTIONAL       = 'optional'    # noqa
    PARAMARRAY     = 'paramarray'  # noqa
    CALL           = 'call'        # noqa
    GOTO           = 'goto'        # noqa
    GOSUB          = 'gosub'       # noqa
    RETURN         = 'return'      # noqa
    EXIT           = 'exit'        # noqa
    ON             = 'on'          # noqa
    ERROR          = 'error'       # noqa
    RESUME         = 'resume'      # noqa
    OPTION         = 'option'      # noqa
    DECLARE        = 'declare'     # noqa
    TYPE           = 'type'        # noqa
    ENUM           = 'enum'        # noqa
    CLASS          = 'class'       # noqa
    MODULE         = 'module'      # noqa
    PROPERTY       = 'property'    # noqa
    GET            = 'get'         # noqa
    NOTHING        = 'nothing'     # noqa
    NULL           = 'null'        # noqa
    EMPTY          = 'empty'       # noqa
    ME             = 'me'          # noqa
    AND            = 'and'         # noqa
    OR             = 'or'          # noqa
    NOT            = 'not'         # noqa
    XOR            = 'xor'         # noqa
    EQV            = 'eqv'         # noqa
    IMP            = 'imp'         # noqa
    MOD            = 'mod'         # noqa
    LIKE           = 'like'        # noqa
    IS             = 'is'          # noqa
    EACH           = 'each'        # noqa
    IN             = 'in'          # noqa
    PRESERVE       = 'preserve'    # noqa
    EXPLICIT       = 'explicit'    # noqa
    COMPARE        = 'compare'     # noqa
    BASE           = 'base'        # noqa
    ERASE          = 'erase'       # noqa
    STOP           = 'stop'        # noqa
    DEBUG          = 'debug'       # noqa
    PRINT          = 'print'       # noqa
    EVENT          = 'event'       # noqa
    RAISEEVENT     = 'raiseevent'  # noqa
    IMPLEMENTS     = 'implements'  # noqa
    LIB            = 'lib'         # noqa
    ALIAS          = 'alias'       # noqa
    WITHEVENTS     = 'withevents'  # noqa
    TYPEOF         = 'typeof'      # noqa

    PLUS           = '+'           # noqa
    MINUS          = '-'           # noqa
    STAR           = '*'           # noqa
    SLASH          = '/'           # noqa
    BACKSLASH      = '\\'          # noqa
    CARET          = '^'           # noqa
    AMPERSAND      = '&'           # noqa
    EQ             = '='           # noqa
    NEQ            = '<>'          # noqa
    ASSIGN         = ':='          # noqa
    LT             = '<'           # noqa
    GT             = '>'           # noqa
    LTE            = '<='          # noqa
    GTE            = '>='          # noqa
    DOT            = '.'           # noqa
    BANG           = '!'           # noqa

    LPAREN         = '('           # noqa
    RPAREN         = ')'           # noqa
    COMMA          = ','           # noqa
    SEMICOLON      = ';'           # noqa
    COLON          = ':'           # noqa

    NEWLINE        = 'newline'     # noqa
    COMMENT        = 'comment'     # noqa
    EOF            = 'eof'         # noqa

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
