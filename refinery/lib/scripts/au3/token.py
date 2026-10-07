from __future__ import annotations

import enum

from dataclasses import dataclass


class Au3TokenKind(enum.Enum):
    INTEGER             = 'integer'           # noqa
    FLOAT               = 'float'             # noqa
    STRING              = 'string'            # noqa
    VARIABLE            = 'variable'          # noqa
    MACRO               = 'macro'             # noqa
    IDENTIFIER          = 'identifier'        # noqa

    AND                 = 'and'               # noqa
    OR                  = 'or'                # noqa
    NOT                 = 'not'               # noqa
    IF                  = 'if'                # noqa
    THEN                = 'then'              # noqa
    ELSE                = 'else'              # noqa
    ELSEIF              = 'elseif'             # noqa
    ENDIF               = 'endif'             # noqa
    WHILE               = 'while'             # noqa
    WEND                = 'wend'              # noqa
    DO                  = 'do'                # noqa
    UNTIL               = 'until'             # noqa
    FOR                 = 'for'               # noqa
    NEXT                = 'next'              # noqa
    TO                  = 'to'                # noqa
    STEP                = 'step'              # noqa
    IN                  = 'in'                # noqa
    EXITLOOP            = 'exitloop'          # noqa
    CONTINUELOOP        = 'continueloop'      # noqa
    SELECT              = 'select'            # noqa
    CASE                = 'case'              # noqa
    ENDSELECT           = 'endselect'         # noqa
    SWITCH              = 'switch'            # noqa
    ENDSWITCH           = 'endswitch'         # noqa
    CONTINUECASE        = 'continuecase'       # noqa
    DIM                 = 'dim'               # noqa
    REDIM               = 'redim'             # noqa
    LOCAL               = 'local'             # noqa
    GLOBAL              = 'global'            # noqa
    CONST               = 'const'             # noqa
    STATIC              = 'static'            # noqa
    FUNC                = 'func'              # noqa
    ENDFUNC             = 'endfunc'           # noqa
    RETURN              = 'return'            # noqa
    EXIT                = 'exit'              # noqa
    BYREF               = 'byref'             # noqa
    WITH                = 'with'              # noqa
    ENDWITH             = 'endwith'           # noqa
    TRUE                = 'true'              # noqa
    FALSE               = 'false'             # noqa
    DEFAULT             = 'default'           # noqa
    NULL                = 'null'              # noqa
    VOLATILE            = 'volatile'          # noqa
    ENUM                = 'enum'              # noqa

    ASSIGN_OR_EQ        = '='                 # noqa
    EQ_STRICT           = '=='                # noqa
    NE                  = '<>'                # noqa
    LE                  = '<='                # noqa
    GE                  = '>='                # noqa
    PLUS_ASSIGN         = '+='                # noqa
    MINUS_ASSIGN        = '-='                # noqa
    MUL_ASSIGN          = '*='                # noqa
    DIV_ASSIGN          = '/='                # noqa
    CONCAT_ASSIGN       = '&='                # noqa
    PLUS                = '+'                 # noqa
    MINUS               = '-'                 # noqa
    STAR                = '*'                 # noqa
    SLASH               = '/'                 # noqa
    CARET               = '^'                 # noqa
    AMP                 = '&'                 # noqa
    LT                  = '<'                 # noqa
    GT                  = '>'                 # noqa
    QUESTION            = '?'                 # noqa
    COLON               = ':'                 # noqa
    LPAREN              = '('                 # noqa
    RPAREN              = ')'                 # noqa
    LBRACKET            = '['                 # noqa
    RBRACKET            = ']'                 # noqa
    COMMA               = ','                 # noqa
    DOT                 = '.'                 # noqa

    DIRECTIVE           = 'directive'         # noqa
    COMMENT             = 'comment'           # noqa
    NEWLINE             = 'newline'           # noqa
    ERROR               = 'error'             # noqa
    EOF                 = 'eof'               # noqa

    @property
    def is_keyword(self) -> bool:
        return self in _KEYWORDS_SET


KEYWORD_SPELLINGS: dict[Au3TokenKind, str] = {
    Au3TokenKind.AND           : 'And',
    Au3TokenKind.OR            : 'Or',
    Au3TokenKind.NOT           : 'Not',
    Au3TokenKind.IF            : 'If',
    Au3TokenKind.THEN          : 'Then',
    Au3TokenKind.ELSE          : 'Else',
    Au3TokenKind.ELSEIF        : 'ElseIf',
    Au3TokenKind.ENDIF         : 'EndIf',
    Au3TokenKind.WHILE         : 'While',
    Au3TokenKind.WEND          : 'Wend',
    Au3TokenKind.DO            : 'Do',
    Au3TokenKind.UNTIL         : 'Until',
    Au3TokenKind.FOR           : 'For',
    Au3TokenKind.NEXT          : 'Next',
    Au3TokenKind.TO            : 'To',
    Au3TokenKind.STEP          : 'Step',
    Au3TokenKind.IN            : 'In',
    Au3TokenKind.EXITLOOP      : 'ExitLoop',
    Au3TokenKind.CONTINUELOOP  : 'ContinueLoop',
    Au3TokenKind.SELECT        : 'Select',
    Au3TokenKind.CASE          : 'Case',
    Au3TokenKind.ENDSELECT     : 'EndSelect',
    Au3TokenKind.SWITCH        : 'Switch',
    Au3TokenKind.ENDSWITCH     : 'EndSwitch',
    Au3TokenKind.CONTINUECASE  : 'ContinueCase',
    Au3TokenKind.DIM           : 'Dim',
    Au3TokenKind.REDIM         : 'ReDim',
    Au3TokenKind.LOCAL         : 'Local',
    Au3TokenKind.GLOBAL        : 'Global',
    Au3TokenKind.CONST         : 'Const',
    Au3TokenKind.STATIC        : 'Static',
    Au3TokenKind.FUNC          : 'Func',
    Au3TokenKind.ENDFUNC       : 'EndFunc',
    Au3TokenKind.RETURN        : 'Return',
    Au3TokenKind.EXIT          : 'Exit',
    Au3TokenKind.BYREF         : 'ByRef',
    Au3TokenKind.WITH          : 'With',
    Au3TokenKind.ENDWITH       : 'EndWith',
    Au3TokenKind.TRUE          : 'True',
    Au3TokenKind.FALSE         : 'False',
    Au3TokenKind.DEFAULT       : 'Default',
    Au3TokenKind.NULL          : 'Null',
    Au3TokenKind.VOLATILE      : 'Volatile',
    Au3TokenKind.ENUM          : 'Enum',
}

KEYWORDS: dict[str, Au3TokenKind] = {
    spelling.lower(): kind for kind, spelling in KEYWORD_SPELLINGS.items()
}

_KEYWORDS_SET = frozenset(KEYWORDS.values())


@dataclass
class Au3Token:
    kind: Au3TokenKind
    value: str
    offset: int

    def __repr__(self):
        v = self.value
        if len(v) > 15:
            v = F'{v[:8]}..{v[-4:]}'
        return F'Token({self.kind.name}, {v!r}, {self.offset})'
