from __future__ import annotations

import enum

from dataclasses import dataclass


class JsTokenKind(enum.Enum):
    INTEGER         = 'integer'          # noqa
    FLOAT           = 'float'            # noqa
    BIGINT          = 'bigint'           # noqa
    STRING_SINGLE   = 'sq-string'        # noqa
    STRING_DOUBLE   = 'dq-string'        # noqa
    TEMPLATE_FULL   = 'template-full'    # noqa
    TEMPLATE_HEAD   = 'template-head'    # noqa
    TEMPLATE_MIDDLE = 'template-middle'  # noqa
    TEMPLATE_TAIL   = 'template-tail'    # noqa
    REGEXP          = 'regexp'           # noqa

    IDENTIFIER      = 'identifier'       # noqa

    VAR             = 'var'              # noqa
    LET             = 'let'              # noqa
    CONST           = 'const'            # noqa
    FUNCTION        = 'function'         # noqa
    CLASS           = 'class'            # noqa
    IF              = 'if'               # noqa
    ELSE            = 'else'             # noqa
    FOR             = 'for'              # noqa
    WHILE           = 'while'            # noqa
    DO              = 'do'               # noqa
    SWITCH          = 'switch'           # noqa
    CASE            = 'case'             # noqa
    DEFAULT         = 'default'          # noqa
    BREAK           = 'break'            # noqa
    CONTINUE        = 'continue'         # noqa
    RETURN          = 'return'           # noqa
    THROW           = 'throw'            # noqa
    TRY             = 'try'              # noqa
    CATCH           = 'catch'            # noqa
    FINALLY         = 'finally'          # noqa
    NEW             = 'new'              # noqa
    DELETE          = 'delete'           # noqa
    TYPEOF          = 'typeof'           # noqa
    VOID            = 'void'             # noqa
    INSTANCEOF      = 'instanceof'       # noqa
    IN              = 'in'               # noqa
    OF              = 'of'               # noqa
    IMPORT          = 'import'           # noqa
    EXPORT          = 'export'           # noqa
    FROM            = 'from'             # noqa
    AS              = 'as'               # noqa
    YIELD           = 'yield'            # noqa
    AWAIT           = 'await'            # noqa
    ASYNC           = 'async'            # noqa
    EXTENDS         = 'extends'          # noqa
    SUPER           = 'super'            # noqa
    THIS            = 'this'             # noqa
    NULL            = 'null'             # noqa
    TRUE            = 'true'             # noqa
    FALSE           = 'false'            # noqa
    DEBUGGER        = 'debugger'         # noqa
    WITH            = 'with'             # noqa

    PLUS            = '+'                # noqa
    MINUS           = '-'                # noqa
    STAR            = '*'                # noqa
    SLASH           = '/'                # noqa
    PERCENT         = '%'                # noqa
    STAR2           = '**'               # noqa
    EQUALS          = '='                # noqa
    PLUS_ASSIGN     = '+='               # noqa
    MINUS_ASSIGN    = '-='               # noqa
    STAR_ASSIGN     = '*='               # noqa
    SLASH_ASSIGN    = '/='               # noqa
    PERCENT_ASSIGN  = '%='               # noqa
    STAR2_ASSIGN    = '**='              # noqa
    AMP_ASSIGN      = '&='               # noqa
    PIPE_ASSIGN     = '|='               # noqa
    CARET_ASSIGN    = '^='               # noqa
    LT2_ASSIGN      = '<<='              # noqa
    GT2_ASSIGN      = '>>='              # noqa
    GT3_ASSIGN      = '>>>='             # noqa
    AND_ASSIGN      = '&&='              # noqa
    OR_ASSIGN       = '||='              # noqa
    NULLISH_ASSIGN  = '??='              # noqa
    EQ2             = '=='               # noqa
    EQ3             = '==='              # noqa
    BANG_EQ         = '!='               # noqa
    BANG_EQ2        = '!=='              # noqa
    LT              = '<'                # noqa
    GT              = '>'                # noqa
    LT_EQ           = '<='               # noqa
    GT_EQ           = '>='               # noqa
    AND             = '&&'               # noqa
    OR              = '||'               # noqa
    QQ              = '??'               # noqa
    BANG            = '!'                # noqa
    AMP             = '&'                # noqa
    PIPE            = '|'                # noqa
    CARET           = '^'                # noqa
    TILDE           = '~'                # noqa
    LT2             = '<<'               # noqa
    GT2             = '>>'               # noqa
    GT3             = '>>>'              # noqa
    INC             = '++'               # noqa
    DEC             = '--'               # noqa
    DOT             = '.'                # noqa
    ELLIPSIS        = '...'              # noqa
    QUESTION_DOT    = '?.'               # noqa
    ARROW           = '=>'               # noqa
    QUESTION        = '?'                # noqa
    COLON           = ':'                # noqa

    LPAREN          = '('                # noqa
    RPAREN          = ')'                # noqa
    LBRACE          = '{'                # noqa
    RBRACE          = '}'                # noqa
    LBRACKET        = '['                # noqa
    RBRACKET        = ']'                # noqa
    SEMICOLON       = ';'                # noqa
    COMMA           = ','                # noqa

    NEWLINE         = 'newline'          # noqa
    COMMENT         = 'comment'          # noqa
    EOF             = 'eof'              # noqa

    @property
    def is_keyword(self):
        return self in _KEYWORDS_SET

    @property
    def is_assignment(self):
        return self in _ASSIGNMENT_SET


KEYWORDS: dict[str, JsTokenKind] = {
    tok.value: tok for tok in [
        JsTokenKind.VAR,
        JsTokenKind.LET,
        JsTokenKind.CONST,
        JsTokenKind.FUNCTION,
        JsTokenKind.CLASS,
        JsTokenKind.IF,
        JsTokenKind.ELSE,
        JsTokenKind.FOR,
        JsTokenKind.WHILE,
        JsTokenKind.DO,
        JsTokenKind.SWITCH,
        JsTokenKind.CASE,
        JsTokenKind.DEFAULT,
        JsTokenKind.BREAK,
        JsTokenKind.CONTINUE,
        JsTokenKind.RETURN,
        JsTokenKind.THROW,
        JsTokenKind.TRY,
        JsTokenKind.CATCH,
        JsTokenKind.FINALLY,
        JsTokenKind.NEW,
        JsTokenKind.DELETE,
        JsTokenKind.TYPEOF,
        JsTokenKind.VOID,
        JsTokenKind.INSTANCEOF,
        JsTokenKind.IN,
        JsTokenKind.OF,
        JsTokenKind.IMPORT,
        JsTokenKind.EXPORT,
        JsTokenKind.FROM,
        JsTokenKind.AS,
        JsTokenKind.YIELD,
        JsTokenKind.AWAIT,
        JsTokenKind.ASYNC,
        JsTokenKind.EXTENDS,
        JsTokenKind.SUPER,
        JsTokenKind.THIS,
        JsTokenKind.NULL,
        JsTokenKind.TRUE,
        JsTokenKind.FALSE,
        JsTokenKind.DEBUGGER,
        JsTokenKind.WITH,
    ]
}

_KEYWORDS_SET = frozenset(KEYWORDS.values())

FUTURE_RESERVED: frozenset[str] = frozenset({
    'enum',
    'implements',
    'interface',
    'package',
    'private',
    'protected',
    'public',
    'static',
})

_ASSIGNMENT_SET = frozenset({
    JsTokenKind.EQUALS,
    JsTokenKind.PLUS_ASSIGN,
    JsTokenKind.MINUS_ASSIGN,
    JsTokenKind.STAR_ASSIGN,
    JsTokenKind.SLASH_ASSIGN,
    JsTokenKind.PERCENT_ASSIGN,
    JsTokenKind.STAR2_ASSIGN,
    JsTokenKind.AMP_ASSIGN,
    JsTokenKind.PIPE_ASSIGN,
    JsTokenKind.CARET_ASSIGN,
    JsTokenKind.LT2_ASSIGN,
    JsTokenKind.GT2_ASSIGN,
    JsTokenKind.GT3_ASSIGN,
    JsTokenKind.AND_ASSIGN,
    JsTokenKind.OR_ASSIGN,
    JsTokenKind.NULLISH_ASSIGN,
})


@dataclass
class JsToken:
    kind: JsTokenKind
    value: str
    offset: int

    def __repr__(self):
        v = self.value
        if len(v) > 15:
            v = F'{v[:8]}..{v[-4:]}'
        return F'Token({self.kind.name}, {v!r}, {self.offset})'
