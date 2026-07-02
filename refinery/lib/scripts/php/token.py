from __future__ import annotations

import enum

from dataclasses import dataclass


class PhpTokenKind(enum.Enum):
    INLINE_HTML     = 'inline-html'      # noqa
    OPEN_TAG        = 'open-tag'         # noqa
    OPEN_TAG_ECHO   = 'open-tag-echo'    # noqa
    CLOSE_TAG       = 'close-tag'        # noqa

    INTEGER         = 'integer'          # noqa
    FLOAT           = 'float'            # noqa
    STRING_SINGLE   = 'sq-string'        # noqa
    STRING_DOUBLE   = 'dq-string'        # noqa
    SHELL_EXEC      = 'backtick-string'  # noqa
    HEREDOC         = 'heredoc'          # noqa
    NOWDOC          = 'nowdoc'           # noqa

    VARIABLE        = 'variable'         # noqa
    IDENTIFIER      = 'identifier'       # noqa

    INCLUDE         = 'include'          # noqa
    INCLUDE_ONCE    = 'include_once'     # noqa
    REQUIRE         = 'require'          # noqa
    REQUIRE_ONCE    = 'require_once'     # noqa
    EVAL            = 'eval'             # noqa
    PRINT           = 'print'            # noqa
    ECHO            = 'echo'             # noqa
    EXIT            = 'exit'             # noqa

    LOGICAL_OR      = 'or'               # noqa
    LOGICAL_XOR     = 'xor'              # noqa
    LOGICAL_AND     = 'and'              # noqa
    INSTANCEOF      = 'instanceof'       # noqa
    NEW             = 'new'              # noqa
    CLONE           = 'clone'            # noqa
    YIELD           = 'yield'            # noqa

    IF              = 'if'               # noqa
    ELSEIF          = 'elseif'           # noqa
    ELSE            = 'else'             # noqa
    ENDIF           = 'endif'            # noqa
    DO              = 'do'               # noqa
    WHILE           = 'while'            # noqa
    ENDWHILE        = 'endwhile'         # noqa
    FOR             = 'for'              # noqa
    ENDFOR          = 'endfor'           # noqa
    FOREACH         = 'foreach'          # noqa
    ENDFOREACH      = 'endforeach'       # noqa
    SWITCH          = 'switch'           # noqa
    ENDSWITCH       = 'endswitch'        # noqa
    CASE            = 'case'             # noqa
    DEFAULT         = 'default'          # noqa
    MATCH           = 'match'            # noqa
    BREAK           = 'break'            # noqa
    CONTINUE        = 'continue'         # noqa
    GOTO            = 'goto'             # noqa
    RETURN          = 'return'           # noqa
    THROW           = 'throw'            # noqa
    TRY             = 'try'              # noqa
    CATCH           = 'catch'            # noqa
    FINALLY         = 'finally'          # noqa
    DECLARE         = 'declare'          # noqa
    ENDDECLARE      = 'enddeclare'       # noqa
    AS              = 'as'               # noqa

    FUNCTION        = 'function'         # noqa
    FN              = 'fn'               # noqa
    CONST           = 'const'            # noqa
    USE             = 'use'              # noqa
    INSTEADOF       = 'insteadof'        # noqa
    GLOBAL          = 'global'           # noqa
    STATIC          = 'static'           # noqa
    ABSTRACT        = 'abstract'         # noqa
    FINAL           = 'final'            # noqa
    PRIVATE         = 'private'          # noqa
    PROTECTED       = 'protected'        # noqa
    PUBLIC          = 'public'           # noqa
    READONLY        = 'readonly'         # noqa
    VAR             = 'var'              # noqa
    UNSET           = 'unset'            # noqa
    ISSET           = 'isset'            # noqa
    EMPTY           = 'empty'            # noqa
    HALT_COMPILER   = '__halt_compiler'  # noqa
    LIST            = 'list'             # noqa
    ARRAY           = 'array'            # noqa
    CALLABLE        = 'callable'         # noqa

    CLASS           = 'class'            # noqa
    TRAIT           = 'trait'            # noqa
    INTERFACE       = 'interface'        # noqa
    ENUM            = 'enum'             # noqa
    EXTENDS         = 'extends'          # noqa
    IMPLEMENTS      = 'implements'       # noqa
    NAMESPACE       = 'namespace'        # noqa

    LINE            = '__LINE__'         # noqa
    FILE            = '__FILE__'         # noqa
    DIR             = '__DIR__'          # noqa
    CLASS_C         = '__CLASS__'        # noqa
    TRAIT_C         = '__TRAIT__'        # noqa
    METHOD_C        = '__METHOD__'       # noqa
    FUNC_C          = '__FUNCTION__'     # noqa
    NS_C            = '__NAMESPACE__'    # noqa

    PLUS            = '+'                # noqa
    MINUS           = '-'                # noqa
    STAR            = '*'                # noqa
    SLASH           = '/'                # noqa
    PERCENT         = '%'                # noqa
    POW             = '**'               # noqa
    DOT             = '.'                # noqa
    EQUALS          = '='                # noqa
    PLUS_EQUAL      = '+='               # noqa
    MINUS_EQUAL     = '-='               # noqa
    MUL_EQUAL       = '*='               # noqa
    DIV_EQUAL       = '/='               # noqa
    MOD_EQUAL       = '%='               # noqa
    POW_EQUAL       = '**='              # noqa
    CONCAT_EQUAL    = '.='               # noqa
    AND_EQUAL       = '&='               # noqa
    OR_EQUAL        = '|='               # noqa
    XOR_EQUAL       = '^='               # noqa
    SL_EQUAL        = '<<='              # noqa
    SR_EQUAL        = '>>='              # noqa
    COALESCE_EQUAL  = '??='              # noqa
    BOOLEAN_OR      = '||'               # noqa
    BOOLEAN_AND     = '&&'               # noqa
    IS_EQUAL        = '=='               # noqa
    IS_NOT_EQUAL    = '!='               # noqa
    IS_IDENTICAL    = '==='              # noqa
    IS_NOT_IDENTICAL = '!=='             # noqa
    LT              = '<'                # noqa
    GT              = '>'                # noqa
    IS_SMALLER_OR_EQUAL = '<='           # noqa
    IS_GREATER_OR_EQUAL = '>='           # noqa
    SPACESHIP       = '<=>'              # noqa
    SL              = '<<'               # noqa
    SR              = '>>'               # noqa
    COALESCE        = '??'               # noqa
    AMP             = '&'                # noqa
    PIPE            = '|'                # noqa
    CARET           = '^'                # noqa
    TILDE           = '~'                # noqa
    BANG            = '!'                # noqa
    INC             = '++'               # noqa
    DEC             = '--'               # noqa
    AT              = '@'                # noqa
    QUESTION        = '?'                # noqa
    COLON           = ':'                # noqa
    DOUBLE_ARROW    = '=>'               # noqa
    OBJECT_OPERATOR = '->'               # noqa
    NULLSAFE_OPERATOR = '?->'            # noqa
    DOUBLE_COLON    = '::'               # noqa
    NS_SEPARATOR    = '\\'               # noqa
    ELLIPSIS        = '...'              # noqa
    ATTRIBUTE       = '#['               # noqa

    INT_CAST        = '(int)'            # noqa
    FLOAT_CAST      = '(float)'          # noqa
    STRING_CAST     = '(string)'         # noqa
    ARRAY_CAST      = '(array)'          # noqa
    OBJECT_CAST     = '(object)'         # noqa
    BOOL_CAST       = '(bool)'           # noqa
    UNSET_CAST      = '(unset)'          # noqa

    LPAREN          = '('                # noqa
    RPAREN          = ')'                # noqa
    LBRACE          = '{'                # noqa
    RBRACE          = '}'                # noqa
    LBRACKET        = '['                # noqa
    RBRACKET        = ']'                # noqa
    SEMICOLON       = ';'                # noqa
    COMMA           = ','                # noqa
    DOLLAR          = '$'                # noqa

    COMMENT         = 'comment'          # noqa
    DOC_COMMENT     = 'doc-comment'      # noqa
    NEWLINE         = 'newline'          # noqa
    ERROR           = 'error'            # noqa
    EOF             = 'eof'              # noqa

    @property
    def is_keyword(self) -> bool:
        return self in _KEYWORDS_SET

    @property
    def is_cast(self) -> bool:
        return self in _CAST_SET


KEYWORDS: dict[str, PhpTokenKind] = {
    tok.value: tok for tok in [
        PhpTokenKind.INCLUDE,
        PhpTokenKind.INCLUDE_ONCE,
        PhpTokenKind.REQUIRE,
        PhpTokenKind.REQUIRE_ONCE,
        PhpTokenKind.EVAL,
        PhpTokenKind.PRINT,
        PhpTokenKind.ECHO,
        PhpTokenKind.EXIT,
        PhpTokenKind.LOGICAL_OR,
        PhpTokenKind.LOGICAL_XOR,
        PhpTokenKind.LOGICAL_AND,
        PhpTokenKind.INSTANCEOF,
        PhpTokenKind.NEW,
        PhpTokenKind.CLONE,
        PhpTokenKind.YIELD,
        PhpTokenKind.IF,
        PhpTokenKind.ELSEIF,
        PhpTokenKind.ELSE,
        PhpTokenKind.ENDIF,
        PhpTokenKind.DO,
        PhpTokenKind.WHILE,
        PhpTokenKind.ENDWHILE,
        PhpTokenKind.FOR,
        PhpTokenKind.ENDFOR,
        PhpTokenKind.FOREACH,
        PhpTokenKind.ENDFOREACH,
        PhpTokenKind.SWITCH,
        PhpTokenKind.ENDSWITCH,
        PhpTokenKind.CASE,
        PhpTokenKind.DEFAULT,
        PhpTokenKind.MATCH,
        PhpTokenKind.BREAK,
        PhpTokenKind.CONTINUE,
        PhpTokenKind.GOTO,
        PhpTokenKind.RETURN,
        PhpTokenKind.THROW,
        PhpTokenKind.TRY,
        PhpTokenKind.CATCH,
        PhpTokenKind.FINALLY,
        PhpTokenKind.DECLARE,
        PhpTokenKind.ENDDECLARE,
        PhpTokenKind.AS,
        PhpTokenKind.FUNCTION,
        PhpTokenKind.FN,
        PhpTokenKind.CONST,
        PhpTokenKind.USE,
        PhpTokenKind.INSTEADOF,
        PhpTokenKind.GLOBAL,
        PhpTokenKind.STATIC,
        PhpTokenKind.ABSTRACT,
        PhpTokenKind.FINAL,
        PhpTokenKind.PRIVATE,
        PhpTokenKind.PROTECTED,
        PhpTokenKind.PUBLIC,
        PhpTokenKind.READONLY,
        PhpTokenKind.VAR,
        PhpTokenKind.UNSET,
        PhpTokenKind.ISSET,
        PhpTokenKind.EMPTY,
        PhpTokenKind.HALT_COMPILER,
        PhpTokenKind.LIST,
        PhpTokenKind.ARRAY,
        PhpTokenKind.CALLABLE,
        PhpTokenKind.CLASS,
        PhpTokenKind.TRAIT,
        PhpTokenKind.INTERFACE,
        PhpTokenKind.ENUM,
        PhpTokenKind.EXTENDS,
        PhpTokenKind.IMPLEMENTS,
        PhpTokenKind.NAMESPACE,
        PhpTokenKind.LINE,
        PhpTokenKind.FILE,
        PhpTokenKind.DIR,
        PhpTokenKind.CLASS_C,
        PhpTokenKind.TRAIT_C,
        PhpTokenKind.METHOD_C,
        PhpTokenKind.FUNC_C,
        PhpTokenKind.NS_C,
    ]
}

_KEYWORDS_SET = frozenset(KEYWORDS.values())

_CAST_SET = frozenset({
    PhpTokenKind.INT_CAST,
    PhpTokenKind.FLOAT_CAST,
    PhpTokenKind.STRING_CAST,
    PhpTokenKind.ARRAY_CAST,
    PhpTokenKind.OBJECT_CAST,
    PhpTokenKind.BOOL_CAST,
    PhpTokenKind.UNSET_CAST,
})

MAGIC_CONSTANTS = frozenset({
    PhpTokenKind.LINE,
    PhpTokenKind.FILE,
    PhpTokenKind.DIR,
    PhpTokenKind.CLASS_C,
    PhpTokenKind.TRAIT_C,
    PhpTokenKind.METHOD_C,
    PhpTokenKind.FUNC_C,
    PhpTokenKind.NS_C,
})

CAST_KEYWORDS: dict[str, PhpTokenKind] = {
    'int'     : PhpTokenKind.INT_CAST,
    'integer' : PhpTokenKind.INT_CAST,
    'float'   : PhpTokenKind.FLOAT_CAST,
    'double'  : PhpTokenKind.FLOAT_CAST,
    'real'    : PhpTokenKind.FLOAT_CAST,
    'string'  : PhpTokenKind.STRING_CAST,
    'array'   : PhpTokenKind.ARRAY_CAST,
    'object'  : PhpTokenKind.OBJECT_CAST,
    'bool'    : PhpTokenKind.BOOL_CAST,
    'boolean' : PhpTokenKind.BOOL_CAST,
    'unset'   : PhpTokenKind.UNSET_CAST,
}


@dataclass
class PhpToken:
    kind: PhpTokenKind
    value: str
    offset: int

    def __repr__(self):
        v = self.value
        if len(v) > 15:
            v = F'{v[:8]}..{v[-4:]}'
        return F'Token({self.kind.name}, {v!r}, {self.offset})'
