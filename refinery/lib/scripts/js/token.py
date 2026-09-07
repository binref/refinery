from __future__ import annotations

import enum

from dataclasses import dataclass

WHITESPACE = (
    '\u0009\u000b\u000c\u0020\u00a0\u1680\u2000\u2001\u2002\u2003'
    '\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000'
    '\ufeff'
)
"""
The ECMA-262 WhiteSpace production: the tab, the vertical tab, the form feed and the zero width
no-break space, together with `<USP>`, every code point of the Unicode general category `Zs`. These
separate tokens and carry no other meaning, which is what distinguishes them from
`LINE_TERMINATORS` — a newline additionally ends a line, and the parser reads that as a place a
semicolon may be inserted. A lexer that folded the two together would insert semicolons where the
language does not.

Every member is written as an escape rather than as itself, because most of them have no width and
the rest are indistinguishable from a space: spelled as characters, the set cannot be read in a
diff and an editor that trims or normalizes whitespace edits the grammar invisibly.

Spelled out rather than derived from `unicodedata` at import time, and rather than left to
Python's `str.isspace`, which is a third set again: it takes `U+001C` through `U+001F` and
`U+0085`, which the language does not, and leaves `U+FEFF`, which the language takes.
"""

ASCII_WHITESPACE = '\u0009\u000a\u000c\u000d\u0020'
"""
The WHATWG definition of ASCII whitespace, which is what a forgiving base64 decode removes from the
argument of `atob` before it reads it. It is a third set beside the two above and a subset of
neither's purpose: it holds two line terminators, and it holds none of the space separators, so a
`U+00A0` or a `U+FEFF` in such an argument is a character the decode refuses rather than skips.
"""

LINE_TERMINATORS = '\u000a\u000d\u2028\u2029'
"""
The ECMA-262 LineTerminator production: the line feed, the carriage return, the line separator and
the paragraph separator. A `\\r\\n` pair is one terminator and not two. The last two are
written as escapes for the reason `WHITESPACE` is: a raw `U+2028` in a Python source file is a
line break to `str.splitlines` and to most editors, and to Python's own tokenizer it is not.
"""


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
    PRIVATE_IDENTIFIER = 'private-identifier'  # noqa

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
    AT              = '@'                # noqa

    NEWLINE         = 'newline'          # noqa
    COMMENT         = 'comment'          # noqa
    HASHBANG        = 'hashbang'         # noqa
    ERROR           = 'error'            # noqa
    EOF             = 'eof'              # noqa

    #: A kind is a singleton compared by identity, so its identity is its hash; the base class
    #: hashes the member's name through a Python-level call on every set or dictionary lookup.
    __hash__ = object.__hash__

    @property
    def is_keyword(self):
        return self in _KEYWORDS_SET

    @property
    def is_assignment(self):
        return self in _ASSIGNMENT_SET

    @property
    def is_string(self):
        return self in _STRING_SET


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

RESERVED_WORD_NAMES: frozenset[str] = frozenset(
    set(KEYWORDS) - {'let', 'of', 'from', 'as', 'async', 'await', 'yield'} | {'enum'}
)
"""
The words no name may be, whatever the mode and whatever encloses it. ECMA-262 refuses a name whose
StringValue is that of a ReservedWord (12.7.2) with `await` and `yield` excepted, because those two
are names wherever the enclosing function does not make them operators, which is a question about
that function rather than about the word.

`KEYWORDS` is every word the scan gives a kind of its own, which is more than these: five of them
are read as terminals in some positions and as names in others, and `let`, `of`, `from`, `as` and
`async` name things in programs that run. A word added to `KEYWORDS` therefore has to be put on one
side of this or the other, and the side is whether any program may use it as a name.
"""

TERMINAL_IDENTIFIERS: frozenset[str] = frozenset({
    'get',
    'set',
    'static',
    'target',
    'meta',
    'assert',
})
"""
The words a production matches as a terminal although the scan hands them over as identifiers, so
that a name written as one of them may be read as the terminal instead. `class C { static m(){} }`
declares one member and `class C { static; m(){} }` declares two.
"""

SPELLING_REFUSED_NAMES: frozenset[str] = frozenset({
    'eval',
    'arguments',
})
"""
The names whose two spellings a running engine tells apart, so that re-spelling one from the name it
denotes changes what the file does. ECMA-262 states the early error over the StringValue and refuses
both spellings, and V8 refuses both the moment it compiles the function for real — but it does not
compile a function it has not been asked to run, and its pre-parser reads the escaped spelling
without complaint. So `'use strict'; function f(eval) {}` is a file V8 refuses outright and
`'use strict'; function f(ev\\u0061l) {}` is one it loads, and a file whose function is never called
runs or does not depending on which of the two was written.

Measured against Node 24 over 28 words in 12 positions: these two in a parameter list are the whole
of where the spelling decides, and every other word ECMA-262 reserves is refused in both spellings
alike. Nothing here says the escaped spelling is a program — only that writing the name out is a
different one, which is the whole of what a synthesizer needs to know.
"""


def spells_only_a_name(name: str) -> bool:
    """
    Whether *name* written as itself is read as that name and as nothing else. Two kinds of word
    are not: one a production matches as a terminal, and one a rule is stated over the spelling of.
    In either case the source spelling is the only text that says which reading was meant, and a
    synthesizer that re-spells such a name from what it denotes writes the other one.
    """
    return (
        name not in KEYWORDS
        and name not in TERMINAL_IDENTIFIERS
        and name not in SPELLING_REFUSED_NAMES
    )


_STRING_SET = frozenset({JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE})

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
    """
    One token, where `value` is the text the source spelled it with. `terminated` reports whether a
    token that needs a closing delimiter found one: a line or a file can end in the middle of a
    literal, and whoever reads the text between the delimiters cannot tell from that text alone —
    the last character of a string that ends in an escaped quote is a quote either way.
    """
    kind: JsTokenKind
    value: str
    offset: int
    terminated: bool = True

    def __repr__(self):
        v = self.value
        if len(v) > 15:
            v = F'{v[:8]}..{v[-4:]}'
        return F'Token({self.kind.name}, {v!r}, {self.offset})'
