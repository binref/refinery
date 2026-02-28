"""
ASN.1 Module Definition Compiler

Parses standard ASN.1 module definition syntax and produces the Python DSL
objects used by the refinery ASN.1 reader. Supports the subset of ASN.1
notation used in cryptographic RFCs (X.509, CMS, PKCS, TSP, etc.).

Usage::

    from refinery.lib.asn1.compiler import compile_asn1

    schemas = compile_asn1('''
        X509 DEFINITIONS EXPLICIT TAGS ::= BEGIN
            Certificate ::= SEQUENCE {
                tbsCertificate      TBSCertificate,
                signatureAlgorithm  AlgorithmIdentifier,
                signatureValue      BIT STRING
            }
        END
    ''')
"""
from __future__ import annotations

import re
from enum import Enum, auto

from refinery.lib.asn1.schema import (
    CLASS_APPLICATION,
    CLASS_CONTEXT,
    ANY,
    BIT_STRING,
    BOOLEAN,
    ENUMERATED,
    GEN_TIME,
    IA5_STRING,
    INTEGER,
    NULL,
    OCTET_STRING,
    OID,
    PRINTABLE_STRING,
    UTF8_STRING,
    UTC_TIME,
    Choice,
    F,
    SchemaType,
    Seq,
    SeqOf,
    SetOf,
)


class _TT(Enum):
    IDENT = auto()
    NUMBER = auto()
    LBRACE = auto()
    RBRACE = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    COMMA = auto()
    ASSIGN = auto()
    DOTDOT = auto()
    SEMICOLON = auto()
    PIPE = auto()
    EOF = auto()


_TOKEN_PATTERN = re.compile(r'''
    (?P<comment>--[^\n]*)
  | (?P<assign>::=)
  | (?P<dotdot>\.\.\.?)
  | (?P<number>-?[0-9]+)
  | (?P<ident>[A-Za-z][A-Za-z0-9-]*)
  | (?P<lbrace>\{)
  | (?P<rbrace>\})
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<lbracket>\[)
  | (?P<rbracket>\])
  | (?P<comma>,)
  | (?P<semicolon>;)
  | (?P<pipe>\|)
  | (?P<ws>\s+)
''', re.VERBOSE)


class _Token:
    __slots__ = ('type', 'value', 'pos')

    def __init__(self, type: _TT, value: str, pos: int):
        self.type = type
        self.value = value
        self.pos = pos

    def __repr__(self) -> str:
        return f'Token({self.type.name}, {self.value!r})'


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_PATTERN.match(text, pos)
        if m is None:
            raise SyntaxError(f'unexpected character at position {pos}: {text[pos]!r}')
        pos = m.end()
        if m.lastgroup in ('comment', 'ws'):
            continue
        if m.lastgroup == 'assign':
            tokens.append(_Token(_TT.ASSIGN, '::=', m.start()))
        elif m.lastgroup == 'dotdot':
            tokens.append(_Token(_TT.DOTDOT, '..', m.start()))
        elif m.lastgroup == 'number':
            tokens.append(_Token(_TT.NUMBER, m.group(), m.start()))
        elif m.lastgroup == 'ident':
            tokens.append(_Token(_TT.IDENT, m.group(), m.start()))
        elif m.lastgroup == 'lbrace':
            tokens.append(_Token(_TT.LBRACE, '{', m.start()))
        elif m.lastgroup == 'rbrace':
            tokens.append(_Token(_TT.RBRACE, '}', m.start()))
        elif m.lastgroup == 'lparen':
            tokens.append(_Token(_TT.LPAREN, '(', m.start()))
        elif m.lastgroup == 'rparen':
            tokens.append(_Token(_TT.RPAREN, ')', m.start()))
        elif m.lastgroup == 'lbracket':
            tokens.append(_Token(_TT.LBRACKET, '[', m.start()))
        elif m.lastgroup == 'rbracket':
            tokens.append(_Token(_TT.RBRACKET, ']', m.start()))
        elif m.lastgroup == 'comma':
            tokens.append(_Token(_TT.COMMA, ',', m.start()))
        elif m.lastgroup == 'semicolon':
            tokens.append(_Token(_TT.SEMICOLON, ';', m.start()))
        elif m.lastgroup == 'pipe':
            tokens.append(_Token(_TT.PIPE, '|', m.start()))
    tokens.append(_Token(_TT.EOF, '', len(text)))
    return tokens


_BUILTIN_TYPE_MAP: dict[str, int] = {
    'BOOLEAN': BOOLEAN,
    'INTEGER': INTEGER,
    'NULL': NULL,
    'ENUMERATED': ENUMERATED,
    'UTCTime': UTC_TIME,
    'GeneralizedTime': GEN_TIME,
    'UTF8String': UTF8_STRING,
    'PrintableString': PRINTABLE_STRING,
    'IA5String': IA5_STRING,
    'T61String': 20,
    'TeletexString': 20,
    'BMPString': 30,
    'VisibleString': 26,
    'GeneralString': 27,
    'NumericString': 18,
    'UniversalString': 28,
}


class _Parser:
    def __init__(self, tokens: list[_Token], externals: dict[str, SchemaType] | None = None):
        self._tokens = tokens
        self._pos = 0
        self._assignments: dict[str, object] = {}
        self._tag_default: str = 'EXPLICIT'
        self._externals = externals or {}

    def _peek(self) -> _Token:
        return self._tokens[self._pos]

    def _advance(self) -> _Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect_type(self, tt: _TT) -> _Token:
        tok = self._advance()
        if tok.type != tt:
            raise SyntaxError(
                f'expected {tt.name}, got {tok.type.name} ({tok.value!r}) at position {tok.pos}')
        return tok

    def _expect_ident(self, value: str | None = None) -> _Token:
        tok = self._expect_type(_TT.IDENT)
        if value is not None and tok.value != value:
            raise SyntaxError(
                f'expected {value!r}, got {tok.value!r} at position {tok.pos}')
        return tok

    def _check_ident(self, value: str) -> bool:
        tok = self._peek()
        return tok.type == _TT.IDENT and tok.value == value

    def _check_type(self, tt: _TT) -> bool:
        return self._peek().type == tt

    def _try_consume_ident(self, value: str) -> bool:
        if self._check_ident(value):
            self._advance()
            return True
        return False

    def parse_module(self) -> dict[str, SchemaType]:
        # module_name
        self._expect_type(_TT.IDENT)
        self._expect_ident('DEFINITIONS')

        # optional tag default
        if self._check_ident('IMPLICIT'):
            self._advance()
            self._expect_ident('TAGS')
            self._tag_default = 'IMPLICIT'
        elif self._check_ident('EXPLICIT'):
            self._advance()
            self._expect_ident('TAGS')
            self._tag_default = 'EXPLICIT'

        # optional EXTENSIBILITY IMPLIED
        self._try_consume_ident('EXTENSIBILITY')
        self._try_consume_ident('IMPLIED')

        self._expect_type(_TT.ASSIGN)
        self._expect_ident('BEGIN')

        # optional EXPORTS
        if self._check_ident('EXPORTS'):
            self._advance()
            while not self._check_type(_TT.SEMICOLON):
                self._advance()
            self._advance()  # consume semicolon

        # optional IMPORTS
        if self._check_ident('IMPORTS'):
            self._parse_imports()

        # assignments until END
        while not self._check_ident('END'):
            if self._check_type(_TT.EOF):
                break
            self._parse_assignment()

        return self._resolve()

    def _parse_imports(self) -> None:
        self._expect_ident('IMPORTS')
        while not self._check_type(_TT.SEMICOLON):
            # ident_list FROM module_name
            names: list[str] = []
            while True:
                names.append(self._expect_type(_TT.IDENT).value)
                if self._check_type(_TT.COMMA):
                    self._advance()
                else:
                    break
            self._expect_ident('FROM')
            self._expect_type(_TT.IDENT)
            # optional OID value after module name
            if self._check_type(_TT.LBRACE):
                self._skip_braces()
        self._expect_type(_TT.SEMICOLON)

    def _parse_assignment(self) -> None:
        name_tok = self._expect_type(_TT.IDENT)
        name = name_tok.value
        self._expect_type(_TT.ASSIGN)
        schema = self._parse_type()
        self._assignments[name] = schema

    def _parse_type(self) -> object:
        # tagged type: [N] IMPLICIT/EXPLICIT Type
        if self._check_type(_TT.LBRACKET):
            return self._parse_tagged_type()

        tok = self._peek()

        if tok.type == _TT.IDENT:
            val = tok.value

            if val == 'SEQUENCE':
                self._advance()
                if self._check_type(_TT.LBRACE):
                    return self._parse_sequence()
                elif self._check_ident('OF'):
                    self._advance()
                    element = self._parse_type()
                    return ('SeqOf', element)
                elif self._check_type(_TT.LPAREN):
                    self._skip_constraint()
                    if self._check_ident('OF'):
                        self._advance()
                        element = self._parse_type()
                        return ('SeqOf', element)
                    return SEQUENCE
                return SEQUENCE

            if val == 'SET':
                self._advance()
                if self._check_type(_TT.LBRACE):
                    return self._parse_set_body()
                elif self._check_ident('OF'):
                    self._advance()
                    element = self._parse_type()
                    return ('SetOf', element)
                elif self._check_type(_TT.LPAREN):
                    self._skip_constraint()
                    if self._check_ident('OF'):
                        self._advance()
                        element = self._parse_type()
                        return ('SetOf', element)
                    return SET
                return SET

            if val == 'CHOICE':
                self._advance()
                return self._parse_choice()

            if val == 'ENUMERATED':
                self._advance()
                if self._check_type(_TT.LBRACE):
                    self._skip_braces()
                return ENUMERATED

            if val == 'BIT':
                self._advance()
                self._expect_ident('STRING')
                if self._check_type(_TT.LPAREN):
                    self._skip_constraint()
                if self._check_type(_TT.LBRACE):
                    self._skip_braces()
                return BIT_STRING

            if val == 'OCTET':
                self._advance()
                self._expect_ident('STRING')
                if self._check_type(_TT.LPAREN):
                    self._skip_constraint()
                return OCTET_STRING

            if val == 'OBJECT':
                self._advance()
                self._expect_ident('IDENTIFIER')
                return OID

            if val == 'ANY':
                self._advance()
                if self._check_ident('DEFINED'):
                    self._advance()
                    self._expect_ident('BY')
                    self._expect_type(_TT.IDENT)
                return ANY

            if val == 'BOOLEAN':
                self._advance()
                return BOOLEAN

            if val == 'INTEGER':
                self._advance()
                if self._check_type(_TT.LPAREN):
                    self._skip_constraint()
                if self._check_type(_TT.LBRACE):
                    self._skip_braces()
                return INTEGER

            if val == 'NULL':
                self._advance()
                return NULL

            if val in _BUILTIN_TYPE_MAP:
                self._advance()
                if self._check_type(_TT.LPAREN):
                    self._skip_constraint()
                return _BUILTIN_TYPE_MAP[val]

            # type reference
            self._advance()
            if self._check_type(_TT.LPAREN):
                self._skip_constraint()
            return ('TypeRef', val)

        raise SyntaxError(
            f'unexpected token {tok.type.name} ({tok.value!r}) at position {tok.pos} while parsing type')

    def _parse_tagged_type(self) -> object:
        self._expect_type(_TT.LBRACKET)

        tag_class_val = CLASS_CONTEXT
        if self._check_ident('APPLICATION'):
            self._advance()
            tag_class_val = CLASS_APPLICATION

        tag_num = int(self._expect_type(_TT.NUMBER).value)
        self._expect_type(_TT.RBRACKET)

        tagging: str | None = None
        if self._check_ident('IMPLICIT'):
            self._advance()
            tagging = 'IMPLICIT'
        elif self._check_ident('EXPLICIT'):
            self._advance()
            tagging = 'EXPLICIT'

        if tagging is None:
            tagging = self._tag_default

        inner = self._parse_type()
        return ('Tagged', tag_num, tagging, inner, tag_class_val)

    def _parse_sequence(self) -> object:
        self._expect_type(_TT.LBRACE)
        fields: list[object] = []

        while not self._check_type(_TT.RBRACE):
            # extension marker
            if self._check_type(_TT.DOTDOT):
                self._advance()
                if self._check_type(_TT.DOTDOT):
                    self._advance()
                if self._check_type(_TT.COMMA):
                    self._advance()
                continue

            field = self._parse_field()
            fields.append(field)

            if self._check_type(_TT.COMMA):
                self._advance()

        self._expect_type(_TT.RBRACE)
        return ('Seq', fields)

    def _parse_set_body(self) -> object:
        self._expect_type(_TT.LBRACE)
        fields: list[object] = []

        while not self._check_type(_TT.RBRACE):
            if self._check_type(_TT.DOTDOT):
                self._advance()
                if self._check_type(_TT.DOTDOT):
                    self._advance()
                if self._check_type(_TT.COMMA):
                    self._advance()
                continue

            field = self._parse_field()
            fields.append(field)

            if self._check_type(_TT.COMMA):
                self._advance()

        self._expect_type(_TT.RBRACE)
        return ('Set', fields)

    def _parse_field(self) -> object:
        name = self._expect_type(_TT.IDENT).value
        ftype = self._parse_type()

        optional = False
        default = None
        has_default = False

        if self._check_ident('OPTIONAL'):
            self._advance()
            optional = True
        elif self._check_ident('DEFAULT'):
            self._advance()
            has_default = True
            default = self._parse_default_value()

        return ('Field', name, ftype, optional, has_default, default)

    def _parse_default_value(self) -> object:
        tok = self._peek()
        if tok.type == _TT.NUMBER:
            self._advance()
            return int(tok.value)
        if tok.type == _TT.IDENT:
            if tok.value == 'TRUE':
                self._advance()
                return True
            if tok.value == 'FALSE':
                self._advance()
                return False
            if tok.value == 'NULL':
                self._advance()
                return None
            # named value or enumerated value - consume it
            self._advance()
            # could be a named number from INTEGER { ... }
            return tok.value
        # fallback: skip until COMMA/RBRACE
        self._advance()
        return None

    def _parse_choice(self) -> object:
        self._expect_type(_TT.LBRACE)
        alts: list[object] = []

        while not self._check_type(_TT.RBRACE):
            if self._check_type(_TT.DOTDOT):
                self._advance()
                if self._check_type(_TT.DOTDOT):
                    self._advance()
                if self._check_type(_TT.COMMA):
                    self._advance()
                continue

            name = self._expect_type(_TT.IDENT).value
            atype = self._parse_type()
            alts.append(('Alt', name, atype))

            if self._check_type(_TT.COMMA):
                self._advance()

        self._expect_type(_TT.RBRACE)
        return ('Choice', alts)

    def _skip_constraint(self) -> None:
        self._expect_type(_TT.LPAREN)
        depth = 1
        while depth > 0:
            tok = self._advance()
            if tok.type == _TT.LPAREN:
                depth += 1
            elif tok.type == _TT.RPAREN:
                depth -= 1
            elif tok.type == _TT.EOF:
                raise SyntaxError('unexpected EOF in constraint')

    def _skip_braces(self) -> None:
        self._expect_type(_TT.LBRACE)
        depth = 1
        while depth > 0:
            tok = self._advance()
            if tok.type == _TT.LBRACE:
                depth += 1
            elif tok.type == _TT.RBRACE:
                depth -= 1
            elif tok.type == _TT.EOF:
                raise SyntaxError('unexpected EOF in braces')

    def _resolve(self) -> dict[str, SchemaType]:
        resolved: dict[str, SchemaType] = {}
        resolved.update(self._externals)

        def resolve_type(t: object) -> SchemaType:
            if isinstance(t, int) or t is ANY:
                return t

            if isinstance(t, tuple):
                tag = t[0]

                if tag == 'TypeRef':
                    name = t[1]
                    if name in resolved:
                        return resolved[name]
                    if name in self._assignments:
                        resolved[name] = _resolve_assignment(name)
                        return resolved[name]
                    if name in _BUILTIN_TYPE_MAP:
                        return _BUILTIN_TYPE_MAP[name]
                    return ANY

                if tag == 'Seq':
                    fields = t[1]
                    return Seq(*[_resolve_field(f) for f in fields])

                if tag == 'Set':
                    fields = t[1]
                    return Seq(*[_resolve_field(f) for f in fields])

                if tag == 'SeqOf':
                    return SeqOf(resolve_type(t[1]))

                if tag == 'SetOf':
                    return SetOf(resolve_type(t[1]))

                if tag == 'Choice':
                    alts = t[1]
                    return Choice(*[_resolve_alt(a) for a in alts])

                if tag == 'Tagged':
                    # This is handled at the field level, shouldn't appear standalone
                    # at top level except in assignment like:
                    #   Foo ::= [0] IMPLICIT Bar
                    # In that case, just resolve the inner type
                    return resolve_type(t[3])

            return ANY

        def _resolve_field(f: object) -> F:
            assert isinstance(f, tuple) and f[0] == 'Field'
            _, name, ftype, optional, has_default, default = f

            implicit: int | None = None
            explicit: int | None = None
            tag_class_val: int = CLASS_CONTEXT

            # unwrap tagged type
            actual_type = ftype
            if isinstance(ftype, tuple) and ftype[0] == 'Tagged':
                tag_num, tagging, inner, tag_class_val = ftype[1], ftype[2], ftype[3], ftype[4]
                actual_type = inner
                if tagging == 'IMPLICIT':
                    implicit = tag_num
                else:
                    explicit = tag_num

            resolved_type = resolve_type(actual_type)

            kwargs: dict[str, object] = {}
            if implicit is not None:
                kwargs['implicit'] = implicit
            if explicit is not None:
                kwargs['explicit'] = explicit
            if tag_class_val != CLASS_CONTEXT:
                kwargs['tag_class'] = tag_class_val
            if has_default:
                kwargs['default'] = default
            elif optional:
                kwargs['optional'] = True

            return F(name, resolved_type, **kwargs)  # type: ignore

        def _resolve_alt(a: object) -> F:
            assert isinstance(a, tuple) and a[0] == 'Alt'
            _, name, atype = a

            implicit: int | None = None
            explicit: int | None = None
            tag_class_val: int = CLASS_CONTEXT

            actual_type = atype
            if isinstance(atype, tuple) and atype[0] == 'Tagged':
                tag_num, tagging, inner, tag_class_val = atype[1], atype[2], atype[3], atype[4]
                actual_type = inner
                if tagging == 'IMPLICIT':
                    implicit = tag_num
                else:
                    explicit = tag_num

            resolved_type = resolve_type(actual_type)

            kwargs: dict[str, object] = {}
            if implicit is not None:
                kwargs['implicit'] = implicit
            if explicit is not None:
                kwargs['explicit'] = explicit
            if tag_class_val != CLASS_CONTEXT:
                kwargs['tag_class'] = tag_class_val

            return F(name, resolved_type, **kwargs)  # type: ignore

        def _resolve_assignment(name: str) -> SchemaType:
            if name in resolved:
                return resolved[name]
            raw = self._assignments[name]
            # place a sentinel to detect cycles
            resolved[name] = ANY
            result = resolve_type(raw)
            resolved[name] = result
            return result

        for name in self._assignments:
            if name not in resolved:
                _resolve_assignment(name)

        return resolved


def compile_asn1(
    text: str,
    externals: dict[str, SchemaType] | None = None,
) -> dict[str, SchemaType]:
    """
    Parse ASN.1 module definition text and return a dictionary mapping
    type names to DSL schema objects.

    Args:
        text: ASN.1 module text with ``DEFINITIONS ::= BEGIN ... END`` envelope.
        externals: Pre-resolved type names to inject (e.g. from other modules).

    Returns:
        Dictionary mapping type names to schema objects (Seq, SeqOf, etc.).
    """
    tokens = _tokenize(text)
    parser = _Parser(tokens, externals)
    return parser.parse_module()
