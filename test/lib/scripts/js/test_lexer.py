from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.lexer import JsLexer
from refinery.lib.scripts.js.token import JsTokenKind


class TestJsLexer(TestBase):

    def _tokens(self, source: str) -> list[tuple[JsTokenKind, str]]:
        lexer = JsLexer(source)
        result = []
        for tok in lexer.tokenize():
            if tok.kind == JsTokenKind.EOF:
                break
            result.append((tok.kind, tok.value))
        return result

    def _token_kinds(self, source: str) -> list[JsTokenKind]:
        return [k for k, _ in self._tokens(source)]

    def test_integer_decimal(self):
        tokens = self._tokens('42')
        self.assertEqual(tokens, [(JsTokenKind.INTEGER, '42')])

    def test_integer_hex(self):
        tokens = self._tokens('0xFF')
        self.assertEqual(tokens, [(JsTokenKind.INTEGER, '0xFF')])

    def test_integer_octal(self):
        tokens = self._tokens('0o77')
        self.assertEqual(tokens, [(JsTokenKind.INTEGER, '0o77')])

    def test_integer_binary(self):
        tokens = self._tokens('0b1010')
        self.assertEqual(tokens, [(JsTokenKind.INTEGER, '0b1010')])

    def test_float_decimal(self):
        tokens = self._tokens('3.14')
        self.assertEqual(tokens, [(JsTokenKind.FLOAT, '3.14')])

    def test_float_leading_dot(self):
        tokens = self._tokens('.5')
        self.assertEqual(tokens, [(JsTokenKind.FLOAT, '.5')])

    def test_float_exponent(self):
        tokens = self._tokens('1e10')
        self.assertEqual(tokens, [(JsTokenKind.FLOAT, '1e10')])

    def test_float_exponent_negative(self):
        tokens = self._tokens('2.5e-3')
        self.assertEqual(tokens, [(JsTokenKind.FLOAT, '2.5e-3')])

    def test_bigint(self):
        tokens = self._tokens('100n')
        self.assertEqual(tokens, [(JsTokenKind.BIGINT, '100n')])

    def test_bigint_hex(self):
        tokens = self._tokens('0xFFn')
        self.assertEqual(tokens, [(JsTokenKind.BIGINT, '0xFFn')])

    def test_numeric_separators(self):
        tokens = self._tokens('1_000_000')
        self.assertEqual(tokens, [(JsTokenKind.INTEGER, '1_000_000')])

    def test_string_single(self):
        tokens = self._tokens("'hello'")
        self.assertEqual(tokens, [(JsTokenKind.STRING_SINGLE, "'hello'")])

    def test_string_double(self):
        tokens = self._tokens('"world"')
        self.assertEqual(tokens, [(JsTokenKind.STRING_DOUBLE, '"world"')])

    def test_string_escape(self):
        tokens = self._tokens(r"'he\'llo'")
        self.assertEqual(tokens, [(JsTokenKind.STRING_SINGLE, r"'he\'llo'")])

    def test_string_unicode_escape(self):
        tokens = self._tokens(r"'\u0041'")
        self.assertEqual(tokens, [(JsTokenKind.STRING_SINGLE, r"'\u0041'")])

    def test_template_full(self):
        tokens = self._tokens('`hello`')
        self.assertEqual(tokens, [(JsTokenKind.TEMPLATE_FULL, '`hello`')])

    def test_template_with_expression(self):
        kinds = self._token_kinds('`a${x}b`')
        self.assertEqual(kinds, [
            JsTokenKind.TEMPLATE_HEAD,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.TEMPLATE_TAIL,
        ])

    def test_template_multiple_expressions(self):
        kinds = self._token_kinds('`${a}mid${b}end`')
        self.assertEqual(kinds, [
            JsTokenKind.TEMPLATE_HEAD,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.TEMPLATE_MIDDLE,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.TEMPLATE_TAIL,
        ])

    def test_template_nested(self):
        kinds = self._token_kinds('`${`inner`}`')
        self.assertEqual(kinds, [
            JsTokenKind.TEMPLATE_HEAD,
            JsTokenKind.TEMPLATE_FULL,
            JsTokenKind.TEMPLATE_TAIL,
        ])

    def test_regexp(self):
        tokens = self._tokens('/abc/gi')
        self.assertEqual(tokens, [(JsTokenKind.REGEXP, '/abc/gi')])

    def test_regexp_with_class(self):
        tokens = self._tokens('/[a-z]+/i')
        self.assertEqual(tokens, [(JsTokenKind.REGEXP, '/[a-z]+/i')])

    def test_regexp_vs_division(self):
        kinds = self._token_kinds('x / y')
        self.assertEqual(kinds, [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.SLASH,
            JsTokenKind.IDENTIFIER,
        ])

    def test_regexp_after_equals(self):
        kinds = self._token_kinds('x = /re/')
        self.assertEqual(kinds, [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.EQUALS,
            JsTokenKind.REGEXP,
        ])

    def test_regexp_after_return(self):
        kinds = self._token_kinds('return /re/')
        self.assertEqual(kinds, [
            JsTokenKind.RETURN,
            JsTokenKind.REGEXP,
        ])

    def test_all_keywords(self):
        for kw in (
            'var', 'let', 'const', 'function', 'class', 'if', 'else',
            'for', 'while', 'do', 'switch', 'case', 'default', 'break',
            'continue', 'return', 'throw', 'try', 'catch', 'finally',
            'new', 'delete', 'typeof', 'void', 'instanceof', 'in', 'of',
            'import', 'export', 'from', 'as', 'yield', 'await', 'async',
            'extends', 'super', 'this', 'null', 'true', 'false',
            'debugger', 'with',
        ):
            tokens = self._tokens(kw)
            self.assertEqual(len(tokens), 1, F'keyword {kw!r} not recognized')
            self.assertTrue(
                tokens[0][0].is_keyword or tokens[0][0] in (
                    JsTokenKind.TRUE, JsTokenKind.FALSE,
                    JsTokenKind.NULL, JsTokenKind.THIS,
                    JsTokenKind.SUPER,
                ),
                F'{kw!r} not classified as keyword',
            )

    def test_identifier(self):
        tokens = self._tokens('myVar')
        self.assertEqual(tokens, [(JsTokenKind.IDENTIFIER, 'myVar')])

    def test_identifier_dollar(self):
        tokens = self._tokens('$el')
        self.assertEqual(tokens, [(JsTokenKind.IDENTIFIER, '$el')])

    def test_identifier_underscore(self):
        tokens = self._tokens('_private')
        self.assertEqual(tokens, [(JsTokenKind.IDENTIFIER, '_private')])

    def test_line_comment(self):
        tokens = self._tokens('x // comment\ny')
        kinds = [k for k, _ in tokens]
        self.assertIn(JsTokenKind.COMMENT, kinds)
        self.assertIn(JsTokenKind.IDENTIFIER, kinds)

    def test_block_comment(self):
        tokens = self._tokens('x /* comment */ y')
        kinds = [k for k, _ in tokens]
        self.assertIn(JsTokenKind.COMMENT, kinds)
        id_count = sum(1 for k in kinds if k == JsTokenKind.IDENTIFIER)
        self.assertEqual(id_count, 2)

    def test_block_comment_with_newline(self):
        tokens = self._tokens('x /*\n*/ y')
        kinds = [k for k, _ in tokens]
        self.assertIn(JsTokenKind.NEWLINE, kinds)

    def test_newlines(self):
        tokens = self._tokens('x\ny')
        kinds = [k for k, _ in tokens]
        self.assertEqual(kinds, [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.NEWLINE,
            JsTokenKind.IDENTIFIER,
        ])

    def test_operators_basic(self):
        for src, expected in [
            ('+', JsTokenKind.PLUS),
            ('-', JsTokenKind.MINUS),
            ('*', JsTokenKind.STAR),
            ('%', JsTokenKind.PERCENT),
            ('!', JsTokenKind.BANG),
            ('~', JsTokenKind.TILDE),
        ]:
            tokens = self._tokens(src)
            self.assertEqual(tokens, [(expected, src)], F'failed for {src!r}')

    def test_operators_multi_char(self):
        for src, expected in [
            ('===', JsTokenKind.EQ3),
            ('!==', JsTokenKind.BANG_EQ2),
            ('>>>', JsTokenKind.GT3),
            ('>>=', JsTokenKind.GT2_ASSIGN),
            ('>>>=', JsTokenKind.GT3_ASSIGN),
            ('**', JsTokenKind.STAR2),
            ('=>', JsTokenKind.ARROW),
            ('&&', JsTokenKind.AND),
            ('||', JsTokenKind.OR),
            ('??', JsTokenKind.QQ),
            ('?.', JsTokenKind.QUESTION_DOT),
            ('...', JsTokenKind.ELLIPSIS),
            ('&&=', JsTokenKind.AND_ASSIGN),
            ('||=', JsTokenKind.OR_ASSIGN),
            ('??=', JsTokenKind.NULLISH_ASSIGN),
        ]:
            tokens = self._tokens(src)
            self.assertEqual(len(tokens), 1, F'expected 1 token for {src!r}, got {tokens}')
            self.assertEqual(tokens[0][0], expected, F'wrong kind for {src!r}')

    def test_punctuation(self):
        for src, expected in [
            ('(', JsTokenKind.LPAREN),
            (')', JsTokenKind.RPAREN),
            ('{', JsTokenKind.LBRACE),
            ('}', JsTokenKind.RBRACE),
            ('[', JsTokenKind.LBRACKET),
            (']', JsTokenKind.RBRACKET),
            (';', JsTokenKind.SEMICOLON),
            (',', JsTokenKind.COMMA),
        ]:
            tokens = self._tokens(src)
            self.assertEqual(tokens, [(expected, src)], F'failed for {src!r}')

    def test_arrow_function_tokens(self):
        kinds = self._token_kinds('(x) => x')
        self.assertEqual(kinds, [
            JsTokenKind.LPAREN,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.RPAREN,
            JsTokenKind.ARROW,
            JsTokenKind.IDENTIFIER,
        ])

    def test_complex_expression_tokens(self):
        kinds = self._token_kinds('a.b(c, d)')
        self.assertEqual(kinds, [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.DOT,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.LPAREN,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.COMMA,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.RPAREN,
        ])

    def test_optional_chaining(self):
        kinds = self._token_kinds('a?.b')
        self.assertEqual(kinds, [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.QUESTION_DOT,
            JsTokenKind.IDENTIFIER,
        ])
