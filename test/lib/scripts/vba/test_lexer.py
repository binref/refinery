from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.vba.lexer import VbaLexer
from refinery.lib.scripts.vba.token import VbaTokenKind


class TestVbaLexer(TestBase):

    def _tokens(self, source: str) -> list[tuple[VbaTokenKind, str]]:
        lexer = VbaLexer(source)
        result = []
        for tok in lexer.tokenize():
            if tok.kind == VbaTokenKind.EOF:
                break
            result.append((tok.kind, tok.value))
        return result

    def _token_kinds(self, source: str) -> list[VbaTokenKind]:
        return [k for k, _ in self._tokens(source)]

    def test_integer_decimal(self):
        tokens = self._tokens('42')
        self.assertEqual(tokens, [(VbaTokenKind.INTEGER, '42')])

    def test_integer_hex(self):
        tokens = self._tokens('&HFF')
        self.assertEqual(tokens, [(VbaTokenKind.INTEGER, '&HFF')])

    def test_integer_hex_with_suffix(self):
        tokens = self._tokens('&HFF&')
        self.assertEqual(tokens, [(VbaTokenKind.INTEGER, '&HFF&')])

    def test_integer_octal(self):
        tokens = self._tokens('&O77')
        self.assertEqual(tokens, [(VbaTokenKind.INTEGER, '&O77')])

    def test_float_decimal(self):
        tokens = self._tokens('3.14')
        self.assertEqual(tokens, [(VbaTokenKind.FLOAT, '3.14')])

    def test_float_exponent(self):
        tokens = self._tokens('1e10')
        self.assertEqual(tokens, [(VbaTokenKind.FLOAT, '1e10')])

    def test_string_simple(self):
        tokens = self._tokens('"Hello"')
        self.assertEqual(tokens, [(VbaTokenKind.STRING, '"Hello"')])

    def test_string_escaped_quote(self):
        tokens = self._tokens('"He said ""hi"""')
        self.assertEqual(tokens, [(VbaTokenKind.STRING, '"He said ""hi"""')])

    def test_date_literal(self):
        tokens = self._tokens('#12/31/2024#')
        self.assertEqual(tokens, [(VbaTokenKind.DATE_LITERAL, '#12/31/2024#')])

    def test_boolean_true(self):
        tokens = self._tokens('True')
        self.assertEqual(tokens, [(VbaTokenKind.BOOLEAN_TRUE, 'True')])

    def test_boolean_false(self):
        tokens = self._tokens('False')
        self.assertEqual(tokens, [(VbaTokenKind.BOOLEAN_FALSE, 'False')])

    def test_keyword_case_insensitive(self):
        tokens = self._tokens('Sub')
        self.assertEqual(tokens, [(VbaTokenKind.SUB, 'Sub')])
        tokens2 = self._tokens('SUB')
        self.assertEqual(tokens2, [(VbaTokenKind.SUB, 'SUB')])
        tokens3 = self._tokens('sub')
        self.assertEqual(tokens3, [(VbaTokenKind.SUB, 'sub')])

    def test_identifier(self):
        tokens = self._tokens('myVar')
        self.assertEqual(tokens, [(VbaTokenKind.IDENTIFIER, 'myVar')])

    def test_identifier_with_type_suffix(self):
        tokens = self._tokens('x$')
        self.assertEqual(tokens, [(VbaTokenKind.IDENTIFIER, 'x$')])

    def test_operators(self):
        tokens = self._tokens('+ - * / \\ ^ &')
        kinds = [k for k, _ in tokens]
        self.assertEqual(kinds, [
            VbaTokenKind.PLUS, VbaTokenKind.MINUS,
            VbaTokenKind.STAR, VbaTokenKind.SLASH,
            VbaTokenKind.BACKSLASH, VbaTokenKind.CARET,
            VbaTokenKind.AMPERSAND,
        ])

    def test_comparison_operators(self):
        tokens = self._tokens('= <> < > <= >=')
        kinds = [k for k, _ in tokens]
        self.assertEqual(kinds, [
            VbaTokenKind.EQ, VbaTokenKind.NEQ,
            VbaTokenKind.LT, VbaTokenKind.GT,
            VbaTokenKind.LTE, VbaTokenKind.GTE,
        ])

    def test_comment_apostrophe(self):
        tokens = self._tokens("x = 1 ' this is a comment")
        kinds = [k for k, _ in tokens]
        self.assertIn(VbaTokenKind.COMMENT, kinds)

    def test_comment_rem(self):
        tokens = self._tokens('Rem This is a comment')
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], VbaTokenKind.COMMENT)

    def test_newline(self):
        tokens = self._tokens('x\ny')
        kinds = [k for k, _ in tokens]
        self.assertIn(VbaTokenKind.NEWLINE, kinds)

    def test_colon_separator(self):
        tokens = self._tokens('x = 1 : y = 2')
        kinds = [k for k, _ in tokens]
        self.assertIn(VbaTokenKind.COLON, kinds)

    def test_line_continuation(self):
        tokens = self._tokens('x = 1 + _\n2')
        kinds = [k for k, _ in tokens]
        self.assertNotIn(VbaTokenKind.NEWLINE, kinds)

    def test_parentheses(self):
        tokens = self._tokens('()')
        kinds = [k for k, _ in tokens]
        self.assertEqual(kinds, [VbaTokenKind.LPAREN, VbaTokenKind.RPAREN])

    def test_dot_and_bang(self):
        tokens = self._tokens('.Name !Key')
        kinds = [k for k, _ in tokens]
        self.assertEqual(kinds[:2], [VbaTokenKind.DOT, VbaTokenKind.IDENTIFIER])
        self.assertEqual(kinds[2:], [VbaTokenKind.BANG, VbaTokenKind.IDENTIFIER])

    def test_logical_keywords(self):
        for kw, expected in [
            ('And', VbaTokenKind.AND),
            ('Or', VbaTokenKind.OR),
            ('Not', VbaTokenKind.NOT),
            ('Xor', VbaTokenKind.XOR),
            ('Eqv', VbaTokenKind.EQV),
            ('Imp', VbaTokenKind.IMP),
            ('Mod', VbaTokenKind.MOD),
            ('Like', VbaTokenKind.LIKE),
            ('Is', VbaTokenKind.IS),
        ]:
            with self.subTest(keyword=kw):
                tokens = self._tokens(kw)
                self.assertEqual(tokens[0][0], expected)

    def test_multiple_newlines_collapsed(self):
        tokens = self._tokens('x\n\n\ny')
        newlines = [k for k, _ in tokens if k == VbaTokenKind.NEWLINE]
        self.assertEqual(len(newlines), 1)

    def test_line_continuation_trailing_spaces(self):
        tokens = self._tokens('x = 1 + _  \n2')
        kinds = [k for k, _ in tokens]
        self.assertNotIn(VbaTokenKind.NEWLINE, kinds)
        self.assertEqual(kinds, [
            VbaTokenKind.IDENTIFIER,
            VbaTokenKind.EQ,
            VbaTokenKind.INTEGER,
            VbaTokenKind.PLUS,
            VbaTokenKind.INTEGER,
        ])

    def test_line_continuation_trailing_tab(self):
        tokens = self._tokens('x = 1 + _\t\n2')
        kinds = [k for k, _ in tokens]
        self.assertNotIn(VbaTokenKind.NEWLINE, kinds)
        self.assertEqual(kinds, [
            VbaTokenKind.IDENTIFIER,
            VbaTokenKind.EQ,
            VbaTokenKind.INTEGER,
            VbaTokenKind.PLUS,
            VbaTokenKind.INTEGER,
        ])

    def test_empty_string(self):
        tokens = self._tokens('""')
        self.assertEqual(tokens, [(VbaTokenKind.STRING, '""')])
