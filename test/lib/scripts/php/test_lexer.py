from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.php.lexer import PhpLexer
from refinery.lib.scripts.php.token import PhpTokenKind as K


class TestPhpLexer(TestBase):

    def _tokens(self, source: str) -> list[tuple[K, str]]:
        result = []
        for tok in PhpLexer(source=source).tokenize():
            if tok.kind is K.EOF:
                break
            result.append((tok.kind, tok.value))
        return result

    def _kinds(self, source: str) -> list[K]:
        return [k for k, _ in self._tokens(source)]

    def test_plain_html_no_php(self):
        tokens = self._tokens('<html>hello</html>')
        self.assertEqual(tokens, [(K.INLINE_HTML, '<html>hello</html>')])

    def test_html_before_open_tag(self):
        tokens = self._tokens('<div><?php')
        self.assertEqual(tokens, [
            (K.INLINE_HTML, '<div>'),
            (K.OPEN_TAG, '<?php'),
        ])

    def test_open_tag_echo(self):
        tokens = self._tokens('<?= $x')
        self.assertEqual(tokens, [
            (K.OPEN_TAG_ECHO, '<?='),
            (K.VARIABLE, '$x'),
        ])

    def test_close_tag_returns_to_html(self):
        tokens = self._tokens('<?php $x; ?><br>')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.VARIABLE, '$x'),
            (K.SEMICOLON, ';'),
            (K.CLOSE_TAG, '?>'),
            (K.INLINE_HTML, '<br>'),
        ])

    def test_variable(self):
        tokens = self._tokens('<?php $name')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.VARIABLE, '$name'),
        ])

    def test_integer_decimal(self):
        tokens = self._tokens('<?php 42')
        self.assertEqual(tokens, [(K.OPEN_TAG, '<?php'), (K.INTEGER, '42')])

    def test_integer_hex(self):
        tokens = self._tokens('<?php 0xFF')
        self.assertEqual(tokens, [(K.OPEN_TAG, '<?php'), (K.INTEGER, '0xFF')])

    def test_integer_binary(self):
        tokens = self._tokens('<?php 0b1010')
        self.assertEqual(tokens, [(K.OPEN_TAG, '<?php'), (K.INTEGER, '0b1010')])

    def test_integer_underscore_separator(self):
        tokens = self._tokens('<?php 1_000_000')
        self.assertEqual(tokens, [(K.OPEN_TAG, '<?php'), (K.INTEGER, '1_000_000')])

    def test_float_exponent(self):
        tokens = self._tokens('<?php 3.14e2')
        self.assertEqual(tokens, [(K.OPEN_TAG, '<?php'), (K.FLOAT, '3.14e2')])

    def test_single_quoted_string(self):
        tokens = self._tokens("<?php 'a\\'b'")
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.STRING_SINGLE, "'a\\'b'"),
        ])

    def test_double_quoted_string(self):
        tokens = self._tokens('<?php "hello $world"')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.STRING_DOUBLE, '"hello $world"'),
        ])

    def test_double_quoted_complex_interpolation(self):
        tokens = self._tokens('<?php "{$obj->p}"')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.STRING_DOUBLE, '"{$obj->p}"'),
        ])

    def test_heredoc(self):
        tokens = self._tokens('<?php <<<EOT\nline $x\nEOT;\n')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.HEREDOC, '<<<EOT\nline $x\nEOT'),
            (K.SEMICOLON, ';'),
        ])

    def test_nowdoc(self):
        tokens = self._tokens("<?php <<<'EOT'\nraw $x\nEOT;\n")
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.NOWDOC, "<<<'EOT'\nraw $x\nEOT"),
            (K.SEMICOLON, ';'),
        ])

    def test_keyword_case_insensitive(self):
        self.assertEqual(self._kinds('<?php FUNCTION'), [K.OPEN_TAG, K.FUNCTION])
        self.assertEqual(self._kinds('<?php Function'), [K.OPEN_TAG, K.FUNCTION])
        self.assertEqual(self._kinds('<?php function'), [K.OPEN_TAG, K.FUNCTION])

    def test_identifier_not_keyword(self):
        tokens = self._tokens('<?php myFunc')
        self.assertEqual(tokens, [(K.OPEN_TAG, '<?php'), (K.IDENTIFIER, 'myFunc')])

    def test_cast_int(self):
        tokens = self._tokens('<?php (int) $x')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.INT_CAST, '(int)'),
            (K.VARIABLE, '$x'),
        ])

    def test_cast_with_alias(self):
        self.assertEqual(self._kinds('<?php (integer)'), [K.OPEN_TAG, K.INT_CAST])
        self.assertEqual(self._kinds('<?php (boolean)'), [K.OPEN_TAG, K.BOOL_CAST])
        self.assertEqual(self._kinds('<?php (double)'), [K.OPEN_TAG, K.FLOAT_CAST])

    def test_paren_not_cast(self):
        tokens = self._tokens('<?php ($x)')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.LPAREN, '('),
            (K.VARIABLE, '$x'),
            (K.RPAREN, ')'),
        ])

    def test_attribute_open(self):
        tokens = self._tokens('<?php #[Attr]')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.ATTRIBUTE, '#['),
            (K.IDENTIFIER, 'Attr'),
            (K.RBRACKET, ']'),
        ])

    def test_hash_comment(self):
        tokens = self._tokens('<?php # a comment\n$x')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.COMMENT, '# a comment'),
            (K.VARIABLE, '$x'),
        ])

    def test_nullsafe_operator(self):
        tokens = self._tokens('<?php $a?->b')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.VARIABLE, '$a'),
            (K.NULLSAFE_OPERATOR, '?->'),
            (K.IDENTIFIER, 'b'),
        ])

    def test_spaceship_operator(self):
        tokens = self._tokens('<?php $a <=> $b')
        self.assertEqual(self._kinds('<?php $a <=> $b'), [
            K.OPEN_TAG, K.VARIABLE, K.SPACESHIP, K.VARIABLE,
        ])
        self.assertEqual(tokens[2], (K.SPACESHIP, '<=>'))

    def test_coalesce_assign(self):
        tokens = self._tokens('<?php $a ??= 1')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.VARIABLE, '$a'),
            (K.COALESCE_EQUAL, '??='),
            (K.INTEGER, '1'),
        ])

    def test_namespace_separator(self):
        tokens = self._tokens('<?php \\Foo\\Bar')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.NS_SEPARATOR, '\\'),
            (K.IDENTIFIER, 'Foo'),
            (K.NS_SEPARATOR, '\\'),
            (K.IDENTIFIER, 'Bar'),
        ])

    def test_ellipsis(self):
        tokens = self._tokens('<?php ...$args')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.ELLIPSIS, '...'),
            (K.VARIABLE, '$args'),
        ])

    def test_heredoc_closes_at_newline_only(self):
        # A closing label followed by a space/comment must NOT close the heredoc.
        src = '<?php $x = <<<EOT\nhello\nEOT // not closed\nEOT;\n'
        tokens = self._tokens(src)
        heredoc = next(t for k, t in tokens if k is K.HEREDOC)
        self.assertIn('EOT // not closed', heredoc)

    def test_heredoc_closes_at_semicolon(self):
        src = '<?php $x = <<<EOT\nhello\nEOT;\n'
        tokens = self._tokens(src)
        kinds = [k for k, _ in tokens]
        self.assertIn(K.HEREDOC, kinds)
        self.assertIn(K.SEMICOLON, kinds)

    def test_prefixed_int_leading_underscore_is_error(self):
        tokens = self._tokens('<?php 0x_FF')
        kinds = [k for k, _ in tokens]
        self.assertIn(K.ERROR, kinds)

    def test_prefixed_int_trailing_underscore_is_error(self):
        tokens = self._tokens('<?php 0xFF_')
        kinds = [k for k, _ in tokens]
        self.assertIn(K.ERROR, kinds)

    def test_prefixed_int_valid(self):
        tokens = self._tokens('<?php 0xFF')
        self.assertEqual(tokens, [
            (K.OPEN_TAG, '<?php'),
            (K.INTEGER, '0xFF'),
        ])
