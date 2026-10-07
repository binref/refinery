from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.lexer import Au3Lexer, decode_au3_string, encode_au3_string
from refinery.lib.scripts.au3.token import KEYWORD_SPELLINGS, Au3TokenKind as K
from refinery.units.formats.a3x import A3X_KEYWORDS


class TestAu3Lexer(TestBase):

    def _tokens(self, source: str) -> list[tuple[K, str]]:
        result = []
        for tok in Au3Lexer(source=source).tokenize():
            if tok.kind is K.EOF:
                break
            result.append((tok.kind, tok.value))
        return result

    def _kinds(self, source: str) -> list[K]:
        return [k for k, _ in self._tokens(source)]

    def test_keyword_case_insensitive(self):
        for spelling in ('If', 'IF', 'if', 'iF'):
            self.assertEqual(self._kinds(spelling), [K.IF])

    def test_keyword_with_word_boundary(self):
        self.assertEqual(self._kinds('Ifx'), [K.IDENTIFIER])
        self.assertEqual(self._kinds('If x'), [K.IF, K.IDENTIFIER])

    def test_variable(self):
        self.assertEqual(self._tokens('$name'), [(K.VARIABLE, '$name')])

    def test_macro(self):
        self.assertEqual(self._tokens('@ScriptDir'), [(K.MACRO, '@ScriptDir')])

    def test_underscore_identifier(self):
        self.assertEqual(self._tokens('_foo'), [(K.IDENTIFIER, '_foo')])

    def test_integer_decimal(self):
        self.assertEqual(self._tokens('42'), [(K.INTEGER, '42')])

    def test_integer_hex(self):
        self.assertEqual(self._tokens('0xFF'), [(K.INTEGER, '0xFF')])

    def test_hex_without_digits_is_not_a_number(self):
        self.assertEqual(self._kinds('0x'), [K.INTEGER, K.IDENTIFIER])

    def test_float(self):
        self.assertEqual(self._tokens('3.14'), [(K.FLOAT, '3.14')])
        self.assertEqual(self._tokens('.5'), [(K.FLOAT, '.5')])
        self.assertEqual(self._tokens('1.5e-3'), [(K.FLOAT, '1.5e-3')])
        self.assertEqual(self._tokens('2e3'), [(K.FLOAT, '2e3')])

    def test_dot_without_digits_is_an_operator(self):
        self.assertEqual(self._tokens('$o.a'), [
            (K.VARIABLE, '$o'),
            (K.DOT, '.'),
            (K.IDENTIFIER, 'a'),
        ])

    def test_string_double_quoted(self):
        self.assertEqual(self._tokens('"hello"'), [(K.STRING, '"hello"')])

    def test_string_single_quoted(self):
        self.assertEqual(self._tokens("'hello'"), [(K.STRING, "'hello'")])

    def test_string_doubled_quote_escape(self):
        self.assertEqual(self._tokens('"a""b"'), [(K.STRING, '"a""b"')])

    def test_string_unterminated_runs_to_end_of_line(self):
        self.assertEqual(self._tokens('"abc\n$x'), [
            (K.STRING, '"abc'),
            (K.NEWLINE, ''),
            (K.VARIABLE, '$x'),
        ])

    def test_line_comment(self):
        self.assertEqual(self._tokens('$x ; comment'), [
            (K.VARIABLE, '$x'),
            (K.COMMENT, '; comment'),
        ])

    def test_block_comment(self):
        self.assertEqual(self._tokens('#cs one #ce'), [(K.COMMENT, '#cs one #ce')])
        self.assertEqual(
            self._tokens('#comments-start one #comments-end'),
            [(K.COMMENT, '#comments-start one #comments-end')],
        )

    def test_block_comment_nesting(self):
        self.assertEqual(
            self._tokens('#cs outer #cs inner #ce outer #ce'),
            [(K.COMMENT, '#cs outer #cs inner #ce outer #ce')],
        )

    def test_block_comment_unterminated_runs_to_end(self):
        self.assertEqual(self._tokens('#cs no end'), [(K.COMMENT, '#cs no end')])

    def test_block_comment_unterminated_excludes_the_final_line_break(self):
        self.assertEqual(self._tokens('#cs no end\n'), [
            (K.COMMENT, '#cs no end'),
            (K.NEWLINE, ''),
        ])
        self.assertEqual(self._tokens('#cs no end\r\n'), [
            (K.COMMENT, '#cs no end'),
            (K.NEWLINE, ''),
        ])

    def test_block_comment_word_boundary(self):
        self.assertEqual(self._kinds('#csfoo'), [K.DIRECTIVE])

    def test_directive(self):
        self.assertEqual(
            self._tokens('#include <Array.au3>'),
            [(K.DIRECTIVE, '#include <Array.au3>')],
        )
        self.assertEqual(
            self._tokens('#AutoIt3Wrapper_Res_Description=x'),
            [(K.DIRECTIVE, '#AutoIt3Wrapper_Res_Description=x')],
        )

    def test_newline(self):
        self.assertEqual(self._kinds('$x\n$y'), [K.VARIABLE, K.NEWLINE, K.VARIABLE])
        self.assertEqual(self._kinds('$x\r\n$y'), [K.VARIABLE, K.NEWLINE, K.VARIABLE])

    def test_consecutive_breaks_collapse_into_one_newline(self):
        self.assertEqual(self._kinds('$x\n\n\n$y'), [K.VARIABLE, K.NEWLINE, K.VARIABLE])
        self.assertEqual(self._kinds('$x\n \n\t$y'), [K.VARIABLE, K.NEWLINE, K.VARIABLE])

    def test_line_continuation_joins_lines(self):
        self.assertEqual(self._kinds('$x _\n+ $y'), [K.VARIABLE, K.PLUS, K.VARIABLE])

    def test_line_continuation_with_trailing_comment(self):
        self.assertEqual(
            self._kinds('$x _ ; keep\n+ $y'),
            [K.VARIABLE, K.PLUS, K.VARIABLE],
        )

    def test_line_continuation_across_blank_lines(self):
        self.assertEqual(
            self._kinds('$x _\n\n\n+ $y'),
            [K.VARIABLE, K.PLUS, K.VARIABLE],
        )

    def test_bare_underscore_with_content_is_an_error(self):
        self.assertEqual(self._kinds('$x _ $y'), [K.VARIABLE, K.ERROR, K.VARIABLE])

    def test_two_char_operators(self):
        self.assertEqual(self._kinds('=='), [K.EQ_STRICT])
        self.assertEqual(self._kinds('<>'), [K.NE])
        self.assertEqual(self._kinds('<='), [K.LE])
        self.assertEqual(self._kinds('>='), [K.GE])
        self.assertEqual(self._kinds('+='), [K.PLUS_ASSIGN])
        self.assertEqual(self._kinds('-='), [K.MINUS_ASSIGN])
        self.assertEqual(self._kinds('*='), [K.MUL_ASSIGN])
        self.assertEqual(self._kinds('/='), [K.DIV_ASSIGN])
        self.assertEqual(self._kinds('&='), [K.CONCAT_ASSIGN])

    def test_longest_match_wins(self):
        self.assertEqual(self._kinds('$x==$y'), [K.VARIABLE, K.EQ_STRICT, K.VARIABLE])
        self.assertEqual(self._kinds('$x<>$y'), [K.VARIABLE, K.NE, K.VARIABLE])

    def test_single_equals(self):
        self.assertEqual(self._kinds('$x=$y'), [K.VARIABLE, K.ASSIGN_OR_EQ, K.VARIABLE])

    def test_unknown_character_is_an_error(self):
        self.assertEqual(self._kinds('$x!'), [K.VARIABLE, K.ERROR])

    def test_offsets(self):
        tokens = list(Au3Lexer(source='If $x Then').tokenize())
        self.assertEqual([t.offset for t in tokens], [0, 3, 6, 10])

    def test_decode_string_doubled_quote(self):
        self.assertEqual(decode_au3_string('"a""b"'), 'a"b')
        self.assertEqual(decode_au3_string("'a''b'"), "a'b")

    def test_decode_string_unterminated(self):
        self.assertEqual(decode_au3_string('"abc'), 'abc')

    def test_encode_decode_round_trip(self):
        for quote in ('"', "'"):
            value = F'a{quote}b'
            self.assertEqual(decode_au3_string(encode_au3_string(value, quote)), value)

    def test_keyword_spellings_match_a3x_decompiler(self):
        self.assertEqual(set(KEYWORD_SPELLINGS.values()), set(A3X_KEYWORDS) - {''})
