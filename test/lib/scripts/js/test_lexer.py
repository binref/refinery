from __future__ import annotations

import inspect
import itertools
import unicodedata
import unittest

from collections.abc import Iterable

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    completion_values,
    node_executable,
)

from refinery.lib.scripts.js.lexer import JsLexer
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.token import (
    ASCII_WHITESPACE,
    LINE_TERMINATORS,
    WHITESPACE,
    JsToken,
    JsTokenKind,
)


NAMED_WHITESPACE = [0x0009, 0x000B, 0x000C, 0xFEFF]
"""
The code points the ECMA-262 WhiteSpace production names one at a time: the tab, the vertical tab,
the form feed and the zero width no-break space. Its one remaining alternative is `<USP>`, which is
every code point of the Unicode general category `Zs`.
"""

NAMED_LINE_TERMINATORS = [0x000A, 0x000D]
"""
The code points the ECMA-262 LineTerminator production names one at a time: the line feed and the
carriage return. The two it has left are the line separator and the paragraph separator, which are
the whole of the Unicode general categories `Zl` and `Zp`.
"""

WHATWG_ASCII_WHITESPACE = [0x0009, 0x000A, 0x000C, 0x000D, 0x0020]
"""
The code points the WHATWG Infra Standard calls ASCII whitespace: `U+0009` TAB, `U+000A` LF,
`U+000C` FF, `U+000D` CR and `U+0020` SPACE. The vertical tab is not among them.
"""

A_LINE_BREAK_BEFORE_THE_CLOSING_SLASH = inspect.cleandoc("""
    x = / zzz
    zzz /;
""")

A_LINE_BREAK_BEHIND_A_BACKSLASH = inspect.cleandoc(R"""
    x = /zz\
    z/;
""")

A_LINE_BREAK_INSIDE_A_CHARACTER_CLASS = inspect.cleandoc("""
    x = /[zz
    z]/;
""")


def _named(code_point: int) -> str:
    return F'U+{code_point:04X}'


def _spelled(code_points: Iterable[int]) -> list[str]:
    return sorted(_named(code_point) for code_point in code_points)


def _code_points_of_category(*categories: str) -> set[int]:
    wanted = frozenset(categories)
    return {cp for cp in range(0x110000) if unicodedata.category(chr(cp)) in wanted}


def _tokens_of(source: str) -> list[tuple[JsTokenKind, str]]:
    lexer = JsLexer(source)
    result = []
    for tok in lexer.tokenize():
        if tok.kind == JsTokenKind.EOF:
            break
        result.append((tok.kind, tok.value))
    return result


def _tokens_with_termination(source: str) -> list[tuple[JsTokenKind, str, bool]]:
    lexer = JsLexer(source)
    result = []
    for tok in lexer.tokenize():
        if tok.kind == JsTokenKind.EOF:
            break
        result.append((tok.kind, tok.value, tok.terminated))
    return result


def _html_comment_of(source: str) -> int | None:
    lexer = JsLexer(source)
    for _ in lexer.tokenize():
        pass
    return lexer.html_comment


class TestJsLexer(TestBase):

    def _tokens(self, source: str) -> list[tuple[JsTokenKind, str]]:
        return _tokens_of(source)

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

    def test_regexp_vs_division(self):
        kinds = self._token_kinds('x / y')
        self.assertEqual(kinds, [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.SLASH,
            JsTokenKind.IDENTIFIER,
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

    def test_a_line_comment_runs_to_the_end_of_its_line_and_no_further(self):
        self.assertEqual(self._tokens('x // comment\ny'), [
            (JsTokenKind.IDENTIFIER, 'x'),
            (JsTokenKind.COMMENT, '// comment'),
            (JsTokenKind.NEWLINE, '\n'),
            (JsTokenKind.IDENTIFIER, 'y'),
        ])

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

    def test_a_hash_bang_line_is_one_token_at_the_start(self):
        tokens = self._tokens('#!/usr/bin/env node\nvar x = 1;')
        self.assertEqual(tokens[:3], [
            (JsTokenKind.HASHBANG, '#!/usr/bin/env node'),
            (JsTokenKind.NEWLINE, '\n'),
            (JsTokenKind.VAR, 'var'),
        ])

    def test_shebang_only_at_position_zero(self):
        tokens = self._tokens('var x;\n#!/usr/bin/env node')
        kinds = [k for k, _ in tokens]
        self.assertIn(JsTokenKind.ERROR, kinds)

    def test_private_identifier(self):
        self.assertEqual(
            self._tokens('#field'), [(JsTokenKind.PRIVATE_IDENTIFIER, '#field')])

    def test_private_identifier_after_dot(self):
        self.assertEqual(self._token_kinds('this.#x'), [
            JsTokenKind.THIS,
            JsTokenKind.DOT,
            JsTokenKind.PRIVATE_IDENTIFIER,
        ])

    def test_hash_without_name_is_error(self):
        self.assertEqual(self._tokens('#'), [(JsTokenKind.ERROR, '#')])

    def test_at_token(self):
        self.assertEqual(self._tokens('@'), [(JsTokenKind.AT, '@')])

    def _bounded_tokens(self, source: str, limit: int = 16) -> list[tuple[JsTokenKind, str]]:
        """
        The first *limit* tokens of *source*, the end of file among them. A scan that consumes no
        input yields tokens forever, so reading the whole stream would hang where this read fails.
        """
        return [
            (token.kind, token.value)
            for token in itertools.islice(JsLexer(source).tokenize(), limit)
        ]

    def test_a_backslash_that_begins_no_escape_is_a_token_that_consumes_it(self):
        backslash = '\\'
        self.assertEqual(self._bounded_tokens(backslash), [
            (JsTokenKind.ERROR, backslash),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._bounded_tokens(F'a{backslash}b'), [
            (JsTokenKind.IDENTIFIER, 'a'),
            (JsTokenKind.ERROR, backslash),
            (JsTokenKind.IDENTIFIER, 'b'),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._bounded_tokens(F'a{backslash}'), [
            (JsTokenKind.IDENTIFIER, 'a'),
            (JsTokenKind.ERROR, backslash),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._bounded_tokens(F'a{backslash}{backslash}b'), [
            (JsTokenKind.IDENTIFIER, 'a'),
            (JsTokenKind.ERROR, backslash),
            (JsTokenKind.ERROR, backslash),
            (JsTokenKind.IDENTIFIER, 'b'),
            (JsTokenKind.EOF, ''),
        ])

    def test_a_unicode_escape_in_an_identifier_is_still_one_identifier(self):
        self.assertEqual(
            self._bounded_tokens(R'\u0061bc'),
            [(JsTokenKind.IDENTIFIER, R'\u0061bc'), (JsTokenKind.EOF, '')])
        self.assertEqual(
            self._bounded_tokens(R'a\u0062c'),
            [(JsTokenKind.IDENTIFIER, R'a\u0062c'), (JsTokenKind.EOF, '')])

    def _statements(self, source: str) -> int:
        return len(JsParser(source).parse().body)

    def test_a_code_point_escape_naming_no_code_point_ends_with_the_literal_it_is_in(self):
        source = R"x = '\u{110000}'; y;"
        self.assertEqual(self._bounded_tokens(source), [
            (JsTokenKind.IDENTIFIER, 'x'),
            (JsTokenKind.EQUALS, '='),
            (JsTokenKind.STRING_SINGLE, R"'\u{110000}'"),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.IDENTIFIER, 'y'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._statements(source), 2)

    def test_a_code_point_escape_whose_brace_is_never_closed_ends_with_its_literal(self):
        source = R"x = '\u{41'; y;"
        self.assertEqual(self._bounded_tokens(source), [
            (JsTokenKind.IDENTIFIER, 'x'),
            (JsTokenKind.EQUALS, '='),
            (JsTokenKind.STRING_SINGLE, R"'\u{41'"),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.IDENTIFIER, 'y'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._statements(source), 2)

    def test_a_code_point_escape_naming_nothing_is_read_the_same_between_double_quotes(self):
        source = R'x = "\u{110000}"; y;'
        self.assertEqual(self._bounded_tokens(source), [
            (JsTokenKind.IDENTIFIER, 'x'),
            (JsTokenKind.EQUALS, '='),
            (JsTokenKind.STRING_DOUBLE, R'"\u{110000}"'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.IDENTIFIER, 'y'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._statements(source), 2)

    def test_a_digit_of_another_script_is_a_digit_of_no_numeral(self):
        self.assertEqual(self._bounded_tokens('x = \u0661\u0662\u0663; y;'), [
            (JsTokenKind.IDENTIFIER, 'x'),
            (JsTokenKind.EQUALS, '='),
            (JsTokenKind.ERROR, '\u0661'),
            (JsTokenKind.ERROR, '\u0662'),
            (JsTokenKind.ERROR, '\u0663'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.IDENTIFIER, 'y'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._bounded_tokens('x = \u00B2; y;'), [
            (JsTokenKind.IDENTIFIER, 'x'),
            (JsTokenKind.EQUALS, '='),
            (JsTokenKind.ERROR, '\u00B2'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.IDENTIFIER, 'y'),
            (JsTokenKind.SEMICOLON, ';'),
            (JsTokenKind.EOF, ''),
        ])

    def test_a_digit_of_another_script_behind_a_numeral_is_no_digit_of_it(self):
        for digit in ['\u0661', '\u00B2', '\uFF11']:
            with self.subTest(digit=F'U+{ord(digit):04X}'):
                self.assertEqual(self._bounded_tokens(F'x = 1{digit}; y;'), [
                    (JsTokenKind.IDENTIFIER, 'x'),
                    (JsTokenKind.EQUALS, '='),
                    (JsTokenKind.INTEGER, '1'),
                    (JsTokenKind.ERROR, digit),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.IDENTIFIER, 'y'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.EOF, ''),
                ])

    def test_a_decimal_digit_of_another_script_is_part_of_a_name_and_no_other_digit_is(self):
        """
        `U+0661` and `U+FF11` are of general category `Nd`, which a name may hold; the superscript
        `U+00B2` and the circled `U+2460` are of category `No`, which it may not.
        """
        for digit in ['\u0661', '\uFF11']:
            with self.subTest(digit=F'U+{ord(digit):04X}'):
                self.assertEqual(self._bounded_tokens(F'x{digit} = 1; y;'), [
                    (JsTokenKind.IDENTIFIER, F'x{digit}'),
                    (JsTokenKind.EQUALS, '='),
                    (JsTokenKind.INTEGER, '1'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.IDENTIFIER, 'y'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.EOF, ''),
                ])
        for digit in ['\u00B2', '\u2460']:
            with self.subTest(digit=F'U+{ord(digit):04X}'):
                self.assertEqual(self._bounded_tokens(F'x{digit} = 1; y;'), [
                    (JsTokenKind.IDENTIFIER, 'x'),
                    (JsTokenKind.ERROR, digit),
                    (JsTokenKind.EQUALS, '='),
                    (JsTokenKind.INTEGER, '1'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.IDENTIFIER, 'y'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.EOF, ''),
                ])

    def test_a_hash_bang_line_ends_at_a_line_terminator_and_that_ending_ends_a_line(self):
        endings = [chr(0x000A), chr(0x000D), chr(0x000D) + chr(0x000A), chr(0x2028), chr(0x2029)]
        for ending in endings:
            with self.subTest(ending=' '.join(_spelled(map(ord, ending)))):
                source = F'#!x{ending}y;'
                self.assertEqual(self._bounded_tokens(source), [
                    (JsTokenKind.HASHBANG, '#!x'),
                    (JsTokenKind.NEWLINE, ending),
                    (JsTokenKind.IDENTIFIER, 'y'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.EOF, ''),
                ])
                self.assertEqual(self._statements(source), 1)

    def test_a_file_that_is_only_a_hash_bang_line_holds_only_that_token(self):
        self.assertEqual(self._bounded_tokens('#!/usr/bin/env node'), [
            (JsTokenKind.HASHBANG, '#!/usr/bin/env node'),
            (JsTokenKind.EOF, ''),
        ])
        self.assertEqual(self._statements('#!/usr/bin/env node'), 0)

    def test_a_joiner_may_stand_inside_a_name_and_may_not_open_one(self):
        for joiner in [chr(0x200C), chr(0x200D)]:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                self.assertEqual(self._bounded_tokens(F'x = a{joiner}b; y;'), [
                    (JsTokenKind.IDENTIFIER, 'x'),
                    (JsTokenKind.EQUALS, '='),
                    (JsTokenKind.IDENTIFIER, F'a{joiner}b'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.IDENTIFIER, 'y'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.EOF, ''),
                ])
                self.assertEqual(self._bounded_tokens(F'x = {joiner}ab; y;'), [
                    (JsTokenKind.IDENTIFIER, 'x'),
                    (JsTokenKind.EQUALS, '='),
                    (JsTokenKind.ERROR, joiner),
                    (JsTokenKind.IDENTIFIER, 'ab'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.IDENTIFIER, 'y'),
                    (JsTokenKind.SEMICOLON, ';'),
                    (JsTokenKind.EOF, ''),
                ])

    def _scan_regexp(self, source: str, pos: int = 0) -> tuple[JsToken | None, int]:
        lexer = JsLexer(source, pos)
        return lexer.scan_regexp(), lexer.pos

    def test_a_regexp_scan_reads_the_whole_literal_and_stops_behind_it(self):
        for literal in ['/zzz/', '/zzz/gi', '/[/]/', '/[/]/gi', R'/a\/b/', R'/[\]/]/']:
            with self.subTest(literal=literal):
                self.assertEqual(
                    self._scan_regexp(F'x = {literal};', 4),
                    (JsToken(JsTokenKind.REGEXP, literal, 4), 4 + len(literal)))

    def test_the_flags_of_a_regexp_are_the_name_characters_written_against_it(self):
        self.assertEqual(
            self._scan_regexp('/zzz/gi.flags'), (JsToken(JsTokenKind.REGEXP, '/zzz/gi', 0), 7))
        self.assertEqual(
            self._scan_regexp('/zzz/ .flags'), (JsToken(JsTokenKind.REGEXP, '/zzz/', 0), 5))

    def test_a_regexp_scan_that_reaches_the_end_of_its_line_reads_nothing_and_stays(self):
        """
        A regular expression literal never spans a line break, not even one behind a backslash,
        which in a string literal would continue the line.
        """
        for source in [
            A_LINE_BREAK_BEFORE_THE_CLOSING_SLASH,
            A_LINE_BREAK_BEHIND_A_BACKSLASH,
            A_LINE_BREAK_INSIDE_A_CHARACTER_CLASS,
        ]:
            with self.subTest(source=source):
                self.assertEqual(self._scan_regexp(source, 4), (None, 4))

    def test_a_regexp_scan_that_reaches_the_end_of_the_file_reads_the_literal_it_ends_inside(self):
        """
        A lone slash at the end of the file opens no literal, since a pattern holds at least one
        character.
        """
        for source, text in [('x = / zzz', '/ zzz'), ('x = /[zzz', '/[zzz')]:
            with self.subTest(source=source):
                self.assertEqual(
                    self._scan_regexp(source, 4),
                    (JsToken(JsTokenKind.REGEXP, text, 4, False), len(source)))
        self.assertEqual(self._scan_regexp('x = /', 4), (None, 4))

    def test_a_regexp_scan_where_no_slash_stands_reads_nothing_and_stays(self):
        for source, pos in [('zzz', 0), ('x + y', 2), ('x = zzz', 4), (' /zzz/', 0), ('', 0)]:
            with self.subTest(source=source, pos=pos):
                self.assertEqual(self._scan_regexp(source, pos), (None, pos))


class TestTheWhitespaceProductionsAreThreeSetsAndNotOne(TestBase):
    """
    The token whitespace separates tokens, the line terminators end a line, and the ASCII whitespace
    is what a forgiving base64 decode skips in the argument of `atob`.
    """

    def test_the_whitespace_production_is_the_four_named_characters_and_the_space_separators(self):
        self.assertEqual(
            _spelled({*NAMED_WHITESPACE, *_code_points_of_category('Zs')}),
            _spelled(map(ord, WHITESPACE)))

    def test_the_line_terminator_production_is_the_two_controls_and_the_two_separators(self):
        self.assertEqual(
            _spelled({*NAMED_LINE_TERMINATORS, *_code_points_of_category('Zl', 'Zp')}),
            _spelled(map(ord, LINE_TERMINATORS)))

    def test_no_character_both_separates_two_tokens_and_ends_the_line_they_stand_on(self):
        self.assertEqual([], _spelled(map(ord, set(WHITESPACE) & set(LINE_TERMINATORS))))

    def test_ascii_whitespace_is_the_five_code_points_the_whatwg_definition_names(self):
        self.assertEqual(_spelled(WHATWG_ASCII_WHITESPACE), _spelled(map(ord, ASCII_WHITESPACE)))

    def test_ascii_whitespace_is_the_ascii_of_the_language_without_the_vertical_tab(self):
        language = {ord(c) for c in WHITESPACE + LINE_TERMINATORS if ord(c) < 0x80}
        self.assertEqual(_spelled(language - {0x000B}), _spelled(map(ord, ASCII_WHITESPACE)))
        self.assertEqual(
            _spelled([0x000A, 0x000D]),
            _spelled(map(ord, set(ASCII_WHITESPACE) & set(LINE_TERMINATORS))))
        self.assertEqual(
            _spelled([0x0020]),
            _spelled({ord(c) for c in ASCII_WHITESPACE} & _code_points_of_category('Zs')))


#: Characters a name may hold but not open with. The first seven are named by `Other_ID_Continue`,
#: whose general categories no name could otherwise hold; then come the two joiners, which the
#: language names itself, and the rest are of the categories `Nd`, `Mn`, `Mc` and `Pc`.
A_CHARACTER_A_NAME_HOLDS_AND_NEVER_OPENS_WITH = (
    0x00B7,
    0x0387,
    0x1369,
    0x1371,
    0x19DA,
    0x30FB,
    0xFF65,
    0x200C,
    0x200D,
    0x0661,
    0xFF11,
    0x0300,
    0x0903,
    0x203F,
    0xFE33,
)

#: Characters a name may open with, and so hold anywhere. `_` and `$` are named by the language
#: itself, the next six by `Other_ID_Start`, whose general categories no name could otherwise open
#: with, and the rest are of the categories `Lt`, `Lo`, `Lm` and `Nl`.
A_CHARACTER_A_NAME_OPENS_WITH = (
    0x005F,
    0x0024,
    0x1885,
    0x1886,
    0x2118,
    0x212E,
    0x309B,
    0x309C,
    0x2160,
    0x01C5,
    0x00AA,
    0x30FA,
    0x30FC,
    0xFF66,
    0x3005,
)

A_CHARACTER_NO_NAME_HOLDS = (
    0x00B2,
    0x2460,
    0x00BD,
    0x19DB,
    0x00A9,
    0xFF64,
    0x00B6,
    0x00B8,
    0x058F,
    0x30A0,
)

A_CHARACTER_AND_WHERE_IT_MAY_STAND_IN_A_NAME = {
    **{code: (False, True) for code in A_CHARACTER_A_NAME_HOLDS_AND_NEVER_OPENS_WITH},
    **{code: (True, True) for code in A_CHARACTER_A_NAME_OPENS_WITH},
    **{code: (False, False) for code in A_CHARACTER_NO_NAME_HOLDS},
}


def _a_name_opened_by(character: str) -> str:
    return F'var {character}ab = 7; {character}ab;'


def _a_name_holding(character: str) -> str:
    return F'var a{character}b = 7; a{character}b;'


def _the_name_a_declaration_binds(source: str) -> str | None:
    token = next(itertools.islice(JsLexer(source).tokenize(), 1, 2))
    return token.value if token.kind is JsTokenKind.IDENTIFIER else None


def _where_each_character_may_stand() -> dict[str, tuple[bool, bool]]:
    return {
        _named(code): answer
        for code, answer in A_CHARACTER_AND_WHERE_IT_MAY_STAND_IN_A_NAME.items()
    }


class TestANameIsWrittenWithTheCharactersTheLanguageReadsOneFrom(TestBase):

    def test_the_lexer_ends_a_name_exactly_where_the_language_ends_one(self):
        self.assertEqual(
            {
                _named(code): (
                    _the_name_a_declaration_binds(_a_name_opened_by(chr(code)))
                    == F'{chr(code)}ab',
                    _the_name_a_declaration_binds(_a_name_holding(chr(code)))
                    == F'a{chr(code)}b',
                )
                for code in A_CHARACTER_AND_WHERE_IT_MAY_STAND_IN_A_NAME
            },
            _where_each_character_may_stand(),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheCharactersNodeReadsANameFrom(TestBase):
    """
    SECURITY: every program here is written out by this module and Node runs only those. Nothing
    from `samples` may ever be handed to the engine.
    """

    def test_node_reads_a_name_opened_by_and_holding_the_characters_pinned_here(self):
        rows = A_CHARACTER_AND_WHERE_IT_MAY_STAND_IN_A_NAME
        programs = list(itertools.chain.from_iterable(
            (_a_name_opened_by(chr(code)), _a_name_holding(chr(code))) for code in rows
        ))
        values = completion_values(programs, JsEvaluation.SCRIPT)
        self.assertEqual(
            {
                _named(code): (values[2 * index] == '7', values[2 * index + 1] == '7')
                for index, code in enumerate(rows)
            },
            _where_each_character_may_stand(),
        )


class TestScriptCodeHasTwoMoreCommentOpeners(TestBase):
    """
    In a script, `<!--` opens a comment wherever a comment may open, and `-->` opens one only where
    nothing but whitespace and comments stands before it on its line, the head of the file included
    (ECMA-262 §B.1.1). Each runs to the end of its line like `//`; anywhere else `-->` is a
    decrement followed by `>`.
    """

    def test_the_opener_opens_a_comment_wherever_it_stands(self):
        rows = {
            '<!-- note\ny': [
                (JsTokenKind.COMMENT, '<!-- note'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.IDENTIFIER, 'y'),
            ],
            'x <!-- note\ny': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.COMMENT, '<!-- note'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.IDENTIFIER, 'y'),
            ],
            'x <!--': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.COMMENT, '<!--'),
            ],
            'a <!--b': [
                (JsTokenKind.IDENTIFIER, 'a'),
                (JsTokenKind.COMMENT, '<!--b'),
            ],
            'x /* c */ <!-- d\ny': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.COMMENT, '/* c */'),
                (JsTokenKind.COMMENT, '<!-- d'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.IDENTIFIER, 'y'),
            ],
        }
        self.assertEqual({source: _tokens_of(source) for source in rows}, rows)

    def test_the_closer_opens_a_comment_at_the_head_of_its_line(self):
        rows = {
            '--> note\ny': [
                (JsTokenKind.COMMENT, '--> note'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.IDENTIFIER, 'y'),
            ],
            'x\n--> note\ny': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.COMMENT, '--> note'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.IDENTIFIER, 'y'),
            ],
            'x\n   --> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.COMMENT, '--> note'),
            ],
            'x\n/* c */ --> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.COMMENT, '/* c */'),
                (JsTokenKind.COMMENT, '--> note'),
            ],
            'x /* c\n */ --> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.COMMENT, '/* c\n */'),
                (JsTokenKind.NEWLINE, ''),
                (JsTokenKind.COMMENT, '--> note'),
            ],
            'x // c\n--> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.COMMENT, '// c'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.COMMENT, '--> note'),
            ],
            '#!/usr/bin/env node\n--> note': [
                (JsTokenKind.HASHBANG, '#!/usr/bin/env node'),
                (JsTokenKind.NEWLINE, '\n'),
                (JsTokenKind.COMMENT, '--> note'),
            ],
            'x\r\n--> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.NEWLINE, '\r\n'),
                (JsTokenKind.COMMENT, '--> note'),
            ],
            '-->': [
                (JsTokenKind.COMMENT, '-->'),
            ],
        }
        self.assertEqual({source: _tokens_of(source) for source in rows}, rows)

    def test_the_closer_is_a_decrement_and_a_greater_than_anywhere_else(self):
        rows = {
            'a-->b': [
                (JsTokenKind.IDENTIFIER, 'a'),
                (JsTokenKind.DEC, '--'),
                (JsTokenKind.GT, '>'),
                (JsTokenKind.IDENTIFIER, 'b'),
            ],
            'x; --> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.SEMICOLON, ';'),
                (JsTokenKind.DEC, '--'),
                (JsTokenKind.GT, '>'),
                (JsTokenKind.IDENTIFIER, 'note'),
            ],
            'x /* c */ --> note': [
                (JsTokenKind.IDENTIFIER, 'x'),
                (JsTokenKind.COMMENT, '/* c */'),
                (JsTokenKind.DEC, '--'),
                (JsTokenKind.GT, '>'),
                (JsTokenKind.IDENTIFIER, 'note'),
            ],
        }
        self.assertEqual({source: _tokens_of(source) for source in rows}, rows)

    def test_neither_delimiter_is_read_inside_a_literal(self):
        rows = {
            "'-->'": [(JsTokenKind.STRING_SINGLE, "'-->'")],
            '"<!--"': [(JsTokenKind.STRING_DOUBLE, '"<!--"')],
            '`x\n--> y`': [(JsTokenKind.TEMPLATE_FULL, '`x\n--> y`')],
        }
        self.assertEqual({source: _tokens_of(source) for source in rows}, rows)

    def test_a_shift_takes_both_angle_brackets_before_the_opener_is_looked_for(self):
        self.assertEqual(
            _tokens_of('a <<!--b'),
            [
                (JsTokenKind.IDENTIFIER, 'a'),
                (JsTokenKind.LT2, '<<'),
                (JsTokenKind.BANG, '!'),
                (JsTokenKind.DEC, '--'),
                (JsTokenKind.IDENTIFIER, 'b'),
            ],
        )

    def test_the_scan_records_where_the_first_delimiter_stands(self):
        rows = {
            'x <!-- a\n--> b'   : 2,
            '--> a\nx <!-- b'   : 0,
            'x /* a */ --> b'   : None,
            "'<!--' + `-->`"    : None,
        }
        self.assertEqual({source: _html_comment_of(source) for source in rows}, rows)


class TestANumeralEndsWhereTheGrammarEndsOne(TestBase):
    """
    A numeral ends where the productions of ECMA-262 §12.9.3 end it: a separator stands between two
    digits of one run and nowhere else, a radix prefix needs digits, an exponent needs a digit
    behind its sign, a legacy octal literal takes no separator, fraction, exponent or `n`, the
    integer part of a `0`-led decimal takes no separator while its fraction and exponent take them,
    and the character behind a numeral may be neither an IdentifierStart nor a digit.
    """

    def test_a_numeral_node_compiles_is_one_terminated_token(self):
        rows = {
            '1_000': (JsTokenKind.INTEGER, '1_000'),
            '08.1_1': (JsTokenKind.FLOAT, '08.1_1'),
            '08e1_0': (JsTokenKind.FLOAT, '08e1_0'),
            '09.5_5': (JsTokenKind.FLOAT, '09.5_5'),
            '08.1_1e2_2': (JsTokenKind.FLOAT, '08.1_1e2_2'),
            '0x1_F': (JsTokenKind.INTEGER, '0x1_F'),
            '0b1_0': (JsTokenKind.INTEGER, '0b1_0'),
            '0o7_7': (JsTokenKind.INTEGER, '0o7_7'),
            '1_0.5_0e1_0': (JsTokenKind.FLOAT, '1_0.5_0e1_0'),
            '10n': (JsTokenKind.BIGINT, '10n'),
            '0x1fn': (JsTokenKind.BIGINT, '0x1fn'),
            '0b1n': (JsTokenKind.BIGINT, '0b1n'),
            '0o7n': (JsTokenKind.BIGINT, '0o7n'),
            '0n': (JsTokenKind.BIGINT, '0n'),
            '1_0n': (JsTokenKind.BIGINT, '1_0n'),
            '010': (JsTokenKind.INTEGER, '010'),
            '00': (JsTokenKind.INTEGER, '00'),
            '08': (JsTokenKind.INTEGER, '08'),
            '09.5': (JsTokenKind.FLOAT, '09.5'),
            '09e1': (JsTokenKind.FLOAT, '09e1'),
            '08.5e1': (JsTokenKind.FLOAT, '08.5e1'),
            '0': (JsTokenKind.INTEGER, '0'),
            '0.5': (JsTokenKind.FLOAT, '0.5'),
            '0.5_5': (JsTokenKind.FLOAT, '0.5_5'),
            '0.0e0': (JsTokenKind.FLOAT, '0.0e0'),
            '0e0': (JsTokenKind.FLOAT, '0e0'),
            '0.e1': (JsTokenKind.FLOAT, '0.e1'),
            '5.': (JsTokenKind.FLOAT, '5.'),
            '5.e1': (JsTokenKind.FLOAT, '5.e1'),
            '1.e1': (JsTokenKind.FLOAT, '1.e1'),
            '.5': (JsTokenKind.FLOAT, '.5'),
            '.5e-1': (JsTokenKind.FLOAT, '.5e-1'),
            '1e-3': (JsTokenKind.FLOAT, '1e-3'),
            '1E+3': (JsTokenKind.FLOAT, '1E+3'),
            '0b0': (JsTokenKind.INTEGER, '0b0'),
            '0O17': (JsTokenKind.INTEGER, '0O17'),
            '0B1': (JsTokenKind.INTEGER, '0B1'),
            '0X1f': (JsTokenKind.INTEGER, '0X1f'),
        }
        self.assertEqual(
            {source: _tokens_with_termination(source) for source in rows},
            {source: [(kind, text, True)] for source, (kind, text) in rows.items()},
        )

    def test_a_numeral_node_refuses_ends_where_the_grammar_ends_it_and_is_unterminated(self):
        rows = {
            '004E': [(JsTokenKind.INTEGER, '004', False), (JsTokenKind.IDENTIFIER, 'E', True)],
            '007e1': [(JsTokenKind.INTEGER, '007', False), (JsTokenKind.IDENTIFIER, 'e1', True)],
            '01n': [(JsTokenKind.INTEGER, '01', False), (JsTokenKind.IDENTIFIER, 'n', True)],
            '00n': [(JsTokenKind.INTEGER, '00', False), (JsTokenKind.IDENTIFIER, 'n', True)],
            '09n': [(JsTokenKind.INTEGER, '09', False), (JsTokenKind.IDENTIFIER, 'n', True)],
            '08_1': [(JsTokenKind.INTEGER, '08', False), (JsTokenKind.IDENTIFIER, '_1', True)],
            '09_1': [(JsTokenKind.INTEGER, '09', False), (JsTokenKind.IDENTIFIER, '_1', True)],
            '0_1': [(JsTokenKind.INTEGER, '0', False), (JsTokenKind.IDENTIFIER, '_1', True)],
            '0_0': [(JsTokenKind.INTEGER, '0', False), (JsTokenKind.IDENTIFIER, '_0', True)],
            '0_': [(JsTokenKind.INTEGER, '0', False), (JsTokenKind.IDENTIFIER, '_', True)],
            '0e': [(JsTokenKind.INTEGER, '0', False), (JsTokenKind.IDENTIFIER, 'e', True)],
            '0x': [(JsTokenKind.INTEGER, '0x', False)],
            '0b': [(JsTokenKind.INTEGER, '0b', False)],
            '0o': [(JsTokenKind.INTEGER, '0o', False)],
            '0b2': [(JsTokenKind.INTEGER, '0b', False), (JsTokenKind.INTEGER, '2', True)],
            '0x_1': [(JsTokenKind.INTEGER, '0x', False), (JsTokenKind.IDENTIFIER, '_1', True)],
            '0x1_': [(JsTokenKind.INTEGER, '0x1', False), (JsTokenKind.IDENTIFIER, '_', True)],
            '0x1g': [(JsTokenKind.INTEGER, '0x1', False), (JsTokenKind.IDENTIFIER, 'g', True)],
            '0x1n_': [(JsTokenKind.BIGINT, '0x1n', False), (JsTokenKind.IDENTIFIER, '_', True)],
            '1n1': [(JsTokenKind.BIGINT, '1n', False), (JsTokenKind.INTEGER, '1', True)],
            '1_': [(JsTokenKind.INTEGER, '1', False), (JsTokenKind.IDENTIFIER, '_', True)],
            '1__0': [(JsTokenKind.INTEGER, '1', False), (JsTokenKind.IDENTIFIER, '__0', True)],
            '1_e3': [(JsTokenKind.INTEGER, '1', False), (JsTokenKind.IDENTIFIER, '_e3', True)],
            '1e': [(JsTokenKind.INTEGER, '1', False), (JsTokenKind.IDENTIFIER, 'e', True)],
            '1e_1': [(JsTokenKind.INTEGER, '1', False), (JsTokenKind.IDENTIFIER, 'e_1', True)],
            '1e+': [
                (JsTokenKind.INTEGER, '1', False),
                (JsTokenKind.IDENTIFIER, 'e', True),
                (JsTokenKind.PLUS, '+', True),
            ],
            '1e3e': [(JsTokenKind.FLOAT, '1e3', False), (JsTokenKind.IDENTIFIER, 'e', True)],
            '1.e': [(JsTokenKind.FLOAT, '1.', False), (JsTokenKind.IDENTIFIER, 'e', True)],
            '1._5': [(JsTokenKind.FLOAT, '1.', False), (JsTokenKind.IDENTIFIER, '_5', True)],
            '1.5_': [(JsTokenKind.FLOAT, '1.5', False), (JsTokenKind.IDENTIFIER, '_', True)],
            '1_.5': [
                (JsTokenKind.INTEGER, '1', False),
                (JsTokenKind.IDENTIFIER, '_', True),
                (JsTokenKind.FLOAT, '.5', True),
            ],
            '.5_': [(JsTokenKind.FLOAT, '.5', False), (JsTokenKind.IDENTIFIER, '_', True)],
            '3in y': [
                (JsTokenKind.INTEGER, '3', False),
                (JsTokenKind.IN, 'in', True),
                (JsTokenKind.IDENTIFIER, 'y', True),
            ],
            '1.toString()': [
                (JsTokenKind.FLOAT, '1.', False),
                (JsTokenKind.IDENTIFIER, 'toString', True),
                (JsTokenKind.LPAREN, '(', True),
                (JsTokenKind.RPAREN, ')', True),
            ],
        }
        self.assertEqual({source: _tokens_with_termination(source) for source in rows}, rows)


A_ZERO_LED_DECIMAL_WITH_A_SEPARATOR_BEHIND_ITS_INTEGER_PART = {
    'x = 08.1_1;': '8.11',
    'x = 09.5_5;': '9.55',
    'x = 08.1_1e2_2;': '8.11e+22',
    'x = 08e1_0;': '80000000000',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatNodeMakesOfASeparatorBehindAZeroLedIntegerPart(TestBase):

    def test_node_evaluates_each_spelling_to_the_value_the_grammar_gives_it(self):
        rows = A_ZERO_LED_DECIMAL_WITH_A_SEPARATOR_BEHIND_ITS_INTEGER_PART
        self.assertEqual(
            dict(zip(rows, completion_values(list(rows), JsEvaluation.SCRIPT))),
            rows,
        )


class TestABlockCommentReportsWhetherItWasClosed(TestBase):

    def test_a_block_comment_is_terminated_exactly_where_the_closer_was_found(self):
        rows = {
            'x /**/ y': [
                (JsTokenKind.IDENTIFIER, 'x', True),
                (JsTokenKind.COMMENT, '/**/', True),
                (JsTokenKind.IDENTIFIER, 'y', True),
            ],
            'x /* c */': [(JsTokenKind.IDENTIFIER, 'x', True), (JsTokenKind.COMMENT, '/* c */', True)],
            'x /* c *': [(JsTokenKind.IDENTIFIER, 'x', True), (JsTokenKind.COMMENT, '/* c *', False)],
            'x /* c /': [(JsTokenKind.IDENTIFIER, 'x', True), (JsTokenKind.COMMENT, '/* c /', False)],
            'x /* c': [(JsTokenKind.IDENTIFIER, 'x', True), (JsTokenKind.COMMENT, '/* c', False)],
            'x /*': [(JsTokenKind.IDENTIFIER, 'x', True), (JsTokenKind.COMMENT, '/*', False)],
            '/* a\n b': [(JsTokenKind.COMMENT, '/* a\n b', False), (JsTokenKind.NEWLINE, '', True)],
        }
        self.assertEqual({source: _tokens_with_termination(source) for source in rows}, rows)

    def test_the_lexer_records_where_the_comment_the_file_ends_inside_began(self):
        rows = {
            'x /* c */': None,
            'x // c': None,
            'x /* c': 2,
            'x /* c */ y /* d': 12,
            '/*': 0,
        }

        def open_comment(source: str) -> int | None:
            lexer = JsLexer(source)
            for _ in lexer.tokenize():
                pass
            return lexer.open_comment

        self.assertEqual({source: open_comment(source) for source in rows}, rows)
