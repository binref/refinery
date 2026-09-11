from __future__ import annotations

import pathlib

from typing import Generator, NamedTuple

from test import TestBase

from refinery.lib.scripts.ps1.lexer import Ps1Lexer, Ps1LexerMode, reads_as_one_numeral
from refinery.lib.scripts.ps1.token import (
    forces_new_token,
    forces_new_token_after_number,
    is_whitespace,
    Ps1Token,
    Ps1TokenKind,
)


class _Reading(NamedTuple):
    token: Ps1Token
    end: int


class TestPs1Lexer(TestBase):

    def _tokens(self, source: str, mode: Ps1LexerMode = Ps1LexerMode.EXPRESSION) -> list[tuple[Ps1TokenKind, str]]:
        lexer = Ps1Lexer(source)
        lexer.mode = mode
        gen = lexer.tokenize()
        result = []
        tok = next(gen)
        while tok.kind != Ps1TokenKind.EOF:
            result.append((tok.kind, tok.value))
            tok = next(gen)
        return result

    def test_integer_decimal(self):
        tokens = self._tokens('42')
        self.assertEqual(tokens, [(Ps1TokenKind.INTEGER, '42')])

    def test_integer_hex(self):
        tokens = self._tokens('0xFF')
        self.assertEqual(tokens, [(Ps1TokenKind.INTEGER, '0xFF')])

    def test_integer_long(self):
        tokens = self._tokens('100L')
        self.assertEqual(tokens, [(Ps1TokenKind.INTEGER, '100L')])

    def test_real_decimal(self):
        tokens = self._tokens('3.14')
        self.assertEqual(tokens, [(Ps1TokenKind.REAL, '3.14')])

    def test_real_scientific(self):
        tokens = self._tokens('1e10')
        self.assertEqual(tokens, [(Ps1TokenKind.REAL, '1e10')])

    def test_real_suffix_kb(self):
        tokens = self._tokens('64kb')
        self.assertEqual(tokens, [(Ps1TokenKind.REAL, '64kb')])

    def test_variable_simple(self):
        tokens = self._tokens('$x')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$x')])

    def test_variable_scoped(self):
        tokens = self._tokens('$global:x')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$global:x')])

    def test_variable_env(self):
        tokens = self._tokens('$env:PATH')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$env:PATH')])

    def test_variable_braced(self):
        tokens = self._tokens('${my var}')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '${my var}')])

    def test_variable_special_dollar(self):
        tokens = self._tokens('$$')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$$')])

    def test_variable_special_question(self):
        tokens = self._tokens('$?')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$?')])

    def test_splat_variable(self):
        tokens = self._tokens('@params')
        self.assertEqual(tokens, [(Ps1TokenKind.SPLAT_VARIABLE, '@params')])

    def test_string_verbatim(self):
        tokens = self._tokens("'hello world'")
        self.assertEqual(tokens, [(Ps1TokenKind.STRING_VERBATIM, "'hello world'")])

    def test_string_verbatim_escaped_quote(self):
        tokens = self._tokens("'it''s'")
        self.assertEqual(tokens, [(Ps1TokenKind.STRING_VERBATIM, "'it''s'")])

    def test_string_expandable(self):
        tokens = self._tokens('"hello $name"')
        self.assertEqual(tokens, [(Ps1TokenKind.STRING_EXPAND, '"hello $name"')])

    def test_here_string_verbatim(self):
        src = "@'\nline one\nline two\n'@"
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.HSTRING_VERBATIM)

    def test_here_string_expandable(self):
        src = '@"\nline $one\nline two\n"@'
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.HSTRING_EXPAND)

    def test_operators_arithmetic(self):
        tokens = self._tokens('1 + 2 - 3 * 4 / 5 % 6')
        kinds = [t[0] for t in tokens]
        self.assertIn(Ps1TokenKind.PLUS, kinds)
        self.assertIn(Ps1TokenKind.DASH, kinds)
        self.assertIn(Ps1TokenKind.STAR, kinds)
        self.assertIn(Ps1TokenKind.SLASH, kinds)
        self.assertIn(Ps1TokenKind.PERCENT, kinds)

    def test_operator_range(self):
        tokens = self._tokens('1..10')
        self.assertEqual(tokens[0], (Ps1TokenKind.INTEGER, '1'))
        self.assertEqual(tokens[1], (Ps1TokenKind.DOTDOT, '..'))
        self.assertEqual(tokens[2], (Ps1TokenKind.INTEGER, '10'))

    def test_operator_comparison(self):
        tokens = self._tokens('$x -eq 1')
        self.assertEqual(tokens[1], (Ps1TokenKind.OPERATOR, '-eq'))

    def test_operator_logical(self):
        tokens = self._tokens('$a -and $b -or $c')
        ops = [t for t in tokens if t[0] == Ps1TokenKind.OPERATOR]
        self.assertEqual(ops[0][1], '-and')
        self.assertEqual(ops[1][1], '-or')

    def test_assignment_operators(self):
        for op_str, kind in [
            ('=', Ps1TokenKind.EQUALS),
            ('+=', Ps1TokenKind.PLUS_ASSIGN),
            ('-=', Ps1TokenKind.DASH_ASSIGN),
            ('*=', Ps1TokenKind.STAR_ASSIGN),
            ('/=', Ps1TokenKind.SLASH_ASSIGN),
            ('%=', Ps1TokenKind.PERCENT_ASSIGN),
        ]:
            tokens = self._tokens(F'$x {op_str} 1')
            self.assertEqual(tokens[1][0], kind)

    def test_increment_decrement(self):
        tokens = self._tokens('$i++')
        self.assertEqual(tokens[1], (Ps1TokenKind.INCREMENT, '++'))
        tokens = self._tokens('$i--')
        self.assertEqual(tokens[1], (Ps1TokenKind.DECREMENT, '--'))

    def test_grouping(self):
        tokens = self._tokens('($x)')
        kinds = [t[0] for t in tokens]
        self.assertEqual(kinds, [
            Ps1TokenKind.LPAREN,
            Ps1TokenKind.VARIABLE,
            Ps1TokenKind.RPAREN,
        ])

    def test_at_lparen(self):
        tokens = self._tokens('@(1)')
        self.assertEqual(tokens[0], (Ps1TokenKind.AT_LPAREN, '@('))

    def test_at_lbrace(self):
        tokens = self._tokens('@{x=1}')
        self.assertEqual(tokens[0], (Ps1TokenKind.AT_LBRACE, '@{'))

    def test_dollar_lparen(self):
        tokens = self._tokens('$($x)')
        self.assertEqual(tokens[0], (Ps1TokenKind.DOLLAR_LPAREN, '$('))

    def test_pipe(self):
        tokens = self._tokens('$x | $y')
        self.assertEqual(tokens[1], (Ps1TokenKind.PIPE, '|'))

    def test_keywords(self):
        for kw in [
            'if', 'elseif', 'else', 'while', 'for', 'foreach', 'do',
            'switch', 'function', 'return', 'try', 'catch', 'finally',
            'throw', 'trap', 'break', 'continue', 'exit', 'param',
            'begin', 'process', 'end', 'in', 'filter', 'data', 'class',
            'using', 'until', 'enum', 'dynamicparam',
        ]:
            tokens = self._tokens(kw)
            self.assertTrue(tokens[0][0].is_keyword, F'{kw} not recognized as keyword')

    def test_comment_line(self):
        tokens = self._tokens('$x # a comment')
        kinds = [t[0] for t in tokens]
        self.assertIn(Ps1TokenKind.VARIABLE, kinds)

    def test_comment_block(self):
        tokens = self._tokens('$x <# block #> $y')
        kinds = [t[0] for t in tokens]
        self.assertEqual(kinds.count(Ps1TokenKind.VARIABLE), 2)

    def test_newline(self):
        tokens = self._tokens('$x\n$y')
        kinds = [t[0] for t in tokens]
        self.assertIn(Ps1TokenKind.NEWLINE, kinds)

    def test_semicolon(self):
        tokens = self._tokens('$x; $y')
        self.assertEqual(tokens[1], (Ps1TokenKind.SEMICOLON, ';'))

    def test_double_colon(self):
        tokens = self._tokens('[int]::MaxValue')
        kinds = [t[0] for t in tokens]
        self.assertIn(Ps1TokenKind.DOUBLE_COLON, kinds)

    def test_generic_token(self):
        tokens = self._tokens('Write-Host', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, 'Write-Host'))

    def test_identifier_no_dash_in_expression_mode(self):
        tokens = self._tokens('Name-like')
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, 'Name'))
        self.assertEqual(tokens[1], (Ps1TokenKind.OPERATOR, '-like'))

    def test_redirection(self):
        tokens = self._tokens('> file.txt')
        self.assertEqual(tokens[0][0], Ps1TokenKind.REDIRECTION)

    def test_redirection_append(self):
        tokens = self._tokens('>> file.txt')
        self.assertEqual(tokens[0][0], Ps1TokenKind.REDIRECTION)

    def test_comma(self):
        tokens = self._tokens('1, 2, 3')
        commas = [t for t in tokens if t[0] == Ps1TokenKind.COMMA]
        self.assertEqual(len(commas), 2)

    def test_exclaim(self):
        tokens = self._tokens('!$x')
        self.assertEqual(tokens[0], (Ps1TokenKind.EXCLAIM, '!'))

    def test_expandable_string_with_nested_subexpression_quotes(self):
        src = '"result: $($x.ToString("N2"))"'
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.STRING_EXPAND)
        self.assertEqual(tokens[0][1], src)

    def test_expandable_string_nested_parens_in_subexpr(self):
        src = '"val: $((1+2))"'
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.STRING_EXPAND)
        self.assertEqual(tokens[0][1], src)

    def test_expandable_string_nested_sq_in_subexpr(self):
        src = '''"val: $($h['key'])"'''
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.STRING_EXPAND)
        self.assertEqual(tokens[0][1], src)

    def test_multiplier_suffix_requires_b(self):
        for suffix in ('kb', 'mb', 'gb', 'tb', 'pb', 'KB', 'MB', 'GB', 'TB', 'PB'):
            tokens = self._tokens(F'5{suffix}')
            self.assertEqual(tokens[0][0], Ps1TokenKind.REAL, F'5{suffix} should be REAL')
        tokens = self._tokens('5d')
        self.assertEqual(tokens[0][0], Ps1TokenKind.REAL, '5d should be REAL')
        for letter in ('k', 'm', 'g', 't', 'p', 'K', 'M', 'G', 'T', 'P'):
            tokens = self._tokens(F'5{letter}')
            self.assertNotEqual(
                tokens[0][0], Ps1TokenKind.REAL,
                F'5{letter} should NOT be REAL (multiplier requires trailing b)',
            )

    def test_real_with_decimal_point_and_multiplier_suffix(self):
        for suffix in ('kb', 'mb', 'gb', 'tb', 'pb', 'KB', 'MB', 'GB', 'TB', 'PB'):
            src = F'1.5{suffix}'
            tokens = self._tokens(src)
            self.assertEqual(
                tokens, [(Ps1TokenKind.REAL, src)],
                F'{src} should be a single REAL token',
            )
        tokens = self._tokens('2.0d')
        self.assertEqual(tokens, [(Ps1TokenKind.REAL, '2.0d')])

    def test_real_scientific_with_multiplier_suffix(self):
        tokens = self._tokens('1.5e2kb')
        self.assertEqual(tokens, [(Ps1TokenKind.REAL, '1.5e2kb')])
        tokens = self._tokens('1e3mb')
        self.assertEqual(tokens, [(Ps1TokenKind.REAL, '1e3mb')])

    def test_hex_integer_with_multiplier_suffix(self):
        for suffix in ('kb', 'mb', 'gb', 'tb', 'pb', 'KB', 'MB', 'GB', 'TB', 'PB'):
            src = F'0x10{suffix}'
            tokens = self._tokens(src)
            self.assertEqual(
                tokens, [(Ps1TokenKind.REAL, src)],
                F'{src} should be a single REAL token',
            )

    def test_expandable_here_string_with_subexpression(self):
        src = '@"\n$($x.ToString())\n"@'
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.HSTRING_EXPAND)
        self.assertEqual(tokens[0][1], src)

    def test_wildcard_question_marks_single_token(self):
        tokens = self._tokens('???t?', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens, [(Ps1TokenKind.GENERIC_TOKEN, '???t?')])

    def test_wildcard_question_star_mix(self):
        tokens = self._tokens('??*', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens, [(Ps1TokenKind.GENERIC_TOKEN, '??*')])

    def test_single_question_mark_stays_separate(self):
        tokens = self._tokens('?', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens, [(Ps1TokenKind.GENERIC_TOKEN, '?')])

    def test_expandable_here_string_with_nested_here_string(self):
        src = '@"\n$(@"\ninner\n"@)\n"@'
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.HSTRING_EXPAND)
        self.assertEqual(tokens[0][1], src)

    def test_stream_redirection_2_to_null(self):
        tokens = self._tokens('2>$null', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '2>'))
        self.assertEqual(tokens[1], (Ps1TokenKind.VARIABLE, '$null'))

    def test_stream_redirection_2_append(self):
        tokens = self._tokens('2>>file.txt', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '2>>'))

    def test_stream_redirection_2_merge(self):
        tokens = self._tokens('2>&1', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '2>&1'))

    def test_stream_redirection_star(self):
        tokens = self._tokens('*>$null')
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '*>'))
        self.assertEqual(tokens[1], (Ps1TokenKind.VARIABLE, '$null'))

    def test_stream_redirection_3_merge(self):
        tokens = self._tokens('3>&2', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '3>&2'))

    def test_bare_merge_redirection_allows_stream_1(self):
        tokens = self._tokens('>&1', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '>&1'))

    def test_bare_merge_redirection_rejects_stream_2(self):
        tokens = self._tokens('>&2', mode=Ps1LexerMode.ARGUMENT)
        # bare >&2 is invalid; should lex as > followed by & and 2
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '>'))

    def test_digit_not_stream_redirection(self):
        tokens = self._tokens('9>file')
        self.assertEqual(tokens[0], (Ps1TokenKind.INTEGER, '9'))
        self.assertEqual(tokens[1], (Ps1TokenKind.REDIRECTION, '>'))

    def test_reserved_input_operator_is_not_a_redirection_token(self):
        expected = [
            (Ps1TokenKind.GENERIC_TOKEN, 'echo'),
            (Ps1TokenKind.GENERIC_TOKEN, 'a'),
            (Ps1TokenKind.REDIRECT_IN, '<'),
            (Ps1TokenKind.GENERIC_TOKEN, 'b'),
        ]
        self.assertEqual(self._tokens('echo a < b', mode=Ps1LexerMode.ARGUMENT), expected)

    def test_reserved_input_operator_and_output_redirection_are_separate_tokens(self):
        expected = [
            (Ps1TokenKind.GENERIC_TOKEN, 'Get-Content'),
            (Ps1TokenKind.REDIRECT_IN, '<'),
            (Ps1TokenKind.GENERIC_TOKEN, 'in.txt'),
            (Ps1TokenKind.REDIRECTION, '>'),
            (Ps1TokenKind.GENERIC_TOKEN, 'out.txt'),
        ]
        source = 'Get-Content < in.txt > out.txt'
        self.assertEqual(self._tokens(source, mode=Ps1LexerMode.ARGUMENT), expected)

    def test_input_operator_without_whitespace_does_not_split_a_bare_word(self):
        tokens = self._tokens('echo a<b', mode=Ps1LexerMode.ARGUMENT)
        expected = [
            (Ps1TokenKind.GENERIC_TOKEN, 'echo'),
            (Ps1TokenKind.GENERIC_TOKEN, 'a<b'),
        ]
        self.assertEqual(tokens, expected)

    def test_special_variable_dollar_does_not_consume_trailing(self):
        tokens = self._tokens('$$foo')
        self.assertEqual(tokens[0], (Ps1TokenKind.VARIABLE, '$$'))
        self.assertEqual(tokens[1], (Ps1TokenKind.GENERIC_TOKEN, 'foo'))

    def test_special_variable_question_does_not_consume_trailing(self):
        tokens = self._tokens('$?foo')
        self.assertEqual(tokens[0], (Ps1TokenKind.VARIABLE, '$?'))
        self.assertEqual(tokens[1], (Ps1TokenKind.GENERIC_TOKEN, 'foo'))

    def test_special_variable_caret_does_not_consume_trailing(self):
        tokens = self._tokens('$^foo')
        self.assertEqual(tokens[0], (Ps1TokenKind.VARIABLE, '$^'))
        self.assertEqual(tokens[1], (Ps1TokenKind.GENERIC_TOKEN, 'foo'))

    def test_drive_qualified_variable(self):
        tokens = self._tokens('$HKLM:Software')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$HKLM:Software')])

    def test_drive_qualified_variable_cert(self):
        tokens = self._tokens('$cert:CurrentUser')
        self.assertEqual(tokens, [(Ps1TokenKind.VARIABLE, '$cert:CurrentUser')])

    def test_drive_qualified_does_not_consume_double_colon(self):
        tokens = self._tokens('$x::StaticMember')
        self.assertEqual(tokens[0], (Ps1TokenKind.VARIABLE, '$x'))
        self.assertEqual(tokens[1], (Ps1TokenKind.DOUBLE_COLON, '::'))

    def test_a_decimal_integer_swallows_the_dot_that_joins_it_to_a_word(self):
        tokens = self._tokens('7.ToString')
        self.assertEqual(tokens, [(Ps1TokenKind.GENERIC_TOKEN, '7.ToString')])

    def test_a_decimal_integer_swallows_the_dot_that_joins_it_to_a_variable(self):
        tokens = self._tokens('7.$method')
        self.assertEqual(tokens, [(Ps1TokenKind.GENERIC_EXPAND, '7.$method')])

    def test_a_numeral_that_ended_before_the_dot_reads_a_member_access(self):
        for numeral, kind in (
            ('0xFF', Ps1TokenKind.INTEGER),
            ('1L', Ps1TokenKind.INTEGER),
            ('3.5', Ps1TokenKind.REAL),
            ('1e3', Ps1TokenKind.REAL),
            ('1kb', Ps1TokenKind.REAL),
            ('1d', Ps1TokenKind.REAL),
        ):
            with self.subTest(numeral=numeral):
                self.assertEqual(self._tokens(F'{numeral}.ToString'), [
                    (kind, numeral),
                    (Ps1TokenKind.DOT, '.'),
                    (Ps1TokenKind.GENERIC_TOKEN, 'ToString'),
                ])

    def test_a_numeral_gives_a_trailing_dot_back_only_to_the_range_operator(self):
        self.assertEqual(self._tokens('3...5'), [
            (Ps1TokenKind.INTEGER, '3'),
            (Ps1TokenKind.DOTDOT, '..'),
            (Ps1TokenKind.REAL, '.5'),
        ])

    def test_a_numeral_touching_a_character_that_starts_no_token_is_that_word(self):
        for source in ('1x', '3.5x', '1e3x', "3'a'", '3"a"', '3:a', '3@y', '0xFF[0]'):
            with self.subTest(source=source):
                self.assertEqual(self._tokens(source), [(Ps1TokenKind.GENERIC_TOKEN, source)])

    def test_a_numeral_ends_where_the_next_character_starts_its_own_token(self):
        for source, tail in (
            ('3+1', [(Ps1TokenKind.PLUS, '+'), (Ps1TokenKind.INTEGER, '1')]),
            ('3-4', [(Ps1TokenKind.DASH, '-'), (Ps1TokenKind.INTEGER, '4')]),
            ('3%2', [(Ps1TokenKind.PERCENT, '%'), (Ps1TokenKind.INTEGER, '2')]),
            ('3/2', [(Ps1TokenKind.SLASH, '/'), (Ps1TokenKind.INTEGER, '2')]),
            ('3;', [(Ps1TokenKind.SEMICOLON, ';')]),
            ('3)', [(Ps1TokenKind.RPAREN, ')')]),
        ):
            with self.subTest(source=source):
                self.assertEqual(self._tokens(source), [(Ps1TokenKind.INTEGER, '3'), *tail])

    def test_a_closing_bracket_ends_a_numeral_where_an_opening_one_does_not(self):
        self.assertEqual(self._tokens('3]'), [
            (Ps1TokenKind.INTEGER, '3'),
            (Ps1TokenKind.RBRACKET, ']'),
        ])
        self.assertEqual(self._tokens('3[0]'), [(Ps1TokenKind.GENERIC_TOKEN, '3[0]')])

    def test_a_numeral_standing_alone_in_an_argument_is_still_a_numeral(self):
        for source, kind in (
            ('3', Ps1TokenKind.INTEGER),
            ('3.', Ps1TokenKind.REAL),
            ('3.5', Ps1TokenKind.REAL),
            ('0xFF', Ps1TokenKind.INTEGER),
            ('1kb', Ps1TokenKind.REAL),
        ):
            with self.subTest(source=source):
                tokens = self._tokens(source, mode=Ps1LexerMode.ARGUMENT)
                self.assertEqual(tokens, [(kind, source)])

    def test_a_numeral_touching_anything_in_an_argument_is_one_word(self):
        for source in ('3.ToString', '0xFF.GetType', '3.5.GetType', '1kb.GetType', '3..5', '3[0]'):
            with self.subTest(source=source):
                tokens = self._tokens(source, mode=Ps1LexerMode.ARGUMENT)
                self.assertEqual(tokens, [(Ps1TokenKind.GENERIC_TOKEN, source)])

    def test_trailing_dot_number_preserved_before_whitespace(self):
        tokens = self._tokens('7. ')
        self.assertEqual(tokens[0], (Ps1TokenKind.REAL, '7.'))

    def test_trailing_dot_number_preserved_at_eof(self):
        tokens = self._tokens('7.')
        self.assertEqual(tokens[0], (Ps1TokenKind.REAL, '7.'))

    def test_trailing_dot_number_preserved_before_operator(self):
        tokens = self._tokens('7.+ 3')
        self.assertEqual(tokens[0], (Ps1TokenKind.REAL, '7.'))
        self.assertEqual(tokens[1], (Ps1TokenKind.PLUS, '+'))

    def test_real_with_digits_after_dot_unchanged(self):
        tokens = self._tokens('7.5')
        self.assertEqual(tokens[0], (Ps1TokenKind.REAL, '7.5'))

    def test_backtick_line_continuation(self):
        tokens = self._tokens('$x +`\n$y')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.NEWLINE, kinds)

    def test_parameter_question_mark(self):
        tokens = self._tokens('-?', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens, [(Ps1TokenKind.PARAMETER, '-?')])

    def test_here_string_verbatim_bare_cr(self):
        src = "@'\rline one\rline two\r'@"
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.HSTRING_VERBATIM)

    def test_here_string_expandable_bare_cr(self):
        src = '@"\rline one\rline two\r"@'
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.HSTRING_EXPAND)

    def test_input_redirection(self):
        tokens = self._tokens('Get-Content < file.txt', mode=Ps1LexerMode.ARGUMENT)
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.REDIRECTION, kinds)
        self.assertIn(Ps1TokenKind.REDIRECT_IN, kinds)
        redir = next(t for t in tokens if t[0] == Ps1TokenKind.REDIRECT_IN)
        self.assertEqual(redir[1], '<')

    def test_input_redirection_does_not_break_block_comment(self):
        tokens = self._tokens('<# comment #> $x')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.REDIRECT_IN, kinds)
        self.assertIn(Ps1TokenKind.VARIABLE, kinds)

    def test_expandable_string_subexpr_with_here_string_containing_apostrophe_and_paren(self):
        src = "\"text $(@'\nit's ) here\n'@) suffix\""
        tokens = self._tokens(src)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0][0], Ps1TokenKind.STRING_EXPAND)
        self.assertIn('suffix', tokens[0][1])

    def test_label_token(self):
        tokens = self._tokens(':outer while ($true) { break :outer }')
        self.assertEqual(tokens[0], (Ps1TokenKind.LABEL, ':outer'))
        label_tokens = [t for t in tokens if t[0] == Ps1TokenKind.LABEL]
        self.assertEqual(len(label_tokens), 2)

    def test_numbered_redirection_suppressed_in_expression_mode(self):
        tokens = self._tokens('$x + 1>$null')
        kinds = [t[0] for t in tokens]
        idx = kinds.index(Ps1TokenKind.INTEGER)
        self.assertEqual(tokens[idx][1], '1')
        redir_token = next(t for t in tokens if t[0] == Ps1TokenKind.REDIRECTION)
        self.assertEqual(redir_token[1], '>')

    def test_numbered_redirection_in_argument_mode(self):
        tokens = self._tokens('Write-Error fail 2>$null', mode=Ps1LexerMode.ARGUMENT)
        kinds = [t[0] for t in tokens]
        self.assertIn(Ps1TokenKind.REDIRECTION, kinds)
        redir_token = next(t for t in tokens if t[0] == Ps1TokenKind.REDIRECTION)
        self.assertEqual(redir_token[1], '2>')

    def test_dotdot_path_in_argument_mode(self):
        tokens = self._tokens('..\\..\\file.exe', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '..\\..\\file.exe'))

    def test_dotdot_forward_slash_path_in_argument_mode(self):
        tokens = self._tokens('../../file.txt', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '../../file.txt'))

    def test_dotdot_range_in_expression_mode(self):
        tokens = self._tokens('1..10')
        self.assertEqual(tokens[1], (Ps1TokenKind.DOTDOT, '..'))

    def test_dotdot_range_with_whitespace_in_argument_mode(self):
        tokens = self._tokens('1 .. 10', mode=Ps1LexerMode.ARGUMENT)
        dotdots = [t for t in tokens if t[0] == Ps1TokenKind.DOTDOT]
        self.assertEqual(len(dotdots), 1)

    def test_dashdash_argument_in_argument_mode(self):
        tokens = self._tokens('--no-pager', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '--no-pager'))

    def test_dashdash_standalone_in_argument_mode(self):
        tokens = self._tokens('-- foo', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.DECREMENT, '--'))

    def test_dashdash_in_expression_mode(self):
        tokens = self._tokens('--$x')
        self.assertEqual(tokens[0], (Ps1TokenKind.DECREMENT, '--'))

    def test_plusplus_argument_in_argument_mode(self):
        tokens = self._tokens('++count', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '++count'))

    def test_dot_letter_generic_token_in_argument_mode(self):
        tokens = self._tokens('.gitignore', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '.gitignore'))

    def test_dot_source_variable_not_generic(self):
        tokens = self._tokens('. $script', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.DOT, '.'))

    def test_dot_source_string_not_generic(self):
        tokens = self._tokens(". 'script.ps1'", mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.DOT, '.'))

    def test_star_wildcard_in_argument_mode(self):
        tokens = self._tokens('*.txt', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '*.txt'))

    def test_slash_path_in_argument_mode(self):
        tokens = self._tokens('/etc/hosts', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '/etc/hosts'))

    def test_star_standalone_in_argument_mode(self):
        tokens = self._tokens('* foo', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.STAR, '*'))

    def test_star_in_expression_mode(self):
        tokens = self._tokens('2 * 3')
        stars = [t for t in tokens if t[0] == Ps1TokenKind.STAR]
        self.assertEqual(len(stars), 1)

    def test_star_bracket_glob_in_argument_mode(self):
        tokens = self._tokens('*[a-z]*', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '*[a-z]*'))

    def test_hyphenated_parameter_name(self):
        tokens = self._tokens('-no-pager', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.PARAMETER, '-no-pager'))

    def test_a_dash_argument_names_a_parameter_before_a_letter_underscore_or_question_mark(self):
        for source in ('-Recurse', '-_1', '-?'):
            with self.subTest(source=source):
                tokens = self._tokens(source, mode=Ps1LexerMode.ARGUMENT)
                self.assertEqual(tokens, [(Ps1TokenKind.PARAMETER, source)])

    def test_a_dash_argument_before_anything_else_is_part_of_the_word_around_it(self):
        for source, kind in (
            ('-1', Ps1TokenKind.GENERIC_TOKEN),
            ('-1.5', Ps1TokenKind.GENERIC_TOKEN),
            ('-.5', Ps1TokenKind.GENERIC_TOKEN),
            ('-0xFF', Ps1TokenKind.GENERIC_TOKEN),
            ('-1L', Ps1TokenKind.GENERIC_TOKEN),
            ('-1e3', Ps1TokenKind.GENERIC_TOKEN),
            ('-1d', Ps1TokenKind.GENERIC_TOKEN),
            ('-1kb', Ps1TokenKind.GENERIC_TOKEN),
            ('-1x', Ps1TokenKind.GENERIC_TOKEN),
            ('--1', Ps1TokenKind.GENERIC_TOKEN),
            ("-'a'", Ps1TokenKind.GENERIC_TOKEN),
            ('-', Ps1TokenKind.GENERIC_TOKEN),
            ('-$x', Ps1TokenKind.GENERIC_EXPAND),
        ):
            with self.subTest(source=source):
                tokens = self._tokens(source, mode=Ps1LexerMode.ARGUMENT)
                self.assertEqual(tokens, [(kind, source)])

    def test_a_dash_argument_followed_by_a_space_is_the_word_dash_on_its_own(self):
        tokens = self._tokens('- x', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens, [
            (Ps1TokenKind.GENERIC_TOKEN, '-'),
            (Ps1TokenKind.GENERIC_TOKEN, 'x'),
        ])

    def test_a_dash_argument_is_a_word_wherever_an_argument_may_stand(self):
        self.assertEqual(self._tokens('-1,2', mode=Ps1LexerMode.ARGUMENT), [
            (Ps1TokenKind.GENERIC_TOKEN, '-1'),
            (Ps1TokenKind.COMMA, ','),
            (Ps1TokenKind.INTEGER, '2'),
        ])
        self.assertEqual(self._tokens('1,-2', mode=Ps1LexerMode.ARGUMENT), [
            (Ps1TokenKind.INTEGER, '1'),
            (Ps1TokenKind.COMMA, ','),
            (Ps1TokenKind.GENERIC_TOKEN, '-2'),
        ])
        self.assertEqual(self._tokens('-Name -2', mode=Ps1LexerMode.ARGUMENT), [
            (Ps1TokenKind.PARAMETER, '-Name'),
            (Ps1TokenKind.GENERIC_TOKEN, '-2'),
        ])

    def test_a_dash_joins_a_numeral_into_a_word_only_in_an_argument(self):
        """
        The sign is left for `refinery.lib.scripts.ps1.parser.Ps1Parser._parse_signed_numeral` to
        bind, which is what keeps the numeral a numeral where an argument has none at all.
        """
        self.assertEqual(
            self._tokens('-1', mode=Ps1LexerMode.ARGUMENT),
            [(Ps1TokenKind.GENERIC_TOKEN, '-1')],
        )
        self.assertEqual(
            self._tokens('-1', mode=Ps1LexerMode.EXPRESSION),
            [(Ps1TokenKind.DASH, '-'), (Ps1TokenKind.INTEGER, '1')],
        )

    def test_number_followed_by_variable_in_argument_mode(self):
        tokens = self._tokens('123$var', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_EXPAND, '123$var'))

    def test_at_sign_mid_generic_token_in_argument_mode(self):
        tokens = self._tokens('path/@/file', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, 'path/@/file'))

    def test_variable_slash_path_in_argument_mode(self):
        tokens = self._tokens('$dir/file.txt', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_EXPAND, '$dir/file.txt'))

    def test_variable_backslash_path_in_argument_mode(self):
        tokens = self._tokens('$env:TEMP\\file', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_EXPAND, '$env:TEMP\\file'))

    def test_variable_dash_suffix_in_argument_mode(self):
        tokens = self._tokens('$var-suffix', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_EXPAND, '$var-suffix'))

    def test_generic_token_without_variable_stays_plain(self):
        tokens = self._tokens('hello-world', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, 'hello-world'))

    def test_generic_expand_with_subexpression(self):
        tokens = self._tokens('prefix$(1+2)suffix', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_EXPAND, 'prefix$(1+2)suffix'))

    def test_generic_token_bare_dollar_no_variable(self):
        tokens = self._tokens('$+rest', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0][0], Ps1TokenKind.GENERIC_TOKEN)

    def test_variable_dot_remains_variable_in_argument_mode(self):
        tokens = self._tokens('$var.prop', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.VARIABLE, '$var'))

    def test_variable_space_remains_variable_in_argument_mode(self):
        tokens = self._tokens('$var foo', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.VARIABLE, '$var'))

    def test_parameter_with_embedded_quote_becomes_generic_token(self):
        tokens = self._tokens("-fil'e'", mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, "-fil'e'"))

    def test_double_colon_generic_token_in_argument_mode(self):
        tokens = self._tokens('::path', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '::path'))

    def test_compound_assignment_generic_token_in_argument_mode(self):
        for op in ('+=', '-=', '*=', '/=', '%='):
            with self.subTest(op=op):
                tokens = self._tokens(F'{op}value', mode=Ps1LexerMode.ARGUMENT)
                self.assertEqual(len(tokens), 1)
                self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, F'{op}value'))

    def test_compound_assignment_operator_with_space_in_argument_mode(self):
        expected = {
            '+=': Ps1TokenKind.PLUS_ASSIGN,
            '-=': Ps1TokenKind.DASH_ASSIGN,
            '*=': Ps1TokenKind.STAR_ASSIGN,
            '/=': Ps1TokenKind.SLASH_ASSIGN,
            '%=': Ps1TokenKind.PERCENT_ASSIGN,
        }
        for op, kind in expected.items():
            with self.subTest(op=op):
                tokens = self._tokens(F'{op} value', mode=Ps1LexerMode.ARGUMENT)
                self.assertEqual(tokens[0], (kind, op))

    def test_double_colon_not_label(self):
        tokens = self._tokens('[System.IO]::Path')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.LABEL, kinds)
        self.assertIn(Ps1TokenKind.DOUBLE_COLON, kinds)


class TestPs1LexerModeInvariance(TestBase):
    """
    `Ps1TokenKind.mode_invariant` claims that a token of such a kind reads the same way at the same
    position in either `Ps1LexerMode`. The PowerShell parser keeps such a token as lookahead across
    a mode change rather than re-reading the source, so a kind that does not belong in the set hands
    the parser a token the new mode would never have produced, and nothing in the output says so.

    The claim is checked over PowerShell nobody wrote for it: the metadata collector that this
    project runs on Windows PowerShell 5.1, the project updater, and two PowerShell malware samples,
    one a fragment-array dropper and one a script padded with roughly a hundred junk statements.
    """

    _SCRIPTS = (
        'refinery/run-pwsh.ps1',
        'update.ps1',
    )

    _SAMPLES = (
        'baa48c748d58d0c715fc2b7fbe74610213c070814762a2774cc6d57d4522a73d',
        '34f5eab91e26c1c2073740ed76af289fdd0df985385d3d198f5be7165d79745f',
    )

    def _corpus(self) -> dict[str, str]:
        root = pathlib.Path(__file__).resolve().parents[4]
        corpus = {name: (root / name).read_text('utf8') for name in self._SCRIPTS}
        for sha256 in self._SAMPLES:
            corpus[sha256[:8]] = self.download_sample(sha256).decode('utf8')
        return corpus

    def _readings(self, source: str) -> Generator[tuple[int, _Reading, _Reading], None, None]:
        """
        Every position in `source` that some sequence of scans can reach, in either mode, together
        with what each mode reads there. The frontier starts at the beginning of the source and
        grows by the end of every scan, so a position that only one of the two modes can arrive at
        is visited as well. This is the whole domain a parser can hold lookahead over, and it does
        not depend on knowing which positions the lexer treats specially.
        """
        frontier = [0]
        visited: set[int] = set()
        while frontier:
            position = frontier.pop()
            if position in visited:
                continue
            visited.add(position)
            readings: dict[Ps1LexerMode, _Reading] = {}
            for mode in Ps1LexerMode:
                lexer = Ps1Lexer(source, pos=position, mode=mode)
                token = lexer.scan()
                readings[mode] = _Reading(token, lexer.pos)
                if lexer.pos > position:
                    frontier.append(lexer.pos)
            yield (
                position,
                readings[Ps1LexerMode.EXPRESSION],
                readings[Ps1LexerMode.ARGUMENT],
            )

    def test_mode_invariant_kinds_read_identically_in_the_other_mode(self):
        violations: list[str] = []
        invariant_tokens = 0
        divergences = 0
        for name, source in self._corpus().items():
            for position, expression, argument in self._readings(source):
                if expression == argument:
                    if expression.token.kind.mode_invariant:
                        invariant_tokens += 1
                    continue
                divergences += 1
                for reading in (expression, argument):
                    if not reading.token.kind.mode_invariant:
                        continue
                    violations.append(
                        F'{name}@{position}: {reading.token.kind.name} {reading.token.value!r} is'
                        F' claimed mode invariant, but EXPRESSION reads {expression.token!r} up to'
                        F' {expression.end} and ARGUMENT reads {argument.token!r} up to'
                        F' {argument.end}'
                    )
        if violations:
            self.fail('\n'.join([
                'tokens of a mode invariant kind that the other mode reads differently:',
                *violations,
            ]))
        self.assertTrue(invariant_tokens, 'the corpus produced no token of a mode invariant kind')
        self.assertTrue(divergences, 'the corpus never made the two modes read a position apart')


class TestPs1NumeralBoundary(TestBase):
    """
    Whether a numeral written as one spelling is still that numeral once the text behind it is
    written straight against it. Every row is one a 5.1 host was measured on: a `Number` token
    where the numeral survived, and a single `Generic` token where the whole thing became one word.
    """

    def _reads(self, table: dict[tuple[str, str], bool], mode: Ps1LexerMode):
        return {row: reads_as_one_numeral(*row, mode) for row in table}

    def test_a_dot_reads_the_member_of_every_numeral_that_ends_before_it(self):
        """
        `3.` opens a real number, so `3.ToString()` is the one word `3.ToString` and 5.1 rejects
        the script. A numeral whose spelling has already ended keeps the dot for the member.
        """
        table = {
            ('3', '.ToString()')    : False,
            ('0xFF', '.GetType()')  : True,
            ('1.5', '.GetType()')   : True,
            ('1kb', '.GetType()')   : True,
            ('1L', '.GetType()')    : True,
            ('1e3', '.GetType()')   : True,
            ('10d', '.GetType()')   : True,
        }
        self.assertEqual(self._reads(table, Ps1LexerMode.EXPRESSION), table)

    def test_no_numeral_survives_an_index_bracket_or_a_static_member(self):
        """
        Neither a bracket nor a colon ends a numeral, so every one of these is a single word
        whatever the numeral was spelled as.
        """
        table = {
            ('3', '[0]')            : False,
            ('0xFF', '[0]')         : False,
            ('1.5', '[0]')          : False,
            ('1kb', '[0]')          : False,
            ('3', '::ToString')     : False,
            ('0xFF', '::MaxValue')  : False,
        }
        self.assertEqual(self._reads(table, Ps1LexerMode.EXPRESSION), table)

    def test_a_sign_joins_the_numeral_and_the_rule_then_applies_to_the_whole_of_it(self):
        """
        Measured, `-1kb.GetType()` reads the member of minus one kilobyte where `-1.GetType()` is
        the one word `-1.GetType`.
        """
        table = {
            ('-1', '.GetType()')    : False,
            ('-1kb', '.GetType()')  : True,
        }
        self.assertEqual(self._reads(table, Ps1LexerMode.EXPRESSION), table)

    def test_a_sign_is_read_where_an_expression_is_and_never_where_a_bare_word_is_a_value(self):
        for spelling in ('-1', '+1', '-0.0', '-1.5', '-1L', '-1kb'):
            with self.subTest(spelling):
                self.assertEqual(
                    reads_as_one_numeral(spelling, '', Ps1LexerMode.EXPRESSION), True)
                self.assertEqual(
                    reads_as_one_numeral(spelling, '', Ps1LexerMode.ARGUMENT), False)

    def test_a_bare_numeral_standing_alone_in_an_argument_is_still_that_numeral(self):
        table = {
            ('1', '')       : True,
            ('1.5', '')     : True,
            ('.5', '')      : True,
            ('0xFF', '')    : True,
            ('1kb', '')     : True,
            ('10d', '')     : True,
            ('1e3', '')     : True,
            ('1E+28d', '')  : True,
        }
        self.assertEqual(self._reads(table, Ps1LexerMode.ARGUMENT), table)

    def test_a_numeral_an_argument_writes_anything_against_is_one_word(self):
        table = {
            ('3', '.ToString()')    : False,
            ('1.5', '.GetType()')   : False,
            ('1kb', '.GetType()')   : False,
            ('0xFF', '.GetType()')  : False,
        }
        self.assertEqual(self._reads(table, Ps1LexerMode.ARGUMENT), table)

    def test_what_decides_is_the_character_the_numeral_is_touched_by(self):
        """
        A member access is written as `.` or `::` and an index as `[`, which is the whole of what
        the writer has when it asks. An answer that depended on the rest of the member chain would
        make a slot unable to decide about its receiver until it had written everything behind it.
        """
        for spelling in ('3', '0xFF', '1.5', '1kb', '1L', '1e3', '10d', '-1', '-1kb'):
            with self.subTest(spelling):
                self.assertEqual(
                    [
                        reads_as_one_numeral(spelling, access, Ps1LexerMode.EXPRESSION)
                        for access in ('.', '::', '[')
                    ],
                    [
                        reads_as_one_numeral(spelling, written, Ps1LexerMode.EXPRESSION)
                        for written in ('.GetType()', '::MaxValue', '[0]')
                    ],
                )


_TOKEN_SEPARATORS = {
    'space'               : ' ',
    'vertical tab'        : '\v',
    'form feed'           : '\f',
    'next line'           : '\u0085',
    'no-break space'      : '\u00A0',
    'em space'            : '\u2003',
    'line separator'      : '\u2028',
    'paragraph separator' : '\u2029',
}

_DASH_SPELLINGS = {
    'hyphen-minus'   : '-',
    'en dash'        : '\u2013',
    'em dash'        : '\u2014',
    'horizontal bar' : '\u2015',
}


def _read_tokens(
    source: str, mode: Ps1LexerMode = Ps1LexerMode.EXPRESSION
) -> list[tuple[Ps1TokenKind, str]]:
    lexer = Ps1Lexer(source, mode=mode)
    return [
        (token.kind, token.value)
        for token in lexer.tokenize()
        if token.kind is not Ps1TokenKind.EOF
    ]


class TestPs1NumeralSpelling(TestBase):
    """
    Which texts Windows PowerShell 5.1 reads as a single `Number` token, and which it reads as a
    single `Generic` token instead. Every text below is one a 5.1 host was measured on. This
    vocabulary spells a `Number` as `Ps1TokenKind.INTEGER` or `Ps1TokenKind.REAL`, and a `Generic`
    as `Ps1TokenKind.GENERIC_TOKEN`.
    """

    def _reading(self, source: str) -> str:
        """
        What 5.1 would call the reading of `source` on its own. A text that reads as anything other
        than one whole numeral or one whole word is described by its token list, so that a
        disagreement says what was read rather than only that it differed.
        """
        tokens = _read_tokens(source)
        if len(tokens) == 1 and tokens[0][1] == source:
            kind = tokens[0][0]
            if kind is Ps1TokenKind.INTEGER or kind is Ps1TokenKind.REAL:
                return 'number'
            if kind is Ps1TokenKind.GENERIC_TOKEN:
                return 'word'
        return repr(tokens)

    def _numbers(self, *sources: str):
        readings = {source: self._reading(source) for source in sources}
        self.assertEqual(readings, dict.fromkeys(sources, 'number'))

    def _words(self, *sources: str):
        readings = {source: self._reading(source) for source in sources}
        self.assertEqual(readings, dict.fromkeys(sources, 'word'))

    def test_a_multiplier_may_follow_a_type_suffix_in_one_numeral(self):
        self._numbers('1lkb', '1dkb', '1Lkb', '1dmb', '1.5dkb', '1.5Lkb', '0xFFdkb')

    def test_a_type_suffix_closes_a_real_a_hexadecimal_and_an_exponent(self):
        self._numbers('1.5L', '1.5l', '1.5d', '1.5e2L', '0xFFd', '0xFFL', '1e3d')

    def test_a_multiplier_closes_every_spelling_of_a_numeral(self):
        self._numbers('1kb', '1pb', '1PB', '1.5kb', '.5kb', '0x1kb', '1e3kb', '1.e1kb')

    def test_a_decimal_point_may_open_or_close_a_numeral(self):
        self._numbers('.5L', '1.', '1.e1', '3.14')

    def test_a_numeral_with_no_suffix_at_all_reads_as_one_number(self):
        self._numbers('42', '0xFF', '100L', '0x0000000000000001')

    def test_a_suffix_written_twice_and_an_unfinished_exponent_are_words(self):
        self._words('1dd', '1LL', '1kbkb', '1kbL', '1e', '1e+', '0x')

    def test_a_multiplier_letter_without_its_b_is_a_word(self):
        self._words('1P', '1k', '1kx', '1b')

    def test_a_binary_literal_and_a_digit_separator_are_words_on_5_1(self):
        """
        Windows PowerShell 5.1 has neither spelling: a binary literal arrived in 7.0 and a digit
        separator never arrived at all.
        """
        self._words('0b1010', '0b', '0b2', '1_000', '0xFF_FF')

    def test_a_binary_literal_stays_a_word_where_an_operand_is_expected(self):
        """
        `1 + 0b1010` is a parse error on 5.1, which it could not be if the word were a numeral.
        """
        self.assertEqual(_read_tokens('1 + 0b1010'), [
            (Ps1TokenKind.INTEGER, '1'),
            (Ps1TokenKind.PLUS, '+'),
            (Ps1TokenKind.GENERIC_TOKEN, '0b1010'),
        ])

    def test_a_ternary_operator_character_does_not_end_a_numeral_on_5_1(self):
        """
        A `?` and a `:` end a numeral from 7.0 onwards, where a ternary operator may follow one.
        """
        self._words('1?', '1:')

    def test_where_a_numeral_ends_differs_between_the_two_lexer_modes(self):
        expression = {
            '1+2': [
                (Ps1TokenKind.INTEGER, '1'),
                (Ps1TokenKind.PLUS, '+'),
                (Ps1TokenKind.INTEGER, '2'),
            ],
            '3..5': [
                (Ps1TokenKind.INTEGER, '3'),
                (Ps1TokenKind.DOTDOT, '..'),
                (Ps1TokenKind.INTEGER, '5'),
            ],
        }
        argument = {
            '1+2'  : [(Ps1TokenKind.GENERIC_TOKEN, '1+2')],
            '3..5' : [(Ps1TokenKind.GENERIC_TOKEN, '3..5')],
        }
        self.assertEqual({source: _read_tokens(source) for source in expression}, expression)
        self.assertEqual(
            {source: _read_tokens(source, Ps1LexerMode.ARGUMENT) for source in argument},
            argument,
        )


class TestPs1TokenSeparation(TestBase):
    """
    The characters Windows PowerShell 5.1 passes over between two tokens, each measured against
    what an ASCII space does in the same place, and the two that end a statement instead.
    """

    def test_every_separator_parts_two_numerals_the_way_a_space_does(self):
        readings = {name: _read_tokens(F'1{c}2') for name, c in _TOKEN_SEPARATORS.items()}
        parted = [(Ps1TokenKind.INTEGER, '1'), (Ps1TokenKind.INTEGER, '2')]
        self.assertEqual(readings, dict.fromkeys(_TOKEN_SEPARATORS, parted))

    def test_every_separator_parts_a_command_from_its_argument(self):
        readings = {
            name: _read_tokens(F'f{c}1', Ps1LexerMode.ARGUMENT)
            for name, c in _TOKEN_SEPARATORS.items()
        }
        parted = [(Ps1TokenKind.GENERIC_TOKEN, 'f'), (Ps1TokenKind.INTEGER, '1')]
        self.assertEqual(readings, dict.fromkeys(_TOKEN_SEPARATORS, parted))

    def test_a_line_ending_ends_the_statement_instead_of_parting_two_tokens(self):
        endings = ('\n', '\r\n')
        readings = {end: [kind for kind, _ in _read_tokens(F'1{end}2')] for end in endings}
        ended = [Ps1TokenKind.INTEGER, Ps1TokenKind.NEWLINE, Ps1TokenKind.INTEGER]
        self.assertEqual(readings, dict.fromkeys(endings, ended))

    def test_a_dash_ends_a_numeral_in_every_spelling(self):
        readings = {name: _read_tokens(F'1{dash}2') for name, dash in _DASH_SPELLINGS.items()}
        expected = {
            name: [
                (Ps1TokenKind.INTEGER, '1'),
                (Ps1TokenKind.DASH, dash),
                (Ps1TokenKind.INTEGER, '2'),
            ]
            for name, dash in _DASH_SPELLINGS.items()
        }
        self.assertEqual(readings, expected)


class TestPs1CharacterClasses(TestBase):
    """
    The three questions `refinery.lib.scripts.ps1.token` answers about a single character: whether
    it stands between two tokens without being one, whether it ends the token being read, and
    whether it ends a token that began with a digit.
    """

    def test_a_character_is_whitespace_exactly_where_a_space_would_stand(self):
        expected = dict.fromkeys(_TOKEN_SEPARATORS.values(), True)
        expected.update(dict.fromkeys(('\r', '\n', '-', '\u2013', 'a', '1'), False))
        self.assertEqual({c: is_whitespace(c) for c in expected}, expected)

    def test_every_separator_ends_the_token_being_read(self):
        classified = {name: forces_new_token(c) for name, c in _TOKEN_SEPARATORS.items()}
        self.assertEqual(classified, dict.fromkeys(_TOKEN_SEPARATORS, True))

    def test_the_end_of_the_source_ends_every_token(self):
        self.assertEqual(forces_new_token(''), True)

    def test_a_line_ending_is_python_whitespace_and_not_powershell_whitespace(self):
        self.assertEqual([c.isspace() for c in '\r\n'], [True, True])
        self.assertEqual([is_whitespace(c) for c in '\r\n'], [False, False])

    def test_a_dash_ends_a_numeral_without_ending_a_word(self):
        classified = {
            name: (forces_new_token_after_number(dash), forces_new_token(dash))
            for name, dash in _DASH_SPELLINGS.items()
        }
        self.assertEqual(classified, dict.fromkeys(_DASH_SPELLINGS, (True, False)))

    def test_a_question_mark_and_a_colon_end_neither_a_numeral_nor_a_word(self):
        classified = {c: (forces_new_token_after_number(c), forces_new_token(c)) for c in '?:'}
        self.assertEqual(classified, {'?': (False, False), ':': (False, False)})


class TestPs1AMemberOperatorIsScannedWhereTheValueEnded(TestBase):
    """
    `Ps1Lexer.scan_member_access` answers the question a reader asks once it has taken a value:
    which member access operator, if any, is written where that value ended. One character has two
    answers there, and 5.1 gives both of them: a `.` before a digit opens a number where a value may
    start and names a member where one has just ended, so `$x.5` reads the property `5` while
    `$x = .5` reads a half.

    Nothing is passed over to reach the operator. The scan reads the position it is asked about and
    no other, which is what leaves whether an operator binds at all to the caller: a space or a
    block comment before the operator is not stepped over here but read as no operator at all.
    """

    #: One value per spelling a value can end with, because where the value ended is what decides
    #: whether a dot is left over for a member: a variable, a bracket, a string, and the numerals
    #: closed by an exponent, a multiplier, a base prefix or a decimal point already spent.
    _VALUES = ('$x', '(1)', "'a'", '1e3', '1kb', '0xFF', '1.5')

    @staticmethod
    def _scanned(
        value: str, written: str, mode: Ps1LexerMode = Ps1LexerMode.EXPRESSION
    ) -> tuple[tuple[Ps1TokenKind, str, int] | None, int]:
        """
        What the scan answers where `value` ends and `written` begins, and where it leaves the
        lexer. The offset the operator was read at and the position left behind say together that
        it was read where the value ended and that nothing was passed over to reach it.
        """
        lexer = Ps1Lexer(value + written, pos=len(value), mode=mode)
        token = lexer.scan_member_access()
        found = None if token is None else (token.kind, token.value, token.offset)
        return (found, lexer.pos)

    @staticmethod
    def _general_scan(
        value: str, written: str, mode: Ps1LexerMode = Ps1LexerMode.EXPRESSION
    ) -> tuple[Ps1TokenKind, str]:
        lexer = Ps1Lexer(value + written, pos=len(value), mode=mode)
        token = next(lexer.tokenize())
        return (token.kind, token.value)

    def test_a_dot_before_a_digit_names_a_member_where_a_value_has_just_ended(self):
        self.assertEqual({value: self._scanned(value, '.5') for value in self._VALUES}, {
            '$x'   : ((Ps1TokenKind.DOT, '.', 2), 3),
            '(1)'  : ((Ps1TokenKind.DOT, '.', 3), 4),
            "'a'"  : ((Ps1TokenKind.DOT, '.', 3), 4),
            '1e3'  : ((Ps1TokenKind.DOT, '.', 3), 4),
            '1kb'  : ((Ps1TokenKind.DOT, '.', 3), 4),
            '0xFF' : ((Ps1TokenKind.DOT, '.', 4), 5),
            '1.5'  : ((Ps1TokenKind.DOT, '.', 3), 4),
        })

    def test_the_general_scan_reads_a_number_at_every_one_of_those_positions(self):
        """
        The two questions differ, which is why the operator has a scan of its own: asked for a token
        where each of these values ends, the lexer reads the half `.5` that opens a value there.
        """
        self.assertEqual(
            {value: self._general_scan(value, '.5') for value in self._VALUES},
            dict.fromkeys(self._VALUES, (Ps1TokenKind.REAL, '.5')),
        )

    def test_each_operator_is_read_by_its_own_spelling(self):
        expression = {
            written: self._scanned('$x', written)
            for written in ('.a', '::a', '[0]')
        }
        self.assertEqual(expression, {
            '.a'  : ((Ps1TokenKind.DOT, '.', 2), 3),
            '::a' : ((Ps1TokenKind.DOUBLE_COLON, '::', 2), 4),
            '[0]' : ((Ps1TokenKind.LBRACKET, '[', 2), 3),
        })

    def test_a_member_and_an_index_are_read_where_a_bare_word_is_a_value_as_well(self):
        argument = {
            written: self._scanned('$x', written, Ps1LexerMode.ARGUMENT)
            for written in ('.a', '[0]')
        }
        self.assertEqual(argument, {
            '.a'  : ((Ps1TokenKind.DOT, '.', 2), 3),
            '[0]' : ((Ps1TokenKind.LBRACKET, '[', 2), 3),
        })

    def test_nothing_between_the_value_and_the_operator_is_passed_over(self):
        self.assertEqual({
            written: self._scanned('$x', written)
            for written in ('', ' .5', '<# c #>.5')
        }, {
            ''          : (None, 2),
            ' .5'       : (None, 2),
            '<# c #>.5' : (None, 2),
        })

    def test_an_operator_a_gap_stands_before_is_read_where_it_is_written(self):
        self.assertEqual(self._scanned('$x ', '.5'), ((Ps1TokenKind.DOT, '.', 3), 4))
        self.assertEqual(self._scanned('$x<# c #>', '.5'), ((Ps1TokenKind.DOT, '.', 9), 10))

    def test_a_second_dot_is_the_range_operator_and_names_no_member(self):
        self.assertEqual(self._scanned('1', '..5'), (None, 1))
        self.assertEqual(self._scanned('$x = 1', '..5'), (None, 6))

    def test_an_access_with_nothing_behind_it_is_refused_where_a_bare_word_is_a_value(self):
        """
        `f $x.` passes the word `$x.` and asks for no member. In an expression the same text is a
        member access whose name is missing, which 5.1 reports as an error rather than reading as a
        word, so the operator is read there.
        """
        self.assertEqual(self._scanned('$x', '.', Ps1LexerMode.ARGUMENT), (None, 2))
        self.assertEqual(
            self._scanned('$x', '.', Ps1LexerMode.EXPRESSION), ((Ps1TokenKind.DOT, '.', 2), 3))
