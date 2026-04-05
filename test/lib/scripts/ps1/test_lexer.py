from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.lexer import Ps1Lexer, Ps1LexerMode
from refinery.lib.scripts.ps1.token import Ps1TokenKind


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

    def test_integer_binary(self):
        tokens = self._tokens('0b1010')
        self.assertEqual(tokens, [(Ps1TokenKind.INTEGER, '0b1010')])

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
            tokens = self._tokens(f'$x {op_str} 1')
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
        for kw in ['if', 'elseif', 'else', 'while', 'for', 'foreach', 'do',
                    'switch', 'function', 'return', 'try', 'catch', 'finally',
                    'throw', 'trap', 'break', 'continue', 'exit', 'param',
                    'begin', 'process', 'end', 'in', 'filter', 'data', 'class',
                    'using', 'until', 'enum', 'dynamicparam']:
            tokens = self._tokens(kw)
            self.assertTrue(tokens[0][0].is_keyword, f'{kw} not recognized as keyword')

    def test_comment_line(self):
        tokens = self._tokens('$x # a comment')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.COMMENT, kinds)
        self.assertIn(Ps1TokenKind.VARIABLE, kinds)

    def test_comment_block(self):
        tokens = self._tokens('$x <# block #> $y')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.COMMENT, kinds)
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
        tokens = self._tokens('Write-Host')
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, 'Write-Host'))

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

    def test_binary_integer_with_multiplier_suffix(self):
        for suffix in ('kb', 'mb', 'gb', 'tb', 'pb', 'KB', 'MB', 'GB', 'TB', 'PB'):
            src = F'0b1010{suffix}'
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
        # bare >&2 without leading digit is invalid per the reference;
        # should lex as plain > followed by & and 2
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '>'))

    def test_digit_not_stream_redirection(self):
        tokens = self._tokens('9>file')
        self.assertEqual(tokens[0], (Ps1TokenKind.INTEGER, '9'))
        self.assertEqual(tokens[1], (Ps1TokenKind.REDIRECTION, '>'))

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

    def test_integer_dot_identifier_not_consumed_as_real(self):
        tokens = self._tokens('7.ToString')
        self.assertEqual(tokens[0], (Ps1TokenKind.INTEGER, '7'))
        self.assertEqual(tokens[1], (Ps1TokenKind.DOT, '.'))
        self.assertEqual(tokens[2], (Ps1TokenKind.GENERIC_TOKEN, 'ToString'))

    def test_integer_dot_variable_not_consumed_as_real(self):
        tokens = self._tokens('7.$method')
        self.assertEqual(tokens[0], (Ps1TokenKind.INTEGER, '7'))
        self.assertEqual(tokens[1], (Ps1TokenKind.DOT, '.'))
        self.assertEqual(tokens[2], (Ps1TokenKind.VARIABLE, '$method'))

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
        self.assertIn(Ps1TokenKind.REDIRECTION, kinds)
        redir = next(t for t in tokens if t[0] == Ps1TokenKind.REDIRECTION)
        self.assertEqual(redir[1], '<')

    def test_input_redirection_does_not_break_block_comment(self):
        tokens = self._tokens('<# comment #> $x')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.COMMENT, kinds)
        self.assertNotIn(Ps1TokenKind.REDIRECTION, kinds)
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
        """In argument mode, ..\\..\\file.exe is a single generic token, not range operators."""
        tokens = self._tokens('..\\..\\file.exe', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '..\\..\\file.exe'))

    def test_dotdot_forward_slash_path_in_argument_mode(self):
        """Forward-slash relative paths also work."""
        tokens = self._tokens('../../file.txt', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '../../file.txt'))

    def test_dotdot_range_in_expression_mode(self):
        """In expression mode, .. is still the range operator."""
        tokens = self._tokens('1..10')
        self.assertEqual(tokens[1], (Ps1TokenKind.DOTDOT, '..'))

    def test_dotdot_range_with_whitespace_in_argument_mode(self):
        """When .. is followed by whitespace in argument mode, it is still DOTDOT."""
        tokens = self._tokens('1 .. 10', mode=Ps1LexerMode.ARGUMENT)
        dotdots = [t for t in tokens if t[0] == Ps1TokenKind.DOTDOT]
        self.assertEqual(len(dotdots), 1)

    def test_dashdash_argument_in_argument_mode(self):
        """In argument mode, --no-pager is a single generic token, not DECREMENT + tokens."""
        tokens = self._tokens('--no-pager', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '--no-pager'))

    def test_dashdash_standalone_in_argument_mode(self):
        """When -- is followed by whitespace in argument mode, it is still DECREMENT."""
        tokens = self._tokens('-- foo', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.DECREMENT, '--'))

    def test_dashdash_in_expression_mode(self):
        """In expression mode, -- is always DECREMENT."""
        tokens = self._tokens('--$x')
        self.assertEqual(tokens[0], (Ps1TokenKind.DECREMENT, '--'))

    def test_plusplus_argument_in_argument_mode(self):
        """In argument mode, ++count is a single generic token, not INCREMENT + tokens."""
        tokens = self._tokens('++count', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '++count'))

    def test_dot_letter_generic_token_in_argument_mode(self):
        """In argument mode, .gitignore is a single generic token."""
        tokens = self._tokens('.gitignore', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '.gitignore'))

    def test_dot_source_variable_not_generic(self):
        """Dot followed by $ is NOT a generic token (it's dot-sourcing)."""
        tokens = self._tokens('. $script', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.DOT, '.'))

    def test_dot_source_string_not_generic(self):
        """Dot followed by a quote is NOT a generic token (it's dot-sourcing)."""
        tokens = self._tokens(". 'script.ps1'", mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.DOT, '.'))

    def test_star_wildcard_in_argument_mode(self):
        """In argument mode, *.txt is a single generic token."""
        tokens = self._tokens('*.txt', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '*.txt'))

    def test_slash_path_in_argument_mode(self):
        """In argument mode, /etc/hosts is a single generic token."""
        tokens = self._tokens('/etc/hosts', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '/etc/hosts'))

    def test_star_standalone_in_argument_mode(self):
        """When * is followed by whitespace in argument mode, it is still STAR."""
        tokens = self._tokens('* foo', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(tokens[0], (Ps1TokenKind.STAR, '*'))

    def test_star_in_expression_mode(self):
        """In expression mode, * is always STAR."""
        tokens = self._tokens('2 * 3')
        stars = [t for t in tokens if t[0] == Ps1TokenKind.STAR]
        self.assertEqual(len(stars), 1)

    def test_star_bracket_glob_in_argument_mode(self):
        """In argument mode, *[a-z]* is a single generic token (glob pattern)."""
        tokens = self._tokens('*[a-z]*', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '*[a-z]*'))

    def test_hyphenated_parameter_name(self):
        """In argument mode, -no-pager is a single parameter token."""
        tokens = self._tokens('-no-pager', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.PARAMETER, '-no-pager'))

    def test_number_followed_by_variable_in_argument_mode(self):
        """In argument mode, 123$var is a single generic token (string interpolation)."""
        tokens = self._tokens('123$var', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, '123$var'))

    def test_at_sign_mid_generic_token_in_argument_mode(self):
        """@ in the middle of a generic token is absorbed as a plain character."""
        tokens = self._tokens('path/@/file', mode=Ps1LexerMode.ARGUMENT)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], (Ps1TokenKind.GENERIC_TOKEN, 'path/@/file'))

    def test_double_colon_not_label(self):
        tokens = self._tokens('[System.IO]::Path')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.LABEL, kinds)
        self.assertIn(Ps1TokenKind.DOUBLE_COLON, kinds)
