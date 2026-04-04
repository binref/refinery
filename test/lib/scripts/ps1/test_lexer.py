from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.lexer import Ps1Lexer
from refinery.lib.scripts.ps1.token import Ps1TokenKind


class TestPs1Lexer(TestBase):

    def _tokens(self, source: str) -> list[tuple[Ps1TokenKind, str]]:
        lexer = Ps1Lexer(source)
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
        self.assertIn(Ps1TokenKind.COMMENT, kinds)

    def test_comment_block(self):
        tokens = self._tokens('$x <# block #> $y')
        kinds = [t[0] for t in tokens]
        self.assertIn(Ps1TokenKind.COMMENT, kinds)

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
        tokens = self._tokens('2>$null')
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '2>'))
        self.assertEqual(tokens[1], (Ps1TokenKind.VARIABLE, '$null'))

    def test_stream_redirection_2_append(self):
        tokens = self._tokens('2>>file.txt')
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '2>>'))

    def test_stream_redirection_2_merge(self):
        tokens = self._tokens('2>&1')
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '2>&1'))

    def test_stream_redirection_star(self):
        tokens = self._tokens('*>$null')
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '*>'))
        self.assertEqual(tokens[1], (Ps1TokenKind.VARIABLE, '$null'))

    def test_stream_redirection_3_merge(self):
        tokens = self._tokens('3>&2')
        self.assertEqual(tokens[0], (Ps1TokenKind.REDIRECTION, '3>&2'))

    def test_digit_not_stream_redirection(self):
        tokens = self._tokens('9>file')
        self.assertEqual(tokens[0], (Ps1TokenKind.INTEGER, '9'))
        self.assertEqual(tokens[1], (Ps1TokenKind.REDIRECTION, '>'))

    def test_backtick_line_continuation(self):
        tokens = self._tokens('$x +`\n$y')
        kinds = [t[0] for t in tokens]
        self.assertNotIn(Ps1TokenKind.NEWLINE, kinds)
