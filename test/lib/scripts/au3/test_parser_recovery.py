from __future__ import annotations

import unittest

from test import TestBase

from refinery.lib.scripts.au3.model import (
    Au3ErrorNode,
    Au3FunctionDeclaration,
    Au3IfStatement,
    Au3SwitchStatement,
    Au3WhileStatement,
)
from refinery.lib.scripts.au3.parser import Au3Parser

_MALFORMED_INPUTS = (
    '$x = = 1\n',
    '$x =\n',
    'Local\n',
    'For $i\n',
    'If\n',
    'If $x Then\n',
    'While 1\n',
    'Do\n',
    'Switch\n',
    'With\n',
    'Func\n',
    'Func F(\n',
    'EndIf\n',
    'Else\n',
    'Wend\n',
    'Until $x\n',
    'Next\n',
    'Case 1\n',
    'EndSelect\n',
    'EndSwitch\n',
    'EndWith\n',
    'EndFunc\n',
    '.prop = 1\n',
    '$\n',
    '@\n',
    '1 +\n',
    '$a[\n',
    'f(,)\n',
    'Local $a = [1,\n',
    'Enum Step\n',
    'ReDim $a[]\n',
    'Volatile\n',
    'If $x Then Else\n',
    'ContinueLoop $x $y\n',
)


class TestAu3ParserRecovery(TestBase):

    def _parse(self, source: str):
        return Au3Parser(source).parse()

    def test_malformed_input_never_raises(self):
        for source in _MALFORMED_INPUTS:
            with self.subTest(source=source):
                script = self._parse(source)
                self.assertNotEqual(script.errors, [])

    def test_malformed_input_still_covers_whole_file(self):
        script = self._parse('$x = = 1\n$y = 2\n')
        self.assertEqual(len(script.body), 2)
        self.assertIsInstance(script.body[0], Au3ErrorNode)

    def test_error_text_is_verbatim_source_slice(self):
        script = self._parse('$x = = 1\n')
        error = script.body[0]
        self.assertEqual(error.text, '$x = = 1')

    def test_error_text_covers_only_its_own_line(self):
        script = self._parse('$x = = 1\n$y = 2\n')
        self.assertEqual(script.body[0].text, '$x = = 1')

    def test_error_after_error_does_not_leak(self):
        script = self._parse('$a = = 1\n$b = = 2\n$c = 3\n')
        self.assertEqual(len(script.body), 3)
        self.assertEqual(script.body[0].text, '$a = = 1')
        self.assertEqual(script.body[1].text, '$b = = 2')
        self.assertEqual(script.body[2].expression.target.name, 'c')

    def test_missing_endif_at_eof(self):
        script = self._parse('If $x Then\n$y = 1\n')
        self.assertIsInstance(script.body[0], Au3IfStatement)
        self.assertNotEqual(script.errors, [])
        self.assertEqual(script.errors[-1].message, 'expected EndIf')

    def test_missing_wend_at_eof(self):
        script = self._parse('While 1\n$x += 1\n')
        self.assertIsInstance(script.body[0], Au3WhileStatement)
        self.assertEqual(script.errors[-1].message, 'expected Wend')

    def test_missing_then_is_synthesized(self):
        script = self._parse('If $x\n$x = 1\nEndIf\n')
        self.assertIsInstance(script.body[0], Au3IfStatement)
        self.assertEqual(script.errors[-1].message, 'expected Then')

    def test_missing_endfunc_at_eof(self):
        script = self._parse('Func F()\n$a = 1\n')
        self.assertEqual(script.errors[-1].message, 'expected EndFunc')

    def test_stray_endif_is_one_token_error(self):
        script = self._parse('EndIf\n')
        self.assertEqual(len(script.body), 1)
        self.assertEqual(script.body[0].text, 'EndIf')
        self.assertEqual(script.body[0].message, 'unexpected EndIf')

    def test_stray_terminator_keeps_rest_of_line(self):
        script = self._parse('Wend\n$x = 1\n')
        self.assertEqual(len(script.body), 2)
        self.assertEqual(script.body[1].expression.target.name, 'x')

    def test_error_node_marks_unparsed(self):
        script = self._parse('$x = = 1\n')
        self.assertTrue(script.body[0].unparsed)

    def test_unterminated_string_runs_to_eol_without_blocking(self):
        script = self._parse('$s = "unterminated\n$x = 1\n')
        self.assertEqual(script.errors, [])
        self.assertEqual(script.body[0].expression.value.value, 'unterminated')
        self.assertEqual(script.body[1].expression.target.name, 'x')

    def test_unterminated_block_comment_consumes_rest_of_file(self):
        script = self._parse('$x = 1\n#cs\n$y = = = broken\n')
        self.assertEqual(len(script.body), 1)
        self.assertEqual(script.errors, [])

    def test_recursion_depth_is_raised(self):
        source = '$x = ' + '(' * 5000 + '1' + ')' * 5000 + '\n'
        with self.assertRaises(RecursionError):
            self._parse(source)

    def test_error_statements_carry_leading_comments(self):
        script = self._parse('; note\n$x = = 1\n')
        self.assertEqual(script.body[0].leading_comments, ['; note'])

    def test_empty_body_between_block_markers(self):
        script = self._parse('If $x Then\nEndIf\n')
        self.assertIsInstance(script.body[0], Au3IfStatement)
        self.assertEqual(script.body[0].body, [])
        self.assertEqual(script.errors, [])

    def test_case_outside_select_is_error(self):
        script = self._parse('Case 1\n')
        self.assertEqual(script.body[0].message, 'unexpected Case')

    def test_single_line_if_with_block_opener_recovers(self):
        script = self._parse('If $x Then While 1\nWend\n')
        self.assertNotEqual(script.errors, [])

    def test_empty_input_has_no_errors(self):
        script = self._parse('')
        self.assertEqual(script.errors, [])
        self.assertEqual(script.body, [])

    def test_multiple_errors_accumulate(self):
        script = self._parse('$x = = 1\n$y = = 2\n')
        self.assertEqual(len(script.errors), 2)

    def test_a_name_the_file_does_not_provide_is_never_synthesized(self):
        """
        A variable, identifier or member name read from a token that is not there would build a
        node no text spells, so a missing name hands the whole statement to recovery instead of
        fabricating a placeholder: every node that reaches a printer must have a name.
        """
        for source in ('Func F(\n', 'For 1 To 2\n$y = 1\nNext\n', '$o.\n', 'ReDim 5\n'):
            with self.subTest(source=source):
                script = self._parse(source)
                self.assertIsInstance(script.body[0], Au3ErrorNode)
                self.assertEqual(
                    [node for node in script.walk() if getattr(node, 'name', None) == ''], [])

    def test_comma_after_assignment_recovers_whole_line(self):
        script = self._parse('$a = 1, $b = 2\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, '$a = 1, $b = 2')
        self.assertEqual(script.errors, [script.body[0]])

    def test_juxtaposed_calls_inside_execute_recovers_whole_line(self):
        script = self._parse('$x = Execute(f(1) g(2))\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, '$x = Execute(f(1) g(2))')
        self.assertEqual(script.errors, [script.body[0]])

    def test_missing_closing_paren_recovers_whole_line(self):
        script = self._parse('$a = f(1\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, '$a = f(1')
        self.assertEqual(script.errors, [script.body[0]])

    def test_single_line_if_with_trailing_text_recovers_whole_line(self):
        script = self._parse('If 1 Then $a = 1, $b = 2\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, 'If 1 Then $a = 1, $b = 2')
        self.assertEqual(script.errors, [script.body[0]])

    def test_return_with_trailing_text_recovers_whole_line(self):
        script = self._parse('Return 1, 2\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, 'Return 1, 2')
        self.assertEqual(script.errors, [script.body[0]])

    def test_recovered_line_excludes_its_trailing_comment(self):
        script = self._parse('$a = 1, $b = 2 ; note\n')
        error = script.body[0]
        self.assertEqual(error.text, '$a = 1, $b = 2')
        self.assertEqual(error.trailing_comments, ['; note'])

    def test_continuation_line_is_recovered_across_both_physical_lines(self):
        script = self._parse('$a = 1, _\n$b = 2\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, '$a = 1, _\n$b = 2')

    def test_boundary_after_statement_keeps_following_statement_top_level(self):
        script = self._parse('If 0 Then\n$a = 1 EndIf\nlive()\n')
        self.assertEqual(len(script.body), 2)
        self.assertIsInstance(script.body[0], Au3IfStatement)
        self.assertEqual(script.body[1].expression.callee.name, 'live')

    def test_boundary_case_keeps_next_case_body_separate(self):
        script = self._parse('Switch $x\nCase 1\n$y = 1 Case 2\n$z = 2\nEndSwitch\n')
        switch = script.body[0]
        self.assertIsInstance(switch, Au3SwitchStatement)
        self.assertEqual(len(switch.cases), 2)
        self.assertEqual(switch.cases[0].body[0].expression.target.name, 'y')
        self.assertEqual(switch.cases[1].body[0].expression.target.name, 'z')

    def test_repaired_statement_before_boundary_keeps_the_boundary(self):
        script = self._parse('If $x Then\n$a = f(1 EndIf\n')
        self.assertEqual(len(script.body), 1)
        node = script.body[0]
        self.assertIsInstance(node, Au3IfStatement)
        self.assertEqual(
            [nested for nested in node.walk() if isinstance(nested, Au3ErrorNode)], [])
        call = node.body[0].expression.value
        self.assertEqual(call.callee.name, 'f')
        self.assertEqual(len(call.arguments), 1)

    def test_unclosed_final_function_holds_rest_of_file_as_its_body(self):
        script = self._parse('Func F()\n$a = 1\n')
        self.assertEqual(len(script.body), 1)
        func = script.body[0]
        self.assertIsInstance(func, Au3FunctionDeclaration)
        self.assertEqual(func.body[0].expression.target.name, 'a')

    def test_a_block_opener_at_eof_without_a_newline_keeps_its_repairs(self):
        """
        A construct that opens a block is multi-line whether or not the file ended before its
        closer, so the byte after the last token decides nothing: a missing final newline must
        not cost the tree the declaration its repairs had read.
        """
        for source in (
            'Func f()',
            'While 1',
            'If $x Then',
            'Switch $x',
            'Select',
            'With $o',
            'For $i = 1 To 2',
        ):
            with self.subTest(source=source):
                script = self._parse(source)
                self.assertNotIsInstance(script.body[0], Au3ErrorNode)
                self.assertNotEqual(script.errors, [])

    def test_a_final_function_without_a_newline_keeps_the_earlier_calls_resolvable(self):
        script = self._parse('Func a()\n    f()\nEndFunc\na()\n\nFunc f()')
        self.assertEqual(len(script.body), 3)
        self.assertIsInstance(script.body[2], Au3FunctionDeclaration)
        self.assertEqual(script.body[2].name.name, 'f')

    def test_a_single_line_if_with_trailing_text_at_eof_recovers_whole_line(self):
        script = self._parse('If 1 Then $a = 1, $b = 2')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, 'If 1 Then $a = 1, $b = 2')

    def test_a_block_keyword_after_a_dot_is_no_boundary(self):
        script = self._parse('$o.EndIf(1) junk\n')
        self.assertEqual(len(script.body), 1)
        self.assertIsInstance(script.body[0], Au3ErrorNode)
        self.assertEqual(script.body[0].text, '$o.EndIf(1) junk')

    @unittest.expectedFailure
    def test_text_after_block_header_is_not_a_statement(self):
        script = self._parse('While 1 junk\nWend\n')
        self.assertEqual(len(script.body[0].body), 0)

    @unittest.expectedFailure
    def test_text_after_block_closer_is_not_a_statement(self):
        script = self._parse('If $x Then\nEndIf $y = 1\n')
        self.assertEqual(len(script.body), 1)
