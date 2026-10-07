from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.model import (
    Au3ErrorNode,
    Au3IfStatement,
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
