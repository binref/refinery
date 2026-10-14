"""
The reader for source text the parser could not read: the raw facts one lexer pass draws from a
line, exactly as the passes that ask about unread text consume them.
"""
from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.analysis.unparsed import read_unparsed


class TestAu3UnparsedReader(TestBase):

    def test_variables_identifiers_and_strings_of_a_mixed_line(self):
        unparsed = read_unparsed('$Twin = "he" & Label($Other)')
        self.assertEqual(unparsed.variables, frozenset({'twin', 'other'}))
        self.assertEqual(unparsed.identifiers, frozenset({'label'}))
        self.assertEqual(unparsed.strings, ('he',))

    def test_computed_callee_after_variable_paren_and_bracket(self):
        for text in ('$f(1)', '(1 + 2)(3)', '$a[0](1)'):
            with self.subTest(text=text):
                self.assertTrue(read_unparsed(text).computed_callee)

    def test_member_call_is_not_a_computed_callee(self):
        unparsed = read_unparsed('$o.m()')
        self.assertFalse(unparsed.computed_callee)

    def test_macros_include_error_state(self):
        unparsed = read_unparsed('$e = @Error + @Extended')
        self.assertEqual(unparsed.macros, frozenset({'error', 'extended'}))

    def test_function_declaration_is_detected(self):
        for text in ('Func F()', 'F(ByRef $x)'):
            with self.subTest(text=text):
                self.assertTrue(read_unparsed(text).declares_function)

    def test_block_keyword_as_a_word_is_detected(self):
        for text in ('$a = 1 EndIf', '$a = "EndIf"', 'If $x Wend'):
            with self.subTest(text=text):
                self.assertTrue(read_unparsed(text).block_keyword)

    def test_text_without_a_block_keyword(self):
        unparsed = read_unparsed('$a = f(1, $b[2])')
        self.assertFalse(unparsed.block_keyword)

    def test_directives_of_a_mixed_line(self):
        unparsed = read_unparsed('$a = 1 #forceref $x')
        self.assertEqual(unparsed.directives, ('#forceref $x',))
