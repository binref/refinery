"""
Every pair here is written by hand: none is taken from a corpus, and none is text this project
printed.
"""
from __future__ import annotations

from test import TestBase
from test.lib.scripts.js.ledger import dropped_source_characters


class TestTheDroppedCharacterOracleReadsCodeInOrder(TestBase):

    def test_two_statements_written_in_the_other_order_do_not_account_for_the_file(self):
        self.assertNotEqual(dropped_source_characters('x = 1; y = 2;', 'y = 1; x = 2;'), '')

    def test_two_arguments_written_in_the_other_order_do_not_account_for_the_call(self):
        self.assertNotEqual(dropped_source_characters('f(a, b);', 'f(b, a);'), '')

    def test_a_file_written_back_with_another_layout_accounts_for_itself(self):
        self.assertEqual(
            dropped_source_characters('if(a){f(1);}', 'if (a) {\n  f(1);\n}\n'),
            '',
        )

    def test_a_character_of_code_that_went_missing_is_reported(self):
        self.assertEqual(dropped_source_characters('f(a, b);', 'f(a);'), ',b')


class TestTheDroppedCharacterOracleReadsCommentsAsCarriers(TestBase):

    def test_a_comment_moved_to_a_statement_boundary_accounts_for_the_file(self):
        self.assertEqual(
            dropped_source_characters(
                'x = f(/* c */ 1); y = 2;',
                'x = f(1);\n/* c */\ny = 2;',
            ),
            '',
        )

    def test_a_comment_the_print_no_longer_holds_is_reported(self):
        self.assertEqual(dropped_source_characters('x = 1; /* c */', 'x = 1;'), '/* c */')

    def test_a_delimiter_inside_a_string_is_code_and_not_a_comment_that_went_missing(self):
        self.assertEqual(dropped_source_characters("x = '/* c */';", "x = '/* c */';"), '')

    def test_a_string_holding_a_comment_the_print_dropped_reports_the_characters(self):
        self.assertEqual(dropped_source_characters("x = '/* c */';", "x = '';"), '/*c*/')


class TestTheDroppedCharacterOracleIsBlindToWhitespace(TestBase):

    def test_a_line_terminator_the_print_dropped_is_not_reported(self):
        self.assertEqual(dropped_source_characters('x = "abc\n', 'x = "abc'), '')
