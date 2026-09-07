"""
What the instruments in `test.lib.scripts.js.ledger` answer, asked of pairs written out here.

Every law elsewhere that says a file comes back whole reads `dropped_source_characters` for its
answer, so a pair the oracle cannot tell apart is a law that passes without asking anything. The
pairs below are the ones it has to tell apart and the ones it has to let through, written as text
rather than taken from any corpus, and none of them is a print this project produced.
"""
from __future__ import annotations

from test import TestBase
from test.lib.scripts.js.ledger import dropped_source_characters


class TestTheDroppedCharacterOracleReadsCodeInOrder(TestBase):

    def test_two_statements_written_in_the_other_order_do_not_account_for_the_file(self):
        self.assertEqual(
            dropped_source_characters('x = 1; y = 2;', 'y = 1; x = 2;'),
            '1y=2;',
        )

    def test_two_arguments_written_in_the_other_order_do_not_account_for_the_call(self):
        self.assertEqual(dropped_source_characters('f(a, b);', 'f(b, a);'), ',b')

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
        """
        A file ending in a string its last line ended, cut of that terminator, is a different file:
        the string of `x = "abc` runs to the end of the file, and the one written before it ends at
        the line break. The oracle answers that nothing went missing because a line terminator is
        whitespace, and the difference is carried by the law that a text no parser could read comes
        back verbatim, in `test.lib.scripts.js.test_parser_recovery`.
        """
        self.assertEqual(dropped_source_characters('x = "abc\n', 'x = "abc'), '')
