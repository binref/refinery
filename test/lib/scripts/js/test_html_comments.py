"""
`<!--` opens a comment wherever a comment may open, the middle of an expression included, so
`var y = x <!-- note` declares `y` and holds what `x` holds. `-->` opens one only where nothing but
whitespace and comments precedes it on its line, the head of the file counting as such a line;
anywhere else those three characters are the decrement operator and `>`, so `a-->b` is the program
`a-- > b`. Each runs to the end of its line the way `//` does. Both belong to the script grammar
only: Node refuses every file holding one when it reads it as a module.

SECURITY: every snippet here is hand-authored and benign, and running it is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    node_executable,
    node_reads_as_a_program,
)
from test.lib.scripts.js.ledger import each_well_formed, folded, printed, prints, well_formed

from refinery.lib.scripts.js.model import JsErrorNode
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import StrictViolation, collect_strict_violations

A_FILE_HOLDING_A_COMMENT_A_STATEMENT_CARRIES = {
    '<!-- note\nconsole.log(1);'                                : prints('1'),
    'var x = 1;\nvar y = x <!-- note\nconsole.log(y);'          : prints('1'),
    'x = 1 <!-- a\n+ 2\nconsole.log(x);'                        : prints('3'),
    'class C {\n<!-- c\np = 1 }\nconsole.log(new C().p);'       : prints('1'),
    'console.log(1) <!-- c\n--> d\nconsole.log(2);'             : prints('1', '2'),
    '--> note\nconsole.log(1);'                                 : prints('1'),
    'console.log(1);\n--> note\nconsole.log(2);'                : prints('1', '2'),
    'console.log(1);\n   --> note\nconsole.log(2);'             : prints('1', '2'),
    'console.log(1);\n/* c */ --> note\nconsole.log(2);'        : prints('1', '2'),
    'console.log(1); /* c\n */ --> note\nconsole.log(2);'       : prints('1', '2'),
    '// c\n--> d\nconsole.log(3);'                              : prints('3'),
    'function f() {\n--> note\nreturn 1;\n}\nconsole.log(f());' : prints('1'),
    'if (1) {\n--> note\nconsole.log(1);\n}'                    : prints('1'),
    'var v = 3\n-->\nconsole.log(v)'                            : prints('3'),
    'console.log(1);\r\n--> note\r\nconsole.log(2);'            : prints('1', '2'),
    'console.log(1);\u2028--> note\u2028console.log(2);'        : prints('1', '2'),
}

A_FILE_HOLDING_A_COMMENT_NO_STATEMENT_CARRIES = {
    'console.log(1); <!-- note'                                 : prints('1'),
    'console.log(1);\n<!--'                                     : prints('1'),
    'if (1) <!-- c\nconsole.log(5);'                            : prints('5'),
    'console.log(1);\n--> note'                                   : prints('1'),
}

A_FILE_HOLDING_A_COMMENT_NO_STATEMENT_CARRIES_PRINTED = {
    'console.log(1); <!-- note'                                 : 'console.log(1);\n<!-- note',
    'console.log(1);\n<!--'                                     : 'console.log(1);\n<!--',
    'if (1) <!-- c\nconsole.log(5);'                            : 'if (1) {\n  <!-- c\n  console.log(5);\n}',
    'console.log(1);\n--> note'                                   : 'console.log(1);\n--> note',
}

#: In `a <<!--b` the longest match reads `<<` first, so what follows is `!--b` and no comment.
A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT = {
    'var a = 2, b = 0;\nconsole.log(a-->b);'                    : prints('true'),
    'var a = 4, b = 1; console.log(a <<!--b);'                  : prints('8'),
    "console.log('-->');"                                       : prints('-->'),
    'console.log(`x\n--> y`);'                                  : prints('x\n--> y'),
    'console.log("<!--");'                                      : prints('<!--'),
    'var s = /<!--/.test("<!--"); console.log(s);'              : prints('true'),
    '\n/-->/.test("-->");\nconsole.log(/-->/.test("-->"));'     : prints('true'),
}

A_FILE_NODE_REFUSES_OVER_A_MISPLACED_CLOSER = [
    'console.log(1); --> note',
    'var a = 1; /* c */ --> note',
]


def _every_file_holding_a_comment() -> dict[str, tuple[str, str | None]]:
    return {
        **A_FILE_HOLDING_A_COMMENT_A_STATEMENT_CARRIES,
        **A_FILE_HOLDING_A_COMMENT_NO_STATEMENT_CARRIES,
    }


def the_module_rule_reported_in(source: str) -> list[str]:
    return [
        violation.rule
        for violation in collect_strict_violations(JsParser(source).parse(), module=True)
    ]


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatNodeMakesOfTheTwoDelimiters(TestBase):

    def test_node_prints_what_each_file_holding_a_comment_is_recorded_as_printing(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual({source: behavior(source) for source in rows}, rows)

    def test_node_prints_what_each_file_spelling_no_comment_is_recorded_as_printing(self):
        rows = A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT
        self.assertEqual({source: behavior(source) for source in rows}, rows)

    def test_node_refuses_a_closer_behind_a_statement_on_its_line(self):
        rows = A_FILE_NODE_REFUSES_OVER_A_MISPLACED_CLOSER
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in rows},
            {source: False for source in rows},
        )

    def test_node_refuses_every_file_holding_a_comment_as_a_module(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            {source: ('', 'SyntaxError') for source in rows},
        )

    def test_node_reads_every_file_spelling_no_comment_as_a_module(self):
        rows = A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT
        self.assertEqual({source: behavior(source, module=True) for source in rows}, rows)


class TestTheVerdictAnswersAsNodeDoes(TestBase):

    def test_a_file_holding_a_comment_is_a_program(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual(each_well_formed(rows), {source: True for source in rows})

    def test_a_file_spelling_no_comment_is_a_program(self):
        rows = A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT
        self.assertEqual(each_well_formed(rows), {source: True for source in rows})

    def test_a_closer_behind_a_statement_on_its_line_is_no_program(self):
        rows = A_FILE_NODE_REFUSES_OVER_A_MISPLACED_CLOSER
        self.assertEqual(each_well_formed(rows), {source: False for source in rows})


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileKeepsWhatItPrints(TestBase):

    def test_a_file_holding_a_comment_prints_the_same_through_printer_and_deobfuscator(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual(
            {source: (behavior(printed(source)), behavior(folded(source))) for source in rows},
            {source: (printing, printing) for source, printing in rows.items()},
        )

    def test_a_file_spelling_no_comment_prints_the_same_through_printer_and_deobfuscator(self):
        rows = A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT
        self.assertEqual(
            {source: (behavior(printed(source)), behavior(folded(source))) for source in rows},
            {source: (printing, printing) for source, printing in rows.items()},
        )


class TestPrintingAFileHoldingACommentIsIdempotent(TestBase):

    def test_the_printed_text_prints_back_to_itself(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual(
            {source: printed(printed(source)) for source in rows},
            {source: printed(source) for source in rows},
        )

    def test_a_comment_no_statement_carries_prints_back_with_the_file(self):
        rows = A_FILE_HOLDING_A_COMMENT_NO_STATEMENT_CARRIES_PRINTED
        self.assertEqual({source: printed(source) for source in rows}, rows)


class TestTheCollectorReportsTheDelimitersUnderTheModuleGoal(TestBase):

    def test_every_file_holding_a_comment_is_reported_on_as_a_module(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual(
            {source: the_module_rule_reported_in(source) for source in rows},
            {source: ['html-comment'] for source in rows},
        )

    def test_the_first_delimiter_is_reported_where_it_stands(self):
        rows = {
            'console.log(1);\n--> note\nconsole.log(2);' : 16,
            '<!-- a\n--> b\nconsole.log(1);'             : 0,
            'console.log(1); <!-- note'                  : 16,
        }
        self.assertEqual(
            {
                source: collect_strict_violations(JsParser(source).parse(), module=True)
                for source in rows
            },
            {source: [StrictViolation(offset, 'html-comment')] for source, offset in rows.items()},
        )

    def test_nothing_is_reported_about_a_file_spelling_no_comment(self):
        rows = A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT
        self.assertEqual(
            {source: the_module_rule_reported_in(source) for source in rows},
            {source: [] for source in rows},
        )

    def test_nothing_is_reported_about_a_file_read_as_a_script(self):
        rows = _every_file_holding_a_comment()
        self.assertEqual(
            {source: collect_strict_violations(JsParser(source).parse()) for source in rows},
            {source: [] for source in rows},
        )


_ALPHA = 'a' * 35
_BETA = 'b' * 35
_GAMMA = 'c' * 36
_DELTA = 'd' * 36
_VALUE = 'z' * 60

A_WRAPPED_LIST_HOLDING_A_CLOSER = {
    F'f({_ALPHA}, --> 1, {_BETA}, {_GAMMA}, {_DELTA});':
        F'f(\n  {_ALPHA}, --> 1,\n  {_BETA},\n  {_GAMMA},\n  {_DELTA}\n);',
    F'x = [{_ALPHA}, --> 1, {_BETA}, {_GAMMA}, {_DELTA}];':
        F'x = [\n  {_ALPHA}, --> 1,\n  {_BETA},\n  {_GAMMA},\n  {_DELTA}\n];',
    F'function g({_ALPHA}, --> 1, {_BETA}, {_GAMMA}, {_DELTA}) {{}}':
        F'function g(\n  {_ALPHA}, --> 1,\n  {_BETA},\n  {_GAMMA},\n  {_DELTA}\n) {{}}',
    F'x = {{p1: {_VALUE}, p2: {_VALUE}, p3: {_VALUE}, --> 1, p4: {_VALUE}}};':
        F'x = {{ p1: {_VALUE}, p2: {_VALUE}, p3: {_VALUE}, --> 1,\n  p4: {_VALUE}\n}};',
}

A_WRAPPED_LIST_HOLDING_A_READABLE_ITEM = {
    F'f({_ALPHA}, 1, {_BETA}, {_GAMMA}, {_DELTA});':
        F'f(\n  {_ALPHA},\n  1,\n  {_BETA},\n  {_GAMMA},\n  {_DELTA}\n);',
    F'x = [{_ALPHA}, 1, {_BETA}, {_GAMMA}, {_DELTA}];':
        F'x = [\n  {_ALPHA},\n  1,\n  {_BETA},\n  {_GAMMA},\n  {_DELTA}\n];',
    F'function g({_ALPHA}, e1, {_BETA}, {_GAMMA}, {_DELTA}) {{}}':
        F'function g(\n  {_ALPHA},\n  e1,\n  {_BETA},\n  {_GAMMA},\n  {_DELTA}\n) {{}}',
    F'x = {{p1: {_VALUE}, p2: {_VALUE}, p3: {_VALUE}, p9: 1, p4: {_VALUE}}};':
        F'x = {{ p1: {_VALUE}, p2: {_VALUE}, p3: {_VALUE},\n  p9: 1,\n  p4: {_VALUE}\n}};',
}


class TestAWrappedListNeverPutsTheCloserAtALineHead(TestBase):

    def test_wrapped_list_item_opening_html_close_comment_is_not_written_at_a_line_head(self):
        rows = A_WRAPPED_LIST_HOLDING_A_CLOSER
        self.assertEqual({source: printed(source) for source in rows}, rows)

    def test_a_list_holding_an_item_the_language_reads_is_broken_at_that_item(self):
        rows = A_WRAPPED_LIST_HOLDING_A_READABLE_ITEM
        self.assertEqual({source: printed(source) for source in rows}, rows)

    def test_printing_the_print_of_a_list_holding_the_closer_writes_it_again(self):
        once = {source: printed(source) for source in A_WRAPPED_LIST_HOLDING_A_CLOSER}
        self.assertEqual({source: printed(text) for source, text in once.items()}, once)

    def test_the_item_reads_back_as_the_text_no_parser_could_read(self):
        rows = A_WRAPPED_LIST_HOLDING_A_CLOSER
        self.assertEqual(
            {
                source: [
                    node.text
                    for node in JsParser(printed(source)).parse().walk_in_order()
                    if isinstance(node, JsErrorNode)
                ]
                for source in rows
            },
            {source: ['--> 1'] for source in rows},
        )

    def test_neither_the_file_nor_the_text_written_for_it_is_a_program(self):
        rows = A_WRAPPED_LIST_HOLDING_A_CLOSER
        self.assertEqual(
            {source: (well_formed(source), well_formed(text)) for source, text in rows.items()},
            {source: (False, False) for source in rows},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeAnswersTheSameAboutAWrappedList(TestBase):

    def test_node_refuses_a_list_holding_the_closer_and_the_text_written_for_it(self):
        rows = A_WRAPPED_LIST_HOLDING_A_CLOSER
        self.assertEqual(
            {
                source: (node_reads_as_a_program(source), node_reads_as_a_program(text))
                for source, text in rows.items()
            },
            {source: (False, False) for source in rows},
        )

    def test_node_reads_a_list_holding_an_item_the_language_reads(self):
        rows = A_WRAPPED_LIST_HOLDING_A_READABLE_ITEM
        self.assertEqual(
            {
                source: (node_reads_as_a_program(source), node_reads_as_a_program(text))
                for source, text in rows.items()
            },
            {source: (True, True) for source in rows},
        )
