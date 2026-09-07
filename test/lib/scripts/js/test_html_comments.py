"""
The two comment delimiters script code has beyond `//` and `/*`, and whether the tool reads them
where the language does.

`<!--` opens a comment wherever a comment may open, the middle of an expression included, so
`var y = x <!-- note` declares `y` and holds what `x` holds. `-->` opens one only where nothing but
whitespace and comments precedes it on its line, the head of the file counting as such a line;
anywhere else those three characters are the decrement operator and `>`, which is what makes
`a-->b` the program `a-- > b`. Each runs to the end of its line the way `//` does (§B.1.1). Both
are script grammar and nothing else: Node refuses every file holding one when it reads it as a
module, with `SyntaxError: HTML comments are not allowed in modules`.

Node decides every expectation here. The question put to it is whether it reads a text at all and
what the text prints, and the law is that the tool answers the same: a file the host runs is a
well-formed program that prints back to a file printing the same, and a file the host refuses is no
program. The collector reports the delimiters under the module goal and nothing else does.

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
from test.lib.scripts.js.ledger import each_well_formed, folded, printed, prints

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import StrictViolation, collect_strict_violations

#: A file holding one of the two delimiters where it opens a comment leading a statement of a
#: statement list, mapped to what Node prints for it: at the head of the file, behind a statement,
#: inside a function body, a block and a class body, in the middle of an expression, and behind
#: whitespace, a comment, and a comment that spans lines. Every line terminator the language has
#: ends such a comment.
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

#: A file holding a comment that no statement of a list carries: one at the end of the file, which
#: the file carries, and one leading the body of a clause, which the body's statement carries. Each
#: prints back holding its comment, as `A_FILE_HOLDING_A_COMMENT_NO_STATEMENT_CARRIES_PRINTED`
#: records, and the lexer records the delimiter, so the module rule reads it.
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

#: A file spelling the characters of a delimiter where they are no delimiter, mapped to what Node
#: prints for it: `-->` behind a statement on its line is a decrement and a `>`, `<<!--` is a shift
#: whose left operand the longest match takes both angle brackets for, and neither delimiter is
#: read inside a string, a template, or a regular expression literal.
A_FILE_SPELLING_THE_CHARACTERS_WHERE_THEY_OPEN_NO_COMMENT = {
    'var a = 2, b = 0;\nconsole.log(a-->b);'                    : prints('true'),
    'var a = 4, b = 1; console.log(a <<!--b);'                  : prints('8'),
    "console.log('-->');"                                       : prints('-->'),
    'console.log(`x\n--> y`);'                                  : prints('x\n--> y'),
    'console.log("<!--");'                                      : prints('<!--'),
    'var s = /<!--/.test("<!--"); console.log(s);'              : prints('true'),
    '\n/-->/.test("-->");\nconsole.log(/-->/.test("-->"));'     : prints('true'),
}

#: A file with `-->` behind a statement on its line where what follows it is no expression. Node
#: refuses each with `SyntaxError: Unexpected token '>'`, a statement in front of the delimiter on
#: its line being what the positional restriction is about.
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
    """
    What each file prints is what the host prints for it, and the text the printer hands back has
    to print the same, as does the text the deobfuscator hands back.
    """

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
    """
    A module refuses both delimiters and a script reads them, so the one rule the collector has
    about them is reported only when the tree is read as module code, once per file at the first
    delimiter the lexer read, whether or not a statement carries the comment, and about nothing
    that spells the characters where they open no comment.
    """

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
