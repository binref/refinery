"""
A comment in every position the grammar lets one stand, and what the tool writes for the file
holding it. Every comment has a carrier. A statement, a class element and a switch clause carry the
comments that led them; a block, a class body, a switch and the file carry the comments standing
behind their last item; the file carries the `#!` line it opens with. A comment standing where no
carrier does — inside an expression, between a keyword and a brace — is carried by the next
statement or by the end of the file, so its position is kept to the statement and no closer. With
comments stripped, every carried comment is gone; a comment inside text the parser could not read
stays, since such text is written as it was written.

Node decides which files are programs, reading each as a script and running none of them.
SECURITY: every snippet here is hand-authored and benign, and nothing is run. Nothing from
`samples` may ever be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
    node_reads_as_a_program,
)
from test.lib.scripts.js.ledger import dropped_source_characters, printed, well_formed

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

#: A file with a comment leading a statement, a class element or a switch clause, or the body of a
#: labeled statement, mapped to what the printer writes for it with comments kept and with them
#: stripped. The comment comes back on a line of its own in front of what it led — on the line of
#: a label's body, where it is a block comment.
A_COMMENT_LEADING_A_STATEMENT = {
    '/* a */ x = 1;': (
        '/* a */\nx = 1;',
        'x = 1;',
    ),
    '// a\nx = 1;': (
        '// a\nx = 1;',
        'x = 1;',
    ),
    'x = 1; /* a */ y = 2;': (
        'x = 1;\n/* a */\ny = 2;',
        'x = 1;\ny = 2;',
    ),
    'x = 1; // a\ny = 2;': (
        'x = 1;\n// a\ny = 2;',
        'x = 1;\ny = 2;',
    ),
    'function f() { /* a */ return 1; }': (
        'function f() {\n  /* a */\n  return 1;\n}',
        'function f() {\n  return 1;\n}',
    ),
    '{ /* a */ x = 1; }': (
        '{\n  /* a */\n  x = 1;\n}',
        '{\n  x = 1;\n}',
    ),
    'class C { /* a */ m() {} }': (
        'class C {\n  /* a */\n  m() {}\n}',
        'class C {\n  m() {}\n}',
    ),
    'class C { m() {} /* a */ n() {} }': (
        'class C {\n  m() {}\n  /* a */\n  n() {}\n}',
        'class C {\n  m() {}\n  n() {}\n}',
    ),
    'switch (x) { /* a */ case 1: y; }': (
        'switch (x) {\n  /* a */\n  case 1:\n    y;\n}',
        'switch (x) {\n  case 1:\n    y;\n}',
    ),
    'switch (x) { case 1: y; /* a */ case 2: z; }': (
        'switch (x) {\n  case 1:\n    y;\n  /* a */\n  case 2:\n    z;\n}',
        'switch (x) {\n  case 1:\n    y;\n  case 2:\n    z;\n}',
    ),
    'switch (x) { case 1: /* a */ y; }': (
        'switch (x) {\n  case 1:\n    /* a */\n    y;\n}',
        'switch (x) {\n  case 1:\n    y;\n}',
    ),
    'switch (x) { case 1: y; /* a */ default: z; }': (
        'switch (x) {\n  case 1:\n    y;\n  /* a */\n  default:\n    z;\n}',
        'switch (x) {\n  case 1:\n    y;\n  default:\n    z;\n}',
    ),
    'l: /* a */ x = 1;': (
        'l: /* a */ x = 1;',
        'l: x = 1;',
    ),
    'l: // a\nx = 1;': (
        'l: // a\nx = 1;',
        'l: x = 1;',
    ),
}

#: A file with a comment leading the body of a clause. A body that is no block is printed as one,
#: and the comment leads the statement inside it; a body that is a block keeps the comment in front
#: of its brace, on the clause's line where it is a block comment.
A_COMMENT_LEADING_A_CLAUSE_BODY = {
    'if (a) /* c */ x = 1;': (
        'if (a) {\n  /* c */\n  x = 1;\n}',
        'if (a) {\n  x = 1;\n}',
    ),
    'if (a) { x; } else /* c */ y;': (
        'if (a) {\n  x;\n} else {\n  /* c */\n  y;\n}',
        'if (a) {\n  x;\n} else {\n  y;\n}',
    ),
    'if (a) /* c */ { x; }': (
        'if (a) /* c */ {\n  x;\n}',
        'if (a) {\n  x;\n}',
    ),
    'if (a) // c\n{ x; }': (
        'if (a) // c\n{\n  x;\n}',
        'if (a) {\n  x;\n}',
    ),
    'if (a) { x; } else /* c */ { y; }': (
        'if (a) {\n  x;\n} else /* c */ {\n  y;\n}',
        'if (a) {\n  x;\n} else {\n  y;\n}',
    ),
    'for (;;) /* c */ x;': (
        'for (; ; ) {\n  /* c */\n  x;\n}',
        'for (; ; ) {\n  x;\n}',
    ),
    'while (a) /* c */ x;': (
        'while (a) {\n  /* c */\n  x;\n}',
        'while (a) {\n  x;\n}',
    ),
    'do /* c */ x; while (a);': (
        'do {\n  /* c */\n  x;\n} while (a);',
        'do {\n  x;\n} while (a);',
    ),
    'with (o) /* c */ x;': (
        'with (o) {\n  /* c */\n  x;\n}',
        'with (o) {\n  x;\n}',
    ),
    'for (;;) /* c */ ;': (
        'for (; ; ) {\n  /* c */\n  ;\n}',
        'for (; ; ) {\n  ;\n}',
    ),
    'for (;;) /* c */ { x; }': (
        'for (; ; ) /* c */ {\n  x;\n}',
        'for (; ; ) {\n  x;\n}',
    ),
}

#: A file with a comment behind the last item of a block, a class body, a switch, a static block or
#: the file itself, which is where the parser used to drop it. It comes back on a line of its own
#: at the end of the list, and a file holding nothing but comments comes back as those.
A_COMMENT_BEHIND_THE_LAST_ITEM = {
    'x = 1; /* a */': (
        'x = 1;\n/* a */',
        'x = 1;',
    ),
    'x = 1;\n// a': (
        'x = 1;\n// a',
        'x = 1;',
    ),
    'x = 1; <!-- a': (
        'x = 1;\n<!-- a',
        'x = 1;',
    ),
    'x = 1;\n--> a': (
        'x = 1;\n--> a',
        'x = 1;',
    ),
    '/* a */': (
        '/* a */',
        '',
    ),
    '// a': (
        '// a',
        '',
    ),
    '/* a */ /* b */': (
        '/* a */\n/* b */',
        '',
    ),
    'function f() { x; /* a */ }': (
        'function f() {\n  x;\n  /* a */\n}',
        'function f() {\n  x;\n}',
    ),
    'function f() { /* a */ }': (
        'function f() {\n  /* a */\n}',
        'function f() {}',
    ),
    'function f() { x; // a\n}': (
        'function f() {\n  x;\n  // a\n}',
        'function f() {\n  x;\n}',
    ),
    'class C { m() {} /* a */ }': (
        'class C {\n  m() {}\n  /* a */\n}',
        'class C {\n  m() {}\n}',
    ),
    'class C { /* a */ }': (
        'class C {\n  /* a */\n}',
        'class C {}',
    ),
    'switch (x) { case 1: y; /* a */ }': (
        'switch (x) {\n  case 1:\n    y;\n  /* a */\n}',
        'switch (x) {\n  case 1:\n    y;\n}',
    ),
    'switch (x) { /* a */ }': (
        'switch (x) {\n  /* a */\n}',
        'switch (x) {}',
    ),
    'class C { static { x; /* a */ } }': (
        'class C {\n  static {\n    x;\n    /* a */\n  }\n}',
        'class C {\n  static {\n    x;\n  }\n}',
    ),
    'class C { static { /* a */ } }': (
        'class C {\n  static {\n    /* a */\n  }\n}',
        'class C {\n  static {}\n}',
    ),
    '{ x; /* a */ } y;': (
        '{\n  x;\n  /* a */\n}\ny;',
        '{\n  x;\n}\ny;',
    ),
    '{ /* a */ } y;': (
        '{\n  /* a */\n}\ny;',
        '{}\ny;',
    ),
    'if (a) { x; /* a */ }': (
        'if (a) {\n  x;\n  /* a */\n}',
        'if (a) {\n  x;\n}',
    ),
    'x = () => { y; /* a */ };': (
        'x = () => {\n  y;\n  /* a */\n};',
        'x = () => {\n  y;\n};',
    ),
    'x = { m() { y; /* a */ } };': (
        'x = { m() {\n  y;\n  /* a */\n} };',
        'x = { m() {\n  y;\n} };',
    ),
}

#: A file with a comment standing where no carrier does: inside an expression, between a keyword
#: and the brace it opens, behind the `export` keyword. Such a comment is carried by the next
#: statement — the first one of a block opening behind it, or the one on the next line — or by the
#: end of the file, and comes back there: its position is kept to the statement and no closer.
A_COMMENT_NO_CARRIER_STANDS_AT = {
    'try /* c */ { x; } catch (e) /* d */ { y; } finally /* e */ { z; }': (
        'try {\n  /* c */\n  x;\n} catch (e) {\n  /* d */\n  y;\n} finally {\n  /* e */\n  z;\n}',
        'try {\n  x;\n} catch (e) {\n  y;\n} finally {\n  z;\n}',
    ),
    'function f() /* c */ { x; }': (
        'function f() {\n  /* c */\n  x;\n}',
        'function f() {\n  x;\n}',
    ),
    'class C /* c */ { m() {} }': (
        'class C {\n  /* c */\n  m() {}\n}',
        'class C {\n  m() {}\n}',
    ),
    'switch (x) /* c */ { case 1: y; }': (
        'switch (x) {\n  /* c */\n  case 1:\n    y;\n}',
        'switch (x) {\n  case 1:\n    y;\n}',
    ),
    'x = () => /* c */ { y; };': (
        'x = () => {\n  /* c */\n  y;\n};',
        'x = () => {\n  y;\n};',
    ),
    'x = () => /* c */ y;': (
        'x = () => y;\n/* c */',
        'x = () => y;',
    ),
    'export /* c */ default x;': (
        'export default x;\n/* c */',
        'export default x;',
    ),
    'export /* c */ var x = 1;': (
        'export var x = 1;\n/* c */',
        'export var x = 1;',
    ),
    'export default /* c */ function f() {}': (
        'export default function f() {\n  /* c */\n}',
        'export default function f() {}',
    ),
    'x = f(/* c */ 1); y = 2;': (
        'x = f(1);\n/* c */\ny = 2;',
        'x = f(1);\ny = 2;',
    ),
    'x = f(/* c */ 1);': (
        'x = f(1);\n/* c */',
        'x = f(1);',
    ),
    'for (/* c */ let i = 0; i < 1; i++) x;': (
        'for (let i = 0; i < 1; i++) {\n  /* c */\n  x;\n}',
        'for (let i = 0; i < 1; i++) {\n  x;\n}',
    ),
    'x = { a: 1 /* c */ }; y;': (
        'x = { a: 1 };\n/* c */\ny;',
        'x = { a: 1 };\ny;',
    ),
    'x = [1, /* c */ 2]; y;': (
        'x = [1, 2];\n/* c */\ny;',
        'x = [1, 2];\ny;',
    ),
}

#: A file opening with a `#!` line, which is a comment the file carries (§12.5): it comes back at
#: the head of the file, and stripping comments strips it.
A_HASH_BANG_LINE = {
    '#!/usr/bin/env node\nx = 1;': (
        '#!/usr/bin/env node\nx = 1;',
        'x = 1;',
    ),
    '#!/usr/bin/env node': (
        '#!/usr/bin/env node',
        '',
    ),
    '#!/usr/bin/env node\n': (
        '#!/usr/bin/env node',
        '',
    ),
    '#!/usr/bin/env node\n/* a */ x = 1; /* b */': (
        '#!/usr/bin/env node\n/* a */\nx = 1;\n/* b */',
        'x = 1;',
    ),
    '#!/usr/bin/env node\n// a': (
        '#!/usr/bin/env node\n// a',
        '',
    ),
}

#: A file spelling `/*` where it opens no comment: the slash begins the regular expression `/ /`.
#: Node reads the first file as `x = / / * c`, and refuses the second, whose last slash opens a
#: regular expression nothing closes; each comes back as read, and neither ends inside a comment.
A_SLASH_THAT_OPENS_NO_COMMENT = {
    'x = / /* c': (
        'x = / / * c;',
        'x = / / * c;',
    ),
    'x = / /* c */': (
        'x = / /* c */',
        'x = / /* c */',
    ),
}

#: A file with a comment leading text the parser could not read. Text opening with `-->` is
#: written on the line of what precedes it, since at the head of a line it would open a comment,
#: and so are the comments leading it. A comment inside the unread text is part of the text and
#: stays when comments are stripped.
A_COMMENT_LEADING_UNREAD_TEXT = {
    'var a = 1; /* c */ --> note': (
        'var a = 1; /* c */ --> note',
        'var a = 1; --> note',
    ),
    'var a = 1; /* c */ /* d */ --> note': (
        'var a = 1; /* c */ /* d */ --> note',
        'var a = 1; --> note',
    ),
    '@@@ /* c */ x = 1;': (
        '@@@ /* c */ x = 1;',
        '@@@ /* c */ x = 1;',
    ),
    'x = 1; @@@ /* c */': (
        'x = 1;\n@@@\n/* c */',
        'x = 1;\n@@@',
    ),
}

#: A file that ends inside a block comment, which Node refuses. The comment is the last thing the
#: file holds and comes back last, whatever the file ended inside besides.
A_COMMENT_THE_FILE_ENDS_INSIDE = {
    'x = 1; /* a': (
        'x = 1;\n/* a',
        'x = 1;',
    ),
    '/* a': (
        '/* a',
        '',
    ),
    'function f() { x; /* a': (
        'function f() {\n  x;\n/* a',
        'function f() {\n  x;',
    ),
    'x = y[a /* c': (
        'x = y[a\n/* c',
        'x = y[a',
    ),
}

#: A file that ends inside a list or a template hole, with a comment standing between the last
#: item and the end. The list has no closer to carry the comment, and may yet be refused along
#: with the statement it stands in, so the end of the file carries it: the printer stops where the
#: file ended and writes the comment behind that.
A_COMMENT_BEFORE_THE_END_OF_A_LIST_THE_FILE_ENDS_INSIDE = {
    'function f() { x; /* a */': (
        'function f() {\n  x;\n/* a */',
        'function f() {\n  x;',
    ),
    'function f() { x; // a': (
        'function f() {\n  x;\n// a',
        'function f() {\n  x;',
    ),
    'class C { m() {} /* a */': (
        'class C {\n  m() {}\n/* a */',
        'class C {\n  m() {}',
    ),
    'switch (x) { case 1: y; /* a */': (
        'switch (x) {\n  case 1:\n    y;\n/* a */',
        'switch (x) {\n  case 1:\n    y;',
    ),
    'class C { static { x; /* a */': (
        'class C {\n  static {\n    x;\n/* a */',
        'class C {\n  static {\n    x;',
    ),
    '{ x; /* a */': (
        '{\n  x;\n/* a */',
        '{\n  x;',
    ),
    'x = `abc${a /* c */': (
        'x = `abc${a\n/* c */',
        'x = `abc${a',
    ),
    'x = `abc${ /* c */': (
        'x = `abc${\n/* c */',
        'x = `abc${',
    ),
}

#: A file already in the form the printer writes, holding a comment behind its last statement:
#: each prints back exactly as written. These were the rows of the ledger entry this module retired.
A_FILE_ALREADY_IN_THE_PRINTERS_FORM = (
    'x = 1;\n/* note */',
    'x = 1;\n// note',
    'x = 1;\n/* note',
)


def every_program_holding_a_comment() -> dict[str, tuple[str, str]]:
    return {
        **A_COMMENT_LEADING_A_STATEMENT,
        **A_COMMENT_LEADING_A_CLAUSE_BODY,
        **A_COMMENT_BEHIND_THE_LAST_ITEM,
        **A_COMMENT_NO_CARRIER_STANDS_AT,
        **A_HASH_BANG_LINE,
        'x = / /* c': A_SLASH_THAT_OPENS_NO_COMMENT['x = / /* c'],
    }


def every_file_holding_a_comment_that_is_no_program() -> dict[str, tuple[str, str]]:
    return {
        **A_COMMENT_LEADING_UNREAD_TEXT,
        **A_COMMENT_THE_FILE_ENDS_INSIDE,
        **A_COMMENT_BEFORE_THE_END_OF_A_LIST_THE_FILE_ENDS_INSIDE,
        'x = / /* c */': A_SLASH_THAT_OPENS_NO_COMMENT['x = / /* c */'],
    }


def every_file_holding_a_comment() -> dict[str, tuple[str, str]]:
    return {**every_program_holding_a_comment(), **every_file_holding_a_comment_that_is_no_program()}


def _stripped(source: str) -> str:
    return JsSynthesizer(strip_comments=True).convert(JsParser(source).parse())


def _kept_and_stripped(source: str) -> tuple[str, str]:
    return printed(source), _stripped(source)


class TestEveryCommentHasACarrier(TestBase):

    def test_the_printer_writes_each_file_as_recorded(self):
        rows = every_file_holding_a_comment()
        self.assertEqual({source: _kept_and_stripped(source) for source in rows}, rows)

    def test_printing_the_printed_text_again_changes_nothing(self):
        rows = every_file_holding_a_comment()
        self.assertEqual(
            {source: (printed(kept), _stripped(stripped)) for source, (kept, stripped) in rows.items()},
            rows,
        )

    def test_no_character_of_a_file_goes_missing_with_comments_kept(self):
        rows = every_file_holding_a_comment()
        self.assertEqual(
            {source: dropped_source_characters(source, kept) for source, (kept, _) in rows.items()},
            {source: '' for source in rows},
        )

    def test_a_file_already_in_the_printers_form_prints_back_as_written(self):
        rows = A_FILE_ALREADY_IN_THE_PRINTERS_FORM
        self.assertEqual({source: printed(source) for source in rows}, {source: source for source in rows})


class TestAFileIsAProgramWhereNodeReadsOne(TestBase):

    @staticmethod
    def _by_group() -> dict[str, bool]:
        return {
            **{source: True for source in every_program_holding_a_comment()},
            **{source: False for source in every_file_holding_a_comment_that_is_no_program()},
        }

    def test_the_verdict_answers_by_group(self):
        self.assertEqual(
            {source: well_formed(source) for source in every_file_holding_a_comment()},
            self._by_group(),
        )

    def test_the_file_says_whether_it_ended_inside_a_comment(self):
        rows = every_file_holding_a_comment()
        self.assertEqual(
            {source: JsParser(source).parse().terminated for source in rows},
            {source: source not in A_COMMENT_THE_FILE_ENDS_INSIDE for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_a_program_exactly_where_the_verdict_says(self):
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in every_file_holding_a_comment()},
            self._by_group(),
        )


class TestTheDeobfuscatorKeepsTheCarriers(TestBase):
    """
    A pass rewrites statements and never a carrier: the `#!` line, a comment behind the last
    statement of a body or of the file, and the comment the file ended inside all come back.
    """

    def test_each_carried_comment_comes_back_where_it_stood(self):
        rows = {
            'console.log(1); /* a */': 'console.log(1);\n/* a */',
            'console.log(1); /* a': 'console.log(1);\n/* a',
            '#!/usr/bin/env node\nconsole.log(1);': '#!/usr/bin/env node\nconsole.log(1);',
            'function f() { console.log(1); /* a */ } f();': 'function f() {\n  console.log(1);\n  /* a */\n}\nf();',
        }
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)
