"""
SECURITY: every snippet here is hand-authored and benign, and Node only reads each one as a script,
running none of them. Nothing from `samples` may ever be fed to this.
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

#: A comment standing where no carrier does is carried by the next statement, which may be the first
#: one of a block opening behind it, or by the end of the file, and comes back there.
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
        'export default function f() {}\n/* c */',
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

#: In `x = / /* c` the two slashes are the regular expression `/ /`, so `/*` opens no comment: the
#: first file reads as `x = / / * c`, and the second is refused, since its last slash opens a
#: regular expression nothing closes.
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

#: Unread text opening with `-->` is written on the line of what precedes it, together with the
#: comments leading it, because at the head of a line `-->` opens a comment.
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
    'async /*c*/ function f a b {}': (
        'async /*c*/ function f a b {}',
        'async /*c*/ function f a b {}',
    ),
    'switch (a) { case 1: async /*c*/ function f a {} }': (
        'switch (a) {\n  case 1:\n    async /*c*/ function f a {}\n}',
        'switch (a) {\n  case 1:\n    async /*c*/ function f a {}\n}',
    ),
    'x = /* c */ { b() {} d };': (
        'x = { b() {} d };\n/* c */',
        'x = { b() {} d };',
    ),
    '/*c*/ #!x\nvar y = 1;': (
        '/*c*/\n#!x\nvar y = 1;',
        '\n#!x\nvar y = 1;',
    ),
}

#: The unclosed comment comes back even with comments stripped: without it the print would be a
#: program, and the file is not one.
A_COMMENT_THE_FILE_ENDS_INSIDE = {
    'x = 1; /* a': (
        'x = 1;\n/* a',
        'x = 1;\n/* a',
    ),
    '/* a': (
        '/* a',
        '/* a',
    ),
    'function f() { x; /* a': (
        'function f() {\n  x;\n/* a',
        'function f() {\n  x;\n/* a',
    ),
    'x = y[a /* c': (
        'x = y[a\n/* c',
        'x = y[a\n/* c',
    ),
}

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

    def test_the_file_says_whether_it_ended_inside_a_construct(self):
        rows = every_file_holding_a_comment()
        ended_inside = {
            *A_COMMENT_THE_FILE_ENDS_INSIDE,
            *A_COMMENT_BEFORE_THE_END_OF_A_LIST_THE_FILE_ENDS_INSIDE,
        }
        self.assertEqual(
            {source: JsParser(source).parse().terminated for source in rows},
            {source: source not in ended_inside for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_a_program_exactly_where_the_verdict_says(self):
        self.assertEqual(
            {source: node_reads_as_a_program(source) for source in every_file_holding_a_comment()},
            self._by_group(),
        )


class TestTheDeobfuscatorKeepsTheCarriers(TestBase):

    def test_each_carried_comment_comes_back_where_it_stood(self):
        rows = {
            'console.log(1); /* a */': 'console.log(1);\n/* a */',
            'console.log(1); /* a': 'console.log(1);\n/* a',
            '#!/usr/bin/env node\nconsole.log(1);': '#!/usr/bin/env node\nconsole.log(1);',
            'function f() { console.log(1); /* a */ } f();': 'console.log(1);\n/* a */',
        }
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)
