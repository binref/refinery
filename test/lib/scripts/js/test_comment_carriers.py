"""
SECURITY: every snippet here is hand-authored and benign, and Node only reads each one as a script,
running none of them. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import inspect
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
        inspect.cleandoc("""
            /* a */
            x = 1;
        """),
        'x = 1;',
    ),
    inspect.cleandoc("""
        // a
        x = 1;
    """): (
        inspect.cleandoc("""
            // a
            x = 1;
        """),
        'x = 1;',
    ),
    'x = 1; /* a */ y = 2;': (
        inspect.cleandoc("""
            x = 1;
            /* a */
            y = 2;
        """),
        inspect.cleandoc("""
            x = 1;
            y = 2;
        """),
    ),
    inspect.cleandoc("""
        x = 1; // a
        y = 2;
    """): (
        inspect.cleandoc("""
            x = 1;
            // a
            y = 2;
        """),
        inspect.cleandoc("""
            x = 1;
            y = 2;
        """),
    ),
    'function f() { /* a */ return 1; }': (
        inspect.cleandoc("""
            function f() {
              /* a */
              return 1;
            }
        """),
        inspect.cleandoc("""
            function f() {
              return 1;
            }
        """),
    ),
    '{ /* a */ x = 1; }': (
        inspect.cleandoc("""
            {
              /* a */
              x = 1;
            }
        """),
        inspect.cleandoc("""
            {
              x = 1;
            }
        """),
    ),
    'class C { /* a */ m() {} }': (
        inspect.cleandoc("""
            class C {
              /* a */
              m() {}
            }
        """),
        inspect.cleandoc("""
            class C {
              m() {}
            }
        """),
    ),
    'class C { m() {} /* a */ n() {} }': (
        inspect.cleandoc("""
            class C {
              m() {}
              /* a */
              n() {}
            }
        """),
        inspect.cleandoc("""
            class C {
              m() {}
              n() {}
            }
        """),
    ),
    'switch (x) { /* a */ case 1: y; }': (
        inspect.cleandoc("""
            switch (x) {
              /* a */
              case 1:
                y;
            }
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
            }
        """),
    ),
    'switch (x) { case 1: y; /* a */ case 2: z; }': (
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
              /* a */
              case 2:
                z;
            }
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
              case 2:
                z;
            }
        """),
    ),
    'switch (x) { case 1: /* a */ y; }': (
        inspect.cleandoc("""
            switch (x) {
              case 1:
                /* a */
                y;
            }
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
            }
        """),
    ),
    'switch (x) { case 1: y; /* a */ default: z; }': (
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
              /* a */
              default:
                z;
            }
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
              default:
                z;
            }
        """),
    ),
    'l: /* a */ x = 1;': (
        'l: /* a */ x = 1;',
        'l: x = 1;',
    ),
    inspect.cleandoc("""
        l: // a
        x = 1;
    """): (
        inspect.cleandoc("""
            l: // a
            x = 1;
        """),
        'l: x = 1;',
    ),
}

A_COMMENT_LEADING_A_CLAUSE_BODY = {
    'if (a) /* c */ x = 1;': (
        inspect.cleandoc("""
            if (a) {
              /* c */
              x = 1;
            }
        """),
        inspect.cleandoc("""
            if (a) {
              x = 1;
            }
        """),
    ),
    'if (a) { x; } else /* c */ y;': (
        inspect.cleandoc("""
            if (a) {
              x;
            } else {
              /* c */
              y;
            }
        """),
        inspect.cleandoc("""
            if (a) {
              x;
            } else {
              y;
            }
        """),
    ),
    'if (a) /* c */ { x; }': (
        inspect.cleandoc("""
            if (a) /* c */ {
              x;
            }
        """),
        inspect.cleandoc("""
            if (a) {
              x;
            }
        """),
    ),
    inspect.cleandoc("""
        if (a) // c
        { x; }
    """): (
        inspect.cleandoc("""
            if (a) // c
            {
              x;
            }
        """),
        inspect.cleandoc("""
            if (a) {
              x;
            }
        """),
    ),
    'if (a) { x; } else /* c */ { y; }': (
        inspect.cleandoc("""
            if (a) {
              x;
            } else /* c */ {
              y;
            }
        """),
        inspect.cleandoc("""
            if (a) {
              x;
            } else {
              y;
            }
        """),
    ),
    'for (;;) /* c */ x;': (
        inspect.cleandoc("""
            for (; ; ) {
              /* c */
              x;
            }
        """),
        inspect.cleandoc("""
            for (; ; ) {
              x;
            }
        """),
    ),
    'while (a) /* c */ x;': (
        inspect.cleandoc("""
            while (a) {
              /* c */
              x;
            }
        """),
        inspect.cleandoc("""
            while (a) {
              x;
            }
        """),
    ),
    'do /* c */ x; while (a);': (
        inspect.cleandoc("""
            do {
              /* c */
              x;
            } while (a);
        """),
        inspect.cleandoc("""
            do {
              x;
            } while (a);
        """),
    ),
    'with (o) /* c */ x;': (
        inspect.cleandoc("""
            with (o) {
              /* c */
              x;
            }
        """),
        inspect.cleandoc("""
            with (o) {
              x;
            }
        """),
    ),
    'for (;;) /* c */ ;': (
        inspect.cleandoc("""
            for (; ; ) {
              /* c */
              ;
            }
        """),
        inspect.cleandoc("""
            for (; ; ) {
              ;
            }
        """),
    ),
    'for (;;) /* c */ { x; }': (
        inspect.cleandoc("""
            for (; ; ) /* c */ {
              x;
            }
        """),
        inspect.cleandoc("""
            for (; ; ) {
              x;
            }
        """),
    ),
}

A_COMMENT_BEHIND_THE_LAST_ITEM = {
    'x = 1; /* a */': (
        inspect.cleandoc("""
            x = 1;
            /* a */
        """),
        'x = 1;',
    ),
    inspect.cleandoc("""
        x = 1;
        // a
    """): (
        inspect.cleandoc("""
            x = 1;
            // a
        """),
        'x = 1;',
    ),
    'x = 1; <!-- a': (
        inspect.cleandoc("""
            x = 1;
            <!-- a
        """),
        'x = 1;',
    ),
    inspect.cleandoc("""
        x = 1;
        --> a
    """): (
        inspect.cleandoc("""
            x = 1;
            --> a
        """),
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
        inspect.cleandoc("""
            /* a */
            /* b */
        """),
        '',
    ),
    'function f() { x; /* a */ }': (
        inspect.cleandoc("""
            function f() {
              x;
              /* a */
            }
        """),
        inspect.cleandoc("""
            function f() {
              x;
            }
        """),
    ),
    'function f() { /* a */ }': (
        inspect.cleandoc("""
            function f() {
              /* a */
            }
        """),
        'function f() {}',
    ),
    inspect.cleandoc("""
        function f() { x; // a
        }
    """): (
        inspect.cleandoc("""
            function f() {
              x;
              // a
            }
        """),
        inspect.cleandoc("""
            function f() {
              x;
            }
        """),
    ),
    'class C { m() {} /* a */ }': (
        inspect.cleandoc("""
            class C {
              m() {}
              /* a */
            }
        """),
        inspect.cleandoc("""
            class C {
              m() {}
            }
        """),
    ),
    'class C { /* a */ }': (
        inspect.cleandoc("""
            class C {
              /* a */
            }
        """),
        'class C {}',
    ),
    'switch (x) { case 1: y; /* a */ }': (
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
              /* a */
            }
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
            }
        """),
    ),
    'switch (x) { /* a */ }': (
        inspect.cleandoc("""
            switch (x) {
              /* a */
            }
        """),
        'switch (x) {}',
    ),
    'class C { static { x; /* a */ } }': (
        inspect.cleandoc("""
            class C {
              static {
                x;
                /* a */
              }
            }
        """),
        inspect.cleandoc("""
            class C {
              static {
                x;
              }
            }
        """),
    ),
    'class C { static { /* a */ } }': (
        inspect.cleandoc("""
            class C {
              static {
                /* a */
              }
            }
        """),
        inspect.cleandoc("""
            class C {
              static {}
            }
        """),
    ),
    '{ x; /* a */ } y;': (
        inspect.cleandoc("""
            {
              x;
              /* a */
            }
            y;
        """),
        inspect.cleandoc("""
            {
              x;
            }
            y;
        """),
    ),
    '{ /* a */ } y;': (
        inspect.cleandoc("""
            {
              /* a */
            }
            y;
        """),
        inspect.cleandoc("""
            {}
            y;
        """),
    ),
    'if (a) { x; /* a */ }': (
        inspect.cleandoc("""
            if (a) {
              x;
              /* a */
            }
        """),
        inspect.cleandoc("""
            if (a) {
              x;
            }
        """),
    ),
    'x = () => { y; /* a */ };': (
        inspect.cleandoc("""
            x = () => {
              y;
              /* a */
            };
        """),
        inspect.cleandoc("""
            x = () => {
              y;
            };
        """),
    ),
    'x = { m() { y; /* a */ } };': (
        inspect.cleandoc("""
            x = { m() {
              y;
              /* a */
            } };
        """),
        inspect.cleandoc("""
            x = { m() {
              y;
            } };
        """),
    ),
}

#: A comment standing where no carrier does is carried by the next statement, which may be the first
#: one of a block opening behind it, or by the end of the file, and comes back there.
A_COMMENT_NO_CARRIER_STANDS_AT = {
    'try /* c */ { x; } catch (e) /* d */ { y; } finally /* e */ { z; }': (
        inspect.cleandoc("""
            try {
              /* c */
              x;
            } catch (e) {
              /* d */
              y;
            } finally {
              /* e */
              z;
            }
        """),
        inspect.cleandoc("""
            try {
              x;
            } catch (e) {
              y;
            } finally {
              z;
            }
        """),
    ),
    'function f() /* c */ { x; }': (
        inspect.cleandoc("""
            function f() {
              /* c */
              x;
            }
        """),
        inspect.cleandoc("""
            function f() {
              x;
            }
        """),
    ),
    'class C /* c */ { m() {} }': (
        inspect.cleandoc("""
            class C {
              /* c */
              m() {}
            }
        """),
        inspect.cleandoc("""
            class C {
              m() {}
            }
        """),
    ),
    'switch (x) /* c */ { case 1: y; }': (
        inspect.cleandoc("""
            switch (x) {
              /* c */
              case 1:
                y;
            }
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
            }
        """),
    ),
    'x = () => /* c */ { y; };': (
        inspect.cleandoc("""
            x = () => {
              /* c */
              y;
            };
        """),
        inspect.cleandoc("""
            x = () => {
              y;
            };
        """),
    ),
    'x = () => /* c */ y;': (
        inspect.cleandoc("""
            x = () => y;
            /* c */
        """),
        'x = () => y;',
    ),
    'export /* c */ default x;': (
        inspect.cleandoc("""
            export default x;
            /* c */
        """),
        'export default x;',
    ),
    'export /* c */ var x = 1;': (
        inspect.cleandoc("""
            export var x = 1;
            /* c */
        """),
        'export var x = 1;',
    ),
    'export default /* c */ function f() {}': (
        inspect.cleandoc("""
            export default function f() {}
            /* c */
        """),
        'export default function f() {}',
    ),
    'x = f(/* c */ 1); y = 2;': (
        inspect.cleandoc("""
            x = f(1);
            /* c */
            y = 2;
        """),
        inspect.cleandoc("""
            x = f(1);
            y = 2;
        """),
    ),
    'x = f(/* c */ 1);': (
        inspect.cleandoc("""
            x = f(1);
            /* c */
        """),
        'x = f(1);',
    ),
    'for (/* c */ let i = 0; i < 1; i++) x;': (
        inspect.cleandoc("""
            for (let i = 0; i < 1; i++) {
              /* c */
              x;
            }
        """),
        inspect.cleandoc("""
            for (let i = 0; i < 1; i++) {
              x;
            }
        """),
    ),
    'x = { a: 1 /* c */ }; y;': (
        inspect.cleandoc("""
            x = { a: 1 };
            /* c */
            y;
        """),
        inspect.cleandoc("""
            x = { a: 1 };
            y;
        """),
    ),
    'x = [1, /* c */ 2]; y;': (
        inspect.cleandoc("""
            x = [1, 2];
            /* c */
            y;
        """),
        inspect.cleandoc("""
            x = [1, 2];
            y;
        """),
    ),
}

A_HASH_BANG_LINE = {
    inspect.cleandoc("""
        #!/usr/bin/env node
        x = 1;
    """): (
        inspect.cleandoc("""
            #!/usr/bin/env node
            x = 1;
        """),
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
    inspect.cleandoc("""
        #!/usr/bin/env node
        /* a */ x = 1; /* b */
    """): (
        inspect.cleandoc("""
            #!/usr/bin/env node
            /* a */
            x = 1;
            /* b */
        """),
        'x = 1;',
    ),
    inspect.cleandoc("""
        #!/usr/bin/env node
        // a
    """): (
        inspect.cleandoc("""
            #!/usr/bin/env node
            // a
        """),
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
        inspect.cleandoc("""
            x = 1;
            @@@
            /* c */
        """),
        inspect.cleandoc("""
            x = 1;
            @@@
        """),
    ),
    'async /*c*/ function f a b {}': (
        'async /*c*/ function f a b {}',
        'async /*c*/ function f a b {}',
    ),
    'switch (a) { case 1: async /*c*/ function f a {} }': (
        inspect.cleandoc("""
            switch (a) {
              case 1:
                async /*c*/ function f a {}
            }
        """),
        inspect.cleandoc("""
            switch (a) {
              case 1:
                async /*c*/ function f a {}
            }
        """),
    ),
    'x = /* c */ { b() {} d };': (
        inspect.cleandoc("""
            x = { b() {} d };
            /* c */
        """),
        'x = { b() {} d };',
    ),
    inspect.cleandoc("""
        /*c*/ #!x
        var y = 1;
    """): (
        inspect.cleandoc("""
            /*c*/
            #!x
            var y = 1;
        """),
        '\n#!x\nvar y = 1;',
    ),
}

#: The unclosed comment comes back even with comments stripped: without it the print would be a
#: program, and the file is not one.
A_COMMENT_THE_FILE_ENDS_INSIDE = {
    'x = 1; /* a': (
        inspect.cleandoc("""
            x = 1;
            /* a
        """),
        inspect.cleandoc("""
            x = 1;
            /* a
        """),
    ),
    '/* a': (
        '/* a',
        '/* a',
    ),
    'function f() { x; /* a': (
        inspect.cleandoc("""
            function f() {
              x;
            /* a
        """),
        inspect.cleandoc("""
            function f() {
              x;
            /* a
        """),
    ),
    'x = y[a /* c': (
        inspect.cleandoc("""
            x = y[a
            /* c
        """),
        inspect.cleandoc("""
            x = y[a
            /* c
        """),
    ),
}

A_COMMENT_BEFORE_THE_END_OF_A_LIST_THE_FILE_ENDS_INSIDE = {
    'function f() { x; /* a */': (
        inspect.cleandoc("""
            function f() {
              x;
            /* a */
        """),
        inspect.cleandoc("""
            function f() {
              x;
        """),
    ),
    'function f() { x; // a': (
        inspect.cleandoc("""
            function f() {
              x;
            // a
        """),
        inspect.cleandoc("""
            function f() {
              x;
        """),
    ),
    'class C { m() {} /* a */': (
        inspect.cleandoc("""
            class C {
              m() {}
            /* a */
        """),
        inspect.cleandoc("""
            class C {
              m() {}
        """),
    ),
    'switch (x) { case 1: y; /* a */': (
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
            /* a */
        """),
        inspect.cleandoc("""
            switch (x) {
              case 1:
                y;
        """),
    ),
    'class C { static { x; /* a */': (
        inspect.cleandoc("""
            class C {
              static {
                x;
            /* a */
        """),
        inspect.cleandoc("""
            class C {
              static {
                x;
        """),
    ),
    '{ x; /* a */': (
        inspect.cleandoc("""
            {
              x;
            /* a */
        """),
        inspect.cleandoc("""
            {
              x;
        """),
    ),
    'x = `abc${a /* c */': (
        inspect.cleandoc("""
            x = `abc${a
            /* c */
        """),
        'x = `abc${a',
    ),
    'x = `abc${ /* c */': (
        inspect.cleandoc("""
            x = `abc${
            /* c */
        """),
        'x = `abc${',
    ),
}

A_FILE_ALREADY_IN_THE_PRINTERS_FORM = (
    inspect.cleandoc("""
        x = 1;
        /* note */
    """),
    inspect.cleandoc("""
        x = 1;
        // note
    """),
    inspect.cleandoc("""
        x = 1;
        /* note
    """),
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
            'console.log(1); /* a */': inspect.cleandoc("""
                console.log(1);
                /* a */
            """),
            'console.log(1); /* a': inspect.cleandoc("""
                console.log(1);
                /* a
            """),
            inspect.cleandoc("""
                #!/usr/bin/env node
                console.log(1);
            """): inspect.cleandoc("""
                #!/usr/bin/env node
                console.log(1);
            """),
            'function f() { console.log(1); /* a */ } f();': inspect.cleandoc("""
                console.log(1);
                /* a */
            """),
        }
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)
