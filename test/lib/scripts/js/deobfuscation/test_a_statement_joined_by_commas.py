"""
SECURITY: every program here is hand-authored and benign, and Node runs each of them. Nothing from
`samples` may ever be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.deobfuscation.sequences import JsSequenceStatementSplitting
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


def split(source: str) -> str:
    ast = JsParser(source).parse()
    JsSequenceStatementSplitting().visit(ast)
    return JsSynthesizer().convert(ast)


STATEMENTS_JOINED_BY_COMMAS: dict[str, Program] = {
    'stores in the body of a function': Program(
        a_program("""
            function f(p) { var a, b; a = p.x, b = a + 1; return b; }
            console.log(f({ x: 1 }));
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'in a case': Program(
        a_program("""
            var log = [];
            switch (1) { case 1: log.push(1), log.push(2); }
            console.log(log.join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'in a static block': Program(
        a_program("""
            var log = [];
            class C { static { log.push(1), log.push(2); } }
            console.log(log.join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'the body of a branch': Program(
        a_program("""
            var log = [];
            if (log) log.push(1), log.push(2); else log.push(3), log.push(4);
            console.log(log.join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'the body of a label': Program(
        a_program("""
            var log = [];
            L: log.push(1), log.push(2);
            console.log(log.join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'a part that throws': Program(
        a_program("""
            var log = [];
            try { log.push(1), null.x, log.push(2); } catch (e) { log.push(e.name); }
            console.log(log.join());
            """),
        prints('1,TypeError'),
        Reading.COMMONJS,
    ),
    'a function written after the comma': Program(
        a_program("""
            var n = 0;
            n++, function () { n += 10; }();
            console.log(n);
            """),
        prints('11'),
        Reading.COMMONJS,
    ),
    'an async function written after the comma': Program(
        a_program("""
            var log = [];
            log.push(1), async function () { log.push(2); }();
            console.log(log.join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'a class written after the comma': Program(
        a_program("""
            var log = [];
            log.push(1), class { static x = log.push(2); };
            console.log(log.join());
            """),
        prints('1,2'),
        Reading.COMMONJS,
    ),
    'an object pattern written after the comma': Program(
        a_program("""
            var r, o = { k: 3 };
            r = 0, { k: r } = o;
            console.log(r);
            """),
        prints('3'),
        Reading.COMMONJS,
    ),
    'a member of a var named let written after the comma': Program(
        a_program("""
            var let = [0];
            let.length, let[0] = 5;
            console.log(let[0]);
            """),
        prints('5'),
        Reading.COMMONJS,
    ),
    'the text use strict written first in the body of a function': Program(
        a_program("""
            function f() { 'use strict', u = 1; return typeof u; }
            console.log(f(), typeof u);
            """),
        prints('number number'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStatementJoinedByCommasBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in STATEMENTS_JOINED_BY_COMMAS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_once_its_parts_are_statements(self):
        for label, row in STATEMENTS_JOINED_BY_COMMAS.items():
            with self.subTest(label=label):
                self.assertEqual(row.reading.behaves(split(row.text)), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in STATEMENTS_JOINED_BY_COMMAS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAStatementJoinedByCommasIsWrittenAsOneStatementPerPart(TestBase):

    def test_the_parts_in_a_list_take_the_place_of_the_statement(self):
        self.assertEqual(
            split('f(), a = 1, b = 2;'),
            inspect.cleandoc(
                """
                f();
                a = 1;
                b = 2;
                """
            ),
        )

    def test_a_sequence_in_parentheses_among_the_parts_is_split_with_them(self):
        self.assertEqual(
            split('(f(), (a = 1, b = 2)), g();'),
            inspect.cleandoc(
                """
                f();
                a = 1;
                b = 2;
                g();
                """
            ),
        )

    def test_the_parts_in_the_body_of_a_loop_make_a_block(self):
        self.assertEqual(
            split('while (c()) a = 1, b = 2;'),
            inspect.cleandoc(
                """
                while (c()) {
                  a = 1;
                  b = 2;
                }
                """
            ),
        )

    def test_the_comments_stay_before_the_first_part_and_after_the_last(self):
        self.assertEqual(
            split('f();\n/* before */\na = 1, b = 2; // after\ng();'),
            inspect.cleandoc(
                """
                f();
                /* before */
                a = 1;
                b = 2;
                // after
                g();
                """
            ),
        )

    def test_a_statement_written_inside_an_expression_is_split(self):
        self.assertEqual(
            split('x = function () { a = 1, b = 2; };'),
            inspect.cleandoc(
                """
                x = function() {
                  a = 1;
                  b = 2;
                };
                """
            ),
        )


class TestDeadStoresJoinedByCommasGoAsSeparateOnesDo(TestBase):

    def test_dead_stores_in_one_comma_sequence_are_removed_as_separate_ones_are(self):
        def deobfuscated(stores: str) -> str:
            return deobfuscate_source(
                F'function f(p, q) {{ var a, b; {stores} return p.z; }} console.log(f(o1, o2), f(o3, o4));',
                execution=ExecutionModel.commonjs,
            )
        reads_kept = inspect.cleandoc(
            """
            function f(p, q) {
              p.x;
              q.y;
              return p.z;
            }
            console.log(f(o1, o2), f(o3, o4));
            """
        )
        self.assertEqual(
            (deobfuscated('a = p.x, b = q.y;'), deobfuscated('a = p.x; b = q.y;')),
            (reads_kept, reads_kept),
        )
