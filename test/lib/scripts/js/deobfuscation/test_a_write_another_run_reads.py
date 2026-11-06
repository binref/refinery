from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

ANOTHER_RUN_READS: dict[str, Program] = {
    'a guard running the function once': Program(
        a_program("""
            var done;
            function once() { if (done) { return 'skip'; } done = true; return 'run'; }
            once();
            console.log(once());
            """),
        prints('skip'),
        Reading.COMMONJS,
    ),
    'a counter': Program(
        a_program("""
            var n = 0;
            function next() { n = n + 1; return n; }
            next();
            console.log(next());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a later run reading what an earlier one stored': Program(
        a_program("""
            var last;
            function remember(v) { var previous = last; last = v; return previous; }
            remember(1);
            console.log(remember(2));
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a var of an enclosing function the first run leaves for the second': Program(
        a_program("""
            function outer() {
              var t;
              function f(n) { var seen = t; t = n; return seen; }
              f(1);
              return f(2);
            }
            console.log(outer());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a file-level var the run that called it again reads': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              function h() { if (n) f(0); }
              h();
              return x;
            }
            console.log(f(1));
            """),
        prints('0'),
        Reading.COMMONJS,
    ),
    'a var of an enclosing function the run that called it again reads': Program(
        a_program("""
            function outer() {
              var x;
              function f(n) {
                x = n;
                function h() { if (n) f(0); }
                h();
                return x;
              }
              return f(1);
            }
            console.log(outer());
            """),
        prints('0'),
        Reading.COMMONJS,
    ),
}

A_NESTED_FUNCTION_WRITES_A_LOCAL: dict[str, Program] = {
    'a nested function incrementing the local of the run calling it': Program(
        a_program("""
            function f() {
              var n = 0;
              function increment() { n = n + 1; }
              increment();
              increment();
              return n;
            }
            console.log(f());
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'a closure of an earlier run called by a later one': Program(
        a_program("""
            var saved;
            function outer(n) {
              var t = 0;
              function stash() { saved = function () { t = t + 1; }; }
              function peek() { return t; }
              if (n) return [stash, peek];
              saved();
            }
            var p = outer(1);
            p[0]();
            outer(0);
            console.log(p[1]());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
    'a closure of an earlier run calling a nested function a later run calls by name': Program(
        a_program("""
            var saved;
            function outer(n) {
              var t = 0;
              function bump() { t = t + 1; }
              function stash() { saved = function () { bump(); }; }
              function peek() { return t; }
              if (n) return [stash, peek];
              saved();
            }
            var p = outer(1);
            p[0]();
            outer(0);
            console.log(p[1]());
            """),
        prints('1'),
        Reading.COMMONJS,
    ),
}

EVERY_PROGRAM = {**ANOTHER_RUN_READS, **A_NESTED_FUNCTION_WRITES_A_LOCAL}

A_WRITE_A_HOST_READS = a_program("""
    var a;
    var f = function () { a = 2; return a; };
    console.log(f());
    """)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteAnotherRunReadsBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in EVERY_PROGRAM.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in EVERY_PROGRAM.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAWriteAHostReadsIsKept(TestBase):

    def test_the_write_stays(self):
        output = deobfuscate_source(A_WRITE_A_HOST_READS, entrypoints=('a',))
        self.assertIn('a = 2', output)
