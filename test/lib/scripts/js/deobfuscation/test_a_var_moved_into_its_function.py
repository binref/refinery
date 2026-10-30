"""
A file-level `var` whose every reference lies in one function, which
`refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` moves into that function where
every run of it reads only what that run stored
(`refinery.lib.scripts.js.analysis.localization`). Each program is written by hand, and each row
says what Node prints for it run the way its reading names: as a CommonJS file, or as a classic
script where the row reaches the global object.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.options import ExecutionModel

#: Programs with a file-level `var` one function writes before it reads it, which another run of
#: that function writes in between, mapped to what Node prints for each: the run waits at an
#: `await`, a `yield`, the head of a `for await` loop, a point leaving the body of such a loop,
#: which waits for its iterator to close, or the `return` of an async generator, calls itself,
#: calls code that calls it, or reads the `var` after such a call in the statement that makes it.
ANOTHER_RUN_WRITES: dict[str, Program] = {
    'an await': Program(
        a_program("""
            var x;
            async function f(v) {
              x = v;
              await null;
              console.log(x);
            }
            f(1);
            f(2);
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a yield': Program(
        a_program("""
            var x;
            function* f(v) {
              x = v;
              yield;
              console.log(x);
            }
            var a = f(1);
            var b = f(2);
            a.next();
            b.next();
            a.next();
            b.next();
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a for await head': Program(
        a_program("""
            var x;
            async function f(v) {
              x = v;
              for await (var e of [0]);
              console.log(x);
            }
            f(1);
            f(2);
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a break out of a for await loop': Program(
        a_program("""
            var x;
            async function f(v) {
              out: {
                for await (var e of [0]) {
                  x = v;
                  break out;
                }
                x = 0;
              }
              console.log(x);
            }
            f(1);
            f(2);
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a continue of an outer loop out of a for await loop': Program(
        a_program("""
            var x;
            async function f(v) {
              outer: for (var i = 0; i < 1; i++) {
                for await (var e of [0]) {
                  x = v;
                  continue outer;
                }
              }
              console.log(x);
            }
            f(1);
            f(2);
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a return out of a for await loop': Program(
        a_program("""
            var x;
            async function f(v) {
              try {
                for await (var e of [0]) {
                  x = v;
                  return;
                }
              } finally {
                console.log(x);
              }
            }
            f(1);
            f(2);
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a throw out of a for await loop caught outside it': Program(
        a_program("""
            var x;
            async function f(v) {
              try {
                for await (var e of [0]) {
                  x = v;
                  throw 0;
                }
              } catch (error) {
                console.log(x);
              }
            }
            f(1);
            f(2);
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'the return of an async generator': Program(
        a_program("""
            var x;
            async function* f(v) {
              x = v;
              try {
                return 0;
              } finally {
                console.log(x);
              }
            }
            f(1).next();
            f(2).next();
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a call of itself': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              if (n) f(n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.COMMONJS,
    ),
    'a call of a function that calls it': Program(
        a_program("""
            var x;
            function g(n) {
              f(n);
            }
            function f(n) {
              x = n;
              if (n) g(n - 1);
              console.log(x);
            }
            f(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a call of code that calls it': Program(
        a_program("""
            var x;
            function f(n, g) {
              x = n;
              g();
              console.log(x);
            }
            f(1, function () { f(2, function () {}); });
            """),
        prints('2', '2'),
        Reading.COMMONJS,
    ),
    'a read after the call in one statement': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              console.log(n ? f(0) : 'inner', x);
              return 'r';
            }
            f(1);
            """),
        prints('inner 0', 'r 0'),
        Reading.COMMONJS,
    ),
}

#: Programs with a file-level `var` one function writes before it reads it in its body, and which an
#: expression of its parameter list reads or writes, mapped to what Node prints for each: those
#: expressions run in a scope of their own, which a `var` declared in the body does not reach.
READ_OR_WRITTEN_IN_THE_PARAMETERS: dict[str, Program] = {
    'a parameter default that reads it': Program(
        a_program("""
            var x;
            function f(v = x) {
              x = v;
              console.log(v);
            }
            f(1);
            f();
            """),
        prints('1', '1'),
        Reading.COMMONJS,
    ),
    'a parameter default that writes it': Program(
        a_program("""
            'use strict';
            var x;
            function f(n, d = (x = 7)) {
              x = n;
              console.log(x, d);
            }
            f(1);
            """),
        prints('1 7'),
        Reading.COMMONJS,
    ),
}

#: Classic scripts with a file-level `var` one function writes before it reads it, which the
#: function also reaches as a property of a name holding the global object, mapped to what Node
#: prints for each: the `var` is that property only while the file declares it.
REACHED_THROUGH_THE_GLOBAL_OBJECT: dict[str, Program] = {
    'a member of a name holding the global object': Program(
        a_program("""
            var G = this;
            var x;
            function f(v) {
              x = v;
              console.log(G.x);
            }
            f(1);
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a read after a write by name in a function called twice': Program(
        a_program("""
            var g;
            var w = global || {};
            function f() { g = 1; console.log(w.g); }
            f();
            f();
            """),
        prints('1', '1'),
        Reading.SCRIPT,
    ),
}

#: Programs with a file-level `var` one function writes before it reads it, which no other run of
#: that function writes in between, mapped to what Node prints for each: the run reads it before
#: it calls itself, calls itself or waits before it stores it, calls code that cannot run it, or
#: returns from an async function, which does not wait there.
NO_OTHER_RUN_WRITES: dict[str, Program] = {
    'a read before the call': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              console.log(x);
              if (n) f(n - 1);
            }
            f(2);
            """),
        prints('2', '1', '0'),
        Reading.COMMONJS,
    ),
    'a call before the store': Program(
        a_program("""
            var x;
            function f(n) {
              if (n) f(n - 1);
              x = n;
              console.log(x);
            }
            f(2);
            """),
        prints('0', '1', '2'),
        Reading.COMMONJS,
    ),
    'an await before the store': Program(
        a_program("""
            var x;
            async function f(v) {
              await null;
              x = v;
              console.log(x);
            }
            f(1);
            f(2);
            """),
        prints('1', '2'),
        Reading.COMMONJS,
    ),
    'a call of code that cannot run it': Program(
        a_program("""
            var x;
            function g(v) {
              return v + 1;
            }
            function f(n) {
              x = g(n);
              console.log(x);
            }
            f(1);
            f(2);
            """),
        prints('2', '3'),
        Reading.COMMONJS,
    ),
    'the return of an async function': Program(
        a_program("""
            var x;
            async function f(v) {
              x = v;
              try {
                return 0;
              } finally {
                console.log(x);
              }
            }
            f(1);
            f(2);
            """),
        prints('1', '2'),
        Reading.COMMONJS,
    ),
}


STAYS = {**ANOTHER_RUN_WRITES, **READ_OR_WRITTEN_IN_THE_PARAMETERS}

EVERY_PROGRAM = {**STAYS, **REACHED_THROUGH_THE_GLOBAL_OBJECT, **NO_OTHER_RUN_WRITES}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAVarMovedIntoItsFunctionBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in EVERY_PROGRAM.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in EVERY_PROGRAM.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAVarMovesWhereEachRunReadsOnlyWhatItStored(TestBase):

    def test_a_var_another_run_or_the_parameter_list_may_write_stays_at_the_top_of_the_file(self):
        for label, row in STAYS.items():
            with self.subTest(label=label):
                text = deobfuscate_source(row.text, execution=ExecutionModel.commonjs)
                self.assertIn('var x;', text.splitlines())

    def test_a_var_no_other_run_writes_leaves_the_top_of_the_file(self):
        for label, row in NO_OTHER_RUN_WRITES.items():
            with self.subTest(label=label):
                text = deobfuscate_source(row.text, execution=ExecutionModel.commonjs)
                self.assertNotIn('var x;', text.splitlines())
