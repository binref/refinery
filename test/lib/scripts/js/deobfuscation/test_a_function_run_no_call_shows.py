"""
A function whose body runs where no call of its name shows: through the global object, through its
own `arguments`, through the `caller` of a function it calls, through `new.target`, or at a step of
a generator object. Such a run may store into a file-level `var` between the store of another run
and its read, so the `var` stays at the top of the file
(`refinery.lib.scripts.js.analysis.localization`), and a value is not carried past it
(`refinery.lib.scripts.js.analysis.effects.EffectModel.function_escapes`). Each program is written
by hand, and each row says what Node prints for it run the way its reading names: as a CommonJS
file, or as a classic script where the row reaches the global object.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.options import ExecutionModel

#: Programs with a file-level `var` one function writes before it reads it, which another run of
#: that function writes in between, a run no call of the function's name shows, mapped to what
#: Node prints for each.
ANOTHER_RUN_NO_CALL_SHOWS: dict[str, Program] = {
    'a call of itself through the global object': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              if (n) globalThis.f(n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.SCRIPT,
    ),
    'a call of itself through a computed key of the global object': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              if (n) globalThis['f'](n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.SCRIPT,
    ),
    'a call of itself through this': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              if (n) this.f(n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.SCRIPT,
    ),
    'a call of itself through a name holding the global object': Program(
        a_program("""
            var G = this;
            var x;
            function f(n) {
              x = n;
              if (n) G.f(n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.SCRIPT,
    ),
    'a call of itself through its arguments': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              if (n) arguments.callee(n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.COMMONJS,
    ),
    'a call of itself through a name holding its arguments': Program(
        a_program("""
            var x;
            function f(n) {
              var a = arguments;
              x = n;
              if (n) a.callee(n - 1);
              console.log(x);
            }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.COMMONJS,
    ),
    'a call of it through the caller of a function it calls': Program(
        a_program("""
            var x;
            function g() {
              g.caller(0);
            }
            function f(n) {
              x = n;
              if (n) g();
              console.log(x);
            }
            f(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a call of it through the caller read with a string key': Program(
        a_program("""
            var x;
            function g() {
              g['caller'](0);
            }
            function f(n) {
              x = n;
              if (n) g();
              console.log(x);
            }
            f(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a construction of itself through new.target': Program(
        a_program("""
            var x;
            function F(n) {
              x = n;
              if (n) new new.target(0);
              console.log(x);
            }
            new F(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a step of a generator that calls it': Program(
        a_program("""
            var x;
            function* gen() {
              f(0);
              yield 1;
            }
            var it = gen();
            function f(n) {
              x = n;
              if (n) it.next();
              console.log(x);
            }
            f(1);
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a step of another generator object of itself': Program(
        a_program("""
            var x;
            var other;
            function* f(n) {
              x = n;
              if (n) other.next();
              console.log(x);
              yield;
            }
            other = f(0);
            f(1).next();
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
    'a step of another async generator object of itself': Program(
        a_program("""
            var x;
            var other;
            async function* f(n) {
              x = n;
              if (n) other.next();
              console.log(x);
            }
            other = f(0);
            f(1).next();
            """),
        prints('0', '0'),
        Reading.COMMONJS,
    ),
}

#: Programs reading a value past a run of the function that writes it, a run no call of the
#: function's name shows, mapped to what Node prints for each.
A_VALUE_READ_PAST_A_RUN_NO_CALL_SHOWS: dict[str, Program] = {
    'a value read past a call of its writer through the global object': Program(
        a_program("""
            var x = 1;
            function f() {
              x = 2;
            }
            globalThis.f();
            console.log(x);
            """),
        prints('2'),
        Reading.SCRIPT,
    ),
    'a value read past a step of a generator that writes it': Program(
        a_program("""
            function g() {
              function* gen() {
                y = 2;
                yield;
              }
              var it = gen();
              var y = 1;
              it.next();
              console.log(y);
            }
            g();
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
}

EVERY_PROGRAM = {**ANOTHER_RUN_NO_CALL_SHOWS, **A_VALUE_READ_PAST_A_RUN_NO_CALL_SHOWS}

_EXECUTION = {
    Reading.SCRIPT: ExecutionModel.script,
    Reading.COMMONJS: ExecutionModel.commonjs,
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionRunWhereNoCallOfItsNameShowsBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in EVERY_PROGRAM.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in EVERY_PROGRAM.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAVarAnotherRunNoCallShowsWritesStays(TestBase):

    def test_the_var_stays_at_the_top_of_the_file(self):
        for label, row in ANOTHER_RUN_NO_CALL_SHOWS.items():
            with self.subTest(label=label):
                text = deobfuscate_source(row.text, execution=_EXECUTION[row.reading])
                self.assertIn('var x;', text.splitlines())
