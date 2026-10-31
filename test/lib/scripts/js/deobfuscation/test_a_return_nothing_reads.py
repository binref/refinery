"""
The `return` ending the body of a function whose every call throws the value away, which
`refinery.lib.scripts.js.deobfuscation.unused.JsUnusedCodeRemoval` takes the value from: a value
that costs nothing to compute goes with its `return`, a store becomes a statement of its own, which
the removal of unused variables reads, and any other value stays returned. Each program is written
by hand, and each row says what Node prints for it.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    completion_values,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import Program, a_program, prints

from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval

#: Functions ending in a `return` whose calls discard the value, mapped to what Node prints for each
#: run as a CommonJS file: a store nothing reads, a store another function reads, an `async`
#: function settling its promise with an object that has a `then`, a call returned for its effect, a
#: function expression and an object literal read where the statement begins, a read that throws
#: because nothing declares the name or its `let` has not run, a read that runs a getter, a
#: recursive function, a constructor, a generator never resumed, and a function one call of which
#: reads the value.
RETURNS_NOTHING_READS: dict[str, Program] = {
    'a store nothing reads': Program(
        a_program("""
            (function () {
              var lookup;
              var table = ['a', 'b'];
              return lookup = function (index) {
                return table[index];
              };
            })();
            console.log('done');
            """),
        prints('done'),
    ),
    'a store another function reads': Program(
        a_program("""
            var out;
            (function () {
              return out = function () {
                return 'kept';
              };
            })();
            console.log(out());
            """),
        prints('kept'),
    ),
    'an async function settling with an object that has a then': Program(
        a_program("""
            (async function () {
              var settled;
              return settled = {
                then: function (resolve) {
                  console.log('then');
                  resolve(1);
                }
              };
            })();
            """),
        prints('then'),
    ),
    'an async function settling with an array whose prototype has a then': Program(
        a_program("""
            Array.prototype.then = function (resolve) {
              console.log('then');
              resolve(1);
            };
            (async function () {
              return [1];
            })();
            """),
        prints('then'),
    ),
    'a call returned for its effect': Program(
        a_program("""
            function outer() {
              (function () {
                return console.log('effect');
              })();
            }
            outer();
            """),
        prints('effect'),
    ),
    'a function expression returned and called': Program(
        a_program("""
            function outer() {
              (function () {
                return function () {
                  console.log('called');
                }.call(0);
              })();
            }
            outer();
            """),
        prints('called'),
    ),
    'an object literal returned and read': Program(
        a_program("""
            function outer() {
              (function () {
                return { a: console.log('object') }.a;
              })();
            }
            outer();
            """),
        prints('object'),
    ),
    'a read of a name nothing declares': Program(
        a_program("""
            function outer() {
              (function () {
                return missing;
              })();
            }
            try {
              outer();
            } catch (error) {
              console.log(error.name);
            }
            """),
        prints('ReferenceError'),
    ),
    'a read of a let before it runs': Program(
        a_program("""
            function outer() {
              (function () {
                return later;
              })();
              let later = 1;
            }
            try {
              outer();
            } catch (error) {
              console.log(error.name);
            }
            """),
        prints('ReferenceError'),
    ),
    'a read that runs a getter': Program(
        a_program("""
            var holder = {
              get value() {
                console.log('getter');
                return 1;
              }
            };
            function outer() {
              (function () {
                return holder.value;
              })();
            }
            outer();
            """),
        prints('getter'),
    ),
    'a recursive function': Program(
        a_program("""
            function outer() {
              function count(n) {
                if (n > 0) {
                  count(n - 1);
                }
                return console.log(n);
              }
              count(2);
            }
            outer();
            """),
        prints('0', '1', '2'),
    ),
    'a constructor': Program(
        a_program("""
            function outer() {
              function Point() {
                this.x = 1;
                return console.log('constructed');
              }
              new Point();
            }
            outer();
            """),
        prints('constructed'),
    ),
    'a generator never resumed': Program(
        a_program("""
            (function* () {
              return console.log('never');
            })();
            console.log('end');
            """),
        prints('end'),
    ),
    'a function one call of which reads the value': Program(
        a_program("""
            function outer() {
              function value() {
                return console.log('read'), 5;
              }
              value();
              console.log(value());
            }
            outer();
            """),
        prints('read', 'read', '5'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReturnNothingReadsBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in RETURNS_NOTHING_READS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in RETURNS_NOTHING_READS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAReturnNothingReadsGivesUpItsValue(TestJsDeobfuscator):

    def _unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    def test_a_returned_store_nothing_reads_goes_with_the_table_its_value_reads(self):
        source = inspect.cleandoc("""
            (function () {
              var lookup;
              var table = ['a', 'b'];
              return lookup = function (index) {
                return table[index];
              };
            })();
            SINK('done');
            """)
        expected = inspect.cleandoc("""
            (function() {})();
            SINK('done');
            """)
        self.assertEqual(expected, self._unused(source))

    def test_a_returned_call_stays_a_return(self):
        source = inspect.cleandoc("""
            function outer() {
              (function () {
                return SINK(1);
              })();
            }
            outer();
            """)
        expected = inspect.cleandoc("""
            function outer() {
              (function() {
                return SINK(1);
              })();
            }
            outer();
            """)
        self.assertEqual(expected, self._unused(source))

    def test_a_returned_read_of_a_local_goes(self):
        source = inspect.cleandoc("""
            function outer() {
              (function () {
                var kept = SINK(1);
                return kept;
              })();
            }
            outer();
            """)
        expected = inspect.cleandoc("""
            function outer() {
              (function() {
                var kept = SINK(1);
              })();
            }
            outer();
            """)
        self.assertEqual(expected, self._unused(source))

    def test_a_returned_undefined_goes_like_a_literal(self):
        source = inspect.cleandoc("""
            function outer() {
              function step(n) {
                SINK(n);
                return undefined;
              }
              step(1);
            }
            outer();
            """)
        expected = inspect.cleandoc("""
            function outer() {
              function step(n) {
                SINK(n);
              }
              step(1);
            }
            outer();
            """)
        self.assertEqual(expected, self._unused(source))

    def test_an_async_function_keeps_a_returned_store_of_an_object(self):
        source = inspect.cleandoc("""
            (async function() {
              var settled;
              return settled = { then: SINK };
            })();
            """)
        self.assertEqual(source, self._unused(source))

    def test_a_function_one_call_of_which_reads_the_value_keeps_its_return(self):
        source = inspect.cleandoc("""
            function outer() {
              function value() {
                return SINK(1), 5;
              }
              value();
              SINK(value());
            }
            outer();
            """)
        self.assertEqual(source, self._unused(source))

    def test_a_function_a_host_may_call_keeps_its_return(self):
        source = inspect.cleandoc("""
            function value() {
              var kept;
              return kept = SINK(1);
            }
            value();
            """)
        self.assertEqual(source, self._unused(source))


#: Scripts ending in a call whose function returns a value every call of it in the text discards,
#: which the script's own completion value then is.
SCRIPTS_COMPLETING_WITH_A_DISCARDED_RETURN = (
    'var S;\n(function () { var t = [1, 2]; return S = function (i) { return t[i]; }; })();\n',
    '(function () { return Math.random() < 2 ? 1 : 2; })();\n',
    '(function () { var r = Math.random(); globalThis.k = r; return 5; })();\n',
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReturnTheScriptCompletesWithStaysWhereTheCompletionIsKept(TestBase):

    def test_each_script_still_completes_with_the_value_of_its_last_call(self):
        deobfuscated = [
            deobfuscate_source(program, preserve_script_return=True)
            for program in SCRIPTS_COMPLETING_WITH_A_DISCARDED_RETURN
        ]
        for evaluation in JsEvaluation:
            before = completion_values(SCRIPTS_COMPLETING_WITH_A_DISCARDED_RETURN, evaluation)
            after = completion_values(deobfuscated, evaluation)
            for program, source_value, result_value in zip(SCRIPTS_COMPLETING_WITH_A_DISCARDED_RETURN, before, after):
                with self.subTest(evaluation=evaluation.value, program=program):
                    self.assertEqual(result_value, source_value)
