"""
A lookup by key: a function whose body opens with a switch on its parameter whose every case returns
an expression, which `refinery.lib.scripts.js.deobfuscation.evaluator.JsFunctionEvaluator` folds
into each call. The statements after the switch run where no case matches, and the call is folded
only where every name they read has an answer. Each program is written by hand, and each row says
what Node prints for it.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

#: Lookups by key followed by statements of their own, mapped to what Node prints for each run as a
#: CommonJS file: a return of `undefined`, of a parameter named `undefined`, of an `undefined` a
#: `with` body supplies, of a name the program changes, a store, a case returning a local the
#: statements after the switch assign, and a discriminant and a case test reading a name the program
#: changes.
LOOKUPS_BY_KEY: dict[str, Program] = {
    'a return of undefined after the switch': Program(
        a_program("""
            function lookup(key) {
              switch (key) {
                case 'm':
                  return Math;
                case 'j':
                  return JSON;
              }
              return undefined;
            }
            console.log(lookup('m').abs(-2), lookup('j').stringify([1]), lookup('x'));
            """),
        prints('2 [1] undefined'),
    ),
    'a return of a parameter named undefined after the switch': Program(
        a_program("""
            function make(undefined) {
              function lookup(key) {
                switch (key) {
                  case 'm':
                    return Math;
                }
                return undefined;
              }
              return lookup('x');
            }
            console.log(make(7));
            """),
        prints('7'),
    ),
    'a return of an undefined a with body supplies after the switch': Program(
        a_program("""
            var scope = { undefined: 5 };
            var result;
            with (scope) {
              result = (function () {
                function lookup(key) {
                  switch (key) {
                    case 'm':
                      return Math;
                  }
                  return undefined;
                }
                return lookup('x');
              })();
            }
            console.log(result);
            """),
        prints('5'),
        Reading.COMMONJS,
    ),
    'a case returning a local the statements after the switch assign': Program(
        a_program("""
            function lookup(key) {
              switch (key) {
                case 'a':
                  return later;
              }
              var later = 5;
              return later;
            }
            console.log(lookup('a'), lookup('b'));
            """),
        prints('undefined 5'),
    ),
    'a return of a name the program changes after the switch': Program(
        a_program("""
            var fallback = 1;
            function lookup(key) {
              switch (key) {
                case 'm':
                  return Math;
              }
              return fallback;
            }
            fallback = 2;
            console.log(lookup('x'));
            """),
        prints('2'),
    ),
    'a store after the switch': Program(
        a_program("""
            var misses = 0;
            function lookup(key) {
              switch (key) {
                case 'm':
                  return Math;
              }
              misses = misses + 1;
              return undefined;
            }
            lookup('x');
            lookup('y');
            console.log(misses);
            """),
        prints('2'),
    ),
    'a discriminant reading a name the program changes': Program(
        a_program("""
            var suffix = '';
            function lookup(key) {
              switch (key + suffix) {
                case 'm':
                  return Math;
                case 'mx':
                  return JSON;
              }
              return undefined;
            }
            suffix = 'x';
            console.log(lookup('m') === JSON);
            """),
        prints('true'),
    ),
    'a case test reading a name the program changes': Program(
        a_program("""
            var wanted = 'a';
            function lookup(key) {
              switch (key) {
                case wanted:
                  return Math;
              }
              return undefined;
            }
            wanted = 'b';
            console.log(lookup('a'), lookup('b') === Math);
            """),
        prints('undefined true'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALookupByKeyBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in LOOKUPS_BY_KEY.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in LOOKUPS_BY_KEY.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestALookupByKeyIsFoldedWhereTheStatementsAfterItResolve(TestJsDeobfuscator):

    def test_each_call_of_a_lookup_ending_in_a_return_of_undefined_is_folded(self):
        source = inspect.cleandoc("""
            function lookup(key) {
              switch (key) {
                case 'm':
                  return Math;
                case 'p':
                  return globalThis.process;
              }
              return undefined;
            }
            SINK(lookup('m'), lookup('p'), lookup('x'));
            """)
        self.assertEqual('SINK(Math, globalThis.process, void 0);', self._evaluate(source))

    def test_a_lookup_ending_in_a_return_of_a_parameter_named_undefined_is_kept(self):
        source = inspect.cleandoc("""
            function make(undefined) {
              function lookup(key) {
                switch (key) {
                  case 'm':
                    return Math;
                }
                return undefined;
              }
              return lookup('x');
            }
            SINK(make(7));
            """)
        self.assertEqual(source, self._evaluate(source))

    def test_a_lookup_ending_in_a_return_of_a_name_the_program_changes_is_kept(self):
        source = inspect.cleandoc("""
            var fallback = 1;
            function lookup(key) {
              switch (key) {
                case 'm':
                  return Math;
              }
              return fallback;
            }
            fallback = 2;
            SINK(lookup('x'));
            """)
        self.assertEqual(source, self._evaluate(source))

    def test_a_lookup_whose_case_test_reads_a_constant_is_folded(self):
        source = inspect.cleandoc("""
            const wanted = 'a';
            function lookup(key) {
              switch (key) {
                case wanted:
                  return globalThis.process;
              }
            }
            SINK(lookup('a'), lookup('b'));
            """)
        expected = inspect.cleandoc("""
            const wanted = 'a';
            SINK(globalThis.process, void 0);
            """)
        self.assertEqual(expected, self._evaluate(source))

    def test_a_lookup_whose_case_test_reads_a_name_the_program_changes_is_kept(self):
        source = inspect.cleandoc("""
            var wanted = 'a';
            function lookup(key) {
              switch (key) {
                case wanted:
                  return Math;
              }
            }
            wanted = 'b';
            SINK(lookup('a'));
            """)
        self.assertEqual(source, self._evaluate(source))
