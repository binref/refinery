from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.paramcopy import JsParameterCopyCoalescing

#: Functions whose body opens by copying parameters into locals, each called so that Node prints
#: what the locals held.
A_PARAMETER_COPIED_AT_ENTRY = [
    'function f(a_1, n_1) { var a, n, i; a = a_1, n = n_1; for (i = 0; i < n; i++) {'
    ' a.push(a.shift()); } return a; } console.log(f([1, 2, 3], 1));',
    'function f(...r_1) { var r; r = r_1; r.length = 1; return r[0] + r.length; }'
    ' console.log(f(4, 5, 6));',
    "function f(a_1) { 'use strict'; var a; a = a_1; arguments[0] = 9; return a + arguments[0]; }"
    ' console.log(f(1));',
    'function f(a_1) { var a; a = a_1; function g() { return a + 1; } return g(); }'
    ' console.log(f(1));',
]


class TestParameterCopyCoalescing(TestJsDeobfuscator):

    def _coalesce(self, source: str) -> str:
        return self._run_transformer(source, JsParameterCopyCoalescing)

    def test_parameters_copied_at_entry_take_the_names_of_the_locals(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a, n) {
                  var i;
                  for (i = 0; i < n; i++) {
                    a.push(a.shift());
                  }
                  return a;
                }
                """
            ),
            self._coalesce(
                'function f(a_1, n_1) { var a, n, i; a = a_1, n = n_1;'
                ' for (i = 0; i < n; i++) { a.push(a.shift()); } return a; }'
            ),
        )

    def test_a_rest_parameter_copied_at_entry_takes_the_name_of_the_local(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(...r) {
                  r.length = 1;
                  return r[0];
                }
                """
            ),
            self._coalesce('function f(...r_1) { var r; r = r_1; r.length = 1; return r[0]; }'),
        )

    def test_only_the_copies_a_parameter_can_take_the_place_of_are_folded(self):
        """
        A parameter read again, a local written again, a copy after a statement that runs, a local
        declared with `let`, and a sloppy body reading its `arguments`, which aliases a parameter
        list like this one: none of these copies can be folded.
        """
        for source in (
            'function f(a_1) { var a; a = a_1; return a + a_1; }',
            'function f(a_1) { var a; a = a_1; a = 2; return a; }',
            'function f(a_1) { var a; g(); a = a_1; return a; }',
            'function f(a_1) { let a; a = a_1; return a; }',
            'function f(a_1) { var a; a = a_1; arguments[0] = 9; return a; }',
        ):
            with self.subTest(source):
                self.assertEqual(self._run_transformers(source), self._coalesce(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_function_prints_what_it_printed(self):
        for source in A_PARAMETER_COPIED_AT_ENTRY:
            with self.subTest(source):
                coalesced = self._coalesce(source)
                self.assertNotEqual(self._run_transformers(source), coalesced)
                self.assertEqual(behavior(source), behavior(coalesced))
