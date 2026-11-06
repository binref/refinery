from __future__ import annotations

import inspect
import unittest

from test import opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.deobfuscation.paramcopy import JsParameterCopyCoalescing

A_PARAMETER_COPIED_AT_ENTRY = [
    'function f(a_1, n_1) { var a, n, i; a = a_1, n = n_1; for (i = 0; i < n; i++) {'
    ' a.push(a.shift()); } return a; } console.log(f([1, 2, 3], 1));',
    'function f(...r_1) { var r; r = r_1; r.length = 1; return r[0] + r.length; }'
    ' console.log(f(4, 5, 6));',
    'function f(a_1) { "use strict"; var a; a = a_1; arguments[0] = 9; return a + arguments[0]; }'
    ' console.log(f(1));',
    'function f(a_1) { var a; a = a_1; function g() { return a + 1; } return g(); }'
    ' console.log(f(1));',
    'function f({k: a_1}, ...[b_1]) { var a, b; a = a_1, b = b_1; return a + b; }'
    ' console.log(f({k: 1}, 2));',
]

A_PARAMETER_COPY_THE_LOCAL_CANNOT_REPLACE = {
    'var a = "outer"; function f(a_1, h = () => a) { var a; a = a_1; return h() + ":" + a; }'
    ' console.log(f(Math.random() < 2 ? "arg" : ""));\n': 'outer:arg\n',
    'function f({x} = {}, x_1) { var x; x = x_1; return x; }'
    ' console.log(f(undefined, Math.random() < 2 ? 3 : 0));\n': '3\n',
    'function f(a_1) { var a; function a_1() { return 9; } a = a_1; return typeof a; }'
    ' console.log(f(Math.random() < 2 ? 1 : 0));\n': 'function\n',
    'function f(a_1) { var a; a = a_1; for (var a in {x: 1}) {} return a; }'
    ' console.log(f(Math.random() < 2 ? 1 : 0));\n': 'x\n',
    'function f(a_1) { var a, b; b = a, a = a_1; return [a, b]; }'
    ' console.log(JSON.stringify(f(Math.random() < 2 ? 1 : 0)));\n': '[1,null]\n',
    'function f({a_1}) { var a; a = a_1; return a; }'
    ' console.log(f({ a_1: Math.random() < 2 ? 5 : 0, a: 6 }));\n': '5\n',
    'function f({a_1 = 1}) { var a; a = a_1; return a; }'
    ' console.log(f({ a_1: Math.random() < 2 ? 5 : 0, a: 6 }));\n': '5\n',
}

A_COPY_THE_PARAMETER_CAN_STILL_TAKE_THE_PLACE_OF = {
    'function f(a_1) { var a; a = a_1; return a + a_1; }': inspect.cleandoc(
        """
        function f(a) {
          return a + a;
        }
        """
    ),
    'function f(a_1) { var a; a = a_1; a = 2; return a; }': inspect.cleandoc(
        """
        function f(a) {
          a = 2;
          return a;
        }
        """
    ),
    'function f(a_1) { var a; g(); a = a_1; return a; }': inspect.cleandoc(
        """
        function f(a) {
          g();
          return a;
        }
        """
    ),
    'function f(a_1) { let a; a = a_1; return a; }': inspect.cleandoc(
        """
        function f(a) {
          return a;
        }
        """
    ),
}


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

    def test_a_copy_a_sloppy_body_reading_its_arguments_aliases_is_not_folded(self):
        source = 'function f(a_1) { var a; a = a_1; arguments[0] = 9; return a; }'
        self.assertEqual(self._run_transformers(source), self._coalesce(source))

    def test_a_copy_beside_a_further_read_or_write_a_statement_or_a_let_is_left_or_folded(self):
        for source, folded in A_COPY_THE_PARAMETER_CAN_STILL_TAKE_THE_PLACE_OF.items():
            with self.subTest(source):
                self.assertIn(self._coalesce(source), (self._run_transformers(source), folded))

    @opportunity
    def test_a_copy_beside_a_further_read_or_write_a_statement_or_a_let_is_folded(self):
        rows = A_COPY_THE_PARAMETER_CAN_STILL_TAKE_THE_PLACE_OF
        self.assertEqual({source: self._coalesce(source) for source in rows}, rows)

    def test_a_copy_the_renamed_parameter_would_change_the_meaning_of_is_left(self):
        for source in (
            'var a = "o"; function f(a_1, h = () => a) { var a; a = a_1; return h() + a; }',
            'function f({x} = {}, x_1) { var x; x = x_1; return x; }',
            'function f(a_1, a = 5) { var a; a = a_1; return a; }',
            'function f(a_1) { var a; function a_1() { return 9; } a = a_1; return typeof a; }',
            'function f(a_1) { var a; a = a_1; for (var a in {x: 1}) {} return a; }',
            'function f(a_1) { var a; a = a_1; lbl: var a; return a; }',
            'function f(a_1) { var a, b; b = a, a = a_1; return [a, b]; }',
            'function f({a_1}) { var a; a = a_1; return a; }',
            'function f({a_1 = 1}) { var a; a = a_1; return a; }',
        ):
            with self.subTest(source):
                self.assertEqual(self._run_transformers(source), self._coalesce(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_copy_the_local_cannot_replace_still_prints_what_it_printed(self):
        rows = A_PARAMETER_COPY_THE_LOCAL_CANNOT_REPLACE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_function_prints_what_it_printed(self):
        for source in A_PARAMETER_COPIED_AT_ENTRY:
            with self.subTest(source):
                coalesced = self._coalesce(source)
                self.assertNotEqual(self._run_transformers(source), coalesced)
                self.assertEqual(behavior(source), behavior(coalesced))
