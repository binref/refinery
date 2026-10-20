from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import printed

from refinery.lib.scripts.js.deobfuscation.parameters import JsRestPatternParameters

#: Functions whose parameter list ends in a rest pattern and whose `length` nothing reads, mapped to
#: the list the pass writes for each and to what Node prints for the program either way: the pattern
#: alone, after a parameter, holding a default, a hole and a rest element, in strict code reading its
#: own `arguments`, and in an arrow function.
A_REST_PATTERN_WRITTEN_AS_PARAMETERS: dict[str, tuple[str, str]] = {
    'function f(...[a, b]) { return a + b; } console.log(f(1, 2));': (
        inspect.cleandoc(
            """
            function f(a, b) {
              return a + b;
            }
            console.log(f(1, 2));
            """
        ),
        '3\n',
    ),
    'function f(a, ...[b, c]) { return a + b + c; } console.log(f(1, 2, 3));': (
        inspect.cleandoc(
            """
            function f(a, b, c) {
              return a + b + c;
            }
            console.log(f(1, 2, 3));
            """
        ),
        '6\n',
    ),
    'function f(...[a, b = 2]) { return a + b; } console.log(f(1));': (
        inspect.cleandoc(
            """
            function f(a, b = 2) {
              return a + b;
            }
            console.log(f(1));
            """
        ),
        '3\n',
    ),
    'function f(...[a, , c]) { return a + c; } console.log(f(1, 2, 3));': (
        inspect.cleandoc(
            """
            function f(a, ...[, c]) {
              return a + c;
            }
            console.log(f(1, 2, 3));
            """
        ),
        '4\n',
    ),
    'function f(...[a, ...r]) { return a + r.length; } console.log(f(1, 2, 3));': (
        inspect.cleandoc(
            """
            function f(a, ...r) {
              return a + r.length;
            }
            console.log(f(1, 2, 3));
            """
        ),
        '3\n',
    ),
    "'use strict'; function f(...[a, b]) { a = 9; return arguments[0] + b; } console.log(f(1, 2));": (
        inspect.cleandoc(
            """
            'use strict';
            function f(a, b) {
              a = 9;
              return arguments[0] + b;
            }
            console.log(f(1, 2));
            """
        ),
        '3\n',
    ),
    'var f = (...[a, b]) => a + b; console.log(f(1, 2));': (
        inspect.cleandoc(
            """
            var f = (a, b) => a + b;
            console.log(f(1, 2));
            """
        ),
        '3\n',
    ),
}

#: Functions whose parameter list ends in a rest pattern that the pass leaves, mapped to what Node
#: prints for each: the `length` is read, the function is handed to a caller the text does not
#: show, a sloppy body reads its own `arguments`, which plain names would alias, and the pattern is
#: empty.
A_REST_PATTERN_LEFT_AS_IT_IS: dict[str, str] = {
    'function f(...[a, b]) { return a + b; } console.log(f.length, f(1, 2));': '0 3\n',
    'function f(...[a, b]) { return a + b; } console.log([1].map(f).join());': '1\n',
    'function f(...[a, b]) { a = 9; return arguments[0] + b; } console.log(f(1, 2));': '3\n',
    'function f(...[]) { return 1; } console.log(f());': '1\n',
}


class TestARestPatternBecomesParameters(TestJsDeobfuscator):

    def _write(self, source: str) -> str:
        return self._run_transformer(source, JsRestPatternParameters)

    def test_each_rest_pattern_becomes_the_list_the_row_records(self):
        rows = A_REST_PATTERN_WRITTEN_AS_PARAMETERS
        self.assertEqual(
            {source: self._write(source) for source in rows},
            {source: written for source, (written, _) in rows.items()},
        )

    def test_each_rest_pattern_the_pass_leaves_is_printed_as_it_is(self):
        rows = A_REST_PATTERN_LEFT_AS_IT_IS
        self.assertEqual(
            {source: self._write(source) for source in rows},
            {source: printed(source) for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_pass(self):
        rows = {
            **{source: prints for source, (_, prints) in A_REST_PATTERN_WRITTEN_AS_PARAMETERS.items()},
            **A_REST_PATTERN_LEFT_AS_IT_IS,
        }
        self.assertEqual(
            {source: (behavior(source), behavior(self._write(source))) for source in rows},
            {source: ((prints, None), (prints, None)) for source, prints in rows.items()},
        )
