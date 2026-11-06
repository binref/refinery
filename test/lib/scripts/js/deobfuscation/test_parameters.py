from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import printed

from refinery.lib.scripts import Expression
from refinery.lib.scripts.js.deobfuscation.parameters import JsRestPatternParameters, parameter_list
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsFunctionDeclaration,
    JsFunctionNode,
    JsVariableDeclaration,
)
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.parser import JsParser

AN_EMPTY_REST_PATTERN = 'function f(...[]) { return 1; } console.log(f());'
AN_EMPTY_REST_PATTERN_DROPPED = inspect.cleandoc(
    """
    function f() {
      return 1;
    }
    console.log(f());
    """
)

#: A name inside a rest pattern counts nothing toward the function's `length` and never aliases
#: `arguments`. As a plain parameter it counts, and in sloppy code with a simple parameter list it
#: aliases `arguments`.
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
    '"use strict"; function f(...[a, b]) { a = 9; return arguments[0] + b; } console.log(f(1, 2));': (
        inspect.cleandoc(
            """
            "use strict";
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

A_REST_PATTERN_LEFT_AS_IT_IS: dict[str, str] = {
    'function f(...[a, b]) { return a + b; } console.log(f.length, f(1, 2));': '0 3\n',
    'function f(...[a, b]) { return a + b; } console.log([1].map(f).join());': '1\n',
    'function f(...[a, b]) { a = 9; return arguments[0] + b; } console.log(f(1, 2));': '3\n',
    'function f(...[a, b]) { return a + b; } class B extends f { static { console.log(super.length); } }'
    ' console.log(f(1, 2));': '0\n3\n',
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

    def test_an_empty_rest_pattern_is_left_as_it_is_or_dropped(self):
        self.assertIn(
            self._write(AN_EMPTY_REST_PATTERN),
            (printed(AN_EMPTY_REST_PATTERN), AN_EMPTY_REST_PATTERN_DROPPED),
        )

    @opportunity
    def test_an_empty_rest_pattern_is_dropped(self):
        self.assertEqual(self._write(AN_EMPTY_REST_PATTERN), AN_EMPTY_REST_PATTERN_DROPPED)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_pass(self):
        rows = {
            **{source: prints for source, (_, prints) in A_REST_PATTERN_WRITTEN_AS_PARAMETERS.items()},
            **A_REST_PATTERN_LEFT_AS_IT_IS,
            AN_EMPTY_REST_PATTERN: '1\n',
        }
        self.assertEqual(
            {source: (behavior(source), behavior(self._write(source))) for source in rows},
            {source: ((prints, None), (prints, None)) for source, prints in rows.items()},
        )

    def test_a_constructor_keeps_its_rest_pattern_where_a_host_reaches_its_class(self):
        source = 'var C = class { constructor(...[a, b]) { this.s = a + b; } }; console.log(new C(1, 2).s);'
        options = DeobfuscationOptions(execution=ExecutionModel.script, entrypoints=('C',))
        self.assertEqual(
            self._run_transformer(source, JsRestPatternParameters, options),
            printed(source),
        )


class TestAParameterListHasTheLengthItIsAsked(TestBase):

    @staticmethod
    def _unpacking(source: str) -> tuple[JsFunctionNode, list[Expression | None]]:
        function = JsParser(source).parse().body[0]
        assert isinstance(function, JsFunctionDeclaration) and function.body is not None
        unpacking = function.body.body[0]
        assert isinstance(unpacking, JsVariableDeclaration)
        pattern = unpacking.declarations[0].id
        assert isinstance(pattern, JsArrayPattern)
        return function, pattern.elements

    def test_no_list_has_a_negative_length(self):
        function, elements = self._unpacking('function f() { var [a, b] = p; return a + b; }')
        self.assertIsNone(parameter_list(elements, function, -1))

    def test_a_length_counting_every_name_is_refused_where_arguments_would_alias_the_names(self):
        function, elements = self._unpacking('function f() { var [a, b] = p; arguments[0] = 9; return a; }')
        self.assertEqual(
            [parameter_list(elements, function, length) is None for length in (0, 1, 2)],
            [False, False, True],
        )
