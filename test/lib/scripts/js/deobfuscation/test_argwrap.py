from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.argwrap import JsAssignmentsAsFunctionArgs


class TestStackUnwrapper(TestJsDeobfuscator):

    @staticmethod
    def _wrapper(name: str = 'wr') -> str:
        return F'function {name}() {{ {name} = function() {{}}; }}'

    def test_statement_expansion(self):
        source = self._wrapper() + 'wr(a = 1, b = 2); g(a, b);'
        result = self._deobfuscate(source)
        goal = inspect.cleandoc(
            """
            a = 1;
            b = 2;
            g(a, b);
            """
        )
        self.assertEqual(result, goal)

    def test_single_arg(self):
        source = self._wrapper() + 'wr(x = 42); g(x);'
        self.assertEqual(self._unwrap(source), inspect.cleandoc(
            """
            x = 42;
            g(x);
            """
        ))

    def test_no_args(self):
        source = self._wrapper() + 'wr(); g();'
        self.assertEqual(self._unwrap(source), 'g();')

    def test_wrapper_removed(self):
        source = self._wrapper() + 'wr(a = 1);'
        self.assertEqual(self._unwrap(source), 'a = 1;')

    def test_non_wrapper_not_affected(self):
        source = 'function noop() {} noop(a, b);'
        self.assertEqual(self._unwrap(source), inspect.cleandoc(
            """
            function noop() {}
            noop(a, b);
            """
        ))

    def test_multiple_wrappers(self):
        source = self._wrapper('wr1') + self._wrapper('wr2') + 'wr1(a = 1); wr2(b = 2); g(a, b);'
        self.assertEqual(self._unwrap(source), inspect.cleandoc(
            """
            a = 1;
            b = 2;
            g(a, b);
            """
        ))

    def test_nested_in_function_body(self):
        source = self._wrapper() + 'function outer() { wr(x = 1, y = 2); return x + y; } outer();'
        self.assertEqual(
            self._unwrap(source),
            inspect.cleandoc(
                """
                function outer() {
                  x = 1;
                  y = 2;
                  return x + y;
                }
                outer();
                """
            ),
        )


class TestRegressionBugs(TestJsDeobfuscator):

    def test_wrapper_removed_despite_shadowed_local(self):
        source = (
            'function wr() { wr = function() {}; }'
            ' wr(a(), b()); function other() { var wr = 1; return wr; }'
        )
        self.assertEqual(
            self._unwrap(source),
            inspect.cleandoc(
                """
                a();
                b();
                function other() {
                  var wr = 1;
                  return wr;
                }
                """
            ),
        )

    def test_argwrap_expression_position_returns_void0(self):
        source = inspect.cleandoc(
            """
            function wr() { wr = function() {}; }
            var y = wr(a = 1, b = 2);
            console.log(y);
            """
        )
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                a = 1;
                b = 2;
                var y = void 0;
                console.log(y);
                """
            ),
        )
        self.assertEqual(
            self._deobfuscate_iterative(source),
            'console.log(void 0);'
        )
