from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.argwrap import JsAssignmentsAsFunctionArgs
from refinery.lib.scripts.js.options import DeobfuscationOptions


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

    def test_argwrap_expression_position_lowered_to_sequence(self):
        source = inspect.cleandoc(
            """
            function wr() { wr = function() {}; }
            var y = wr(a = 1, b = 2);
            console.log(y);
            """
        )
        goal = inspect.cleandoc(
            """
            var y = (a = 1, b = 2, void 0);
            console.log(y);
            """
        )
        self.assertEqual(self._run_transformer(source, JsAssignmentsAsFunctionArgs), goal)
        self.assertEqual(self._deobfuscate_iterative(source), goal)

    def test_single_argument_expression_position_lowered_to_sequence(self):
        source = 'function wr() { wr = function() {}; } var y = wr(x); g(y);'
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                var y = (x, void 0);
                g(y);
                """
            ),
        )

    def test_no_argument_expression_position_is_void0(self):
        source = 'function wr() { wr = function() {}; } var y = wr(); g(y);'
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                var y = void 0;
                g(y);
                """
            ),
        )

    def test_conditional_arm_preserves_short_circuit(self):
        source = 'function wr() { wr = function() {}; } var y = c ? wr(a()) : 0; g(y);'
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                var y = c ? (a(), void 0) : 0;
                g(y);
                """
            ),
        )

    def test_parenthesized_callee_is_expanded_like_a_bare_one(self):
        source = inspect.cleandoc(
            """
            function wr() { wr = function() {}; }
            (wr)(x = 1);
            g(x);
            """
        )
        goal = inspect.cleandoc(
            """
            x = 1;
            g(x);
            """
        )
        self.assertEqual(self._run_transformer(source, JsAssignmentsAsFunctionArgs), goal)
        self.assertEqual(self._deobfuscate_iterative(source), goal)

    def test_spread_argument_call_not_expanded(self):
        source = 'function wr() { wr = function() {}; } var y = wr(...arr); g(y);'
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                function wr() {
                  wr = function() {};
                }
                var y = wr(...arr);
                g(y);
                """
            ),
        )


class TestOnlyAWrapperTheNameActuallyHoldsIsExpanded(TestJsDeobfuscator):

    @staticmethod
    def _wrapper_and_call() -> str:
        return inspect.cleandoc(
            """
            function wr() { wr = function () {}; }
            wr(a = 1);
            """
        )

    def test_a_wrapper_a_parameter_default_cannot_see_is_left_standing(self):
        """
        A parameter default runs in a scope of its own, outside the body, so its `W` is not the
        function the body declares and the call throws.
        """
        source = inspect.cleandoc(
            """
            function f(x = W(console.log(1))) {
              function W() { W = function () {}; }
              return typeof x;
            }
            """
        )
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                function f(x = W(console.log(1))) {
                  function W() {
                    W = function() {};
                  }
                  return typeof x;
                }
                """
            ),
        )

    def test_a_wrapper_nothing_calls_is_left_standing_beside_one_that_expands(self):
        source = inspect.cleandoc(
            """
            function never() { never = function () {}; }
            function used() { used = function () {}; }
            used(a = 1);
            """
        )
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                function never() {
                  never = function() {};
                }
                a = 1;
                """
            ),
        )

    def test_a_wrapper_the_analyst_named_as_a_host_entrypoint_is_left_standing(self):
        source = self._wrapper_and_call()
        self.assertEqual(
            self._run_transformer(
                source,
                JsAssignmentsAsFunctionArgs,
                DeobfuscationOptions(entrypoints=('wr',)),
            ),
            inspect.cleandoc(
                """
                function wr() {
                  wr = function() {};
                }
                wr(a = 1);
                """
            ),
        )

    def test_a_wrapper_no_export_names_is_expanded_beside_an_export_of_that_name(self):
        source = inspect.cleandoc(
            """
            var wr = 1;
            export { wr };
            function outer() {
              function wr() { wr = function () {}; }
              wr(a = 1);
            }
            """
        )
        self.assertEqual(
            self._run_transformer(source, JsAssignmentsAsFunctionArgs),
            inspect.cleandoc(
                """
                var wr = 1;
                export { wr };
                function outer() {
                  a = 1;
                }
                """
            ),
        )
