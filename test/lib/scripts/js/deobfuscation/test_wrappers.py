from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner


class TestCallWrapperInliner(TestJsDeobfuscator):

    def test_simple_wrapper_inlining(self):
        source = (
            "function target(a, b) { return a + b; }"
            "function wrapper(x, y, z, w) { return target(w - -10, y); }"
            "var result = wrapper(1, 2, 3, 4);"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function target(a, b) {
                  return a + b;
                }
                var result = target(4 - -10, 2);
                """
            ),
        )

    def test_pure_call_argument_does_not_block_inlining(self):
        source = (
            "function target(a) { return a + 1; }"
            "function wrapper(x) { return target(x); }"
            "var r = wrapper(String.fromCharCode(65));"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function target(a) {
                  return a + 1;
                }
                var r = target(String.fromCharCode(65));
                """
            ),
        )

    def test_wrapper_preserves_non_wrapper_functions(self):
        source = (
            "function real(x) { console.log(x); return x * 2; }"
            "real(5);"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function real(x) {
                  console.log(x);
                  return x * 2;
                }
                real(5);
                """
            ),
        )

    def test_chained_wrappers(self):
        source = (
            "function target(a) { return a; }"
            "function inner(x, y) { return target(y - -5); }"
            "function outer(a, b, c) { return inner(a, c - -10); }"
            "var r = outer(1, 2, 3);"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function target(a) {
                  return a;
                }
                function inner(x, y) {
                  return target(y - -5);
                }
                var r = inner(1, 3 - -10);
                """
            ),
        )

    def test_wrapper_assigning_parameter_not_inlined(self):
        """
        Substituting the call argument for a written parameter would place it at a write target
        (`g(7 = 5)`), so a wrapper that assigns its own parameter is not a pure function of its
        arguments and must not be inlined.
        """
        source = inspect.cleandoc(
            """
            function w(p) {
              return g(p = 5);
            }
            w(7);
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsCallWrapperInliner))

    def test_wrapper_updating_parameter_not_inlined(self):
        source = inspect.cleandoc(
            """
            function w(p) {
              return g(p++);
            }
            w(7);
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsCallWrapperInliner))
