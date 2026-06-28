from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.parser import JsParser


class TestCallWrapperInliner(TestJsDeobfuscator):

    def test_self_forwarding_wrapper_not_inlined(self):
        """
        `W` forwards to itself, so inlining its call substitutes a body that calls `W` again,
        regenerating an equivalent call on every pass. Inlining it must be refused, or the fold loop
        never reaches a fixpoint. The single-pass output is unchanged either way, so the change flag is
        what distinguishes the refusal from the non-terminating inline.
        """
        ast = JsParser('function W(a) { return W(a); } W(1);').parse()
        t = JsCallWrapperInliner()
        t.visit(ast)
        self.assertFalse(t.changed)

    def test_mutually_forwarding_wrappers_not_inlined(self):
        """
        `W` forwards to `V` and `V` back to `W`; inlining either regenerates a call into the cycle, so
        neither bottoms out. Both are left intact.
        """
        ast = JsParser('function W(a) { return V(a); } function V(a) { return W(a); } W(1);').parse()
        t = JsCallWrapperInliner()
        t.visit(ast)
        self.assertFalse(t.changed)

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

    def test_redeclared_wrapper_is_not_inlined(self):
        """
        The first `v` is a trivial constant wrapper, but `v` is redeclared by a second body that wins
        at runtime, so the call resolves to no single function. The inliner must leave the call intact
        rather than substitute the first body's `return 1`.
        """
        source = (
            "function v() { return 1; }"
            "function v() { SINK.push('x'); return 2; }"
            "SINK.push(v());"
        )
        self.assertEqual(
            self._run_transformer(source, JsCallWrapperInliner),
            inspect.cleandoc(
                """
                function v() {
                  return 1;
                }
                function v() {
                  SINK.push('x');
                  return 2;
                }
                SINK.push(v());
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

    def test_wrapper_deleting_parameter_not_inlined(self):
        source = inspect.cleandoc(
            """
            function w(p) {
              return g(delete p);
            }
            w(7);
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsCallWrapperInliner))
