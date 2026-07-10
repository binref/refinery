from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.restunpack import JsRestArrayUnpacking


class TestVariableDemasking(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_simple_two_params(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0, p1) {
                  return p0 + p1;
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 2; return s[0] + s[1]; }'),
        )

    def test_simple_zero_params_with_locals(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function() {
                  var v0;
                  v0 = 10;
                  return v0;
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 0; s.a = 10; return s.a; }'),
        )

    def test_simple_negative_keys(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  var v0;
                  v0 = p0 + 1;
                  return v0;
                };
                """
            ),
            self._demask(
                'var f = function(...s) { s.length = 1; s[-42] = s[0] + 1; return s[-42]; }'
            ),
        )

    def test_frame_qualified(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.fn = function(p0) {
                  return p0 * 2;
                };
                """
            ),
            self._demask(
                'var NS = {}; NS.fn = function(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }'
            ),
        )

    def test_skips_unresolvable_access(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...s) {
                  s.length = 1;
                  return s[x];
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; return s[x]; }'),
        )

    def test_skips_rest_param_aliased(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...s) {
                  s.length = 1;
                  foo(s);
                  return s[0];
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; foo(s); return s[0]; }'),
        )

    def test_nested_function_unpacked_in_own_scope(self):
        source = inspect.cleandoc(
            """
            var outer = function(...s) {
              s.length = 1;
              s.x = function(...t) { t.length = 0; t.a = 5; return t.a; };
              return s[0] + s.x();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var outer = function(p0) {
                  var v0;
                  v0 = function() {
                    var v0;
                    v0 = 5;
                    return v0;
                  };
                  return p0 + v0();
                };
                """
            ),
            self._demask(source),
        )

    def test_frame_qualified_missing_accesses_skipped(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...r) {
                  A.B.C.length = 2;
                  return A.X.C[0];
                };
                """
            ),
            self._demask('var f = function(...r) { A.B.C.length = 2; return A.X.C[0]; }'),
        )

    def test_skips_rest_param_captured_by_closure(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 1;
              var g = function() {
                return s[0] + 1;
              };
              return s[0] + g();
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_skips_rest_param_named_by_eval(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 1;
              eval("s[2] = 9");
              return s[0];
            };
            """
        )
        self.assertEqual(source, self._demask(source))
