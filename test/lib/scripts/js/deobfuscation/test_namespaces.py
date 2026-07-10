from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening


class TestNamespaceFlattening(TestJsDeobfuscator):

    def _flatten(self, source: str) -> str:
        return self._run_transformer(source, JsNamespaceFlattening)

    def test_basic_namespace_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x, y;
                x = 1;
                y = x + 2;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; NS.y = NS.x + 2;'),
        )

    def test_computed_string_access(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x, y;
                x = 1;
                y = x;
                """
            ),
            self._flatten('var NS = {}; NS["x"] = 1; NS["y"] = NS["x"];'),
        )

    def test_reject_bare_reference(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.x = 1;
                f(NS);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; f(NS);'),
        )

    def test_reject_computed_dynamic_key(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS[key] = 1;
                """
            ),
            self._flatten('var NS = {}; NS[key] = 1;'),
        )

    def test_conflict_skips_conflicting_property(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var y;
                var NS = {};
                NS.x = 1;
                y = 2;
                var x = 10;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; NS.y = 2; var x = 10;'),
        )

    def test_shadowing_nested_function_untouched(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a;
                a = 1;
                function f() {
                  var NS;
                  return NS.b;
                }
                """
            ),
            self._flatten('var NS = {}; NS.a = 1; function f() { var NS; return NS.b; }'),
        )

    def test_non_shadowing_nested_function_rewritten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                function f() {
                  return x;
                }
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; function f() { return NS.x; }'),
        )

    def test_block_scoped_shadow_does_not_block_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                {
                  let x = 9;
                  log(x);
                }
                log(x);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; { let x = 9; log(x); } log(NS.x);'),
        )

    def test_destructured_param_shadow_does_not_block_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                function g([x]) {
                  return x;
                }
                log(x + g([2]));
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; function g([x]) { return x; } log(NS.x + g([2]));'),
        )

    def test_catch_param_shadow_does_not_block_flatten(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x;
                x = 1;
                try {
                  h();
                } catch (x) {
                  log(x);
                }
                log(x);
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; try { h(); } catch (x) { log(x); } log(NS.x);'),
        )

    def test_function_hoisted_when_assignment_precedes_every_use(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function greet() {
                  return 42;
                }
                foo(greet);
                """
            ),
            self._flatten('var NS = {}; NS.greet = function () { return 42; }; foo(NS.greet);'),
        )

    def test_function_kept_in_place_when_a_use_can_run_before_assignment(self):
        """
        `early()` reads the property and runs before the assignment, so a hoisted `function greet(){}`
        would let that call see the function early; the assignment stays in place behind a bare `var`.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var greet;
                function early() {
                  return greet;
                }
                var probe = early();
                greet = function() {
                  return 42;
                };
                """
            ),
            self._flatten(
                'var NS = {}; function early() { return NS.greet; } var probe = early();'
                ' NS.greet = function () { return 42; };'),
        )

    def test_computed_read_before_assignment_keeps_function_in_place(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var greet;
                function early() {
                  return greet;
                }
                var probe = early();
                greet = function() {
                  return 42;
                };
                """
            ),
            self._flatten(
                'var NS = {}; function early() { return NS["greet"]; } var probe = early();'
                ' NS.greet = function () { return 42; };'),
        )

    def test_object_property_init_kept_in_place(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var config;
                config = {};
                config.x = 1;
                """
            ),
            self._flatten('var NS = {}; NS.config = {}; NS.config.x = 1;'),
        )

    def test_named_function_expression_kept_in_place(self):
        """
        Hoisting to `function f(){}` would drop the expression's own name `fact`, leaving the
        recursive call unbound; the in-place form preserves it.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var f;
                f = function fact(n) {
                  return n;
                };
                foo(f);
                """
            ),
            self._flatten('var NS = {}; NS.f = function fact(n) { return n; }; foo(NS.f);'),
        )

    def test_deleted_property_blocks_flattening(self):
        """
        `delete p` on a bare `var` binding is not a property removal, so a namespace with a deleted
        property is left intact.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.x = 1;
                delete NS.x;
                """
            ),
            self._flatten('var NS = {}; NS.x = 1; delete NS.x;'),
        )
