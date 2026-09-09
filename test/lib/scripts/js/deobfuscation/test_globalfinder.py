from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.globalfinder import JsGlobalFinderInlining


class TestGlobalFinderInlining(TestJsDeobfuscator):

    def _find(self, source: str) -> str:
        return self._run_transformer(source, JsGlobalFinderInlining)

    def test_finder_call_becomes_globalthis(self):
        self.assertEqual(self._find('function g() { return globalThis; } g();'), inspect.cleandoc(
            '''
            function g() {
              return globalThis;
            }
            globalThis;
            '''
        ))

    def test_short_circuit_chain_result_assignment_becomes_globalthis(self):
        source = 'function g() { return globalThis || global || window; } var x = g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              return globalThis || global || window;
            }
            var x = globalThis;
            '''
        ))

    def test_bare_host_alias_finder_is_not_substituted(self):
        """
        A finder that just returns `window` throws where the host lacks it (Node refuses `window`),
        so folding its call to `globalThis` would drop that `ReferenceError`; the call is kept.
        """
        source = inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_host_read_before_the_anchor_is_not_substituted(self):
        """
        The `globalThis` anchor is reached only after a bare `window.bar` read that runs first and
        throws where the host lacks `window`, so the finder is not throw-free and its call is kept.
        """
        source = inspect.cleandoc(
            '''
            function g() {
              window.bar;
              return globalThis;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_trapped_host_thunks_are_recognized(self):
        source = (
            'function g() {'
            ' var a = [function () { return globalThis; }, function () { return global; },'
            ' function () { return window; }];'
            ' for (var i = 0; i < a.length; i++) { try { return a[i](); } catch (e) {} }'
            ' } g();'
        )
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              var a = [function() {
                return globalThis;
              }, function() {
                return global;
              }, function() {
                return window;
              }];
              for (var i = 0; i < a.length; i++) {
                try {
                  return a[i]();
                } catch (e) {}
              }
            }
            globalThis;
            '''
        ))

    def test_higher_order_array_of_closures_is_recognized(self):
        source = (
            'function g() { var a = [function () { return globalThis; }];'
            ' var r = a[0](); return r; } g();'
        )
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              var a = [function() {
                return globalThis;
              }];
              var r = a[0]();
              return r;
            }
            globalThis;
            '''
        ))

    def test_or_this_fallback_is_recognized(self):
        source = 'function g() { var r; try { r = window; } catch (e) {} return r || this; } g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              var r;
              try {
                r = window;
              } catch (e) {}
              return r || this;
            }
            globalThis;
            '''
        ))

    def test_namespace_method_finder_receiver_is_materialized(self):
        source = (
            'var NS = {}; NS.f = function() { var r; try { r = window; } catch (e) {}'
            ' return r || this; }; NS.f();'
        )
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            var NS = {};
            NS.f = function() {
              var r;
              try {
                r = window;
              } catch (e) {}
              return r || globalThis;
            };
            NS.f();
            '''
        ))

    def test_non_finder_returning_constant_is_unchanged(self):
        source = inspect.cleandoc(
            '''
            function g() {
              return 1;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_external_call_keeps_function_opaque(self):
        source = inspect.cleandoc(
            '''
            function g() {
              console.log(1);
              return window;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_function_writing_a_global_is_not_a_finder(self):
        source = inspect.cleandoc(
            '''
            function g() {
              leaked = 1;
              return self;
            }
            function r() {
              return leaked;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_call_with_arguments_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            g(1);
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_shadowed_globalthis_declines_substitution(self):
        source = inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            function h() {
              var globalThis;
              return g();
            }
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_returning_a_parameter_is_not_a_finder(self):
        source = inspect.cleandoc(
            '''
            function g(o) {
              var x = window;
              return o;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_reassigned_finder_is_not_substituted(self):
        """
        The finder name is reassigned before the call, so the call may reach the replacement rather
        than the finder; substituting `globalThis` would drop the replacement's side effect.
        """
        source = inspect.cleandoc(
            '''
            function finder() {
              return globalThis;
            }
            finder = function() {
              console.log("side effect");
              return globalThis;
            };
            var g = finder();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_premature_call_to_declarator_finder_is_not_substituted(self):
        """
        The finder is installed by a `var` initializer, so a call textually before it runs while the
        binding is the hoisted `undefined` and throws; rewriting that call to `globalThis` would replace
        the runtime `TypeError` with a value.
        """
        source = inspect.cleandoc(
            '''
            var g = finder();
            var finder = function() {
              return window;
            };
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_redeclared_finder_is_not_substituted(self):
        """
        The name has two declarations, so a call resolves to the last by hoisting; the binding no
        longer pins one function and the call is left intact.
        """
        source = inspect.cleandoc(
            '''
            function finder() {
              return globalThis;
            }
            function finder() {
              return window;
            }
            finder();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_canonical_umd_getglobal_if_chain_folds_its_call(self):
        """
        The canonical UMD/webpack global finder guards each candidate with `typeof x !== 'undefined'`.
        Once `typeof globalThis` folds to `'object'`, the first guard is `true`, dead-code elimination
        makes the body a bare `return globalThis` ahead of the host-conditional arms, and the finder
        folds — those arms being unreachable, not throw-free. So `getGlobal()` becomes `globalThis`.
        """
        source = (
            "function getGlobal() {"
            " if (typeof globalThis !== 'undefined') { return globalThis; }"
            " if (typeof self !== 'undefined') { return self; }"
            " if (typeof window !== 'undefined') { return window; }"
            " if (typeof global !== 'undefined') { return global; }"
            " throw new Error('no global'); }"
            " var g = getGlobal(); console.log(g);"
        )
        self.assertIn('var g = globalThis;', self._deobfuscate(source))

    def test_canonical_umd_getglobal_short_circuit_form_folds(self):
        """
        The `&&`/`||` form of the same finder, led by `globalThis`. `typeof globalThis !== 'undefined'`
        folds to `true`, `true && globalThis` to `globalThis`, and the `|| …` chain to `globalThis`, so
        the body is `return globalThis` and the call folds.
        """
        source = (
            "function getGlobal() {"
            " return (typeof globalThis !== 'undefined' && globalThis) ||"
            " (typeof self !== 'undefined' && self) ||"
            " (typeof global !== 'undefined' && global) || this; }"
            " var g = getGlobal(); console.log(g);"
        )
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            '''
            function getGlobal() {
              return globalThis;
            }
            var g = globalThis;
            console.log(g);
            '''
        ))

    def test_a_thunk_reading_an_outer_const_in_its_dead_zone_is_not_substituted(self):
        """
        The thunk returns `globalThis` but first reads the outer `const c` from a point its declaration
        has not run past, so calling it throws a `ReferenceError` (Node: `Cannot access 'c' before
        initialization`). That throw is deferred per binding rather than flagged on the flow-insensitive
        summary, so folding the finder's call would drop it; the call is kept.
        """
        source = inspect.cleandoc(
            '''
            function g() {
              var r = (function() {
                c;
                return globalThis;
              })();
              const c = 1;
              return r;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_thunk_reading_an_established_outer_const_is_substituted(self):
        """
        The control for the dead-zone case: the same thunk, with `const c` declared before the call, so
        the read runs past the dead zone and cannot throw. The finder folds.
        """
        source = (
            'function g() {'
            ' const c = 1;'
            ' var r = (function () { c; return globalThis; })();'
            ' return r; } g();'
        )
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              const c = 1;
              var r = (function() {
                c;
                return globalThis;
              })();
              return r;
            }
            globalThis;
            '''
        ))

    def test_a_local_proven_to_hold_the_global_short_circuits_a_host_alias(self):
        """
        `t` holds `globalThis`, established before the read, so `t || window` never evaluates `window`
        and cannot throw where the host lacks it. The finder folds.
        """
        source = 'function g() { var t = globalThis; return t || window; } g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              var t = globalThis;
              return t || window;
            }
            globalThis;
            '''
        ))

    def test_a_local_holding_a_host_alias_does_not_short_circuit(self):
        """
        The control: `t` holds `window`, which is not proven truthy in every host, so `t || global` may
        evaluate `global` and throw where the host lacks it. The finder is kept.
        """
        source = inspect.cleandoc(
            '''
            function g() {
              var t = window;
              return t || global;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))
