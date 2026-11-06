from __future__ import annotations

import inspect
import unittest

from test import opportunity
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.globalfinder import JsGlobalFinderInlining
from refinery.lib.scripts.js.options import DeobfuscationOptions


class TestGlobalFinderInlining(TestJsDeobfuscator):

    def _find(self, source: str) -> str:
        return self._run_transformer(source, JsGlobalFinderInlining)

    def _find_in(self, source: str, environment: HostEnvironment) -> str:
        options = DeobfuscationOptions(environment=environment)
        return self._run_transformer(source, JsGlobalFinderInlining, options)

    def test_finder_call_becomes_globalthis(self):
        self.assertEqual(self._find('function g() { return globalThis; } g();'), inspect.cleandoc(
            '''
            function g() {
              return globalThis;
            }
            globalThis;
            '''
        ))

    def test_a_finder_called_through_parentheses_becomes_globalthis(self):
        self.assertEqual(self._find('function g() { return globalThis; } (g)();'), inspect.cleandoc(
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
        source = inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_pinned_node_host_substitutes_a_bare_global_finder(self):
        self.assertEqual(self._find_in(
            'function g() { return global; } g();', HostEnvironment.node), inspect.cleandoc(
            '''
            function g() {
              return global;
            }
            globalThis;
            '''
        ))
        self.assertEqual(
            self._find_in('function g() { return window; } g();', HostEnvironment.node),
            'function g() {\n  return window;\n}\ng();',
        )

    def test_a_pinned_browser_host_substitutes_a_same_realm_alias_finder(self):
        for alias in ('window', 'self'):
            with self.subTest(alias=alias):
                self.assertEqual(self._find_in(
                    F'function g() {{ return {alias}; }} g();', HostEnvironment.browser),
                    F'function g() {{\n  return {alias};\n}}\nglobalThis;',
                )

    def test_a_pinned_browser_host_keeps_a_cross_realm_alias_finder(self):
        self.assertEqual(
            self._find_in('function g() { return top; } g();', HostEnvironment.browser),
            inspect.cleandoc(
                '''
                function g() {
                  return top;
                }
                g();
                '''
            ),
        )

    @opportunity
    def test_a_pinned_browser_host_substitutes_a_frames_finder(self):
        self.assertEqual(
            self._find_in('function g() { return frames; } g();', HostEnvironment.browser),
            inspect.cleandoc(
                '''
                function g() {
                  return frames;
                }
                globalThis;
                '''
            ),
        )

    def test_host_read_before_the_anchor_is_not_substituted(self):
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

    def test_a_finder_called_as_a_method_is_left_as_written(self):
        source = inspect.cleandoc(
            '''
            var NS = {};
            NS.f = function() {
              var r;
              try {
                r = window;
              } catch (e) {}
              return r || this;
            };
            NS.f();
            '''
        )
        self.assertEqual(source, self._find(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_method_called_finder_whose_primary_lookup_threw_returns_its_receiver(self):
        source = inspect.cleandoc(
            '''
            var NS = {};
            NS.f = function () { var r; try { r = window; } catch (e) {} return r || this; };
            console.log(NS.f() === NS);
            '''
        )
        self.assertEqual(before_and_after(source), (('true\n', None), ('true\n', None)))

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
              return globalThis;
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
              return globalThis;
            }
            function r() {
              return leaked;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_call_whose_argument_has_an_effect_keeps_the_effect(self):
        source = inspect.cleandoc(
            '''
            function g() {
              return globalThis;
            }
            g(console.log(1));
            '''
        )
        self.assertIn(self._find(source), (
            source,
            inspect.cleandoc(
                '''
                function g() {
                  return globalThis;
                }
                console.log(1), globalThis;
                '''
            ),
        ))

    def test_shadowed_globalthis_declines_substitution(self):
        source = inspect.cleandoc(
            '''
            function g() {
              return globalThis;
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
              var x = globalThis;
              return o;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_reassigned_finder_is_not_substituted(self):
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
        source = inspect.cleandoc(
            '''
            var g = finder();
            var finder = function() {
              return globalThis;
            };
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_redeclared_finder_is_not_substituted(self):
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
        source = (
            "function getGlobal() {"
            " if (typeof globalThis !== 'undefined') { return globalThis; }"
            " if (typeof self !== 'undefined') { return self; }"
            " if (typeof window !== 'undefined') { return window; }"
            " if (typeof global !== 'undefined') { return global; }"
            " throw new Error('no global'); }"
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

    def test_canonical_umd_getglobal_short_circuit_form_folds(self):
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

    def test_a_local_not_holding_the_global_does_not_short_circuit_a_host_alias(self):
        source = inspect.cleandoc(
            '''
            function g() {
              var t = null;
              return t || global;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_read_in_the_finder_bodys_own_dead_zone_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              var r = c;
              const c = globalThis;
              return r;
            }
            var x = g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_read_past_the_finder_bodys_own_declaration_is_substituted(self):
        source = 'function g() { const c = globalThis; var r = c; return r; } var x = g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              const c = globalThis;
              var r = c;
              return r;
            }
            var x = globalThis;
            '''
        ))

    def test_a_closure_reading_its_own_dead_zone_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              return (function() {
                var x = c;
                const c = globalThis;
                return c;
              })();
            }
            var y = g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_captured_read_reached_before_its_declaration_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              var u = G + 1;
              return globalThis;
            }
            g();
            const G = 5;
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_captured_read_past_its_declaration_is_substituted(self):
        source = 'const G = 5; function g() { var u = G + 1; return globalThis; } g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            const G = 5;
            function g() {
              var u = G + 1;
              return globalThis;
            }
            globalThis;
            '''
        ))

    def test_a_parameter_default_reading_a_host_alias_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g(a = window) {
              return globalThis;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_parameter_the_body_ignores_does_not_block_substitution(self):
        source = 'function g(a) { return globalThis; } g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g(a) {
              return globalThis;
            }
            globalThis;
            '''
        ))

    def test_a_destructuring_default_reading_a_host_alias_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              var [a = window] = [];
              return globalThis;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_catch_handler_reading_a_host_alias_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              try {
                null.x;
                return globalThis;
              } catch (e) {
                return window;
              }
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))

    def test_a_catch_parameter_default_reading_a_host_alias_is_not_substituted(self):
        source = inspect.cleandoc(
            '''
            function g() {
              try {
                throw 0;
              } catch ({ e = window }) {}
              return globalThis;
            }
            g();
            '''
        )
        self.assertEqual(source, self._find(source))
