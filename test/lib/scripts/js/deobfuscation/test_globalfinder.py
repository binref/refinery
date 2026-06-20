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

    def test_finder_result_assignment_becomes_globalthis(self):
        self.assertEqual(self._find('function g() { return window; } var x = g();'), inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            var x = globalThis;
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

    def test_non_finder_returning_constant_is_unchanged(self):
        self.assertEqual(self._find('function g() { return 1; } g();'), inspect.cleandoc(
            '''
            function g() {
              return 1;
            }
            g();
            '''
        ))

    def test_external_call_keeps_function_opaque(self):
        source = 'function g() { console.log(1); return window; } g();'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              console.log(1);
              return window;
            }
            g();
            '''
        ))

    def test_function_writing_a_global_is_not_a_finder(self):
        self.assertEqual(self._find('function g() { leaked = 1; return self; } g();'), inspect.cleandoc(
            '''
            function g() {
              leaked = 1;
              return self;
            }
            g();
            '''
        ))

    def test_call_with_arguments_is_not_substituted(self):
        self.assertEqual(self._find('function g() { return window; } g(1);'), inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            g(1);
            '''
        ))

    def test_shadowed_globalthis_declines_substitution(self):
        source = 'function g() { return window; } function h() { var globalThis; return g(); }'
        self.assertEqual(self._find(source), inspect.cleandoc(
            '''
            function g() {
              return window;
            }
            function h() {
              var globalThis;
              return g();
            }
            '''
        ))

    def test_returning_a_parameter_is_not_a_finder(self):
        self.assertEqual(self._find('function g(o) { var x = window; return o; } g();'), inspect.cleandoc(
            '''
            function g(o) {
              var x = window;
              return o;
            }
            g();
            '''
        ))
