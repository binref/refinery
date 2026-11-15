from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.parser import JsParser

A_CHAIN_OF_WRAPPERS = (
    'function target(a) { return a; }'
    'function inner(x, y) { return target(y - -5); }'
    'function outer(a, b, c) { return inner(a, c - -10); }'
)


class TestCallWrapperInliner(TestJsDeobfuscator):

    def test_self_forwarding_wrapper_not_inlined(self):
        ast = JsParser('function W(a) { return W(a); } W(1);').parse()
        t = JsCallWrapperInliner()
        t.visit(ast)
        self.assertFalse(t.changed)

    def test_mutually_forwarding_wrappers_not_inlined(self):
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

    def test_one_visit_inlines_the_outer_wrapper_of_a_chain_or_the_whole_chain(self):
        self.assertIn(
            self._run_transformer(F'{A_CHAIN_OF_WRAPPERS}var r = outer(1, 2, 3);', JsCallWrapperInliner),
            (
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
                inspect.cleandoc(
                    """
                    function target(a) {
                      return a;
                    }
                    var r = target(3 - -10 - -5);
                    """
                ),
            ),
        )

    def test_a_chain_of_wrappers_deobfuscates_to_the_value_it_computes(self):
        source = F'{A_CHAIN_OF_WRAPPERS}console.log(outer(1, 2, 3));'
        self.assertEqual(self._deobfuscate_iterative(source), 'console.log(18);')

    def test_wrapper_assigning_parameter_not_inlined(self):
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


class TestAnArgumentBoundToEvalStaysAnIndirectCall(TestJsDeobfuscator):

    def test_an_argument_bound_to_eval_is_inlined_as_an_indirect_call(self):
        self.assertEqual(
            'function f() {\n'
            '  var loc = 7;\n'
            '  try {\n'
            "    return (0, eval)('loc');\n"
            '  } catch (e) {\n'
            '    return e.constructor.name;\n'
            '  }\n'
            '}\n'
            'console.log(f());',
            self._run_transformer(
                'function w(cb, s) { return cb(s); }'
                ' function f(){ var loc = 7;'
                " try { return w(eval, 'loc'); } catch (e) { return e.constructor.name; } }"
                ' console.log(f());',
                JsCallWrapperInliner,
            ),
        )


class TestAWrapperAroundADirectEvalStays(TestJsDeobfuscator):

    def test_a_direct_eval_reads_the_scope_of_the_wrapper_and_not_that_of_the_caller(self):
        source = (
            'function w(code) { return eval(code); }'
            ' var x = 1;'
            " function f() { var x = 2; return w('x'); }"
            ' console.log(f());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function w(code) {
                  return eval(code);
                }
                var x = 1;
                function f() {
                  var x = 2;
                  return w('x');
                }
                console.log(f());
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )


class TestAWrapperArgumentIsNotDuplicated(TestJsDeobfuscator):

    def test_a_fresh_value_read_twice_by_the_body_is_not_inlined(self):
        source = (
            'function h(x, y) { return x === y; }'
            ' function w(a) { return h(a, a); }'
            ' console.log(w([]));'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function h(x, y) {
                  return x === y;
                }
                function w(a) {
                  return h(a, a);
                }
                console.log(w([]));
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )

    def test_an_identifier_read_twice_by_the_body_is_inlined(self):
        source = (
            'function h(x, y) { return x === y; }'
            ' function w(a) { return h(a, a); }'
            ' console.log(w(u));'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function h(x, y) {
                  return x === y;
                }
                console.log(h(u, u));
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )


class TestAForwardedCalleeIsNotCaptured(TestJsDeobfuscator):

    def test_a_call_site_shadowing_the_forwarded_name_is_left_alone(self):
        source = (
            'function w(a) { return h(a); }'
            " function h(a) { return 'outer ' + a; }"
            " function t() { var h = function (a) { return 'inner ' + a; }; return w(5); }"
            ' console.log(t());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function w(a) {
                  return h(a);
                }
                function h(a) {
                  return 'outer ' + a;
                }
                function t() {
                  var h = function(a) {
                    return 'inner ' + a;
                  };
                  return w(5);
                }
                console.log(t());
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )


class TestAWrapperArgumentUnderANestedScopeIsNotInlined(TestJsDeobfuscator):

    def test_an_identifier_captured_by_a_returned_arrow_is_not_inlined(self):
        source = (
            'function w(a) { return h(() => a); }'
            ' function h(cb) { return cb; }'
            ' var x = 1; var f = w(x); x = 2; console.log(f());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function w(a) {
                  return h(() => a);
                }
                function h(cb) {
                  return cb;
                }
                var x = 1;
                var f = w(x);
                x = 2;
                console.log(f());
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )

    def test_a_literal_captured_by_a_returned_arrow_is_inlined(self):
        source = (
            'function w(a) { return h(() => a); }'
            ' function h(cb) { return cb; }'
            ' console.log(w(5)());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function h(cb) {
                  return cb;
                }
                console.log(h(() => 5)());
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )

class TestAConstantWrapperMayCallThroughALiteral(TestJsDeobfuscator):

    def test_a_closed_call_body_with_no_name_to_capture_is_inlined(self):
        source = 'function k() { return (1)(); } try { k(); } catch (e) { console.log(e.name); }'
        self.assertEqual(
            inspect.cleandoc(
                """
                try {
                  (1)();
                } catch (e) {
                  console.log(e.name);
                }
                """
            ),
            self._run_transformer(source, JsCallWrapperInliner),
        )
