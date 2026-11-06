from __future__ import annotations

import inspect
import unittest

from test import opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after

from refinery.lib.scripts.js.deobfuscation.iifeaccessor import JsIIFEAccessorPromoter
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestIIFEAccessorPromoter(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def test_does_not_promote_when_an_inner_list_is_handed_out(self):
        source = inspect.cleandoc(
            """
            var get = function() {
              var data = [[72, 105], [66, 121, 101]];
              return function(i) {
                return data[i];
              };
            }();
            """
        )
        self.assertEqual(source, self._promote(source))

    def test_does_not_promote_when_a_computed_key_of_the_closure_calls_a_function(self):
        source = inspect.cleandoc(
            """
            var get = function() {
              var data = { [next()]: 1 };
              return function() {
                return data.a;
              };
            }();
            """
        )
        self.assertEqual(source, self._promote(source))

    def test_fold_xor_accessor_pattern_end_to_end(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [[72, 105], [66, 121, 101]];
                var shift = 28;
                var mask = 42;
                return function (i) {
                    var a = data[i];
                    if (!a) return "";
                    var r = "";
                    for (var j = 0; j < a.length; j++) {
                        var k = j >> shift & j << mask & (shift ^ shift) & 2047;
                        r += String.fromCharCode(a[j] ^ k);
                    }
                    return r;
                };
            }();
            document.write(get(0));
            document.write(get(1));
            """
        )
        result = self._deobfuscate_iterative(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                document.write('Hi');
                document.write('Bye');
                """
            ),
            result,
        )

    def test_does_not_promote_when_closure_is_mutated(self):
        source = inspect.cleandoc(
            """
            var counter = function() {
              var n = 0;
              return function() {
                n++;
                return n;
              };
            }();
            """
        )
        self.assertEqual(source, self._promote(source))

    def test_does_not_promote_when_param_collides_with_closure(self):
        source = inspect.cleandoc(
            """
            var get = function() {
              var data = [1, 2, 3];
              return function(data) {
                return data;
              };
            }();
            """
        )
        self.assertEqual(source, self._promote(source))

    def test_does_not_promote_non_literal_closure(self):
        source = inspect.cleandoc(
            """
            var get = function() {
              var data = computeData();
              return function(i) {
                return data[i];
              };
            }();
            """
        )
        self.assertEqual(source, self._promote(source))

    def test_promotes_through_parenthesised_iife(self):
        source = inspect.cleandoc(
            """
            var get = (function () {
                var data = [1, 2, 3];
                return function (i) { return data[i]; };
            })();
            """
        )
        result = self._promote(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  var data = [1, 2, 3];
                  return data[i];
                }
                """
            ),
            result,
        )

    def test_does_not_promote_self_referencing_named_function(self):
        source = inspect.cleandoc(
            """
            var get = function() {
              var data = [1, 2, 3];
              return function rec(i) {
                return i <= 0 ? data[0] : rec(i - 1);
              };
            }();
            """
        )
        self.assertEqual(source, self._promote(source))

    def test_promotes_when_arguments_used_only_in_nested_function(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [1, 2, 3];
                return function (i) {
                    var inner = function () { return arguments[0]; };
                    return data[i];
                };
            }();
            """
        )
        result = self._promote(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  var data = [1, 2, 3];
                  var inner = function() {
                    return arguments[0];
                  };
                  return data[i];
                }
                """
            ),
            result,
        )

    def test_promotes_when_inner_function_contains_class_field_this(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [1, 2, 3];
                return function (i) {
                    class Helper { value = this.x; }
                    return data[i];
                };
            }();
            """
        )
        result = self._promote(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  var data = [1, 2, 3];
                  class Helper {
                    value = this.x;
                  }
                  return data[i];
                }
                """
            ),
            result,
        )

    def test_the_closure_declarations_are_written_behind_the_inner_prologue(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [72, 105];
                return function (i) { 'use strict'; return data[i]; };
            }();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  'use strict';
                  var data = [72, 105];
                  return data[i];
                }
                """
            ),
            self._promote(source),
        )

    def test_the_whole_prologue_is_stepped_over_and_not_the_directive_alone(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [72, 105];
                return function (i) { 'use strict'; 'other'; return data[i]; };
            }();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  'use strict';
                  'other';
                  var data = [72, 105];
                  return data[i];
                }
                """
            ),
            self._promote(source),
        )

    def test_a_body_that_opens_with_no_prologue_takes_the_declarations_at_its_head(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [72, 105];
                return function (i) { return data[i]; };
            }();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  var data = [72, 105];
                  return data[i];
                }
                """
            ),
            self._promote(source),
        )


_AN_ACCESSOR_RETURNING_A_FUNCTION_OF_EACH_KIND: dict[str, tuple[str, str]] = {
    'var get = function () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' console.log(get(0));': (
        inspect.cleandoc(
            """
            function get(i) {
              var d = [1, 2];
              return d[i];
            }
            console.log(get(0));
            """
        ), '1\n'),
    'var get = function () { var d = [1, 2]; return async function (i) { return d[i]; }; }();'
    ' get(0).then(function (v) { console.log(v); });': (
        inspect.cleandoc(
            """
            async function get(i) {
              var d = [1, 2];
              return d[i];
            }
            get(0).then(function(v) {
              console.log(v);
            });
            """
        ), '1\n'),
    'var get = function () { var d = [1, 2]; return function* (i) { yield d[i]; }; }();'
    ' console.log(get(0).next().value);': (
        inspect.cleandoc(
            """
            function* get(i) {
              var d = [1, 2];
              yield d[i];
            }
            console.log(get(0).next().value);
            """
        ), '1\n'),
    'var get = function () { var d = [1, 2]; return async function* (i) { yield d[i]; }; }();'
    ' get(0).next().then(function (v) { console.log(v.value); });': (
        inspect.cleandoc(
            """
            async function* get(i) {
              var d = [1, 2];
              yield d[i];
            }
            get(0).next().then(function(v) {
              console.log(v.value);
            });
            """
        ), '1\n'),
}


class TestAPromotedAccessorIsTheKindOfFunctionItReturned(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def test_the_declaration_is_written_the_way_the_row_records(self):
        rows = _AN_ACCESSOR_RETURNING_A_FUNCTION_OF_EACH_KIND
        self.assertEqual(
            {source: self._promote(source) for source in rows},
            {source: promoted for source, (promoted, _) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_promotion(self):
        rows = _AN_ACCESSOR_RETURNING_A_FUNCTION_OF_EACH_KIND
        self.assertEqual(
            {source: (behavior(source), behavior(self._promote(source))) for source in rows},
            {
                source: ((printed, None), (printed, None))
                for source, (_, printed) in rows.items()
            },
        )


_AN_ACCESSOR_A_PROMOTION_MUST_LEAVE_ALONE: dict[str, str] = {
    'var get = async function () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' get.then(function (f) { console.log(f(0)); });': '1\n',
    'var get = function* () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' console.log(get.next().value(1));': '2\n',
    'var get = async function* () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' get.next().then(function (r) { console.log(r.value(1)); });': '2\n',
    'var get = function () { var g = () => arguments.length; var d = [1, 2];'
    " return function (i) { return d[i] + ':' + g(); }; }(9, 9); console.log(get(0));": '1:2\n',
}

_AN_ARROW_READING_THE_ARGUMENTS_OF_THE_RETURNED_FUNCTION: dict[str, tuple[str, str]] = {
    'var get = function () { var d = [1, 2]; return function (i) { var g = () => arguments[0];'
    " return d[i] + ':' + g(); }; }(); console.log(get(1));": (
        inspect.cleandoc(
            """
            function get(i) {
              var d = [1, 2];
              var g = () => arguments[0];
              return d[i] + ':' + g();
            }
            console.log(get(1));
            """
        ), '2:1\n'),
    'var get = function () { var d = [1, 2]; return function (i) {'
    ' var g = () => { arguments[0] = 0; }; g(); return d[i]; }; }();'
    ' console.log(get(1));': (
        inspect.cleandoc(
            """
            function get(i) {
              var d = [1, 2];
              var g = () => {
                arguments[0] = 0;
              };
              g();
              return d[i];
            }
            console.log(get(1));
            """
        ), '1\n'),
}

_AN_ACCESSOR_A_PROMOTION_REWRITES: dict[str, tuple[str, str]] = {
    'var get = function () { var d = [1, 2]; return function (i) {'
    ' var h = function () { var g = () => arguments[0]; return g(); };'
    " return d[i] + ':' + h(5); }; }(); console.log(get(1));": (
        inspect.cleandoc(
            """
            function get(i) {
              var d = [1, 2];
              var h = function() {
                var g = () => arguments[0];
                return g();
              };
              return d[i] + ':' + h(5);
            }
            console.log(get(1));
            """
        ), '2:5\n'),
    'var get = function () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' console.log(get(1));': (
        inspect.cleandoc(
            """
            function get(i) {
              var d = [1, 2];
              return d[i];
            }
            console.log(get(1));
            """
        ), '2\n'),
}


class TestWhatTheKindOfTheIIFEAndAnArrowsArgumentsCostThePromotion(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def _canonical(self, source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def test_the_promotion_leaves_each_of_those_accessors_as_it_found_it(self):
        rows = _AN_ACCESSOR_A_PROMOTION_MUST_LEAVE_ALONE
        written = {source: self._canonical(source) for source in rows}
        self.assertEqual({source: self._promote(text) for source, text in written.items()}, written)

    def test_the_promotion_writes_the_declaration_the_row_records(self):
        rows = _AN_ACCESSOR_A_PROMOTION_REWRITES
        self.assertEqual(
            {source: self._promote(source) for source in rows},
            {source: promoted for source, (promoted, _) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_a_promotion_it_declines(self):
        rows = _AN_ACCESSOR_A_PROMOTION_MUST_LEAVE_ALONE
        self.assertEqual(
            {source: (behavior(source), behavior(self._promote(source))) for source in rows},
            {source: ((printed, None), (printed, None)) for source, printed in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_a_promotion_it_makes(self):
        rows = _AN_ACCESSOR_A_PROMOTION_REWRITES
        self.assertEqual(
            {source: (behavior(source), behavior(self._promote(source))) for source in rows},
            {
                source: ((printed, None), (printed, None))
                for source, (_, printed) in rows.items()
            },
        )

    def test_an_arrow_reading_the_returned_functions_arguments_is_left_alone_or_promoted(self):
        rows = _AN_ARROW_READING_THE_ARGUMENTS_OF_THE_RETURNED_FUNCTION
        for source, (promoted, _) in rows.items():
            with self.subTest(source=source):
                self.assertIn(self._promote(source), (self._canonical(source), promoted))

    @opportunity
    def test_an_arrow_reading_the_returned_functions_arguments_does_not_stop_the_promotion(self):
        rows = _AN_ARROW_READING_THE_ARGUMENTS_OF_THE_RETURNED_FUNCTION
        self.assertEqual(
            {source: self._promote(source) for source in rows},
            {source: promoted for source, (promoted, _) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_promoting_an_arrow_reading_its_arguments(self):
        rows = _AN_ARROW_READING_THE_ARGUMENTS_OF_THE_RETURNED_FUNCTION
        self.assertEqual(
            {source: (behavior(source), behavior(self._promote(source))) for source in rows},
            {
                source: ((printed, None), (printed, None))
                for source, (_, printed) in rows.items()
            },
        )


_AN_ACCESSOR_AN_IIFE_BUILDS_IN_A_BLOCK: dict[str, str] = {
    "'use strict';"
    " { var X = function () { var t = 'abc'; return function (i) { return t[i]; }; }(); }"
    ' console.log(X(1));': 'b\n',
    "var X = 1; { const X = function () { var t = 'abc'; return function (i) { return t[i]; }; }();"
    ' console.log(X(1)); } console.log(X);': 'b\n1\n',
    'var r = []; try { r.push(X(1)); } catch (e) { r.push(e.constructor.name); }'
    " { var X = function () { var t = 'abc'; return function (i) { return t[i]; }; }(); }"
    ' r.push(X(2)); console.log(r.join());': 'TypeError,c\n',
}


class TestAnAccessorAnIIFEBuildsInABlockIsNotPromoted(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def _canonical(self, source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def test_the_promotion_leaves_each_accessor_in_a_block_as_it_found_it(self):
        rows = _AN_ACCESSOR_AN_IIFE_BUILDS_IN_A_BLOCK
        written = {source: self._canonical(source) for source in rows}
        self.assertEqual({source: self._promote(text) for source, text in written.items()}, written)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_promotion(self):
        rows = _AN_ACCESSOR_AN_IIFE_BUILDS_IN_A_BLOCK
        self.assertEqual(
            {source: (behavior(source), behavior(self._promote(source))) for source in rows},
            {source: ((printed, None), (printed, None)) for source, printed in rows.items()},
        )

    def test_an_exported_accessor_at_the_top_level_of_a_module_is_promoted(self):
        source = (
            "export var X = function () { var t = 'abc'; return function (i) { return t[i]; }; }();"
            ' console.log(X(1));'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                export function X(i) {
                  var t = 'abc';
                  return t[i];
                }
                console.log(X(1));
                """
            ),
            self._promote(source),
        )


_AN_ACCESSOR_WHOSE_CLOSED_OVER_VALUE_OUTLIVES_A_CALL: dict[str, str] = {
    'var acc = (function () { var t = [0]; return function (i) { t[0] = t[0] + i; return t[0]; }; })();'
    ' console.log(acc(1), acc(1));': '1 2\n',
    "var acc = (function () { var t = ['a']; return function () { return t; }; })();"
    ' console.log(acc() === acc());': 'true\n',
    'var X = function () { var a = [0]; return function () { a[0]++; return a[0]; }; }();'
    ' console.log(X(), X(), X());': '1 2 3\n',
    'var X = function () { var a = [1, 2]; return function () { return a; }; }();'
    ' console.log(X() === X());': 'true\n',
    'var X = function () { var c = {}; return function (k) { c[k] = (c[k] || 0) + 1; return c[k]; }; }();'
    " console.log(X('a'), X('a'));": '1 2\n',
    "var log = (function () { var buf = []; return function (m) { buf.push(m); return buf.length; }; })();"
    " console.log(log('a'), log('b'));": '1 2\n',
    "var seen = (function () { var cache = {}; return function (k) { if (cache[k]) return 'old';"
    " cache[k] = 1; return 'new'; }; })(); console.log(seen('x'), seen('x'));": 'new old\n',
    'var next = (function () { var s = { n: 0 }; return function () { s.n++; return s.n; }; })();'
    ' console.log(next(), next());': '1 2\n',
    'var items = (function () { var list = []; return function () { return list; }; })();'
    ' items().push(1); items().push(2); console.log(items().length);': '2\n',
    'var X = function () { var a = [[1], [2]]; return function (i) { return a[i]; }; }();'
    ' X(0).push(5); console.log(X(0).length);': '2\n',
    'var X = function () { var d = [[1], [2]]; return function (i) { var a = d[i]; return a; }; }();'
    ' X(0).push(5); console.log(X(0).length);': '2\n',
    'var X = function () { var d = [[1], [2]]; return function (i) { var a = d[i]; a.push(9); return a.length; }; }();'
    ' console.log(X(0), X(0));': '2 3\n',
    "var X = function () { var cfg = { list: ['a', 'b'] }; return function () { return cfg.list; }; }();"
    " X().push('c'); console.log(X().length);": '3\n',
    'var keep; var X = function () { var t = [1]; return function () { keep = t; return 0; }; }();'
    ' X(); var k = keep; X(); console.log(k === keep);': 'true\n',
    'var keep; function f(a) { keep = a; } var X = function () { var t = [1]; return function () { f(t); return 0; }; }();'
    ' X(); var k = keep; X(); console.log(k === keep);': 'true\n',
}


_AN_ACCESSOR_THAT_ONLY_READS_WHAT_IT_CLOSES_OVER: dict[str, tuple[str, str]] = {
    "var X = function () { var t = ['abc', 'de']; return function (i) {"
    " return t[i].split('').reverse().join(''); }; }(); console.log(X(0));": (
        inspect.cleandoc(
            """
            function X(i) {
              var t = ['abc', 'de'];
              return t[i].split('').reverse().join('');
            }
            console.log(X(0));
            """
        ), 'cba\n'),
    "var X = function () { var t = ['x', 'y']; return function (c) { return t.indexOf(c); }; }();"
    " console.log(X('y'));": (
        inspect.cleandoc(
            """
            function X(c) {
              var t = ['x', 'y'];
              return t.indexOf(c);
            }
            console.log(X('y'));
            """
        ), '1\n'),
    "var X = function () { var o = { a: 'p', b: 'q' }; return function (k) { return o[k]; }; }();"
    " console.log(X('b'));": (
        inspect.cleandoc(
            """
            function X(k) {
              var o = { a: 'p', b: 'q' };
              return o[k];
            }
            console.log(X('b'));
            """
        ), 'q\n'),
    'var X = function () { var t = [[1, 2], [3]]; return function (i, j) { return t[i][j]; }; }();'
    ' console.log(X(0, 1));': (
        inspect.cleandoc(
            """
            function X(i, j) {
              var t = [[1, 2], [3]];
              return t[i][j];
            }
            console.log(X(0, 1));
            """
        ), '2\n'),
    'var X = function () { var t = [[1, 2], [3]]; return function (i) { var u = t; return u[i][0]; }; }();'
    ' console.log(X(1));': (
        inspect.cleandoc(
            """
            function X(i) {
              var t = [[1, 2], [3]];
              var u = t;
              return u[i][0];
            }
            console.log(X(1));
            """
        ), '3\n'),
}


class TestAnAccessorWhoseClosedOverValueOutlivesACallIsNotPromoted(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def _canonical(self, source: str) -> str:
        return JsSynthesizer().convert(JsParser(source).parse())

    def test_the_promotion_leaves_each_of_those_accessors_as_it_found_it(self):
        rows = _AN_ACCESSOR_WHOSE_CLOSED_OVER_VALUE_OUTLIVES_A_CALL
        written = {source: self._canonical(source) for source in rows}
        self.assertEqual({source: self._promote(text) for source, text in written.items()}, written)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_deobfuscation(self):
        rows = _AN_ACCESSOR_WHOSE_CLOSED_OVER_VALUE_OUTLIVES_A_CALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: ((printed, None), (printed, None)) for source, printed in rows.items()},
        )

    def test_an_accessor_that_only_reads_what_it_closes_over_is_still_promoted(self):
        rows = _AN_ACCESSOR_THAT_ONLY_READS_WHAT_IT_CLOSES_OVER
        self.assertEqual(
            {source: self._promote(source) for source in rows},
            {source: promoted for source, (promoted, _) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_a_promotion_it_makes(self):
        rows = _AN_ACCESSOR_THAT_ONLY_READS_WHAT_IT_CLOSES_OVER
        self.assertEqual(
            {source: (behavior(source), behavior(self._promote(source))) for source in rows},
            {source: ((printed, None), (printed, None)) for source, (_, printed) in rows.items()},
        )
