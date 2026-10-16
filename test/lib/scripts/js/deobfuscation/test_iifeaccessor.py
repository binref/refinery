from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.iifeaccessor import JsIIFEAccessorPromoter
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestIIFEAccessorPromoter(TestJsDeobfuscator):

    def _promote(self, source: str) -> str:
        return self._run_transformer(source, JsIIFEAccessorPromoter)

    def test_promotes_simple_accessor(self):
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [[72, 105], [66, 121, 101]];
                return function (i) { return data[i]; };
            }();
            """
        )
        result = self._promote(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  var data = [[72, 105], [66, 121, 101]];
                  return data[i];
                }
                """
            ),
            result,
        )

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
        """
        The promoted function keeps the mode its inner body declared: the closure's declarations go
        below the Directive Prologue that body opens with, since a declaration written above the
        `'use strict'` would end the prologue and leave the function sloppy.
        """
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [[72, 105]];
                return function (i) { 'use strict'; return data[i]; };
            }();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  'use strict';
                  var data = [[72, 105]];
                  return data[i];
                }
                """
            ),
            self._promote(source),
        )

    def test_the_whole_prologue_is_stepped_over_and_not_the_directive_alone(self):
        """
        A directive the language does not recognize is one all the same, and a declaration wedged in
        front of it would end the run for the `'use strict'` standing ahead of it as well.
        """
        source = inspect.cleandoc(
            """
            var get = function () {
                var data = [[72, 105]];
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
                  var data = [[72, 105]];
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
                var data = [[72, 105]];
                return function (i) { return data[i]; };
            }();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function get(i) {
                  var data = [[72, 105]];
                  return data[i];
                }
                """
            ),
            self._promote(source),
        )


#: An accessor whose closure returns a function of each kind, mapped to the declaration the
#: promotion writes for it and to what Node prints when the program calls it. What a call answers is
#: decided by the kind: a plain function answers the value, an async one a promise, a generator an
#: iterator, and an async generator an iterator of promises. A declaration written without the kind
#: would answer something else, and one written without the `*` over a body holding a `yield` is not
#: even a text an engine reads.
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


#: An accessor a promotion has to leave standing, mapped to what Node prints for it. An `async` IIFE
#: hands back a promise and a generator hands back an iterator, so the name the assignment binds is
#: not the returned function and a declaration of that name answers nothing the program read. An
#: arrow reads the `arguments` of the function around it, so one written in the IIFE's body reads
#: the object the IIFE was called with, which a body carried into a declaration of one parameter no
#: longer has, and one written in the returned function reads an object whose elements alias that
#: function's own parameters.
_AN_ACCESSOR_A_PROMOTION_MUST_LEAVE_ALONE: dict[str, str] = {
    'var get = async function () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' get.then(function (f) { console.log(f(0)); });': '1\n',
    'var get = function* () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' console.log(get.next().value(1));': '2\n',
    'var get = async function* () { var d = [1, 2]; return function (i) { return d[i]; }; }();'
    ' get.next().then(function (r) { console.log(r.value(1)); });': '2\n',
    'var get = function () { var g = () => arguments.length; var d = [1, 2];'
    " return function (i) { return d[i] + ':' + g(); }; }(9, 9); console.log(get(0));": '1:2\n',
    'var get = function () { var d = [1, 2]; return function (i) { var g = () => arguments[0];'
    " return d[i] + ':' + g(); }; }(); console.log(get(1));": '2:1\n',
    'var get = function () { var d = [1, 2]; return function (i) {'
    ' var g = () => { arguments[0] = 0; }; g(); return d[i]; }; }();'
    ' console.log(get(1));': '1\n',
}

#: An accessor the promotion does rewrite, mapped to the text it writes and to what Node prints for
#: the program. The arrow here stands inside a function expression of its own, whose `arguments` is
#: that expression's and not the accessor's, so moving the accessor's body changes nothing about
#: what the arrow reads.
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
    """
    A promotion replaces the IIFE with a declaration of the returned function under the name the
    assignment bound. That is only the same program where the IIFE was a plain function, whose call
    hands back what it returned, and where nothing in the moved body reads an `arguments` object the
    move puts a different function in charge of.
    """

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


#: An accessor an IIFE builds in a block, mapped to what Node prints for the program. A function
#: declared in a block names the block: strict code keeps it there, so a call after the block finds
#: no name, and sloppy code copies it out when the declaration runs, over a variable of its name
#: outside the block. A declarator in the block puts its name where its kind puts it instead.
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
