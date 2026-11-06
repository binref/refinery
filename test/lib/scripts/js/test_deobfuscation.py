from __future__ import annotations

import inspect

from test import opportunity
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.cff import JsControlFlowUnflattening
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.scripts.pipeline import DeobfuscationTimeout


class TestDeadCodeElimination(TestJsDeobfuscator):

    def test_dead_code_string_comparison(self):
        self.assertEqual(
            'live();',
            self._deobfuscate("if ('hello' === 'world') { dead(); } else { live(); }"),
        )

    def test_in_empty_function_guard_folded(self):
        source = inspect.cleandoc(
            """
            function __p_sentinel() {}
            if ("xK9mQ" in __p_sentinel) {
              __p_dead_1();
            }
            function __p_dead_1() { var fake = 999; }
            function real(n) {
              if ("abc" in __p_sentinel) {
                __p_dead_2();
              }
              function __p_dead_2() { var junk = 0; }
              return n + 1;
            }
            console.log(real(5));
            """
        )
        self.assertEqual(self._deobfuscate(source), 'console.log(6);')

    def test_in_empty_function_known_property_folds_true(self):
        source = inspect.cleandoc(
            """
            function sentinel() {}
            if ("length" in sentinel) {
              live();
            } else {
              dead();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), 'live();')

    def test_in_empty_class_guard_folded(self):
        source = inspect.cleandoc(
            """
            class Sentinel {}
            if ("randomJunk" in Sentinel) {
              dead();
            } else {
              live();
            }
            """
        )
        self.assertIn(
            self._deobfuscate(source),
            (
                inspect.cleandoc(
                    """
                    class Sentinel {}
                    live();
                    """
                ),
                'live();',
            ),
        )

    @opportunity
    def test_an_empty_class_only_a_folded_guard_read_is_removed(self):
        source = inspect.cleandoc(
            """
            class Sentinel {}
            if ("randomJunk" in Sentinel) {
              dead();
            } else {
              live();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), 'live();')

    def test_in_const_empty_object_guard_folded(self):
        source = inspect.cleandoc(
            """
            const sentinel = {};
            if ("randomKey" in sentinel) {
              dead();
            } else {
              live();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            """
            live();
            """
        ))

    def test_in_const_empty_object_known_property_folds_true(self):
        source = inspect.cleandoc(
            """
            const obj = {};
            if ("toString" in obj) {
              live();
            } else {
              dead();
            }
            if ("length" in obj) {
              dead2();
            } else {
              live2();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            """
            live();
            live2();
            """
        ))

    def test_in_function_guard_nested_scope(self):
        source = inspect.cleandoc(
            """
            function sentinel() { return 1; }
            function main(n) {
              for (var i = 0; i < n; i++) {
                if ("xK9mQ" in sentinel) {
                  dead();
                }
              }
              return n;
            }
            console.log(main(5));
            """
        )
        self.assertEqual('console.log(5);', self._deobfuscate(source))

    def test_undeclared_dead_write_in_nested_block(self):
        source = inspect.cleandoc(
            """
            function f() {
              for (var i = 0; i < 3; i++) {
                deadVar = function() { return 42; };
              }
              return i;
            }
            console.log(f());
            """
        )
        self.assertEqual('console.log(3);', self._deobfuscate(source))

    def test_in_bare_assignment_empty_function_guard_folded(self):
        source = inspect.cleandoc(
            """
            var sentinel;
            sentinel = function() {};
            if ("xK9mQ" in sentinel) {
              dead();
            } else {
              live();
            }
            """
        )
        self.assertEqual(self._deobfuscate(source), 'live();')

    def test_in_bare_assignment_before_establishing_write_not_folded(self):
        source = inspect.cleandoc(
            """
            var sentinel;
            var present = "xK9mQ" in sentinel;
            sentinel = function() {};
            SINK(present);
            """
        )
        self.assertEqual(self._simplify(source), self._run_transformers(source))


class TestConstantPoolIntegration(TestJsDeobfuscator):

    def test_individual_duplicateLiteralsRemoval(self):
        source = inspect.cleandoc(
            """
            const q = [0, "push"];
            function fizzbuzz(n) {
              var results = [];
              for (var i = 1; i <= n; i++) {
                if (i % 15 === q[0]) {
                  results[q[1]]('FizzBuzz');
                } else {
                  if (i % 3 === q[0]) {
                    results[q[1]]('Fizz');
                  } else {
                    if (i % 5 === q[0]) {
                      results[q[1]]('Buzz');
                    } else {
                      results[q[1]](i);
                    }
                  }
                }
              }
              return results;
            }
            console["log"](fizzbuzz(20));
            """
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            console.log([1, 2, 'Fizz', 4, 'Buzz', 'Fizz', 7, 8, 'Fizz', 'Buzz', 11, 'Fizz', 13, 14, 'FizzBuzz', 16, 17, 'Fizz', 19, 'Buzz']);
            """
        ))


class TestRegressionBugs(TestJsDeobfuscator):

    def test_dispatcher_sparse_payload_preserves_arity(self):
        source = inspect.cleandoc(
            """
            var c = Object["create"](null);
            var p;
            function d(name, flag, rtype, lengths = {}) {
              var output;
              var fns = {
                "f1": function() { var [a, b, c] = p; return a + b + c; }
              };
              if (flag === "clearF") { p = []; }
              if (flag === "createF") {
                function createFunction() {
                  var fn = function (...args) { p = args; return fns[name].apply(this); };
                  var fnLength = lengths[name];
                  if (fnLength) { setLength(fn, fnLength); }
                  return fn;
                }
                output = c[name] || (c[name] = createFunction());
              } else {
                output = fns[name]();
              }
              if (rtype === "wrapF") { return { "wk": output }; }
              else { return output; }
            }
            function setLength() {}
            console.log((p = ["first", , "third"], d("f1")));
            """
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            console.log('firstundefinedthird');
            """
        ))

    def test_cff_preserves_intervening_statements(self):
        source = inspect.cleandoc(
            """
            var _order = ['1', '0'];
            console.log('side effect');
            var _idx = 0;
            while (true) {
              switch (_order[_idx++]) {
                case '0': var b = 2; continue;
                case '1': var a = 1; continue;
              }
              break;
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log('side effect');
                var a = 1;
                var b = 2;
                """
            ),
            self._run_transformer(source, JsControlFlowUnflattening),
        )

    def test_free_variable_not_inlined_past_modifying_call(self):
        source = inspect.cleandoc(
            """
            function modifyGlobal() {
              x = 9;
            }
            var x = 12;
            modifyGlobal();
            console.log(x);
            """
        )
        self.assertIn(
            self._deobfuscate_iterative(source),
            (
                inspect.cleandoc(
                    """
                    var x = 12;
                    x = 9;
                    console.log(x);
                    """
                ),
                'console.log(9);',
            ),
        )

    @opportunity
    def test_a_global_a_call_overwrites_is_read_as_the_value_the_call_stored(self):
        source = inspect.cleandoc(
            """
            function modifyGlobal() {
              x = 9;
            }
            var x = 12;
            modifyGlobal();
            console.log(x);
            """
        )
        self.assertEqual('console.log(9);', self._deobfuscate_iterative(source))

    def test_free_variable_is_inlined_past_harmless_call(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                console.log("good");
                console.log(12);
                """
            ),
            self._deobfuscate_iterative(inspect.cleandoc(
                """
                function harmlessCall() {
                    if (x == 12) {
                        console.log("good");
                    }
                }
                var x = 12;
                harmlessCall();
                console.log(x);
                """
            )))

    def test_local_variable_not_inlined_past_modifying_call(self):
        source = inspect.cleandoc(
            """
            function f() {
              x = 9;
            }
            var a = 1;
            var x = a;
            f();
            console.log(x);
            """
        )
        self.assertIn(
            self._deobfuscate(source),
            (
                inspect.cleandoc(
                    """
                    var x = 1;
                    x = 9;
                    console.log(x);
                    """
                ),
                'console.log(9);',
            ),
        )

    @opportunity
    def test_a_copied_global_a_call_overwrites_is_read_as_the_value_the_call_stored(self):
        source = inspect.cleandoc(
            """
            function f() {
              x = 9;
            }
            var a = 1;
            var x = a;
            f();
            console.log(x);
            """
        )
        self.assertEqual('console.log(9);', self._deobfuscate(source))

    def test_read_of_lexical_in_dead_zone_is_not_relocated(self):
        source = inspect.cleandoc(
            """
            (function () {
                var r = x;
                let x;
                return r;
            })();
            """
        )
        self.assertIn(
            self._deobfuscate(source),
            (
                inspect.cleandoc(
                    """
                    (function() {
                      var r = x;
                      let x;
                    })();
                    """
                ),
                inspect.cleandoc(
                    """
                    (function() {
                      x;
                      let x;
                    })();
                    """
                ),
            ),
        )

    @opportunity
    def test_a_dead_zone_read_whose_binding_nothing_reads_is_kept_as_a_bare_read(self):
        source = inspect.cleandoc(
            """
            (function () {
                var r = x;
                let x;
                return r;
            })();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                (function() {
                  x;
                  let x;
                })();
                """
            ),
            self._deobfuscate(source),
        )

    def test_typeof_of_lexical_in_dead_zone_is_not_folded(self):
        source = inspect.cleandoc(
            """
            (function () {
                var r = typeof x;
                let x;
                return r;
            })();
            """
        )
        self.assertIn(
            self._deobfuscate(source),
            (
                inspect.cleandoc(
                    """
                    (function() {
                      var r = typeof x;
                      let x;
                    })();
                    """
                ),
                inspect.cleandoc(
                    """
                    (function() {
                      typeof x;
                      let x;
                    })();
                    """
                ),
                inspect.cleandoc(
                    """
                    (function() {
                      x;
                      let x;
                    })();
                    """
                ),
            ),
        )

    @opportunity
    def test_a_dead_zone_typeof_whose_binding_nothing_reads_is_kept_without_the_binding(self):
        source = inspect.cleandoc(
            """
            (function () {
                var r = typeof x;
                let x;
                return r;
            })();
            """
        )
        self.assertIn(
            self._deobfuscate(source),
            (
                inspect.cleandoc(
                    """
                    (function() {
                      typeof x;
                      let x;
                    })();
                    """
                ),
                inspect.cleandoc(
                    """
                    (function() {
                      x;
                      let x;
                    })();
                    """
                ),
            ),
        )

    def test_typeof_of_lexical_declared_first_still_folds(self):
        source = inspect.cleandoc(
            """
            console.log((function () {
                let x = 5;
                return typeof x;
            })());
            """
        )
        self.assertEqual("console.log('number');", self._deobfuscate(source))

    @opportunity
    def test_a_call_folded_to_a_value_nothing_reads_leaves_nothing(self):
        source = inspect.cleandoc(
            """
            (function () {
                let x = 5;
                return typeof x;
            })();
            """
        )
        self.assertEqual('', self._deobfuscate(source))

    def test_object_property_reading_lexical_in_dead_zone_is_not_folded(self):
        source = inspect.cleandoc(
            """
            (function () {
                var o = { p: x };
                let x;
                return o.p;
            })();
            """
        )
        self.assertIn(
            self._deobfuscate(source),
            (
                self._run_transformers(source),
                inspect.cleandoc(
                    """
                    (function() {
                      var o = { p: x };
                      let x;
                    })();
                    """
                ),
                inspect.cleandoc(
                    """
                    (function() {
                      x;
                      let x;
                    })();
                    """
                ),
            ),
        )

    @opportunity
    def test_a_dead_zone_read_building_an_object_nothing_reads_is_kept_as_a_bare_read(self):
        source = inspect.cleandoc(
            """
            (function () {
                var o = { p: x };
                let x;
                return o.p;
            })();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                (function() {
                  x;
                  let x;
                })();
                """
            ),
            self._deobfuscate(source),
        )


class TestGlobalAliasStripping(TestJsDeobfuscator):

    def test_const_alias_to_global_preserves_property_assignment(self):
        source = inspect.cleandoc(
            """
            global['_V'] = "7-4111";
            (async () => {
                const c = global;
                console.log(c._V);
            })()
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                global._V = "7-4111";
                (async () => {
                  console.log(_V);
                })();
                """
            ),
            self._deobfuscate(source),
        )

    def test_dead_global_property_is_removed(self):
        source = inspect.cleandoc(
            """
            globalThis['_V'] = "7-4111";
            globalThis['_W'] = "dead";
            (async () => {
                const c = globalThis;
                console.log(c._V);
            })()
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                globalThis._V = "7-4111";
                (async () => {
                  console.log(_V);
                })();
                """
            ),
            self._deobfuscate(source),
        )


class TestOpaquePredicate(TestJsDeobfuscator):

    def test_in_predicate_pruned_without_property_store(self):
        source = inspect.cleandoc(
            """
            function f() {}
            if ("xyz" in f) {
                dead();
            }
            live();
            """
        )
        self.assertEqual(
            'live();',
            self._deobfuscate(source),
        )

    def test_in_predicate_true_when_property_exists(self):
        source = inspect.cleandoc(
            """
            function f() {}
            f.xyz = 1;
            if ("xyz" in f) {
                console.log("Hello World!");
            }
            """
        )
        self.assertEqual(
            'console.log("Hello World!");',
            self._deobfuscate(source),
        )

    def test_in_predicate_builtin_on_nonempty_function(self):
        source = inspect.cleandoc(
            """
            function handler(x) { return x + 1; }
            if ("hasOwnProperty" in handler) {
                live();
            } else {
                dead();
            }
            """
        )
        self.assertEqual(
            'live();',
            self._deobfuscate(source),
        )


class TestDeobfuscationStepBound(TestJsDeobfuscator):

    SOURCE = 'var x = 1; if (x === 1) { SINK(1); } else { dead(); }'

    def test_max_steps_bound_raises(self):
        ast = JsParser(self.SOURCE).parse()
        with self.assertRaises(DeobfuscationTimeout):
            deobfuscate(ast, max_steps=1)

    def test_default_bound_completes_a_normal_program(self):
        ast = JsParser(self.SOURCE).parse()
        deobfuscate(ast)
        self.assertEqual('SINK(1);', JsSynthesizer().convert(ast))
