from __future__ import annotations

import inspect

from test import backlog, opportunity, todo
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.evaluator import JsFunctionEvaluator
from refinery.lib.scripts.js.deobfuscation.interpreter import IrreducibleExpression, JsInterpreter
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.lib.scripts.js.model import (
    JsFunctionDeclaration,
    JsIdentifier,
    JsReturnStatement,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.scripts.js.values import JsBuffer


class TestFunctionEvaluator(TestJsDeobfuscator):

    def test_bare_assignment_function_call_folded(self):
        source = inspect.cleandoc(
            """
            var scale;
            scale = function(n) {
              return n * 3;
            };
            SINK(scale(7));
            """
        )
        self.assertEqual('SINK(21);', self._deobfuscate(source))

    def test_iife_with_nested_arrow_this_not_evaluated(self):
        source = inspect.cleandoc(
            """
            var r = (function(n) {
              return (() => this.x)();
            })(1);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_async_function_call_not_evaluated_to_value(self):
        source = inspect.cleandoc(
            """
            async function m() {
              return 1;
            }
            var p = m();
            SINK(p);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_generator_function_call_not_evaluated_to_value(self):
        source = inspect.cleandoc(
            """
            function* m() {
              return 1;
            }
            var p = m();
            SINK(p);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_reassigned_function_declaration_not_folded(self):
        source = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            f = function() {
              return 9;
            };
            SINK(f());
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_redeclared_function_not_folded(self):
        source = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            function f() {
              return 9;
            }
            SINK(f());
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_premature_call_before_const_definition_not_folded(self):
        source = inspect.cleandoc(
            """
            SINK(f());
            const f = () => 1;
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_premature_call_before_var_definition_not_folded(self):
        source = inspect.cleandoc(
            """
            SINK(f());
            var f = function() {
              return 1;
            };
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_premature_call_before_let_definition_not_folded(self):
        source = inspect.cleandoc(
            """
            SINK(f());
            let f = () => 1;
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_premature_call_before_hoisted_declaration_folded(self):
        source = inspect.cleandoc(
            """
            SINK(f());
            function f() {
              return 1;
            }
            """
        )
        self.assertEqual('SINK(1);', self._evaluate(source))

    def test_nested_callee_not_established_at_outer_call_not_folded(self):
        source = inspect.cleandoc(
            """
            var ns;
            ns = function() {
              return helper();
            };
            var r = ns();
            var helper = function() {
              return 7;
            };
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_nested_callee_established_at_outer_call_folded(self):
        source = inspect.cleandoc(
            """
            var helper = function() {
              return 7;
            };
            var ns = function() {
              return helper();
            };
            var r = ns();
            """
        )
        self.assertEqual('var r = 7;', self._evaluate(source))

    def test_var_initialized_function_call_folded(self):
        source = inspect.cleandoc(
            """
            var f = function() {
              return 1;
            };
            SINK(f());
            """
        )
        self.assertEqual('SINK(1);', self._evaluate(source))

    def test_let_initialized_function_call_folded(self):
        source = inspect.cleandoc(
            """
            let f = () => 1;
            SINK(f());
            """
        )
        self.assertEqual('SINK(1);', self._evaluate(source))

    def test_block_scoped_const_function_call_folded(self):
        source = inspect.cleandoc(
            """
            {
              const f = () => 1;
              SINK(f());
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                {
                  SINK(1);
                }
                """
            ),
            self._evaluate(source),
        )

    def test_call_through_reassigned_nested_callee_not_folded(self):
        source = inspect.cleandoc(
            """
            function inner() {
              return 1;
            }
            inner = function() {
              return 9;
            };
            function outer() {
              return inner();
            }
            SINK(outer());
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_nested_closure_over_reassigned_shadowing_local_not_folded(self):
        source = inspect.cleandoc(
            """
            function g() {
              return 2;
            }
            function mid() {
              function g() {
                return 1;
              }
              g = function() {
                return 9;
              };
              function inner() {
                return g();
              }
              return inner();
            }
            SINK(mid());
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_nested_closure_over_redeclared_shadowing_local_not_folded(self):
        source = inspect.cleandoc(
            """
            function g() {
              return 2;
            }
            function mid() {
              function g() {
                return 1;
              }
              function g() {
                return 9;
              }
              function inner() {
                return g();
              }
              return inner();
            }
            SINK(mid());
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_nested_closure_over_stable_shadowing_local_folds(self):
        source = inspect.cleandoc(
            """
            function g() {
              return 2;
            }
            function mid() {
              function g() {
                return 7;
              }
              function inner() {
                return g();
              }
              return inner();
            }
            SINK(mid());
            """
        )
        expected = inspect.cleandoc(
            """
            function g() {
              return 2;
            }
            SINK(7);
            """
        )
        self.assertEqual(expected, self._evaluate(source))

    def test_call_with_nested_implicit_global_write_not_folded(self):
        source = inspect.cleandoc(
            """
            var SINK = [];
            function v1() {
              function v2() {
                v0 = 12;
              }
              return v2();
            }
            function v5() {
              for (let i = 0; i < 1; i++) {
                SINK.push(v1());
              }
              return v0;
            }
            SINK.push(v5());
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_simple_arithmetic(self):
        source = inspect.cleandoc(
            """
            function calc(op, a, b) {
                switch (op) {
                    case 'add': return a + b;
                    case 'sub': return a - b;
                    case 'mul': return a * b;
                }
            }
            var x = calc('add', 10, 20);
            var y = calc('sub', 100, 42);
            var z = calc('mul', 3, 7);
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 30;
                var y = 58;
                var z = 21;
                """
            ),
            result,
        )

    def test_string_decoder_xor(self):
        source = inspect.cleandoc(
            """
            function decode(encoded, key) {
                var result = '';
                for (var i = 0; i < encoded.length; i++) {
                    result += String.fromCharCode(encoded.charCodeAt(i) ^ key);
                }
                return result;
            }
            var msg = decode('Kfool', 3);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var msg = 'Hello';", result)

    def test_switch_lookup_single_arg(self):
        source = inspect.cleandoc(
            """
            function lookup(key) {
                switch (key) {
                    case 'a': return 'alpha';
                    case 'b': return 'beta';
                    case 'c': return 'gamma';
                }
            }
            var x = lookup('b');
            var y = lookup('a');
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'beta';
                var y = 'alpha';
                """
            ),
            result,
        )

    def test_irreducible_expression_member_access(self):
        source = inspect.cleandoc(
            """
            function getGlobal(mapping) {
                switch (mapping) {
                    case 'a': return globalVar['console'];
                    case 'b': return globalVar['Object'];
                }
            }
            var x = getGlobal('a');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = globalVar['console'];", result)

    def test_irreducible_object_shorthand_substitutes_param(self):
        source = inspect.cleandoc(
            """
            function f(a) { return JSON && { a }; }
            var x = f(7);
            """
        )
        self.assertEqual('var x = JSON && { a: 7 };', self._evaluate(source))

    def test_iife_evaluation(self):
        source = inspect.cleandoc(
            """
            var x = (function(a, b) { return a + b; })(10, 20);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var x = 30;', result)

    def test_iife_arrow_function(self):
        source = inspect.cleandoc(
            """
            var x = ((a, b) => a * b)(6, 7);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var x = 42;', result)

    def test_impure_function_not_evaluated(self):
        source = inspect.cleandoc(
            """
            function impure(x) {
              console.log(x);
              return x + 1;
            }
            var y = impure(5);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_non_literal_args_skipped(self):
        source = inspect.cleandoc(
            """
            function add(a, b) {
              return a + b;
            }
            var x = add(1, y);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_function_preserved_when_partial_resolution(self):
        source = inspect.cleandoc(
            """
            function add(a, b) { return a + b; }
            var x = add(1, 2);
            var y = add(3, z);
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function add(a, b) {
                  return a + b;
                }
                var x = 3;
                var y = add(3, z);
                """
            ),
            result,
        )

    def test_nested_function_calls(self):
        source = inspect.cleandoc(
            """
            function double(x) { return x * 2; }
            function addDoubles(a, b) { return double(a) + double(b); }
            var result = addDoubles(3, 4);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var result = 14;", result)

    def test_string_methods(self):
        source = inspect.cleandoc(
            """
            function upper(s) { return s.toUpperCase(); }
            var x = upper('hello');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'HELLO';", result)

    def test_array_operations(self):
        source = inspect.cleandoc(
            """
            function buildAndJoin(a, b, c) {
                var arr = [a, b, c];
                return arr.join('-');
            }
            var x = buildAndJoin('x', 'y', 'z');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'x-y-z';", result)

    def test_dead_function_chain_removal(self):
        source = inspect.cleandoc(
            """
            function helper(x) { return x + 1; }
            function wrapper(x) { return helper(x) * 2; }
            var result = wrapper(5);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var result = 12;", result)

    def test_loop_safety_limit(self):
        source = inspect.cleandoc(
            """
            function infinite(x) {
              while (true) {
                x++;
              }
              return x;
            }
            var y = infinite(0);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_from_char_code(self):
        source = inspect.cleandoc(
            """
            function decode(a, b, c) {
                return String.fromCharCode(a, b, c);
            }
            var x = decode(72, 105, 33);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hi!';", result)

    def test_array_map(self):
        source = inspect.cleandoc(
            """
            function transform(arr) {
                return arr.map(function(x) { return x * 2; });
            }
            var x = transform([1, 2, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = [2, 4, 6];", result)

    def test_array_filter(self):
        source = inspect.cleandoc(
            """
            function evens(arr) {
                return arr.filter(function(x) { return x % 2 === 0; });
            }
            var x = evens([1, 2, 3, 4, 5, 6]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = [2, 4, 6];", result)

    def test_array_every(self):
        source = inspect.cleandoc(
            """
            function allPositive(arr) {
                return arr.every(function(x) { return x > 0; });
            }
            var a = allPositive([1, 2, 3]);
            var b = allPositive([1, -1, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = true;
                var b = false;
                """
            ),
            result,
        )

    def test_array_some(self):
        source = inspect.cleandoc(
            """
            function hasNegative(arr) {
                return arr.some(function(x) { return x < 0; });
            }
            var a = hasNegative([1, -1, 3]);
            var b = hasNegative([1, 2, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = true;
                var b = false;
                """
            ),
            result,
        )

    def test_array_find(self):
        source = inspect.cleandoc(
            """
            function firstBig(arr) {
                return arr.find(function(x) { return x > 10; });
            }
            var x = firstBig([3, 7, 15, 20]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 15;", result)

    def test_array_find_index(self):
        source = inspect.cleandoc(
            """
            function indexOfBig(arr) {
                return arr.findIndex(function(x) { return x > 10; });
            }
            var x = indexOfBig([3, 7, 15, 20]);
            var y = indexOfBig([1, 2, 3]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 2;
                var y = -1;
                """
            ),
            result,
        )

    def test_array_reduce(self):
        source = inspect.cleandoc(
            """
            function sum(arr) {
                return arr.reduce(function(acc, x) { return acc + x; }, 0);
            }
            var x = sum([1, 2, 3, 4]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 10;", result)

    def test_array_reduce_no_initial(self):
        source = inspect.cleandoc(
            """
            function product(arr) {
                return arr.reduce(function(acc, x) { return acc * x; });
            }
            var x = product([2, 3, 4]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 24;", result)

    def test_array_map_with_arrow(self):
        source = inspect.cleandoc(
            """
            function encode(arr) {
                return arr.map(x => x + 1);
            }
            var x = encode([10, 20, 30]);
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = [11, 21, 31];", result)

    def test_atob_in_function(self):
        source = inspect.cleandoc(
            """
            function d(s) { return atob(s); }
            var x = d('SGVsbG8=');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello';", result)

    def test_helper_call_at_iteration_limit(self):
        source = inspect.cleandoc(
            """
            function sum(arr) {
                var r = 0;
                for (var i = 0; i < arr.length; i++) r += arr[i];
                return r;
            }
            function decode(s) {
                var r = '';
                for (var i = 0; i < s.length; i++) {
                    r += String.fromCharCode(s.charCodeAt(i) ^ 1);
                }
                return sum([r.length, 0]);
            }
            var x = decode('Iello');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var x = 5;', result)

    def test_parenthesized_object_literal_initializer_is_kept_with_or_without_its_parens(self):
        self.assertIn(
            self._simplify('var x = ({a: 1});'), ('var x = ({ a: 1 });', 'var x = { a: 1 };')
        )

    def test_fold_resolves_callee_free_name_in_definition_scope(self):
        source = inspect.cleandoc(
            """
            function g(x) {
              return x + 1;
            }
            function f(n) {
              return g(n) + 10;
            }
            function caller() {
              function g(x) {
                return x + 100;
              }
              return f(5);
            }
            sink(g, f, caller);
            """
        )
        expected = inspect.cleandoc(
            """
            function g(x) {
              return x + 1;
            }
            function f(n) {
              return g(n) + 10;
            }
            function caller() {
              function g(x) {
                return x + 100;
              }
              return 16;
            }
            sink(g, f, caller);
            """
        )
        self.assertEqual(expected, self._evaluate(source))

    def test_irreducible_substitution_declined_when_parameter_reassigned(self):
        source = inspect.cleandoc(
            """
            (function(x) {
              x = 7;
              return x + String;
            })(1);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_irreducible_substitution_declined_for_named_function_expression_self_name(self):
        source = inspect.cleandoc(
            """
            var y = (function f() {
              return f;
            })();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_irreducible_substitution_declined_for_destructured_local(self):
        source = inspect.cleandoc(
            """
            var w = (function() {
              return String;
              var { String } = Math;
            })();
            """
        )
        self.assertIn(self._evaluate(source), (source, 'var w = void 0;'))

    @opportunity
    def test_a_local_returned_before_its_declaration_runs_folds_to_undefined(self):
        source = inspect.cleandoc(
            """
            var w = (function() {
              return String;
              var { String } = Math;
            })();
            """
        )
        self.assertEqual('var w = void 0;', self._evaluate(source))

    def test_array_result_over_the_size_cap_is_not_folded(self):
        elements = ', '.join(str(n) for n in range(300))
        result = self._evaluate(F'[{elements}].map(function (x) {{ return x + 1; }});')
        self.assertEqual(1, result.count('.map('))
        self.assertEqual(0, result.count('300'))

    def test_string_result_over_the_array_size_cap_still_folds(self):
        elements = ', '.join(str(n) for n in range(300))
        folded = F"[{elements}].map(function (x) {{ return x + 1; }}).join('');"
        expected = ''.join(str(n + 1) for n in range(300))
        self.assertEqual(F"'{expected}';", self._evaluate(folded).replace('\n', '').strip())


    def test_const_arrow_with_outer_string(self):
        source = inspect.cleandoc(
            """
            const prefix = 'Hello';
            const greet = (name) => prefix + ', ' + name + '!';
            var msg = greet('World');
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const prefix = 'Hello';
                var msg = 'Hello, World!';
                """
            ),
            result,
        )

    def test_const_function_expression_with_xor_loop(self):
        source = inspect.cleandoc(
            """
            const key = [3, 3, 3, 3, 3];
            const decode = function(encoded) {
                var result = '';
                for (var i = 0; i < encoded.length; i++) {
                    result += String.fromCharCode(encoded.charCodeAt(i) ^ key[i % key.length]);
                }
                return result;
            };
            var msg = decode('Kfool');
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const key = [3, 3, 3, 3, 3];
                var msg = 'Hello';
                """
            ),
            result,
        )

    def test_closure_function_calls_sibling(self):
        source = inspect.cleandoc(
            """
            const inner = (x) => x * 2;
            const outer = (a, b) => inner(a) + inner(b);
            var result = outer(3, 4);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var result = 14;', result)

    def test_buffer_from_base64_toString(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'base64').toString('utf8');
            var x = decode('SGVsbG8=');
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var x = 'Hello';", result)

    @backlog
    def test_a_buffer_decode_is_not_folded_where_the_host_may_lack_buffer(self):
        source = inspect.cleandoc(
            """
            const decode = s => Buffer.from(s, 'base64').toString('utf8');
            var x = decode('SGVsbG8=');
            """
        )
        spliced = "var x = Buffer.from('SGVsbG8=', 'base64').toString('utf8');"
        self.assertIn(self._evaluate(source), (source, spliced))

    def test_buffer_from_hex(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'hex').toString('utf8');
            var x = decode('48656c6c6f');
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var x = 'Hello';", result)

    def test_atob_without_padding(self):
        source = inspect.cleandoc(
            """
            function d(s) { return atob(s); }
            var x = d('b3M');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'os';", result)

    def test_member_write_to_an_argument_the_caller_reads_blocks_evaluation(self):
        source = inspect.cleandoc(
            """
            const modify = function(arr) {
              arr[0] = 99;
              return arr;
            };
            var a = [1, 2, 3];
            var x = modify(a);
            SINK(a);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    @opportunity
    def test_member_write_to_a_fresh_array_argument_folds(self):
        source = inspect.cleandoc(
            """
            const modify = function(arr) {
              arr[0] = 99;
              return arr;
            };
            var x = modify([1, 2, 3]);
            """
        )
        self.assertEqual('var x = [99, 2, 3];', self._evaluate(source))

    def test_function_declaration_with_undeclared_globals_not_evaluated(self):
        source = inspect.cleandoc(
            """
            function fizzbuzz(n) {
              results = [];
              for (var i = 1; i <= n; i++) {
                if (i % 15 === 0) {
                  results.push('FizzBuzz');
                } else {
                  if (i % 3 === 0) {
                    results.push('Fizz');
                  } else {
                    results.push(i);
                  }
                }
              }
              return results;
            }
            console.log(fizzbuzz(20));
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_orphaned_closure_constants_removed(self):
        source = inspect.cleandoc(
            """
            const secret = 'key';
            const decode = (s) => secret + s;
            var x = decode('123');
            console.log(x);
            """
        )
        result = self._deobfuscate_iterative(source)
        self.assertEqual("console.log('key123');", result)

    def test_a_let_never_reassigned_is_read_by_the_call(self):
        source = inspect.cleandoc(
            """
            let prefix = 'Hello';
            const greet = name => prefix + ', ' + name;
            var msg = greet('World');
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                let prefix = 'Hello';
                var msg = 'Hello, World';
                """
            ),
            self._evaluate(source),
        )

    def test_self_assigning_function_not_evaluated(self):
        source = inspect.cleandoc(
            """
            const decode = function(x) {
              decode = function() {
                return [];
              };
              return x;
            };
            var y = decode('test');
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_array_tostring_not_hijacked(self):
        source = inspect.cleandoc(
            """
            const f = () => [72, 101, 108].toString();
            var x = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = '72,101,108';", result)

    def test_param_shadow_blocks_const_resolution(self):
        source = inspect.cleandoc(
            """
            const p = 'OUTER';
            function pick(z) {
              return 'got:' + z;
            }
            function run(p) {
              sink.x = 1;
              return pick(p);
            }
            run('REAL');
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_let_shadow_blocks_closure_capture(self):
        source = inspect.cleandoc(
            """
            const SECRET = 'global';
            function wrap(v) {
              let SECRET = v;
              const f = x => x + SECRET;
              return f('Z');
            }
            """
        )
        spliced = inspect.cleandoc(
            """
            const SECRET = 'global';
            function wrap(v) {
              let SECRET = v;
              return 'Z' + SECRET;
            }
            """
        )
        self.assertIn(self._evaluate(source), (source, spliced))

    def test_a_call_reversing_a_captured_array_stays(self):
        source = inspect.cleandoc(
            """
            const key = [1, 2, 3];
            const dec = s => {
              key.reverse();
              return s + key[0];
            };
            var a = dec('A');
            var b = dec('B');
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_write_only_temp_does_not_block_evaluation(self):
        source = inspect.cleandoc(
            """
            const dec = (s) => { junk = 'x'; return s + '!'; };
            var r = dec('hi');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'hi!';", result)

    def test_global_temp_read_outside_blocks_evaluation(self):
        source = inspect.cleandoc(
            """
            const dec = function(s) {
              rr = s;
              return 'x';
            };
            var y = dec('hi');
            console.log(rr);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_block_scoped_const_fn_not_visible_outside(self):
        source = inspect.cleandoc(
            """
            {
              const f = x => x + 1;
            }
            var y = f(3);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_param_shadowing_function_name_blocks_resolution(self):
        source = inspect.cleandoc(
            """
            const f = x => x + 1;
            function outer(f) {
              return f(10);
            }
            var r = outer(5);
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_sibling_declarator_reference_prevents_removal(self):
        source = inspect.cleandoc(
            """
            const a = (x) => x + 1, b = a;
            var r = a(5);
            console.log(b);
            """
        )
        result = self._evaluate(source)
        expected = inspect.cleandoc(
            """
            const a = x => x + 1, b = a;
            var r = 6;
            console.log(b);
            """
        )
        self.assertEqual(expected, result)


    def test_try_catch_body_executed(self):
        source = inspect.cleandoc(
            """
            function attempt() {
                try {
                    throw 1;
                } catch(e) {
                    return 'caught';
                }
            }
            var r = attempt();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'caught';", result)

    def test_try_catch_param_bound(self):
        source = inspect.cleandoc(
            """
            function attempt() {
                try {
                    throw 1;
                } catch(e) {
                    return e;
                }
            }
            var r = attempt();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 1;', result)

    def test_try_finally_executes(self):
        source = inspect.cleandoc(
            """
            function run() {
                var x = 0;
                try {
                    x = 1;
                } finally {
                    x = 2;
                }
                return x;
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 2;', result)

    def test_try_catch_finally_executes(self):
        source = inspect.cleandoc(
            """
            function run() {
                var x = 0;
                try {
                    throw 1;
                } catch(e) {
                    x = e;
                } finally {
                    x = x + 10;
                }
                return x;
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 11;', result)

    def test_buffer_map_then_tostring(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'base64').map(b => b ^ 1).toString('latin1');
            var x = decode('SEVMTE8=');
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var x = 'IDMMN';", result)

    def test_buffer_filter_then_tostring(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'hex').filter(b => b > 64).toString('utf8');
            var x = decode('4100420043');
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var x = 'ABC';", result)

    def test_nan_as_index_does_not_raise(self):
        source = inspect.cleandoc(
            """
            const f = (s, idx) => s.charAt(idx);
            var r = f('hello', 'x');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'h';", result)

    def test_nan_slice_arg_treated_as_zero(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.slice('x');
            var r = f('abc');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'abc';", result)

    def test_math_floor_nan_returns_nan(self):
        source = inspect.cleandoc(
            """
            const f = () => Math.floor(NaN);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 0 / 0;', result)

    def test_math_round_nan_returns_nan(self):
        source = inspect.cleandoc(
            """
            const f = () => Math.round(NaN);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 0 / 0;', result)

    def test_property_key_not_substituted(self):
        source = inspect.cleandoc(
            """
            const f = (x) => { switch (x) { case 42: return globalObj.x; } };
            var r = f(42);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = globalObj.x;', result)

    def test_object_literal_value_substituted_key_preserved(self):
        source = inspect.cleandoc(
            """
            const f = (x) => ({ x: x });
            var r = f(42);
            """
        )
        result = self._evaluate(source)
        self.assertIn(result, ("var r = { 'x': 42 };", 'var r = { x: 42 };'))

    def test_nested_throw_caught_by_outer_try_catch(self):
        source = inspect.cleandoc(
            """
            function inner() { throw 'caught_value'; }
            function outer() {
                try { inner(); } catch(e) { return e; }
            }
            var r = outer();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'caught_value';", result)

    def test_runtime_error_caught_by_try_catch(self):
        source = inspect.cleandoc(
            """
            function attempt() {
                try {
                    var x = null;
                    x();
                    return 'unreachable';
                } catch(e) {
                    return 'fallback';
                }
            }
            var r = attempt();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'fallback';", result)

    def test_finally_does_not_swallow_return(self):
        source = inspect.cleandoc(
            """
            function run() {
                try { return 42; } finally { var x = 1; }
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 42;', result)

    def test_to_int_infinity_does_not_raise(self):
        source = inspect.cleandoc(
            """
            const f = () => 'hello'.charAt(Infinity);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = '';", result)

    def test_bitwise_not_infinity(self):
        source = inspect.cleandoc(
            """
            const f = () => ~Infinity;
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = -1;', result)

    def test_math_floor_infinity(self):
        source = inspect.cleandoc(
            """
            const f = () => Math.floor(Infinity);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 1e999;', result)

    def test_math_trunc_infinity(self):
        source = inspect.cleandoc(
            """
            const f = () => Math.trunc(Infinity);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 1e999;', result)

    def test_buffer_from_base64url(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'base64').toString('utf8');
            var x = decode('SGVsbG8-');
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var x = 'Hello>';", result)

    def test_a_const_declared_after_the_function_is_read_by_a_call_after_it(self):
        source = inspect.cleandoc(
            """
            const fn = () => x;
            const x = 5;
            var r = fn();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                const x = 5;
                var r = 5;
                """
            ),
            self._evaluate(source),
        )

    def test_finally_runs_when_catch_body_throws(self):
        source = inspect.cleandoc(
            """
            function run() {
                var cleaned = 0;
                try {
                    try {
                        throw 'first';
                    } catch(e) {
                        cleaned = 1;
                        throw 'second';
                    } finally {
                        cleaned = cleaned + 10;
                    }
                } catch(e2) {
                    return cleaned;
                }
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 11;', result)

    def test_finally_runs_when_catch_body_returns(self):
        source = inspect.cleandoc(
            """
            function run() {
                var x = 0;
                try {
                    throw 1;
                } catch(e) {
                    x = e;
                    return x;
                } finally {
                    x = x + 100;
                }
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 1;', result)

    def test_finally_runs_when_try_returns(self):
        source = inspect.cleandoc(
            """
            function run() {
                var x = 0;
                try {
                    x = 1;
                    return x;
                } finally {
                    x = 2;
                }
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 1;', result)

    def test_catch_variable_does_not_leak(self):
        source = inspect.cleandoc(
            """
            function f(e) {
                try { throw 42; } catch(e) {}
                return e;
            }
            var r = f(12);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 12;', result)

    def test_last_index_of_negative_position(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.lastIndexOf('h', -1);
            var r = f('hello');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 0;', result)

    def test_last_index_of_large_negative_position(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.lastIndexOf('l', -5);
            var r = f('hello world');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = -1;', result)

    def test_array_length_nan_assignment_throws_a_range_error(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                try {
                    a['length'] = 0 / 0;
                } catch (e) {
                    return e.name;
                }
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        self.assertEqual('RangeError', JsInterpreter().execute(func, []))

    def test_array_length_infinity_assignment_throws_a_range_error(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                try {
                    a['length'] = 1 / 0;
                } catch (e) {
                    return e.name;
                }
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        self.assertEqual('RangeError', JsInterpreter().execute(func, []))

    def test_array_length_non_integer_assignment_throws_a_range_error(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                try {
                    a['length'] = 1.5;
                } catch (e) {
                    return e.name;
                }
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        self.assertEqual('RangeError', JsInterpreter().execute(func, []))

    def test_array_length_shrink_truncates(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                a['length'] = 2;
                return a;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        self.assertEqual([1, 2], JsInterpreter().execute(func, []))

    def test_array_length_grow_is_not_evaluated_to_an_array_of_undefined(self):
        """
        Raising `length` leaves holes rather than `undefined` elements: `3 in a` is `false` for this
        array, and `true` once the same positions hold `undefined`.
        """
        source = inspect.cleandoc(
            """
            function f() {
              var a = [1, 2, 3];
              a['length'] = 5;
              return a;
            }
            var r = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def _evaluate_in(self, source: str, environment: HostEnvironment) -> str:
        return self._run_transformer(
            source, JsFunctionEvaluator, DeobfuscationOptions(environment=environment))

    def test_typeof_a_host_conditional_global_abstains_without_a_pin(self):
        source = inspect.cleandoc(
            """
            const f = () => typeof Buffer === 'function' ? 'yes' : 'no';
            var r = f();
            """
        )
        self.assertEqual(
            "var r = typeof Buffer === 'function' ? 'yes' : 'no';", self._evaluate(source))

    def test_typeof_a_host_conditional_global_folds_under_a_pin(self):
        source = inspect.cleandoc(
            """
            const f = () => typeof Buffer === 'function' ? 'yes' : 'no';
            var r = f();
            """
        )
        self.assertEqual("var r = 'yes';", self._evaluate_in(source, HostEnvironment.node))
        self.assertEqual("var r = 'no';", self._evaluate_in(source, HostEnvironment.browser))

    def test_calling_null_throws_caught_type_error(self):
        source = inspect.cleandoc(
            """
            function attempt() {
                try {
                    var x = null;
                    x();
                    return 'unreachable';
                } catch(e) {
                    return typeof e;
                }
            }
            var r = attempt();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'object';", result)

    def test_catch_clause_param_shadows_outer_const(self):
        source = inspect.cleandoc(
            """
            const secret = 'outer';
            function run() {
                try {
                    throw 'inner';
                } catch(secret) {
                    return secret;
                }
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        expected = inspect.cleandoc(
            """
            const secret = 'outer';
            var r = 'inner';
            """
        )
        self.assertEqual(expected, result)

    def test_catch_handler_irreducible_runs_finalizer(self):
        source = inspect.cleandoc(
            """
            function run() {
                try {
                    throw 1;
                } catch(e) {
                    return externalVar;
                } finally {
                    return 'final';
                }
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        result = JsInterpreter().execute(func, [])
        self.assertEqual('final', result)

    def test_irreducible_from_try_block_preserves_node(self):
        source = inspect.cleandoc(
            """
            function run() {
                try { return externalVar; } finally {}
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        with self.assertRaises(IrreducibleExpression) as ctx:
            JsInterpreter().execute(func, [])
        node = ctx.exception.node
        self.assertIsInstance(node, JsIdentifier)
        assert isinstance(node, JsIdentifier)
        self.assertEqual('externalVar', node.name)

    def test_buffer_from_result_not_inlined_as_integer_array(self):
        source = inspect.cleandoc(
            """
            const toBytes = s => Buffer.from(s, 'base64');
            var x = toBytes('SGVsbG8=');
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_split_undefined_returns_whole_string(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.split(undefined).length;
            var r = f('foo_undefined_bar');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 1;', result)

    def test_a_hoisted_var_shadowing_the_outer_const_is_the_one_read(self):
        source = inspect.cleandoc(
            """
            const x = 'outer';
            function wrap() {
              const f = () => x;
              var x = 'inner';
              return f();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                const x = 'outer';
                function wrap() {
                  var x = 'inner';
                  return 'inner';
                }
                """
            ),
            self._evaluate(source),
        )

    def test_var_hoisting_shadows_outer_const_in_arg_resolution(self):
        source = inspect.cleandoc(
            """
            const val = 'WRONG';
            function pick(x) {
              return x;
            }
            function wrap() {
              var r = pick(val);
              var val = 'RIGHT';
              return r;
            }
            """
        )
        folded = inspect.cleandoc(
            """
            const val = 'WRONG';
            function wrap() {
              var r = void 0;
              var val = 'RIGHT';
              return r;
            }
            """
        )
        self.assertIn(self._evaluate(source), (source, folded))

    def test_split_negative_limit_returns_all(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.split(',', -1);
            var r = f('a,b,c');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = ['a', 'b', 'c'];", result)

    def test_starts_with_negative_position(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.startsWith('h', -3);
            var r = f('hello');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = true;', result)

    def test_ends_with_negative_position(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.endsWith('hell', -1);
            var r = f('hello');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = false;', result)

    def test_throw_signal_caught_in_arrow_concise_body(self):
        source = inspect.cleandoc(
            """
            function bang() { throw 'boom'; }
            function wrapper() {
                const f = () => bang();
                try { return f(); } catch(e) { return e; }
            }
            var r = wrapper();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'boom';", result)

    def test_array_is_array_false_for_buffer(self):
        source = inspect.cleandoc(
            """
            const f = () => Array.isArray(Buffer.from('AA==', 'base64'));
            var r = f();
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual('var r = false;', result)

    def test_buffer_tostring_with_infinity_element(self):
        source = inspect.cleandoc(
            """
            function run() {
                try { return Buffer.from([72, Infinity, 108]).toString('hex'); }
                catch(e) { return 'caught'; }
            }
            var r = run();
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var r = '48006c';", result)

    def test_buffer_from_list_coerces_null_to_zero(self):
        source = inspect.cleandoc(
            """
            const f = () => Buffer.from([72, null, 108]).toString('latin1');
            var r = f();
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var r = 'H\\0l';", result)

    def test_arr_index_of_negative_from_index(self):
        source = inspect.cleandoc(
            """
            const f = () => [10, 20, 30].indexOf(10, -1);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = -1;', result)

    def test_nested_var_hoisting_shadows_outer_const(self):
        source = inspect.cleandoc(
            """
            const x = 'outer';
            const f = () => x;
            function wrap() {
                const g = () => x;
                if (true) { var x = 'inner'; }
                return g();
            }
            var a = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const x = 'outer';
                function wrap() {
                  if (true) {
                    var x = 'inner';
                  }
                  return x;
                }
                var a = 'outer';
                """
            ),
            result,
        )

    def test_nested_var_hoisting_blocks_const_arg_resolution(self):
        source = inspect.cleandoc(
            """
            const val = 'WRONG';
            function pick(x) {
              return x;
            }
            function wrap() {
              var r = pick(val);
              if (true) {
                var val = 'RIGHT';
              }
              return r;
            }
            """
        )
        folded = inspect.cleandoc(
            """
            const val = 'WRONG';
            function wrap() {
              var r = void 0;
              if (true) {
                var val = 'RIGHT';
              }
              return r;
            }
            """
        )
        self.assertIn(self._evaluate(source), (source, folded))

    def test_two_calls_reading_one_table_fold_alike(self):
        source = inspect.cleandoc(
            """
            const key = [1, 2, 3];
            const enc = (s) => {
                var r = '';
                for (var i = 0; i < s.length; i++) {
                    r += String.fromCharCode(s.charCodeAt(i) ^ key[i % key.length]);
                }
                return r;
            };
            var a = enc('ABC');
            var b = enc('ABC');
            """
        )
        result = self._evaluate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            const key = [1, 2, 3];
            var a = '@@@';
            var b = '@@@';
            """
        ))

    def test_parseInt_nan_radix_does_not_crash(self):
        source = inspect.cleandoc(
            """
            function f() { return parseInt('5', undefined); }
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 5;', result)

    def test_in_operator_nan_index_does_not_crash(self):
        source = inspect.cleandoc(
            """
            function f() { return ({}) in [1, 2, 3]; }
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = false;', result)

    def test_a_let_in_a_block_of_the_caller_leaves_the_const_its_closure_reads(self):
        source = inspect.cleandoc(
            """
            const x = 'outer';
            function wrap() {
                const f = () => x;
                if (true) { let x = 'inner'; }
                return f();
            }
            var r = wrap();
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const x = 'outer';
                var r = 'outer';
                """
            ),
            result,
        )

    def test_let_in_nested_block_does_not_block_arg_resolution(self):
        source = inspect.cleandoc(
            """
            const val = 'OK';
            function pick(x) { return x; }
            function wrap() {
                var r = pick(val);
                if (true) { let val = 'WRONG'; }
                return r;
            }
            var r = wrap();
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const val = 'OK';
                var r = 'OK';
                """
            ),
            result,
        )

    def test_irreducible_in_try_propagates_not_caught(self):
        source = inspect.cleandoc(
            """
            function run() {
                try { return externalVar; } catch(e) { return 'wrong'; }
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        with self.assertRaises(IrreducibleExpression):
            JsInterpreter().execute(func, [])

    def test_runtime_error_in_try_still_caught(self):
        source = inspect.cleandoc(
            """
            function f() {
                try {
                    return 'x'.repeat(Infinity);
                } catch(e) {
                    return 'caught';
                }
            }
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'caught';", result)

    def test_external_mutation_of_closure_array_blocks_fold(self):
        source = inspect.cleandoc(
            """
            const key = [1, 2, 3];
            const enc = s => {
              key.reverse();
              return Buffer.from(s, 'utf8');
            };
            const dec = s => {
              var r = '';
              for (var i = 0; i < s.length; i++) {
                r += String.fromCharCode(s.charCodeAt(i) ^ key[i % key.length]);
              }
              return r;
            };
            var a = enc('x');
            var b = dec('ABC');
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_split_with_undefined_limit_returns_all(self):
        source = inspect.cleandoc(
            """
            function f(s, lim) { return s.split(',', lim); }
            var r = f('a,b,c');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = ['a', 'b', 'c'];", result)

    def test_buffer_tostring_nan_element_coerced_to_zero(self):
        source = inspect.cleandoc(
            """
            const f = () => Buffer.from([72, 101, 108]).map(b => b * NaN).toString('hex');
            var r = f();
            """
        )
        result = self._evaluate_in(source, HostEnvironment.node)
        self.assertEqual("var r = '000000';", result)

    def test_typeof_sibling_function_returns_function(self):
        source = inspect.cleandoc(
            """
            function run() {
                function inner(x) { return x + 1; }
                return typeof inner;
            }
            var r = run();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'function';", result)

    def test_named_function_expression_internal_name_is_local(self):
        source = inspect.cleandoc(
            """
            const decode = function self(s) {
                var r = '';
                for (var i = 0; i < s.length; i++) {
                    r += String.fromCharCode(s.charCodeAt(i) ^ 1);
                }
                return r;
            };
            var x = decode('Idmmn');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello';", result)

    def test_a_later_let_shadowing_the_outer_const_is_the_one_read(self):
        source = inspect.cleandoc(
            """
            const x = 'outer';
            function wrapper() {
              const f = () => x;
              let x = 'inner';
              return f();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                const x = 'outer';
                function wrapper() {
                  let x = 'inner';
                  return 'inner';
                }
                """
            ),
            self._evaluate(source),
        )

    def test_a_later_var_does_not_block_the_read_of_a_const(self):
        source = inspect.cleandoc(
            """
            const secret = 'captured';
            const f = () => secret;
            var unrelated = 'something';
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const secret = 'captured';
                var unrelated = 'something';
                var r = 'captured';
                """
            ),
            result,
        )

    def test_non_extractable_inner_const_shadows_outer(self):
        source = inspect.cleandoc(
            """
            const x = 'WRONG';
            function outer(val) {
              const x = val + val;
              const fn = () => x;
              return fn();
            }
            """
        )
        spliced = inspect.cleandoc(
            """
            const x = 'WRONG';
            function outer(val) {
              const x = val + val;
              return x;
            }
            """
        )
        self.assertIn(self._evaluate(source), (source, spliced))

    def test_split_undefined_separator_with_zero_limit(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.split(undefined, 0).length;
            var r = f('hello world');
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 0;', result)

    def test_unsigned_right_shift_nan_operands(self):
        source = inspect.cleandoc(
            """
            function f() { return NaN >>> 0; }
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 0;', result)

    def test_array_negative_length_assignment_throws_a_range_error(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                try {
                    a['length'] = -1;
                } catch (e) {
                    return e.name;
                }
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        self.assertEqual('RangeError', JsInterpreter().execute(func, []))

    def test_a_call_shifting_a_captured_array_stays(self):
        source = inspect.cleandoc(
            """
            const data = ['first', 'second', 'third'];
            const f = () => data.shift();
            var a = f();
            var b = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_a_const_declared_beside_the_function_is_read_by_its_call(self):
        source = inspect.cleandoc(
            """
            const x = 42, fn = (a) => x + a;
            var r = fn(8);
            """
        )
        result = self._evaluate(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                const x = 42;
                var r = 50;
                """
            ),
            result,
        )

    def test_split_undefined_separator_negative_limit(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.split(undefined, -1);
            var r = f('abc');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = ['abc'];", result)

    def test_buffer_reduce_into_an_array_stands_or_is_an_array_in_node(self):
        source = inspect.cleandoc(
            """
            const f = () => Array.isArray(
                Buffer.from([1, 2, 3]).reduce((acc, v) => { acc.push(v * 2); return acc; }, [])
            );
            var r = f();
            """
        )
        standing = inspect.cleandoc(
            """
            const f = () => Array.isArray(Buffer.from([1, 2, 3]).reduce((acc, v) => {
              acc.push(v * 2);
              return acc;
            }, []));
            var r = f();
            """
        )
        self.assertIn(self._evaluate_in(source, HostEnvironment.node), (standing, 'var r = true;'))

    @opportunity
    def test_buffer_reduce_into_an_array_is_an_array_in_node(self):
        source = inspect.cleandoc(
            """
            const f = () => Array.isArray(
                Buffer.from([1, 2, 3]).reduce((acc, v) => { acc.push(v * 2); return acc; }, [])
            );
            var r = f();
            """
        )
        self.assertEqual('var r = true;', self._evaluate_in(source, HostEnvironment.node))

    def test_pure_function_ref_as_value_does_not_produce_wrong_substitution(self):
        source = inspect.cleandoc(
            """
            function helper(x) { return x + 1; }
            function fn(x) { if (helper) return x; return 0; }
            var r = fn(5);
            """
        )
        result = self._evaluate(source)
        expected = inspect.cleandoc(
            """
            function helper(x) {
              return x + 1;
            }
            var r = 5;
            """
        )
        self.assertEqual(expected, result)


class TestAHofCallbackReadingADeadZoneBindingKeepsItsThrow(TestJsDeobfuscator):

    def test_a_callback_reading_a_dead_zone_binding_is_not_folded(self):
        source = 'var out = [1, 2].map(function (x) { return q + x; });\nlet q = 10;\nconsole.log(out);\n'
        self.assertEqual(
            inspect.cleandoc(
                """
                var out = [1, 2].map(function(x) {
                  return q + x;
                });
                let q = 10;
                console.log(out);
                """
            ),
            self._deobfuscate(source),
        )

    def test_a_callback_reading_an_established_binding_is_folded(self):
        source = 'const q = 10;\nvar out = [1, 2].map(function (x) { return q + x; });\nconsole.log(out);\n'
        self.assertEqual(
            inspect.cleandoc(
                """
                var out = [11, 12];
                console.log(out);
                """
            ),
            self._deobfuscate(source),
        )


class TestHostEntrypointDefinitions(TestJsDeobfuscator):

    def _evaluate_with(self, source: str, *entrypoints: str) -> str:
        return self._run_transformer(
            source,
            JsFunctionEvaluator,
            DeobfuscationOptions(entrypoints=entrypoints),
        )

    def test_folded_entrypoint_definition_is_kept(self):
        source = inspect.cleandoc(
            """
            function run(n) {
              return n + 1;
            }
            SINK(run(1));
            """
        )
        expected = inspect.cleandoc(
            """
            function run(n) {
              return n + 1;
            }
            SINK(2);
            """
        )
        self.assertEqual(expected, self._evaluate_with(source, 'run'))

    def test_folded_helper_definition_is_still_removed(self):
        source = inspect.cleandoc(
            """
            function calc(n) {
              return n + 1;
            }
            SINK(calc(1));
            """
        )
        self.assertEqual('SINK(2);', self._evaluate_with(source, 'run'))

    def test_entrypoint_keeps_its_body_after_its_callee_folds(self):
        source = inspect.cleandoc(
            """
            function helper(n) {
              return n * 2;
            }
            function run() {
              return helper(3);
            }
            SINK(run());
            """
        )
        expected = inspect.cleandoc(
            """
            function run() {
              return 6;
            }
            SINK(6);
            """
        )
        self.assertEqual(expected, self._evaluate_with(source, 'run'))

    def test_nested_function_sharing_an_entrypoint_name_is_not_kept(self):
        source = inspect.cleandoc(
            """
            function outer() {
              function run(n) {
                return n + 1;
              }
              return run(1);
            }
            SINK(outer());
            """
        )
        self.assertEqual('SINK(2);', self._evaluate_with(source, 'run'))

    def test_entrypoint_held_by_a_var_declarator_is_kept(self):
        source = inspect.cleandoc(
            """
            var run = function(n) {
              return n + 1;
            };
            SINK(run(1));
            """
        )
        expected = inspect.cleandoc(
            """
            var run = function(n) {
              return n + 1;
            };
            SINK(2);
            """
        )
        self.assertEqual(expected, self._evaluate_with(source, 'run'))

    @todo
    def test_entrypoint_held_by_a_let_declarator_is_kept(self):
        """
        A top-level `let` is no property of the global object, yet a host calling `run` by name
        still finds it, as a browser does when it runs an `onclick="run()"` attribute.
        """
        source = inspect.cleandoc(
            """
            let run = function(n) {
              return n + 1;
            };
            SINK(run(1));
            """
        )
        expected = inspect.cleandoc(
            """
            let run = function(n) {
              return n + 1;
            };
            SINK(2);
            """
        )
        self.assertEqual(expected, self._evaluate_with(source, 'run'))


class TestEvaluatorAstralStringEncoding(TestJsDeobfuscator):

    def _fold_in_node(self, expression: str) -> str:
        return self._run_transformer(
            F'function f() {{ return {expression}; }} var x = f();',
            JsFunctionEvaluator,
            DeobfuscationOptions(environment=HostEnvironment.node),
        )

    def test_buffer_from_utf8_yields_the_four_utf8_bytes(self):
        self.assertEqual(
            'var x = [240, 159, 152, 128];',
            self._fold_in_node("Array.from(Buffer.from('\U0001F600', 'utf8'))"),
        )

    def test_buffer_from_utf8_hex_encodes_the_character(self):
        self.assertEqual(
            "var x = 'f09f9880';",
            self._fold_in_node("Buffer.from('\U0001F600', 'utf8').toString('hex')"),
        )

    def test_encode_uri_component_percent_encodes_the_character(self):
        self.assertEqual(
            "var x = '%F0%9F%98%80';",
            self._fold("encodeURIComponent('\U0001F600')"),
        )


class TestASplicedBodyReadsNoParameterThatKeptItsName(TestJsDeobfuscator):

    def _the_body_of(self, source: str):
        script = JsParser(source).parse()
        func = next(n for n in script.walk() if isinstance(n, JsFunctionDeclaration))
        returned = next(n for n in func.walk() if isinstance(n, JsReturnStatement))
        return func, returned.argument

    SOURCE = 'function f(n, k) { switch (n) { case 5: return externalThing + k; } }'

    def test_a_parameter_whose_value_has_a_literal_form_is_substituted(self):
        func, returned = self._the_body_of(self.SOURCE)
        spliced = JsFunctionEvaluator._substitute_params_in_clone(
            returned, func, [5.0, 'INNER'], JsFunctionEvaluator())
        self.assertEqual("externalThing + 'INNER'", JsSynthesizer().convert(spliced))

    def test_a_parameter_whose_value_has_no_literal_form_refuses_the_splice(self):
        func, returned = self._the_body_of(self.SOURCE)
        self.assertIsNone(JsFunctionEvaluator._substitute_params_in_clone(
            returned, func, [5.0, JsBuffer(b'A')], JsFunctionEvaluator()))

    def test_a_parameter_the_spliced_expression_does_not_read_is_no_obstacle(self):
        func, returned = self._the_body_of(
            'function f(n, k) { switch (n) { case 5: return externalThing + n; } }')
        spliced = JsFunctionEvaluator._substitute_params_in_clone(
            returned, func, [5.0, JsBuffer(b'A')], JsFunctionEvaluator())
        self.assertEqual('externalThing + 5', JsSynthesizer().convert(spliced))

    def test_a_parameter_that_is_not_a_plain_name_refuses_the_splice(self):
        func, returned = self._the_body_of(
            'function f(n, { k }) { switch (n) { case 5: return externalThing + k; } }')
        self.assertIsNone(JsFunctionEvaluator._substitute_params_in_clone(
            returned, func, [5.0, {'k': 'INNER'}], JsFunctionEvaluator()))
