from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.interpreter import IrreducibleExpression, JsInterpreter
from refinery.lib.scripts.js.model import JsFunctionDeclaration, JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


class TestFunctionEvaluator(TestJsDeobfuscator):

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
        """
        `f` is reassigned after its declaration, so a call runs the new function; folding to the stale
        declaration's body is unsound (Node: the call yields 9, not the folded 1). The model's
        `static_callee` declines the reassigned binding, so the evaluator leaves the call intact.
        """
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
        """
        A name bound by more than one declaration is treated as an unknown function — which body is
        live at a call cannot be proven once a `var`, a conditional, or a block declaration is mixed in
        — so the evaluator declines it rather than trusting a last-wins guess.
        """
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

    def test_object_literal_parens_preserved(self):
        self.assertEqual('var x = ({ a: 1 });', self._simplify('var x = ({a: 1});'))


class TestClosureCapture(TestJsDeobfuscator):

    def test_const_arrow_with_outer_string(self):
        source = inspect.cleandoc(
            """
            const prefix = 'Hello';
            const greet = (name) => prefix + ', ' + name + '!';
            var msg = greet('World');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var msg = 'Hello, World!';", result)

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
        self.assertEqual("var msg = 'Hello';", result)

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
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello';", result)

    def test_buffer_from_hex(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'hex').toString('utf8');
            var x = decode('48656c6c6f');
            """
        )
        result = self._evaluate(source)
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

    def test_implicit_locals_not_blocking_purity(self):
        source = inspect.cleandoc(
            """
            const decode = function(s) {
                rr = '';
                for (var i = 0; i < s.length; i++) {
                    rr += String.fromCharCode(s.charCodeAt(i) ^ 1);
                }
                return rr;
            };
            var x = decode('Idmmn');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello';", result)

    def test_side_effects_member_write_blocks_evaluation(self):
        source = inspect.cleandoc(
            """
            const modify = function(arr) {
              arr[0] = 99;
              return arr;
            };
            var x = modify([1, 2, 3]);
            """
        )
        self.assertEqual(source, self._evaluate(source))

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

    def test_let_binding_not_captured(self):
        source = inspect.cleandoc(
            """
            let prefix = 'Hello';
            const greet = name => prefix + ', ' + name;
            var msg = greet('World');
            """
        )
        self.assertEqual(source, self._evaluate(source))

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
        # A plain Array's toString must use Array semantics ('72,101,108'), never the Buffer.toString
        # interpretation of the same bytes ('Hel').
        source = inspect.cleandoc(
            """
            const f = () => [72, 101, 108].toString();
            var x = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = '72,101,108';", result)

    def test_buffer_from_toString_still_works(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'base64').toString('utf8');
            var x = decode('SGVsbG8=');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello';", result)

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
        self.assertEqual(source, self._evaluate(source))

    def test_shared_mutable_closure_array_isolated(self):
        source = inspect.cleandoc(
            """
            const key = [1, 2, 3];
            const dec = (s) => { key.reverse(); return s + key[0]; };
            var a = dec('A');
            var b = dec('B');
            """
        )
        result = self._evaluate(source)
        expected = inspect.cleandoc(
            """
            var a = 'A3';
            var b = 'B1';
            """
        )
        self.assertEqual(expected, result)

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
        result = self._evaluate(source)
        self.assertEqual("var x = 'IDMMN';", result)

    def test_buffer_filter_then_tostring(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'hex').filter(b => b > 64).toString('utf8');
            var x = decode('4100420043');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'ABC';", result)

    def test_nan_as_index_does_not_raise(self):
        source = inspect.cleandoc(
            """
            const f = (s, idx) => s.charAt(idx);
            var r = f('hello', 0);
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
        self.assertEqual('var r = NaN;', result)

    def test_math_round_nan_returns_nan(self):
        source = inspect.cleandoc(
            """
            const f = () => Math.round(NaN);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = NaN;', result)

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
        self.assertEqual("var r = { 'x': 42 };", result)

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
        self.assertEqual('var r = Infinity;', result)

    def test_math_trunc_infinity(self):
        source = inspect.cleandoc(
            """
            const f = () => Math.trunc(Infinity);
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = Infinity;', result)

    def test_buffer_from_base64url(self):
        source = inspect.cleandoc(
            """
            const decode = (s) => Buffer.from(s, 'base64').toString('utf8');
            var x = decode('SGVsbG8-');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var x = 'Hello>';", result)

    def test_closure_const_declared_after_function_not_captured(self):
        source = inspect.cleandoc(
            """
            const fn = () => x;
            const x = 5;
            var r = fn();
            """
        )
        self.assertEqual(source, self._evaluate(source))

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

    def test_array_length_nan_does_not_raise(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                a['length'] = NaN;
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        result = JsInterpreter().execute(func, [])
        self.assertEqual(0, result)

    def test_array_length_infinity_does_not_raise(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                a['length'] = Infinity;
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        result = JsInterpreter().execute(func, [])
        self.assertEqual(0, result)

    def test_typeof_buffer_is_function(self):
        source = inspect.cleandoc(
            """
            const f = () => typeof Buffer === 'function' ? 'yes' : 'no';
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = 'yes';", result)

    def test_repeat_infinity_does_not_raise_memory_error(self):
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

    def test_calling_null_throws_caught_type_error(self):
        # Calling `null` is a genuine TypeError, so the catch runs and `typeof e` is 'object'.
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

    def test_var_hoisting_shadows_outer_const_in_closure(self):
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
        result = self._evaluate(source)
        self.assertEqual(source, result)

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
        result = self._evaluate(source)
        self.assertEqual(source, result)

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
        result = self._evaluate(source)
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
        result = self._evaluate(source)
        self.assertEqual("var r = '48006c';", result)

    def test_buffer_from_list_coerces_null_to_zero(self):
        source = inspect.cleandoc(
            """
            const f = () => Buffer.from([72, null, 108]).toString('latin1');
            var r = f();
            """
        )
        result = self._evaluate(source)
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
        """
        Inside `wrap`, the `var x` hoists to the function scope, so `g`'s `x` binds to it, not to the
        outer `const x`. Once `f` is inlined and removed, nothing references the outer `const x`, so it
        is dead and removed too — `wrap` keeps reading its own local `x`.
        """
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
                function wrap() {
                  const g = () => x;
                  if (true) {
                    var x = 'inner';
                  }
                  return g();
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
        self.assertEqual(source, self._evaluate(source))

    def test_closure_env_not_corrupted_by_buffer_rejection(self):
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

    def test_let_in_nested_block_does_not_block_closure_capture(self):
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
        self.assertEqual("var r = 'outer';", result)

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

    def test_direct_let_still_shadows_outer_const_for_closure(self):
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
        self.assertEqual(source, self._evaluate(source))

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
        # `enc` mutates the shared `key` via key.reverse() but is unfoldable (it returns a Buffer),
        # so the evaluator cannot model that mutation. At runtime `dec('ABC')` sees key=[3,2,1] and
        # yields 'B@B', not the pre-mutation '@@@'; folding `dec` with the stale [1,2,3] would change
        # semantics, so `dec` must be left unevaluated.
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
        result = self._evaluate(source)
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

    def test_tdz_shadow_from_later_let_blocks_capture(self):
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
        self.assertEqual(source, self._evaluate(source))

    def test_later_var_does_not_block_capture(self):
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
                var unrelated = 'something';
                var r = 'captured';
                """
            ),
            result,
        )

    def test_cross_function_mutation_blocks_closure_fold(self):
        # `enc` reverses the shared `key` but is unfoldable (returns a Buffer), so the mutation is
        # not modelled. Real JS yields b == c == 'B@B' (key=[3,2,1] after enc), not '@@@'; folding
        # `dec` against the stale key would be unsound, so both `dec` calls are left unevaluated.
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
            var a = enc('ignored');
            var b = dec('ABC');
            var c = dec('ABC');
            """
        )
        self.assertEqual(source, self._evaluate(source))

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
        self.assertEqual(source, self._evaluate(source))

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

    def test_array_negative_length_assignment_raises(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                a['length'] = -1;
                return a.length;
            }
            """
        )
        func = JsParser(source).parse().body[0]
        assert isinstance(func, JsFunctionDeclaration)
        with self.assertRaises(Exception):
            JsInterpreter().execute(func, [])

    def test_closure_writeback_only_on_successful_replacement(self):
        source = inspect.cleandoc(
            """
            const data = ['first', 'second', 'third'];
            const f = () => data.shift();
            var a = f();
            var b = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            var a = 'first';
            var b = 'second';
            """
        ))

    def test_multi_declarator_const_sibling_captured(self):
        source = inspect.cleandoc(
            """
            const x = 42, fn = (a) => x + a;
            var r = fn(8);
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = 50;', result)

    def test_split_undefined_separator_negative_limit(self):
        source = inspect.cleandoc(
            """
            const f = (s) => s.split(undefined, -1);
            var r = f('abc');
            """
        )
        result = self._evaluate(source)
        self.assertEqual("var r = ['abc'];", result)

    def test_buffer_reduce_returns_plain_array(self):
        source = inspect.cleandoc(
            """
            const f = () => Array.isArray(
                Buffer.from([1, 2, 3]).reduce((acc, v) => { acc.push(v * 2); return acc; }, [])
            );
            var r = f();
            """
        )
        result = self._evaluate(source)
        self.assertEqual('var r = true;', result)

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
