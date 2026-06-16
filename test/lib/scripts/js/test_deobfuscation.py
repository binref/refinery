from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.parser import JsParser


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
        self.assertEqual(self._deobfuscate(source), inspect.cleandoc(
            """
            class Sentinel {}
            live();
            """
        ))

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
            const sentinel = {};
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
            const obj = {};
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
            f();
            """
        )
        self.assertEqual('3;', self._deobfuscate(source))


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
            function d(name, flag, rtype, lengths) {
              var output;
              var fns = {
                "f1": function() { var [a, b, c] = p; return a + b + c; }
              };
              if (flag === "initF") { p = []; }
              if (flag === "createF") {
                output = c[name] || (c[name] = fns[name]);
              } else {
                output = fns[name]();
              }
              if (rtype === "wrapF") { return { "wk": output }; }
              else { return output; }
            }
            console.log((p = [1, , 3], d("f1")));
            """
        )
        result = self._deobfuscate(source)
        self.assertEqual(result, inspect.cleandoc(
            """
            function f1(a, b, c) {
              return a + b + c;
            }
            console.log(f1(1, undefined, 3));
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
            self._deobfuscate(source),
        )

    def test_free_variable_not_inlined_past_modifying_call(self):
        test = self._deobfuscate_iterative(inspect.cleandoc(
            """
            function modifyGlobal() {
                x = 9;
            }
            var x = 12;
            modifyGlobal();
            console.log(x);
            """
        ))
        self.assertEqual(test, inspect.cleandoc(
            """
            function modifyGlobal() {
              x = 9;
            }
            var x = 12;
            modifyGlobal();
            console.log(x);
            """
        ))

    def test_free_variable_is_inlined_past_harmless_call(self):
        test = self._deobfuscate_iterative(inspect.cleandoc(
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
        ))
        self.assertEqual(test, inspect.cleandoc(
            """
            function harmlessCall() {
              console.log("good");
            }
            harmlessCall();
            console.log(12);
            """
        ))

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
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  x = 9;
                }
                var x = 1;
                f();
                console.log(x);
                """
            ),
            self._deobfuscate(source),
        )

    def test_newline_before_paren_does_not_fuse_statements(self):
        source = 'global["VERSION"] = "9.4533"\n\n(async () => {\n  const c = global;\n})()'
        ast = JsParser(source).parse()
        self.assertEqual(len(ast.body), 2)

    def test_newline_before_template_does_not_create_tagged_template(self):
        source = "var x = foo\n`template`"
        ast = JsParser(source).parse()
        self.assertEqual(len(ast.body), 2)


class TestGlobalAliasStripping(TestJsDeobfuscator):

    def test_global_alias_stripped_when_not_shadowed(self):
        self.assertEqual('y = X;', self._simplify('y = globalThis.X;'))

    def test_global_alias_preserved_when_locally_shadowed(self):
        source = inspect.cleandoc(
            """
            var X = 1;
            y = globalThis.X;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var X = 1;
                y = globalThis.X;
                """
            ),
            self._simplify(source),
        )

    def test_window_alias_stripped_when_not_shadowed(self):
        self.assertEqual('y = console;', self._simplify('y = window.console;'))

    def test_global_alias_preserved_when_shadowed_by_param(self):
        source = inspect.cleandoc(
            """
            function f(X) {
                return globalThis.X;
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(X) {
                  return globalThis.X;
                }
                """
            ),
            self._simplify(source),
        )

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
                  const c = global;
                  console.log(_V);
                })();
                """
            ),
            self._deobfuscate(source),
        )

    def test_dead_global_property_is_removed(self):
        source = inspect.cleandoc(
            """
            global['_V'] = "7-4111";
            global['_W'] = "dead";
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
                  const c = global;
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


class TestParenthesisPreservation(TestJsDeobfuscator):

    def test_paren_preserved_when_inner_has_lower_precedence(self):
        self.assertEqual('var x = (a | b) & c;', self._simplify('var x = (a | b) & c;'))

    def test_paren_preserved_when_inner_is_ternary_inside_binop(self):
        self.assertEqual(
            'var x = (a ? b : c) + d;',
            self._simplify('var x = (a ? b : c) + d;'),
        )

    def test_paren_dropped_when_inner_has_higher_precedence(self):
        self.assertEqual('var x = a + b * c;', self._simplify('var x = a + (b * c);'))

    def test_paren_dropped_around_primary(self):
        self.assertEqual('var x = a + b;', self._simplify('var x = (a) + (b);'))

    def test_paren_preserved_for_right_side_of_same_precedence(self):
        self.assertEqual('var x = a - (b - c);', self._simplify('var x = a - (b - c);'))

    def test_paren_dropped_for_left_side_of_same_precedence(self):
        self.assertEqual('var x = a - b - c;', self._simplify('var x = (a - b) - c;'))

    def test_paren_preserved_for_conditional_as_ternary_test(self):
        self.assertEqual(
            'var x = (a ? b : c) ? d : e;',
            self._simplify('var x = (a ? b : c) ? d : e;'),
        )

    def test_paren_preserved_for_assignment_as_ternary_test(self):
        self.assertEqual(
            'var x = (a = b) ? c : d;',
            self._simplify('var x = (a = b) ? c : d;'),
        )

    def test_paren_preserved_for_numeric_literal_member_object(self):
        self.assertEqual(
            'var x = (5).toString();',
            self._simplify('var x = (5).toString();'),
        )

    def test_paren_dropped_for_numeric_literal_computed_member(self):
        self.assertEqual('var x = 5[k];', self._simplify('var x = (5)[k];'))

    def test_paren_preserved_for_nested_negation(self):
        self.assertEqual('var x = -(-a);', self._simplify('var x = -(-a);'))

    def test_paren_preserved_for_nested_unary_plus(self):
        self.assertEqual('var x = +(+a);', self._simplify('var x = +(+a);'))

    def test_paren_dropped_for_double_logical_not(self):
        self.assertEqual('var x = !!a;', self._simplify('var x = !(!a);'))

    def test_paren_preserved_for_unary_base_of_exponentiation(self):
        self.assertEqual('var x = (-a) ** b;', self._simplify('var x = (-a) ** b;'))

    def test_paren_preserved_for_call_as_new_callee(self):
        self.assertEqual('var x = new (f())();', self._simplify('var x = new (f())();'))

    def test_paren_preserved_for_logical_as_new_callee(self):
        self.assertEqual('var x = new (a || b)();', self._simplify('var x = new (a || b)();'))

    def test_paren_preserved_for_call_in_new_callee_spine(self):
        self.assertEqual('var x = new (a().b)();', self._simplify('var x = new (a().b)();'))

    def test_paren_dropped_for_member_chain_new_callee(self):
        self.assertEqual('var x = new a.b.c();', self._simplify('var x = new (a.b.c)();'))

    def test_paren_preserved_for_operator_tag_of_tagged_template(self):
        self.assertEqual('var r = (a + b)`x`;', self._simplify('var r = (a + b)`x`;'))

    def test_paren_dropped_for_member_tag_of_tagged_template(self):
        self.assertEqual('var r = a.b`x`;', self._simplify('var r = (a.b)`x`;'))

    def test_paren_preserved_for_operator_class_super(self):
        self.assertEqual(
            'var C = class extends (a + b) {};',
            self._simplify('var C = class extends (a + b) {};'),
        )

    def test_paren_dropped_for_member_class_super(self):
        self.assertEqual(
            'var C = class extends a.b {};',
            self._simplify('var C = class extends (a.b) {};'),
        )

    def test_paren_preserved_for_nullish_under_logical_or(self):
        self.assertEqual('var x = (a ?? b) || c;', self._simplify('var x = (a ?? b) || c;'))

    def test_paren_preserved_for_logical_or_under_nullish(self):
        self.assertEqual('var x = (a || b) ?? c;', self._simplify('var x = (a || b) ?? c;'))

    def test_paren_preserved_for_logical_and_under_nullish(self):
        self.assertEqual('var x = a ?? (b && c);', self._simplify('var x = a ?? (b && c);'))

    def test_paren_dropped_for_nullish_chain(self):
        self.assertEqual('var x = a ?? b ?? c;', self._simplify('var x = (a ?? b) ?? c;'))

    def test_paren_preserved_for_optional_chain_member_object(self):
        self.assertEqual('var x = (a?.b).c;', self._simplify('var x = (a?.b).c;'))

    def test_paren_preserved_for_optional_chain_call_callee(self):
        self.assertEqual('var x = (a?.b)();', self._simplify('var x = (a?.b)();'))

    def test_paren_preserved_for_optional_chain_new_callee(self):
        self.assertEqual('new (a?.b)();', self._simplify('new (a?.b)();'))

    def test_paren_dropped_for_plain_member_chain(self):
        self.assertEqual('var x = a.b.c;', self._simplify('var x = (a.b).c;'))

    def test_paren_preserved_for_prefix_update_as_exponent_left_operand(self):
        self.assertEqual('var x = (++a) ** 2;', self._simplify('var x = (++a) ** 2;'))

    def test_paren_preserved_for_await_as_exponent_left_operand(self):
        self.assertEqual('var x = (await a) ** 2;', self._simplify('var x = (await a) ** 2;'))

    def test_paren_preserved_for_destructuring_assignment_statement(self):
        self.assertEqual('({ a } = obj);', self._simplify('({ a } = obj);'))

    def test_paren_preserved_for_prefix_update_in_member_object(self):
        self.assertEqual('(++a).foo;', self._simplify('(++a).foo;'))

    def test_paren_preserved_for_postfix_update_in_member_object(self):
        self.assertEqual('(a++).foo;', self._simplify('(a++).foo;'))

    def test_paren_preserved_for_postfix_update_as_call_callee(self):
        self.assertEqual('(a++)();', self._simplify('(a++)();'))

    def test_paren_preserved_for_optional_tagged_template_as_member_object(self):
        self.assertEqual('var x = (a?.b`s`).c;', self._simplify('var x = (a?.b`s`).c;'))

    def test_paren_preserved_for_optional_chain_as_tagged_template_tag(self):
        self.assertEqual('var x = (a?.b)`s`;', self._simplify('var x = (a?.b)`s`;'))

    def test_paren_dropped_for_plain_tagged_template_as_member_object(self):
        self.assertEqual('var x = a.b`s`.c;', self._simplify('var x = (a.b`s`).c;'))

    def test_paren_preserved_for_sequence_in_conditional_consequent(self):
        self.assertEqual(
            'var x = a ? (f(), g()) : d;',
            self._simplify('var x = a ? (f(), g()) : d;'),
        )

    def test_paren_preserved_for_arrow_in_binary_left(self):
        self.assertEqual('var x = (() => y) + b;', self._simplify('var x = (() => y) + b;'))

    def test_paren_preserved_for_assignment_in_binary_right(self):
        self.assertEqual('var x = a + (b = c);', self._simplify('var x = a + (b = c);'))

    def test_paren_preserved_for_same_precedence_right_subtraction(self):
        self.assertEqual('var x = a - (b - c);', self._simplify('var x = a - (b - c);'))

    def test_paren_dropped_for_same_precedence_left_subtraction(self):
        self.assertEqual('var x = a - b - c;', self._simplify('var x = (a - b) - c;'))

    def test_paren_preserved_for_destructuring_assignment_arrow_body(self):
        self.assertEqual('var f = () => ({ a } = obj);', self._simplify('var f = () => ({ a } = obj);'))
