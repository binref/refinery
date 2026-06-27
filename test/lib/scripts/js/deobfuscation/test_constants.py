from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator


class TestConstantInlining(TestJsDeobfuscator):

    def test_literal_string_inlined(self):
        self.assertEqual("console.log('hello');", self._inline("var x = 'hello'; console.log(x);"))

    def test_literal_number_inlined(self):
        self.assertEqual('console.log(42);', self._inline('var x = 42; console.log(x);'))

    def test_literal_boolean_inlined(self):
        self.assertEqual('console.log(true);', self._inline('var x = true; console.log(x);'))

    def test_reassigned_variable_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'a';
                x = 'b';
                console.log(x);
                """
            ),
            self._inline("var x = 'a'; x = 'b'; console.log(x);"),
        )

    def test_constant_reassigned_by_object_destructuring_not_inlined(self):
        source = inspect.cleandoc(
            """
            var c = false;
            function f() {
              ({ c = 2 } = {});
            }
            f();
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_rebound_by_object_destructuring_default_declaration_not_inlined(self):
        source = inspect.cleandoc(
            """
            var c = 1;
            var { c = d } = o;
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_rebound_by_object_destructuring_declaration_not_inlined(self):
        source = inspect.cleandoc(
            """
            var c = 1;
            var { c } = o;
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_default_in_object_destructuring_declaration_is_inlined(self):
        self.assertEqual(
            'var { a = 2 } = o;',
            self._inline('var b = 2; var { a = b } = o;'),
        )

    def test_compound_assignment_in_nested_function_keeps_declaration(self):
        source = inspect.cleandoc(
            """
            var SINK = [];
            let v = true;
            SINK.push(v ? 1 : 2);
            function f() {
              v <<= 1;
            }
            f();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var SINK = [];
                let v = true;
                SINK.push(true ? 1 : 2);
                function f() {
                  v <<= 1;
                }
                f();
                """
            ),
            self._inline(source),
        )

    def test_constant_mutated_in_anonymous_iife_not_inlined(self):
        source = inspect.cleandoc(
            """
            var SINK = [];
            var v = 1;
            (function() {
              v++;
            })();
            SINK.push(v);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_global_reassigned_in_called_function_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var v0 = 7;
                function reads() {
                  return -v0;
                }
                function writes() {
                  v0 = 9;
                  return reads();
                }
                SINK.push(writes());
                SINK.push(reads());
                """
            ),
            self._inline(
                'var v0 = 7;'
                ' function reads() { return -v0; }'
                ' function writes() { v0 = 9; return reads(); }'
                ' SINK.push(writes());'
                ' SINK.push(reads());'
            ),
        )

    def test_mutated_variable_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                x++;
                console.log(x);
                """
            ),
            self._inline('var x = 1; x++; console.log(x);'),
        )

    def test_var_bound_closure_mutation_seals_variable(self):
        """
        `set` is a function expression bound to a `var`; calling it mutates the captured `x`, so the
        initializer must not be inlined past the call (the closure reassignment would otherwise be
        dropped, folding `return x` to `0`).
        """
        source = inspect.cleandoc(
            """
            function f() {
              var x = 0;
              var set = function() {
                x = 2;
              };
              set();
              return x;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_block_nested_closure_mutation_seals_variable(self):
        """
        `f` is declared inside the loop block, not at the scope top level; calling it still mutates the
        captured `v`, so `v` must not be inlined past the call — otherwise `console.log(v)` folds to
        `console.log(1)`, dropping the reassignment.
        """
        source = inspect.cleandoc(
            """
            var v = 1;
            for (let i = 0; i < 1; i++) {
              function f() {
                v = 2;
              }
              f();
            }
            console.log(v);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_uninitialized_var_compound_assignment_not_inlined(self):
        """
        `x` is declared without an initializer, so `x += 5` reads `undefined` and stores `NaN`; the
        compound assignment is a read-modify-write, not a constant definition, so `x` is not `5`.
        """
        source = inspect.cleandoc(
            """
            var x;
            x += 5;
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_var_bound_closure_mutation_via_indirect_call_not_inlined(self):
        """
        `f` mutates the captured `x`, but invoking it through `f.call(...)` rather than a direct `f()`
        is not a recognized seal point, so the write could land between the assignment and the read;
        `x` is not a stable constant and must not be inlined.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            var f = function() {
              x = 2;
            };
            f.call(null);
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_named_closure_mutation_when_passed_as_callback_not_inlined(self):
        """
        `f` escapes as a callback argument, so the call that mutates the captured `x` happens at an
        unknown point; `x` is therefore not a stable constant and must not be inlined.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              x = 2;
            }
            [0].forEach(f);
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_named_mutator_called_inside_anonymous_callback_not_inlined(self):
        """
        `f` mutates the captured `x` from inside an anonymous callback, so the mutating call runs at
        an unknown point that no seal covers; `x` is not a stable constant and must not be inlined.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              x = 2;
            }
            [0].forEach(function() {
              f();
            });
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_named_mutator_called_inside_iife_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              x = 2;
            }
            (function() {
              f();
            })();
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_single_use_expression_inlined(self):
        self.assertEqual('return a + b;', self._inline('var x = a + b; return x;'))

    def test_multi_use_expression_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = a + b;
                console.log(x);
                return x;
                """
            ),
            self._inline('var x = a + b; console.log(x); return x;'),
        )

    def test_call_init_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = f();
                return x;
                """
            ),
            self._inline('var x = f(); return x;'),
        )

    def test_member_access_init_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = a.b;
                return x;
                """
            ),
            self._inline('var x = a.b; return x;'),
        )

    def test_does_not_cross_function_boundary(self):
        source = (
            "var x = 'outer';"
            'function f() { return x; }'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'outer';
                function f() {
                  return x;
                }
                """
            ),
            self._inline(source),
        )

    def test_function_body_processed(self):
        source = (
            'function f() {'
            "  var x = 'hello';"
            '  return x;'
            '}'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 'hello';
                }
                """
            ),
            self._inline(source),
        )

    def test_long_string_not_duplicated(self):
        long_str = 'a' * 100
        source = F"var x = '{long_str}'; console.log(x); alert(x);"
        self.assertEqual(
            inspect.cleandoc(
                F"""
                var x = '{long_str}';
                console.log(x);
                alert(x);
                """
            ),
            self._inline(source),
        )

    def test_expression_with_mutated_identifier_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var y = a + b;
                a = 99;
                return y;
                """
            ),
            self._inline('var y = a + b; a = 99; return y;'),
        )

    def test_const_array_element_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                x['push']('a');
                if (y === 0) {}
                """
            ),
            self._inline("const p = [0, 'push']; x[p[1]]('a'); if (y === p[0]) {}"),
        )

    def test_const_array_numeric_element(self):
        self.assertEqual('f(42);', self._inline('const p = [42]; f(p[0]);'))

    def test_const_pool_declaration_removed(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                f(0);
                g('push');
                h(0xff);
                """
            ),
            self._inline("const pool = [0, 'push', 0xff]; f(pool[0]); g(pool[1]); h(pool[2]);"),
        )

    def test_var_array_not_inlined_across_functions(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var p = ['a'];
                function f() {
                  return p[0];
                }
                """
            ),
            self._inline("var p = ['a']; function f() { return p[0]; }"),
        )

    def test_const_array_inlined_across_functions(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 'a';
                }
                """
            ),
            self._inline("const p = ['a']; function f() { return p[0]; }"),
        )

    def test_const_array_passed_to_non_mutating_callee_is_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = ['a', 'b'];
                function read(i) {
                  return i[0];
                }
                read(p);
                f('b');
                """
            ),
            self._inline("const p = ['a', 'b']; function read(i){ return i[0]; } read(p); f(p[1]);"),
        )

    def test_const_array_passed_to_mutating_callee_not_inlined(self):
        source = inspect.cleandoc(
            """
            const p = ['a', 'b'];
            function mut(i) {
              i[0] = 'x';
            }
            mut(p);
            f(p[1]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_const_array_passed_to_eval_containing_callee_not_inlined(self):
        source = inspect.cleandoc(
            """
            const p = ['a', 'b'];
            function f(x) {
              eval("x[0]='Z';");
            }
            f(p);
            g(p[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_const_array_passed_to_with_containing_callee_not_inlined(self):
        source = inspect.cleandoc(
            """
            const p = ['a', 'b'];
            function f(x) {
              with (o) {
                x[0] = sneaky;
              }
            }
            f(p);
            g(p[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_non_literal_array_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = [a, 1];
                f(p[0]);
                """
            ),
            self._inline('const p = [a, 1]; f(p[0]);'),
        )

    def test_out_of_bounds_index_unchanged(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = [1, 2];
                f(p[999]);
                """
            ),
            self._inline('const p = [1, 2]; f(p[999]);'),
        )

    def test_non_numeric_index_unchanged(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                const p = [1, 2];
                f(p[x]);
                """
            ),
            self._inline('const p = [1, 2]; f(p[x]);'),
        )

    def test_mutating_method_call_blocks_index_inline(self):
        source = inspect.cleandoc(
            """
            const a = [3, 1, 2];
            a.sort();
            f(a[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_push_mutation_blocks_index_inline(self):
        source = inspect.cleandoc(
            """
            const a = [1, 2];
            a.push(3);
            f(a[1]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_parenthesized_index_write_blocks_inline(self):
        source = inspect.cleandoc(
            """
            const a = [1, 2];
            (a[0]) = 9;
            f(a[0]);
            f(a[1]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_parenthesized_method_call_blocks_inline(self):
        source = inspect.cleandoc(
            """
            const a = [10, 20];
            (a.reverse)();
            f(a[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_tagged_template_call_blocks_inline(self):
        source = inspect.cleandoc(
            """
            const a = [1, 2];
            a.f`x`;
            f(a[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_forin_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'initial';
                for (x in obj) {}
                console.log(x);
                """
            ),
            self._inline("var x = 'initial'; for (x in obj) {} console.log(x);"),
        )

    def test_forof_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'initial';
                for (x of arr) {}
                console.log(x);
                """
            ),
            self._inline("var x = 'initial'; for (x of arr) {} console.log(x);"),
        )

    def test_forof_destructuring_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'initial';
                for ([x] of rows) {}
                console.log(x);
                """
            ),
            self._inline("var x = 'initial'; for ([x] of rows) {} console.log(x);"),
        )

    def test_forof_rest_destructuring_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'initial';
                for ([...x] of rows) {}
                console.log(x);
                """
            ),
            self._inline("var x = 'initial'; for ([...x] of rows) {} console.log(x);"),
        )

    def test_forof_var_declaration_target_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 5;
            for (var x of xs) {
              sink(x);
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_forin_var_declaration_target_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 5;
            for (var x in xs) {
              sink(x);
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_forof_const_declaration_target_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 5;
            for (const x of xs) {
              sink(x);
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_forof_var_destructuring_declaration_target_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 5;
            for (var [x] of rows) {
              sink(x);
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_parenthesized_assignment_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 5;
                console.log(a);
                (a) = 9;
                console.log(a);
                """
            ),
            self._inline('var a = 5; console.log(a); (a) = 9; console.log(a);'),
        )

    def test_parenthesized_update_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 5;
                console.log(a);
                (a)++;
                console.log(a);
                """
            ),
            self._inline('var a = 5; console.log(a); (a)++; console.log(a);'),
        )

    def test_parenthesized_forof_target_not_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 5;
                for ((a) of rows) {}
                console.log(a);
                """
            ),
            self._inline('var a = 5; for ((a) of rows) {} console.log(a);'),
        )

    def test_array_destructuring_marks_mutated(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'hello';
                [x] = getValues();
                console.log(x);
                """
            ),
            self._inline("var x = 'hello'; [x] = getValues(); console.log(x);"),
        )

    def test_object_destructuring_marks_mutated(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'hello';
                ({ y: x } = getValues());
                console.log(x);
                """
            ),
            self._inline("var x = 'hello'; ({y: x} = getValues()); console.log(x);"),
        )

    def test_function_declaration_id_not_replaced(self):
        source = inspect.cleandoc(
            """
            function outer() {
                const x = void 0;
                function inner() {
                    function x() { return 1; }
                    return x();
                }
                return inner();
            }
            """
        )
        result = self._inline(source)
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  const x = void 0;
                  function inner() {
                    function x() {
                      return 1;
                    }
                    return x();
                  }
                  return inner();
                }
                """
            ),
            result,
        )


class TestRegressionBugs(TestJsDeobfuscator):

    def test_expression_not_inlined_across_conditional_boundary(self):
        source = inspect.cleandoc(
            """
            function f(cond) {
              if (cond) {
                var x = a + b;
              }
              return x;
            }
            """
        )
        result = self._inline(source)
        self.assertEqual(result, source)

    def test_free_variable_inlined_without_intervening_call(self):
        source = inspect.cleandoc(
            """
            var x = a + b;
            console.log(x);
            """
        )
        self.assertEqual('console.log(a + b);', self._inline(source))

    def test_var_not_inlined_past_call_with_inner_let_shadow(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              x = 2;
              if (true) {
                let x = 3;
              }
            }
            f();
            console.log(x);
            """
        )
        result = self._inline(source)
        self.assertEqual(source, result)

    def test_const_not_inlined_past_inherited_param_shadow(self):
        source = inspect.cleandoc(
            """
            const k = 5;
            function A(k) {
              function B() {
                return k;
              }
              return B();
            }
            console.log(A(9));
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_const_not_inlined_past_block_let_shadow(self):
        source = inspect.cleandoc(
            """
            const k = 5;
            function f(p) {
              {
                let k = p;
                k += 1;
                return k;
              }
            }
            console.log(f(9));
            """
        )
        self.assertEqual(source, self._inline(source))
