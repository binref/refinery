from __future__ import annotations

import inspect
import unittest

from test import TestBase, a_property_of_the_batch_itself, opportunity
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    before_and_after,
    each_program_still_prints,
    folded,
    prints,
)

from refinery.lib.scripts import TREE_RECURSION_DEPTH
from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.tools import RecursionDepth


class TestConstantInlining(TestJsDeobfuscator):

    def test_literal_string_inlined(self):
        self.assertEqual("console.log('hello');", self._inline("var x = 'hello'; console.log(x);"))

    def test_literal_number_inlined(self):
        self.assertEqual('console.log(42);', self._inline('var x = 42; console.log(x);'))

    def test_literal_boolean_inlined(self):
        self.assertEqual('console.log(true);', self._inline('var x = true; console.log(x);'))

    def test_delete_initializer_is_not_relocated(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                x = 5;
                var t = delete x;
                g();
                f(t);
                """
            ),
            self._inline('x = 5; var t = delete x; g(); f(t);'),
        )
        self.assertEqual(
            'f((1 + 1) * 2);',
            self._inline('var q = 1; var t = (q + 1) * 2; f(t);'))

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

    def test_read_before_mutating_call_inlines_read_after_does_not(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 5;
                var f = function() {
                  x = 9;
                };
                SINK.push(5);
                f();
                SINK.push(x);
                """
            ),
            self._inline(
                'var x = 5;'
                ' var f = function() { x = 9; };'
                ' SINK.push(x);'
                ' f();'
                ' SINK.push(x);'
            ),
        )

    def test_do_while_body_opening_with_try_sees_the_in_loop_mutation(self):
        source = inspect.cleandoc(
            """
            var x = 5;
            var f = function() {
              x = 9;
            };
            do {
              try {
                SINK.push(x);
                f();
              } catch (e) {}
            } while (c);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_for_without_test_body_opening_with_try_sees_the_in_loop_mutation(self):
        source = inspect.cleandoc(
            """
            var x = 5;
            var f = function() {
              x = 9;
            };
            for (; ; ) {
              try {
                SINK.push(x);
                f();
                if (q) {
                  break;
                }
              } catch (e) {}
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_use_before_definition_in_same_statement_not_inlined(self):
        source = inspect.cleandoc(
            """
            var y = (SINK(x), 0), x = 5;
            DONE(y);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_expression_not_inlined_past_free_variable_mutation(self):
        source = inspect.cleandoc(
            """
            function outer(a) {
              var x = a + 5;
              var g = function() {
                a = 100;
              };
              while (cond) {
                g();
                SINK(x);
              }
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_block_nested_closure_mutation_seals_variable(self):
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
        source = inspect.cleandoc(
            """
            var x;
            x += 5;
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_var_bound_closure_mutation_via_indirect_call_not_inlined(self):
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

    def test_constant_mutated_through_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            with (o) {
              x = 2;
            }
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_local_scalar_with_not_naming_it_inlines(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  with (q) {
                    z = 1;
                  }
                  return 1;
                }
                """
            ),
            self._inline('function outer() { var x = 1; with (q) { z = 1; } return x; }'),
        )

    def test_local_scalar_reassigned_through_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            function outer() {
              var x = 1;
              with (q) {
                x = 9;
              }
              return x;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_cross_function_array_element_mutated_through_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            var arr = [10, 20];
            function get() {
              return arr[0];
            }
            with (q) {
              arr[0] = 99;
            }
            SINK(get());
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_cross_function_scalar_reassigned_through_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              return x;
            }
            with (q) {
              x = 2;
            }
            SINK(f());
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_cross_function_with_reassigning_shadowed_param_still_inlines(self):
        declaration_kept = inspect.cleandoc(
            """
            var x = 1;
            function g(x) {
              with (q) {
                x = 2;
              }
            }
            function f() {
              return 1;
            }
            SINK(f());
            """
        )
        declaration_gone = inspect.cleandoc(
            """
            function g(x) {
              with (q) {
                x = 2;
              }
            }
            function f() {
              return 1;
            }
            SINK(f());
            """
        )
        self.assertIn(
            self._inline('var x = 1; function g(x) { with (q) { x = 2; } } function f() { return x; } SINK(f());'),
            (declaration_kept, declaration_gone),
        )

    def test_cross_function_local_reassignable_by_direct_eval_not_inlined(self):
        source = inspect.cleandoc(
            """
            function outer() {
              var x = 1;
              function f() {
                return x;
              }
              eval("x = 2");
              return f();
            }
            SINK(outer());
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_local_constant_read_before_a_direct_eval_in_the_same_function_is_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x = 'a';
                  SINK('a');
                  eval(input);
                  SINK(x);
                }
                """
            ),
            self._inline(inspect.cleandoc(
                """
                function f() {
                  var x = 'a';
                  SINK(x);
                  eval(input);
                  SINK(x);
                }
                """
            )),
        )

    def test_local_array_index_read_before_a_direct_eval_is_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var p = ['a', 'b'];
                  SINK('a');
                  eval(input);
                  SINK(p[1]);
                }
                """
            ),
            self._inline(inspect.cleandoc(
                """
                function f() {
                  var p = ['a', 'b'];
                  SINK(p[0]);
                  eval(input);
                  SINK(p[1]);
                }
                """
            )),
        )

    def test_local_declaration_survives_a_direct_eval_that_could_name_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x = 'a';
                  SINK('a');
                  eval(input);
                }
                """
            ),
            self._inline(inspect.cleandoc(
                """
                function f() {
                  var x = 'a';
                  SINK(x);
                  eval(input);
                }
                """
            )),
        )

    def test_local_reassignable_by_direct_eval_not_inlined_into_an_unordered_callback(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x = 'a';
              setTimeout(function() {
                SINK(x);
              });
              eval(input);
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_local_reassigned_by_function_called_through_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            function W() {
              var b = 10;
              function evil() {
                b = 99;
              }
              with (o) {
                evil();
              }
              return b;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_local_mutated_by_function_aliased_through_with_not_inlined(self):
        source = inspect.cleandoc(
            """
            function W() {
              var b = 10;
              var n = function() {};
              function evil() {
                b = 99;
              }
              with (o) {
                n = evil;
              }
              n();
              return b;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_cross_function_const_read_by_with_invoked_function_not_inlined(self):
        source = inspect.cleandoc(
            """
            function outer() {
              function f() {
                return c;
              }
              with (o) {
                f();
              }
              const c = 5;
              return f();
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_cross_function_reachable_by_opaque_eval_not_inlined(self):
        source = inspect.cleandoc(
            """
            function probe() {
              return c;
            }
            eval(payload);
            const c = 5;
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_written_through_global_alias_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            globalThis.x = 2;
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_mutated_by_transitively_called_function_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            function inner() {
              x = 2;
            }
            function outer() {
              inner();
            }
            outer();
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_not_over_rejected_by_same_named_escaping_mutation(self):
        source = inspect.cleandoc(
            """
            var x = 7;
            function make() {
              var x = 0;
              return function() {
                x = 1;
              };
            }
            sink(make());
            SINK.push(x);
            """
        )
        inlined_declaration_kept = inspect.cleandoc(
            """
            var x = 7;
            function make() {
              var x = 0;
              return function() {
                x = 1;
              };
            }
            sink(make());
            SINK.push(7);
            """
        )
        inlined_declaration_gone = inspect.cleandoc(
            """
            function make() {
              var x = 0;
              return function() {
                x = 1;
              };
            }
            sink(make());
            SINK.push(7);
            """
        )
        self.assertIn(self._inline(source), (inlined_declaration_kept, inlined_declaration_gone))

    def test_constant_mutated_in_function_with_confined_reads_not_inlined_past_the_write(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {
              sink(x);
              x = 2;
              sink(x);
            }
            f();
            """
        )
        self.assertIn(
            self._inline(source),
            (
                source,
                inspect.cleandoc(
                    """
                    var x = 1;
                    function f() {
                      sink(1);
                      x = 2;
                      sink(x);
                    }
                    f();
                    """
                ),
            ),
        )

    def test_constant_mutated_by_redeclared_function_not_inlined(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            function f() {}
            function f() {
              x = 2;
            }
            f();
            sink(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_not_inlined_into_own_function_before_declaration(self):
        source = inspect.cleandoc(
            """
            function f() {
              log(c);
              const c = 5;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_uninitialized_var_not_inlined_into_own_function_before_assignment(self):
        source = inspect.cleandoc(
            """
            function f() {
              log(x);
              var x;
              x = 5;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_not_inlined_into_same_named_free_reference(self):
        source = inspect.cleandoc(
            """
            function read() {
              return v;
            }
            if (cond) {
              const v = 9;
            }
            sink(read());
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

    def test_call_init_left_alone_or_moved_into_its_adjacent_use(self):
        self.assertIn(
            self._inline('var x = f(); return x;'),
            (
                inspect.cleandoc(
                    """
                    var x = f();
                    return x;
                    """
                ),
                'return f();',
            ),
        )

    def test_member_access_init_left_alone_or_moved_into_its_adjacent_use(self):
        self.assertIn(
            self._inline('var x = a.b; return x;'),
            (
                inspect.cleandoc(
                    """
                    var x = a.b;
                    return x;
                    """
                ),
                'return a.b;',
            ),
        )

    def test_member_array_element_increment_not_inlined(self):
        source = inspect.cleandoc(
            """
            var X = {};
            X.Y = [5];
            X.Y[0]++;
            SINK(X.Y[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_member_array_element_delete_not_inlined(self):
        source = inspect.cleandoc(
            """
            var X = {};
            X.Y = [5, 6];
            delete X.Y[0];
            SINK(X.Y[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_a_member_array_of_an_empty_namespace_folds_through_the_pipeline(self):
        self.assertEqual('SINK(6);', self._deobfuscate('var X = {}; X.Y = [5, 6]; SINK(X.Y[1]);'))

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

    def test_var_array_inlined_into_called_function_after_definition(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 'a';
                }
                f();
                """
            ),
            self._inline("var p = ['a']; function f() { return p[0]; } f();"),
        )

    def test_var_inlined_into_an_iife_reader_after_definition(self):
        self.assertEqual(
            "(function() {\n  SINK('abc');\n})();",
            self._inline("var k = 'abc'; (function () { SINK(k); })();"),
        )

    def test_var_inlined_into_a_stored_function_reader_after_definition(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function() {
                  SINK('abc');
                };
                f();
                """
            ),
            self._inline("var k = 'abc'; var f = function () { SINK(k); }; f();"),
        )

    def test_var_array_inlined_into_an_iife_reader_after_definition(self):
        self.assertEqual(
            "(function() {\n  SINK('a');\n})();",
            self._inline("var p = ['a']; (function () { SINK(p[0]); })();"),
        )

    def test_var_not_inlined_into_an_iife_reader_that_runs_too_early(self):
        source = inspect.cleandoc(
            """
            (function() {
              SINK(k);
            })();
            var k = 'abc';
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_guard_read_does_not_block_index_inlining(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = ['x'];
                if (!a) {
                  return;
                }
                f('x');
                """
            ),
            self._inline("var a = ['x']; if (!a) { return; } f(a[0]);"),
        )

    def test_a_truthiness_test_does_not_block_index_inlining(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = ['x'];
                if (a) {
                  f('x');
                }
                """
            ),
            self._inline("var a = ['x']; if (a) { f(a[0]); }"),
        )

    def test_a_void_operand_does_not_block_index_inlining(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = ['x'];
                void a;
                f('x');
                """
            ),
            self._inline("var a = ['x']; void a; f(a[0]);"),
        )

    def test_a_loose_equality_operand_leaves_the_index_read_alone_or_folds_it(self):
        source = inspect.cleandoc(
            """
            var a = ['x'];
            if (a == 1) {
              return;
            }
            f(a[0]);
            """
        )
        self.assertIn(
            self._inline(source),
            (
                source,
                inspect.cleandoc(
                    """
                    var a = ['x'];
                    if (a == 1) {
                      return;
                    }
                    f('x');
                    """
                ),
            ),
        )

    def test_an_argument_escape_still_blocks_index_inlining(self):
        source = inspect.cleandoc(
            """
            var a = ['x'];
            g(a);
            f(a[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_a_with_governed_truthiness_read_still_blocks_index_inlining(self):
        source = inspect.cleandoc(
            """
            function g() {
              var a = ['x'];
              with (o) {
                if (!a) {
                  return;
                }
              }
              f(a[0]);
            }
            """
        )
        self.assertEqual(source, self._inline(source))

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

    def test_intrinsic_alias_inlined_across_functions(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function g() {
                  return new Array(1);
                }
                g();
                """
            ),
            self._inline("var A = Array; function g() { return new A(1); } g();"),
        )

    def test_intrinsic_alias_not_inlined_into_shadowing_scope(self):
        source = inspect.cleandoc(
            """
            var A = Array;
            function g(Array) {
              return new A(1);
            }
            g(0);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_alias_not_inlined_where_its_free_name_is_shadowed(self):
        source = inspect.cleandoc(
            """
            function f() {
              var g = parseInt;
              {
                let parseInt = function(s) {
                  return 99;
                };
                console.log(g('7'));
              }
            }
            f();
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_alias_inlined_where_its_free_name_stays_free(self):
        source = inspect.cleandoc(
            """
            function f() {
              var g = parseInt;
              {
                console.log(g('7'));
              }
            }
            f();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  {
                    console.log(parseInt('7'));
                  }
                }
                f();
                """
            ),
            self._inline(source),
        )

    def test_non_bare_intrinsic_alias_not_inlined(self):
        source = inspect.cleandoc(
            """
            var S = globalThis.String || String;
            function g() {
              return S.fromCharCode(65);
            }
            g();
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_const_not_inlined_into_function_called_earlier_in_same_statement(self):
        source = inspect.cleandoc(
            """
            const d = f(), c = 5;
            function f() {
              return c;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_var_not_inlined_into_function_called_earlier_in_same_statement(self):
        source = inspect.cleandoc(
            """
            var x = f(), c = 5;
            function f() {
              return c;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_const_not_inlined_into_function_in_caller_default_parameter(self):
        source = inspect.cleandoc(
            """
            inner();
            const c = 5;
            function f() {
              return c;
            }
            function inner(a = f()) {
              return a;
            }
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_const_inlined_into_function_in_caller_default_parameter_after_definition(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 5;
                }
                function inner(a = f()) {
                  return a;
                }
                inner();
                """
            ),
            self._inline(
                'const c = 5; function f() { return c; } function inner(a = f()) { return a; } inner();'),
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
            f(p[0]);
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

    def test_non_literal_array_element_left_alone_or_read_where_it_is_used(self):
        self.assertIn(
            self._inline('const p = [a, 1]; f(p[0]);'),
            (
                inspect.cleandoc(
                    """
                    const p = [a, 1];
                    f(p[0]);
                    """
                ),
                'f(a);',
            ),
        )

    def test_out_of_bounds_index_left_alone_or_read_as_undefined(self):
        self.assertIn(
            self._inline('const p = [1, 2]; f(p[999]);'),
            (
                inspect.cleandoc(
                    """
                    const p = [1, 2];
                    f(p[999]);
                    """
                ),
                'f(void 0);',
            ),
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

    def test_push_leaves_the_index_read_alone_or_folds_the_element_it_kept(self):
        source = inspect.cleandoc(
            """
            const a = [1, 2];
            a.push(3);
            f(a[1]);
            """
        )
        self.assertIn(
            self._inline(source),
            (
                source,
                inspect.cleandoc(
                    """
                    const a = [1, 2];
                    a.push(3);
                    f(2);
                    """
                ),
            ),
        )

    def test_parenthesized_index_write_blocks_inline_of_the_written_index(self):
        source = inspect.cleandoc(
            """
            const a = [1, 2];
            (a[0]) = 9;
            f(a[0]);
            f(a[1]);
            """
        )
        self.assertIn(
            self._inline(source),
            (
                source,
                inspect.cleandoc(
                    """
                    const a = [1, 2];
                    (a[0]) = 9;
                    f(a[0]);
                    f(2);
                    """
                ),
            ),
        )

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

    def test_parenthesized_assignment_target_not_inlined_past_the_write(self):
        self.assertIn(
            self._inline('var a = 5; console.log(a); (a) = 9; console.log(a);'),
            (
                inspect.cleandoc(
                    """
                    var a = 5;
                    console.log(a);
                    (a) = 9;
                    console.log(a);
                    """
                ),
                inspect.cleandoc(
                    """
                    var a = 5;
                    console.log(5);
                    (a) = 9;
                    console.log(a);
                    """
                ),
            ),
        )

    @opportunity
    def test_read_before_a_reassignment_takes_the_initial_value(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = 5;
                console.log(5);
                a = 9;
                console.log(a);
                """
            ),
            self._inline('var a = 5; console.log(a); a = 9; console.log(a);'),
        )

    def test_parenthesized_update_target_not_inlined_past_the_update(self):
        self.assertIn(
            self._inline('var a = 5; console.log(a); (a)++; console.log(a);'),
            (
                inspect.cleandoc(
                    """
                    var a = 5;
                    console.log(a);
                    (a)++;
                    console.log(a);
                    """
                ),
                inspect.cleandoc(
                    """
                    var a = 5;
                    console.log(5);
                    (a)++;
                    console.log(a);
                    """
                ),
            ),
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

    def _inline_one_plan_at_a_time(self, source: str) -> str:
        ast = JsParser(source).parse()
        instance = JsConstantInlining()
        instance.options = None
        instance.batching = False
        instance.visit(ast)
        return JsSynthesizer().convert(ast)

    def test_a_substitution_that_clones_a_read_keeps_the_binding_it_was_cloned_from(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Math.floor = function() {
                  return 1;
                };
                console.log(String(Math.floor(1.7)));
                """
            ),
            self._inline(AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND[
                'a two-hop intrinsic alias']),
        )

    def test_a_plan_whose_target_an_earlier_plan_detached_folds_the_next_round(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function inner() {
                  console.log(5 + 1);
                }
                inner();
                """
            ),
            self._inline(AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND[
                'a constant read inside a relocated initializer']),
        )

    @a_property_of_the_batch_itself
    def test_the_same_inlines_fold_the_same_way_one_plan_at_a_time(self):
        rows = AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND
        self.assertEqual(
            {source: self._inline_one_plan_at_a_time(source) for source in rows},
            {source: self._inline(source) for source in rows},
        )

    def test_a_shadowing_declaration_folds_its_outer_name_away_in_the_same_round(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  console.log(9);
                }
                f();
                console.log(5);
                """
            ),
            self._inline(A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE[
                'a shadowing declaration in a nested scope']),
        )

    def test_a_shadowing_declaration_two_scopes_deep_folds_its_outer_name_away(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  function g() {
                    console.log(9);
                  }
                  g();
                }
                f();
                console.log(5);
                """
            ),
            self._inline(A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE[
                'a shadowing declaration two scopes deep']),
        )

    @a_property_of_the_batch_itself
    def test_a_round_a_shadowing_declaration_shares_folds_the_same_way_one_plan_at_a_time(self):
        rows = A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE
        self.assertEqual(
            {source: self._inline_one_plan_at_a_time(source) for source in rows},
            {source: self._inline(source) for source in rows},
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


A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY = {
    'var q = 1;\nconsole.log(JSON.stringify({ q }));\n': (
        'console.log(JSON.stringify({ q: 1 }));',
    ),
    'var q = "a";\nconsole.log(JSON.stringify({ q }));\n': (
        'console.log(JSON.stringify({ q: "a" }));',
    ),
    'var q = 1;\nvar w = 2;\nconsole.log(JSON.stringify({ q, w }));\n': (
        'console.log(JSON.stringify({ q: 1, w: 2 }));',
    ),
    'var q = 1;\nvar o = { q, r: 2 };\nconsole.log(JSON.stringify(o));\n': (
        'var o = { q: 1, r: 2 };\nconsole.log(JSON.stringify(o));',
    ),
    'var q = 1;\nconsole.log(JSON.stringify({ q: q }));\n': (
        'console.log(JSON.stringify({ q: 1 }));',
    ),
    'var p = 5;\nvar o = { q: p };\nvar { q } = o;\nconsole.log(q);\n': (
        'var o = { q: 5 };\nvar { q } = o;\nconsole.log(q);',
        'console.log(5);',
    ),
    'var d = 5;\nvar o = {};\nvar { q = d } = o;\nconsole.log(q);\n': (
        'var o = {};\nvar { q = 5 } = o;\nconsole.log(q);',
        'console.log(5);',
    ),
}


class TestAConstantSubstitutedIntoAShorthandPropertyKeepsItsName(TestBase):

    def test_a_constant_substituted_into_a_shorthand_property_is_written_under_its_name(self):
        for source, texts in A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY.items():
            with self.subTest(source=source):
                self.assertIn(folded(source), texts)


AN_ALIAS_CALL_READING_A_LOCAL_OF_ITS_CALLER = (
    'function f(){ var loc = 7; var g = eval;'
    " try { return g('loc'); } catch (e) { return e.constructor.name; } }"
    ' console.log(f());'
)

AN_ALIAS_CALL_UNDER_A_TYPEOF_GUARD = (
    'function f(){ var loc = 7; var g = eval;'
    " return typeof g('typeof loc'); }"
    ' console.log(f());'
)

AN_ALIAS_OF_EVAL_READ_WITHOUT_A_CALL = (
    'function f(){ var g = eval; return typeof g; } console.log(f());'
)

AN_ALIAS_OF_ANOTHER_GLOBAL_CALLED = (
    "function f(){ var g = parseInt; return g('7'); } console.log(f());"
)


A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL = {
    AN_ALIAS_CALL_READING_A_LOCAL_OF_ITS_CALLER: (
        'function f() {\n'
        '  try {\n'
        '    return loc;\n'
        '  } catch (e) {\n'
        '    return e.constructor.name;\n'
        '  }\n'
        '}\n'
        'console.log(f());'
    ),
    AN_ALIAS_CALL_UNDER_A_TYPEOF_GUARD: (
        'function f() {\n'
        '  return typeof typeof loc;\n'
        '}\n'
        'console.log(f());'
    ),
    AN_ALIAS_OF_EVAL_READ_WITHOUT_A_CALL: (
        "console.log('function');"
    ),
    AN_ALIAS_OF_ANOTHER_GLOBAL_CALLED: (
        'console.log(7);'
    ),
}

WHAT_A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL_PRINTS = {
    AN_ALIAS_CALL_READING_A_LOCAL_OF_ITS_CALLER: 'ReferenceError\n',
    AN_ALIAS_CALL_UNDER_A_TYPEOF_GUARD: 'string\n',
    AN_ALIAS_OF_EVAL_READ_WITHOUT_A_CALL: 'function\n',
    AN_ALIAS_OF_ANOTHER_GLOBAL_CALLED: '7\n',
}


class TestACallThroughANameBoundToEvalStaysIndirect(TestJsDeobfuscator):
    """
    A call whose callee is the name `eval` runs its text in the caller's scope; a call that reaches
    `eval` any other way, such as `var g = eval; g(s)`, runs it in the global scope, where the
    caller's locals are not visible.
    """

    def test_the_name_eval_is_never_written_into_a_callee_position(self):
        rows = A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)

    def test_the_constant_inliner_alone_writes_the_indirect_spelling(self):
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
            self._inline(AN_ALIAS_CALL_READING_A_LOCAL_OF_ITS_CALLER),
        )

    def test_the_constant_inliner_alone_takes_the_bare_name_where_nothing_calls_it(self):
        self.assertEqual(
            'function f() {\n  return typeof eval;\n}\nconsole.log(f());',
            self._inline(AN_ALIAS_OF_EVAL_READ_WITHOUT_A_CALL),
        )

    def test_the_constant_inliner_alone_calls_another_global_bare(self):
        self.assertEqual(
            "function f() {\n  return parseInt('7');\n}\nconsole.log(f());",
            self._inline(AN_ALIAS_OF_ANOTHER_GLOBAL_CALLED),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutACallThroughANameBoundToEval(TestBase):

    def test_the_rewritten_call_sees_no_local_of_its_caller(self):
        rows = WHAT_A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND = {
    'a two-hop intrinsic alias': (
        'var a = Math; var b = a; b.floor = function () { return 1; };'
        ' console.log(String(Math.floor(1.7)));'
    ),
    'a constant read inside a relocated initializer': (
        'const K = 5; function inner() { var t = K + 1; console.log(t); } inner();'
    ),
}

A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE = {
    'a shadowing declaration in a nested scope': (
        'var K = 5; function f() { var K = 9; console.log(K); } f(); console.log(K);'
    ),
    'a shadowing declaration two scopes deep': (
        'var K = 5; function f() { function g() { var K = 9; console.log(K); } g(); }'
        ' f(); console.log(K);'
    ),
}

WHAT_A_DECLARATION_THAT_SHARES_ITS_ROUND_PRINTS = {
    A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE[
        'a shadowing declaration in a nested scope'
    ]: '9\n5\n',
    A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE[
        'a shadowing declaration two scopes deep'
    ]: '9\n5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutADeclarationThatSharesItsRound(TestBase):

    def test_the_outer_name_still_prints_the_same(self):
        rows = WHAT_A_DECLARATION_THAT_SHARES_ITS_ROUND_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


WHAT_AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_PRINTS = {
    AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND[
        'a two-hop intrinsic alias'
    ]: '1\n',
    AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND[
        'a constant read inside a relocated initializer'
    ]: '6\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAnInlineThatSurvivesAnEarlierPlan(TestBase):

    def test_the_rounds_that_were_held_back_still_print_the_same(self):
        rows = WHAT_AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_CHAIN_OF_SINGLE_USE_LOCALS_READ_ACROSS_A_WRITE = {
    'a free global two functions write': (
        'function setp() { p = 0; } function bump() { p = 99; }'
        ' setp(); var x = p + 0; var y = x + 0; bump(); console.log(y);'
    ),
    'a script binding two functions write': (
        'var x = 1; function s() { x = 2; } function f() { x = 9; }'
        ' s(); var t0 = x + 1; var t1 = t0 * 3; f(); console.log(t1);'
    ),
    'a chain three locals long': (
        'var x = 1; function s() { x = 2; } function f() { x = 9; }'
        ' s(); var t0 = x + 1; var t1 = t0 * 3; var t2 = t1 - 4; f(); console.log(t2);'
    ),
}

WHAT_A_CHAIN_OF_SINGLE_USE_LOCALS_READ_ACROSS_A_WRITE_PRINTS = {
    A_CHAIN_OF_SINGLE_USE_LOCALS_READ_ACROSS_A_WRITE[
        'a free global two functions write'
    ]: '0\n',
    A_CHAIN_OF_SINGLE_USE_LOCALS_READ_ACROSS_A_WRITE[
        'a script binding two functions write'
    ]: '9\n',
    A_CHAIN_OF_SINGLE_USE_LOCALS_READ_ACROSS_A_WRITE[
        'a chain three locals long'
    ]: '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAChainReadAcrossAWrite(TestBase):

    def test_the_chain_still_prints_the_value_read_before_the_write(self):
        rows = WHAT_A_CHAIN_OF_SINGLE_USE_LOCALS_READ_ACROSS_A_WRITE_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_MEMBER_ARRAY_READ_THROUGH_ANOTHER_RECEIVER = {
    inspect.cleandoc("""
        function outer(X) {
          function f() { X.Y = [1, 2]; console.log(X.Y[0]); }
          function g() { console.log(X.Y[1]); }
          f();
          g();
        }
        outer({});
    """): '1\n2\n',
    inspect.cleandoc("""
        globalThis.X = {};
        function f() { X.Y = [1, 2]; console.log(X.Y[0]); }
        function g() { console.log(X.Y[1]); }
        f();
        g();
    """): '1\n2\n',
    inspect.cleandoc("""
        function outer(X) {
          X.Y = [1, 2];
          function g(X) { return X.Y[0]; }
          console.log(X.Y[1], g({ Y: [9] }));
        }
        outer({});
    """): '2 9\n',
    inspect.cleandoc("""
        function outer(X) {
          X.Y = [1, 2];
          console.log(X.Y[1], (function (X) { return X.Y[0]; })({ Y: [9] }));
        }
        outer({});
    """): '2 9\n',
    inspect.cleandoc("""
        function outer(X) {
          X.Y = [1, 2];
          { let X = { Y: [9] }; console.log(X.Y[0]); }
          console.log(X.Y[1]);
        }
        outer({});
    """): '9\n2\n',
    inspect.cleandoc("""
        function outer(X) { X.Y = [1, 2]; var Z = X; Z.Y = [5, 6]; console.log(X.Y[0]); }
        outer({});
    """): '5\n',
    inspect.cleandoc("""
        function outer(X, W) { X.Y = [1, 2]; W.Y = [5, 6]; console.log(X.Y[0]); }
        var o = {};
        outer(o, o);
    """): '5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAMemberArrayReadThroughAnotherReceiver(TestBase):

    def test_each_read_prints_the_array_its_receiver_holds(self):
        rows = A_MEMBER_ARRAY_READ_THROUGH_ANOTHER_RECEIVER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_LOCAL_A_LATER_STORE_DEFINES = {
    'function f(q) { var b; b = q; return b + 1; }'
    ' console.log(f(Math.random() < 2 ? 1 : 0), typeof b);': (
        '2 undefined\n'
    ),
    'function f(p, q) { var a, b; a = p, b = q; return a + b + b; }'
    ' console.log(f(Math.random() < 2 ? 1 : 0, 2), typeof a, typeof b);': (
        '5 undefined undefined\n'
    ),
}


class TestALocalALaterStoreDefines(TestJsDeobfuscator):

    def test_inlining_its_one_read_keeps_the_declaration_the_store_writes(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(q) {
                  var b;
                  b = q;
                  return q + 1;
                }
                """
            ),
            self._inline('function f(q) { var b; b = q; return b + 1; }'),
        )

    def test_the_whole_deobfuscation_drops_the_dead_store_with_its_declaration(self):
        self.assertIn(
            self._deobfuscate('function f(q) { var b; b = q; return b + 1; }'),
            (
                inspect.cleandoc(
                    """
                    function f(q) {
                      return q + 1;
                    }
                    """
                ),
                inspect.cleandoc(
                    """
                    function f(b) {
                      return b + 1;
                    }
                    """
                ),
            ),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_store_stays_local(self):
        rows = A_LOCAL_A_LATER_STORE_DEFINES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_STORE_ITS_STATEMENT_DOES_NOT_ALWAYS_RUN = {
    'var b; Math.random() > 2 && (b = 1); console.log(b);\n': 'undefined\n',
    'function f(a) { var b; a > 0 && (b = 1); console.log(b); } f(0); f(1);\n': (
        'undefined\n1\n'
    ),
    'function f(a) { var b; a > 0 ? (b = 1) : 0; console.log(b); } f(0);\n': 'undefined\n',
    'function f(a) { var b; a?.[(b = 2)]; console.log(b); } f(null);\n': 'undefined\n',
    'function f(k) { var y; switch (k) { case 1: console.log(y); break; case (y = 5): break; } }'
    ' f(1);\n': 'undefined\n',
    'function f() { var i, a = {}; for (a[i = 5] in {}); console.log(i); } f();\n': 'undefined\n',
}

A_DECLARATION_A_LABEL_HOLDS = {
    'lbl: var k = 5; console.log(k, k);\n': '5 5\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAStoreItsStatementDoesNotAlwaysRun(TestBase):

    def test_the_read_after_the_statement_keeps_the_value_from_before(self):
        rows = A_STORE_ITS_STATEMENT_DOES_NOT_ALWAYS_RUN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_declaration_a_label_holds_leaves_a_statement_behind(self):
        rows = A_DECLARATION_A_LABEL_HOLDS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAnInOrInstanceofIsNotMovedPastAChangeToWhatItReads(TestJsDeobfuscator):

    def test_the_inliner_leaves_its_declaration_where_it_stands(self):
        for source in (
            "var o = {k: 1}; var r = 'k' in o; delete o.k; f(r);",
            'function C() {} var o = new C(); var r = o instanceof C; C.prototype = {}; f(r);',
        ):
            with self.subTest(source=source):
                self.assertEqual(self._inline(source), JsSynthesizer().convert(JsParser(source).parse()))


AN_IN_OR_INSTANCEOF_BEFORE_A_CHANGE: dict[str, Program] = {
    'in operator across declarators': Program(
        a_program("""
            function f() {
              var o = {}, s = (o.k = 1), r = 'k' in o, d = delete o.k, q = 'k' in o;
              return [r, q].join();
            }
            console.log(f());
            """),
        prints('true,false'),
        Reading.COMMONJS,
    ),
    'in operator separate statements': Program(
        a_program("""
            function f() {
              var o = {};
              var s = o.k = 1;
              var r = 'k' in o;
              var d = delete o.k;
              var q = 'k' in o;
              return [r, q].join();
            }
            console.log(f());
            """),
        prints('true,false'),
        Reading.COMMONJS,
    ),
    'instanceof moved past prototype swap': Program(
        a_program("""
            function f() {
              function C() {}
              var o = new C(), was = o instanceof C, swap = (C.prototype = {}), now = o instanceof C;
              return [was, now].join();
            }
            console.log(f());
            """),
        prints('true,false'),
        Reading.COMMONJS,
    ),
    'instanceof separate statements': Program(
        a_program("""
            function f() {
              function C() {}
              var o = new C();
              var was = o instanceof C;
              var swap = (C.prototype = {});
              var now = o instanceof C;
              return [was, now].join();
            }
            console.log(f());
            """),
        prints('true,false'),
        Reading.COMMONJS,
    ),
}

A_VALUE_READ_BEFORE_A_SUSPENSION: dict[str, Program] = {
    'async await between declarators': Program(
        a_program("""
            var shared = 'before';
            async function f() {
              var a = shared, b = await null, c = a + shared;
              return c;
            }
            f().then(function (v) { console.log(v); });
            shared = 'after';
            """),
        prints('beforeafter'),
        Reading.COMMONJS,
    ),
    'async await separate statements': Program(
        a_program("""
            var shared = 'before';
            async function f() {
              var a = shared;
              var b = await null;
              var c = a + shared;
              return c;
            }
            f().then(function (v) { console.log(v); });
            shared = 'after';
            """),
        prints('beforeafter'),
        Reading.COMMONJS,
    ),
    'yield between declarators': Program(
        a_program("""
            var shared = 'before';
            function* g() {
              var a = shared, b = yield 0, c = a + shared;
              return c;
            }
            var it = g();
            it.next();
            shared = 'after';
            console.log(it.next().value);
            """),
        prints('beforeafter'),
        Reading.COMMONJS,
    ),
    'yield separate statements': Program(
        a_program("""
            var shared = 'before';
            function* g() {
              var a = shared;
              var b = yield 0;
              var c = a + shared;
              return c;
            }
            var it = g();
            it.next();
            shared = 'after';
            console.log(it.next().value);
            """),
        prints('beforeafter'),
        Reading.COMMONJS,
    ),
    'await minified shape': Program(
        a_program("""
            var state = { ready: false };
            async function load() {
              var flag = state.ready, wait = await Promise.resolve(), now = state.ready;
              return [flag, now].join();
            }
            load().then(function (v) { console.log(v); });
            state.ready = true;
            """),
        prints('false,true'),
        Reading.COMMONJS,
    ),
    'await local counter minified': Program(
        a_program("""
            var count = 0;
            async function tick() { count++; }
            async function f() {
              var before = count, w = await tick(), after = count;
              return before + ':' + after;
            }
            f().then(function (v) { console.log(v); });
            """),
        prints('0:1'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAReadBeforeAChangeOrASuspension(TestBase):

    rows = {**AN_IN_OR_INSTANCEOF_BEFORE_A_CHANGE, **A_VALUE_READ_BEFORE_A_SUSPENSION}

    def test_node_prints_what_each_row_pins(self):
        for label, row in self.rows.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in self.rows.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


def _a_chain_of_local_increments(n: int) -> str:
    lines = ['var v0 = 1;']
    for i in range(1, n):
        lines.append(F'var v{i} = v{i - 1} + 1;')
    lines.append('console.log(1);')
    return '\n'.join(lines) + '\n'


class TestADeepChainOfLocalsFoldsToItsPrint(TestBase):
    """
    The chain folds into one binary expression as deep as the chain is long, and every pass walks
    that tree recursively.
    """

    def test_a_chain_of_three_hundred_locals_folds_to_its_print(self):
        self.assertEqual('console.log(1);', deobfuscate_source(_a_chain_of_local_increments(300)))

    @opportunity
    def test_a_chain_of_four_hundred_locals_folds_to_its_print_at_the_default_recursion_limit(self):
        """
        The units solve this problem by raising the recursion limit; ideally, the deobfuscation would
        do without that.
        """
        try:
            output = deobfuscate_source(_a_chain_of_local_increments(400))
        except RecursionError:
            output = None
        self.assertEqual('console.log(1);', output)

    def test_a_chain_of_four_hundred_locals_folds_to_its_print_under_the_limit_the_units_raise(self):
        with RecursionDepth(TREE_RECURSION_DEPTH):
            output = deobfuscate_source(_a_chain_of_local_increments(400))
        self.assertEqual('console.log(1);', output)
