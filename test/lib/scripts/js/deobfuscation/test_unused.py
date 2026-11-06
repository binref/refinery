from __future__ import annotations

import functools
import inspect
import threading
import unittest

from test import TestBase, fastest_processor_time, opportunity, processor_time_ratio, todo
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints, printed

from refinery.lib.scripts import tree_version
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import (
    JsUnusedCodeRemoval,
    _destructuring_target_safe,
)
from refinery.lib.scripts.js.model import JsAssignmentExpression
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting.djs import djs


class TestUnusedCodeRemoval(TestJsDeobfuscator):

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    def test_binding_used_only_in_class_decorator_preserved(self):
        source = inspect.cleandoc(
            """
            var deco = function(x) {
              return x;
            };
            @deco class C {}
            new C();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_pseudo_global_read_through_alias_not_relocated(self):
        source = inspect.cleandoc(
            """
            var g;
            function f() {
              g = 5;
              return globalThis.g;
            }
            console.log(f());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_global_data_property_read_removed(self):
        source = inspect.cleandoc(
            """
            var d = globalThis.TextDecoder;
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_dead_non_data_property_global_read_preserved(self):
        source = inspect.cleandoc(
            """
            var d = globalThis.location;
            console.log(1);
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            globalThis.location;
            console.log(1);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_binding))

    def test_dead_strict_function_caller_read_preserved(self):
        """
        Reading `caller` off a strict-mode function throws a `TypeError`.
        """
        source = inspect.cleandoc(
            """
            var x = function() {
              'use strict';
            }.caller;
            console.log(1);
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            (function() {
              'use strict';
            }.caller);
            console.log(1);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_binding))

    def test_dead_strict_function_computed_caller_read_preserved(self):
        source = inspect.cleandoc(
            """
            var x = function() {
              'use strict';
            }['caller'];
            console.log(1);
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            (function() {
              'use strict';
            }['caller']);
            console.log(1);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_binding))

    def test_dead_global_alias_data_property_read_removed(self):
        source = inspect.cleandoc(
            """
            var g = globalThis || {};
            var d = g.TextDecoder;
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_dead_global_alias_read_before_establishment_preserved(self):
        source = inspect.cleandoc(
            """
            var d = g.TextDecoder;
            var g = globalThis || {};
            console.log(1);
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            g.TextDecoder;
            var g = globalThis || {};
            console.log(1);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_binding))

    def test_a_read_ending_the_directive_prologue_goes_only_after_the_literal_behind_it(self):
        """
        Deleting the read alone would move the `'use strict'` behind it into the Directive Prologue
        and make the script strict.
        """
        source = inspect.cleandoc(
            """
            'abc'[0];
            'use strict';
            if (x) {
              console.log(1);
            }
            """
        )
        without_the_literal = inspect.cleandoc(
            """
            'abc'[0];
            if (x) {
              console.log(1);
            }
            """
        )
        without_either = inspect.cleandoc(
            """
            if (x) {
              console.log(1);
            }
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_literal, without_either))

    @opportunity
    def test_a_read_ending_the_directive_prologue_goes_with_the_literal_behind_it(self):
        source = inspect.cleandoc(
            """
            'abc'[0];
            'use strict';
            if (x) {
              console.log(1);
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                if (x) {
                  console.log(1);
                }
                """
            ),
            self._deobfuscate(source),
        )

    def test_a_read_ending_the_directive_prologue_goes_once_the_literal_has(self):
        source = inspect.cleandoc(
            """
            'abc'[0];
            'hello';
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_a_dead_in_expression_with_a_primitive_right_operand_is_kept(self):
        source = inspect.cleandoc(
            """
            'a' in 'b';
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_a_dead_instanceof_expression_with_a_non_callable_right_operand_is_kept(self):
        source = inspect.cleandoc(
            """
            var x = 3;
            x instanceof 5;
            console.log(x);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_the_read_a_breaking_block_leaves_as_the_script_value_is_kept_on_request(self):
        """
        The labeled block completes through `break L` with an empty value, so the read `x` before it
        is what the program completes with: an `eval` of the file returns `1`.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            x;
            L: {
              break L;
              99;
            }
            """
        )
        options = DeobfuscationOptions(preserve_script_return=True)
        self.assertEqual(source, self._run_transformer(source, JsUnusedCodeRemoval, options))

    @opportunity
    def test_a_read_the_script_ends_on_goes_where_the_script_value_is_not_kept(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            SINK(x);
            x;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 1;
                SINK(x);
                """
            ),
            self._remove_unused(source),
        )

    def test_block_scoped_var_read_outside_block_preserved(self):
        source = inspect.cleandoc(
            """
            function f(cond) {
                if (cond) {
                    var a;
                    a = 1;
                }
                return a;
            }
            console.log(f(true));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(cond) {
                  if (cond) {
                    var a;
                    a = 1;
                  }
                  return a;
                }
                console.log(f(true));
                """
            ),
            self._remove_unused(source),
        )

    def test_aliased_object_mutated_through_alias_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a = { p0: 1 };
              var b = a;
              b.p0 = 2;
              return a.p0;
            }
            console.log(f());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_object_mutated_by_callee_is_kept(self):
        source = inspect.cleandoc(
            """
            function m(x) {
              x.p0 = 9;
            }
            function f() {
              var a = { p0: 1 };
              m(a);
              return a.p0;
            }
            console.log(f());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_aliased_array_mutated_through_alias_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a = [1, 2];
              var b = a;
              b[0] = 9;
              return a[0];
            }
            console.log(f());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_local_dead_declaration_removed(self):
        source = inspect.cleandoc(
            """
            function f() {
                var dead = 1;
                return 2;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 2;
                }
                console.log(f());
                """
            ),
            self._remove_unused(source),
        )

    def test_script_scope_vars_localized_into_their_function(self):
        source = inspect.cleandoc(
            """
            var acc, i, push, dead;
            dead = 1;
            function build(n) {
                acc = [];
                for (i = 1; i <= n; i++) {
                    acc.push(i);
                }
                return acc;
            }
            console.log(build(20));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function build(n) {
                  var acc, i;
                  acc = [];
                  for (i = 1; i <= n; i++) {
                    acc.push(i);
                  }
                  return acc;
                }
                console.log(build(20));
                """
            ),
            self._remove_unused(source),
        )

    def test_script_scope_var_read_before_write_is_not_localized(self):
        source = inspect.cleandoc(
            """
            var counter;
            function next() {
              counter = counter + 1;
              return counter;
            }
            console.log(next(), next());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_initializer_stripped_when_overwritten_before_read(self):
        source = 'function f() { var x = 1; x = 2; return x; }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x;
                  x = 2;
                  return x;
                }
                """
            ),
            self._remove_unused(source),
        )

    def test_dead_pure_call_initializer_stripped(self):
        source = 'function f() { var x = String.fromCharCode(65); x = pick(); return x; }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x;
                  x = pick();
                  return x;
                }
                """
            ),
            self._remove_unused(source),
        )

    def test_dead_pure_call_assignment_removed(self):
        source = 'function f() { var x; x = String.fromCharCode(65); x = read(); return x; }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x;
                  x = read();
                  return x;
                }
                """
            ),
            self._remove_unused(source),
        )

    def test_dead_store_with_effectful_rhs_kept_as_bare_expression(self):
        source = 'function f() { var x; x = sideEffect(); x = 2; return x; }'
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  var x;
                  sideEffect();
                  x = 2;
                  return x;
                }
                """
            ),
            self._remove_unused(source),
        )

    def test_dead_store_calling_a_dead_zone_reader_keeps_its_call(self):
        source = inspect.cleandoc(
            """
            function f() { return q; }
            var dead = f();
            let q = 1;
            console.log(2);
            """
        )
        without_the_store = inspect.cleandoc(
            """
            function f() { return q; }
            f();
            let q = 1;
            console.log(2);
            """
        )
        self.assertIn(
            self._remove_unused(source),
            (self._run_transformers(source), self._run_transformers(without_the_store)),
        )

    def test_dead_store_calling_an_established_reader_is_removed(self):
        source = 'function f() { return q; }\nlet q = 1;\nvar dead = f();\nconsole.log(2);\n'
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_dead_store_calling_a_generator_dead_zone_reader_is_removed(self):
        source = 'function* gen() { return q; }\nvar dead = gen();\nlet q = 1;\nconsole.log(2);\n'
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_dead_store_calling_a_reader_of_its_own_dead_zone_local_is_removed(self):
        source = 'function f() { let x = 1; return x; }\nvar dead = f();\nconsole.log(2);\n'
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_dead_store_calling_a_reader_of_its_own_dead_zone_from_within_keeps_its_call(self):
        source = inspect.cleandoc(
            """
            function f() {
              var d = c;
              let c;
              return d;
            }
            var x = f();
            console.log(2);
            """
        )
        without_the_store = inspect.cleandoc(
            """
            function f() {
              var d = c;
              let c;
              return d;
            }
            f();
            console.log(2);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_store))

    def test_dead_store_calling_a_reader_of_an_owned_class_dead_zone_keeps_its_call(self):
        source = inspect.cleandoc(
            """
            function f() {
              var d = C;
              class C {}
              return d;
            }
            var x = f();
            console.log(2);
            """
        )
        without_the_store = inspect.cleandoc(
            """
            function f() {
              var d = C;
              class C {}
              return d;
            }
            f();
            console.log(2);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_store))

    def test_dead_store_calling_a_nested_reader_of_its_own_dead_zone_keeps_its_call(self):
        source = inspect.cleandoc(
            """
            function f() {
              function inner() {
                return c;
              }
              var d = inner();
              let c = 1;
              return d;
            }
            var x = f();
            console.log(2);
            """
        )
        without_the_store = inspect.cleandoc(
            """
            function f() {
              function inner() {
                return c;
              }
              var d = inner();
              let c = 1;
              return d;
            }
            f();
            console.log(2);
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_store))

    def test_store_to_captured_binding_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x = 1;
              x = 2;
              return function() {
                return x;
              };
            }
            """
        )
        without_the_dead_initializer = inspect.cleandoc(
            """
            function f() {
              var x;
              x = 2;
              return function() {
                return x;
              };
            }
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_dead_initializer))

    @opportunity
    def test_a_dead_initializer_of_a_captured_binding_goes(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x = 1;
              x = 2;
              return function() {
                return x;
              };
            }
            """
        )
        expected = inspect.cleandoc(
            """
            function f() {
              var x;
              x = 2;
              return function() {
                return x;
              };
            }
            """
        )
        self.assertEqual(expected, self._remove_unused(source))

    def test_conditionally_overwritten_store_is_kept(self):
        source = inspect.cleandoc(
            """
            function f(c) {
              var x = 1;
              if (c) {
                x = 2;
              }
              return x;
            }
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_global_removed_without_reflection_surface(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            console.log(2);
            """
        )
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_global_alias_compound_read_preserves_prior_write(self):
        source = inspect.cleandoc(
            """
            globalThis.X = 1;
            globalThis.X += 2;
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_global_alias_member_read_preserves_declared_global(self):
        source = inspect.cleandoc(
            """
            var g = 7;
            console.log(globalThis.g);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_reflection_surface_preserves_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            eval('deadGlobal');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_indirect_comma_eval_preserves_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            (0, eval)('deadGlobal');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_computed_literal_eval_preserves_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            window['eval']('deadGlobal');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_escaping_constructor_read_preserves_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            var F = (function() {}).constructor;
            F('deadGlobal')();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_invoked_constructor_read_still_removes_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            console.log(''.__proto__.constructor.name);
            """
        )
        self.assertEqual(
            "console.log(''.__proto__.constructor.name);",
            self._remove_unused(source),
        )

    def test_eval_alias_preserves_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            var e = eval;
            e('deadGlobal');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_shadowed_eval_still_removes_dead_global(self):
        source = inspect.cleandoc(
            """
            function eval() {
              return 0;
            }
            var deadGlobal = 1;
            console.log(eval());
            """
        )
        expected = inspect.cleandoc(
            """
            function eval() {
              return 0;
            }
            console.log(eval());
            """
        )
        self.assertEqual(expected, self._remove_unused(source))

    def test_strip_globals_keeps_reflection_reachable_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            eval('deadGlobal');
            """
        )
        ast = JsParser(source).parse()
        JsUnusedCodeRemoval(preserve_globals=False).visit(ast)
        self.assertEqual(source, JsSynthesizer().convert(ast))

    def test_reflection_surface_preserves_dead_split_global(self):
        source = inspect.cleandoc(
            """
            var x;
            x = 1;
            eval('x');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_reflection_surface_preserves_dead_function(self):
        source = inspect.cleandoc(
            """
            function dead() {
              return 1;
            }
            eval('dead()');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_function_local_read_only_by_in_function_eval_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x;
              x = 7;
              eval('x');
            }
            f();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_function_local_const_read_only_by_in_function_eval_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              const x = 5;
              eval('x');
            }
            f();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_nested_function_read_only_by_in_function_eval_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              function g() {
                return 1;
              }
              eval('g()');
            }
            f();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_destructured_local_read_only_by_in_function_eval_is_kept(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a;
              [a] = [1];
              eval('a');
            }
            f();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    @staticmethod
    def _destructuring_parts(source: str):
        ast = JsParser(source).parse()
        assign = next(n for n in ast.walk_in_order() if isinstance(n, JsAssignmentExpression))
        return assign.left, assign.right

    def test_destructuring_array_literal_source_is_safe(self):
        left, right = self._destructuring_parts('[a] = [1];')
        self.assertTrue(_destructuring_target_safe(left, right))

    def test_destructuring_non_array_source_is_unsafe(self):
        left, right = self._destructuring_parts('[a] = xs;')
        self.assertFalse(_destructuring_target_safe(left, right))

    def test_destructuring_object_proto_method_source_is_safe(self):
        left, right = self._destructuring_parts('({k: a} = {__proto__(){}});')
        self.assertTrue(_destructuring_target_safe(left, right))

    def test_destructuring_object_proto_shorthand_source_is_safe(self):
        left, right = self._destructuring_parts('({k: a} = {__proto__});')
        self.assertTrue(_destructuring_target_safe(left, right))

    def test_destructuring_object_proto_colon_source_is_unsafe(self):
        left, right = self._destructuring_parts('({k: a} = {__proto__: p});')
        self.assertFalse(_destructuring_target_safe(left, right))

    def test_destructuring_object_getter_source_is_unsafe(self):
        left, right = self._destructuring_parts('({k: a} = {get k(){}});')
        self.assertFalse(_destructuring_target_safe(left, right))

    @opportunity
    def test_destructuring_object_getter_at_a_key_the_pattern_does_not_read_is_safe(self):
        left, right = self._destructuring_parts('({k: a} = {get x(){}});')
        self.assertTrue(_destructuring_target_safe(left, right))

    def test_destructuring_object_spread_source_is_unsafe(self):
        left, right = self._destructuring_parts('({k: a} = {...o});')
        self.assertFalse(_destructuring_target_safe(left, right))

    def test_function_local_read_in_a_with_block_is_kept(self):
        source = inspect.cleandoc(
            """
            function f(o) {
              var x;
              x = 7;
              with (o) {
                x;
              }
            }
            f({});
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_no_reflection_still_removes_dead_split_global(self):
        source = inspect.cleandoc(
            """
            var x;
            x = 1;
            console.log(2);
            """
        )
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_no_init_var_captured_by_closure_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x;
              return function() {
                return x;
              };
            }
            console.log(f()());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_function_local_var_not_kept_by_shadowing_closure(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x;
              return function(x) {
                return x;
              };
            }
            console.log(f()(9));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return function(x) {
                    return x;
                  };
                }
                console.log(f()(9));
                """
            ),
            self._remove_unused(source),
        )

    def test_assigned_var_captured_by_closure_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x;
              x = 5;
              return function() {
                return x;
              };
            }
            console.log(f()());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_block_assigned_var_captured_by_closure_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x;
              if (cond) {
                x = 5;
              }
              return function() {
                return x;
              };
            }
            console.log(f()(), cond);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_strip_globals_keeps_global_read_by_closure(self):
        source = inspect.cleandoc(
            """
            var h;
            function uses() {
              return h;
            }
            console.log(uses());
            """
        )
        ast = JsParser(source).parse()
        JsUnusedCodeRemoval(preserve_globals=False).visit(ast)
        self.assertEqual(source, JsSynthesizer().convert(ast))

    def test_bare_dead_declaration_reports_change(self):
        source = inspect.cleandoc(
            """
            function f() {
              var unused;
              return 1;
            }
            console.log(f());
            """
        )
        ast = JsParser(source).parse()
        transformer = JsUnusedCodeRemoval()
        transformer.visit(ast)
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 1;
                }
                console.log(f());
                """
            ),
            JsSynthesizer().convert(ast),
        )
        self.assertTrue(transformer.changed)

    def test_closure_assignment_to_captured_var_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x = 0;
              var setter = function() {
                x = 2;
              };
              setter();
              return x;
            }
            console.log(f());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_computed_key_initializer_side_effect_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var x = { [g()]: 1 };
              return 7;
            }
            console.log(f());
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            function f() {
              ({ [g()]: 1 });
              return 7;
            }
            console.log(f());
            """
        )
        self.assertIn(self._remove_unused(source), (source, without_the_binding))

    def _remove_unused_unwrapped(self, source: str) -> str:
        """
        Runs the simplifications first, as the deobfuscation does, so that a statement-level
        object-pattern assignment reaches unused-code removal without the parentheses it must be
        written in.
        """
        return self._run_transformers(source, JsSimplifications, JsUnusedCodeRemoval)

    def test_uncalled_function_removed(self):
        source = inspect.cleandoc(
            """
            function alive() { return 1; }
            function dead() { return 2; }
            console.log(alive());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function alive() {
                  return 1;
                }
                console.log(alive());
                """
            ),
        )

    def test_dead_destructuring_removed(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a, b;
                [a, b] = [1, 2];
                return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function f() {
                  return 3;
                }
                console.log(f());
                """
            ),
        )

    def test_dead_destructuring_with_side_effect_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a, b;
                [a, b] = effect();
                return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function f() {
                  var a, b;
                  [a, b] = effect();
                  return 3;
                }
                console.log(f());
                """
            ),
        )

    def test_dead_destructuring_non_iterable_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a, b;
              [a, b] = 5;
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(self._remove_unused(source), source)

    def test_destructuring_a_compound_assignment_reads_is_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a;
              [a] = [1];
              a += 1;
              return a;
            }
            console.log(f());
            """
        )
        self.assertEqual(self._remove_unused(source), source)

    def test_dead_destructuring_beside_a_compound_assignment_never_strands_its_target(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a, b;
              [a, b] = [1, 2];
              a += 1;
              return 3;
            }
            console.log(f());
            """
        )
        without_the_destructuring = inspect.cleandoc(
            """
            function f() {
              var a;
              a += 1;
              return 3;
            }
            console.log(f());
            """
        )
        without_either = inspect.cleandoc(
            """
            function f() {
              return 3;
            }
            console.log(f());
            """
        )
        self.assertIn(
            self._remove_unused(source),
            (source, without_the_destructuring, without_either),
        )

    @opportunity
    def test_destructuring_read_only_by_a_dead_compound_assignment_goes_with_it(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a, b;
              [a, b] = [1, 2];
              a += 1;
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual('console.log(3);', self._deobfuscate(source))

    def test_dead_destructuring_beside_a_for_of_never_strands_the_loop_target(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a, b;
              [a, b] = [1, 2];
              for (a of [7, 8]) {}
              return 3;
            }
            console.log(f());
            """
        )
        without_the_destructuring = inspect.cleandoc(
            """
            function f() {
              var a;
              for (a of [7, 8]) {}
              return 3;
            }
            console.log(f());
            """
        )
        without_either = inspect.cleandoc(
            """
            function f() {
              return 3;
            }
            console.log(f());
            """
        )
        self.assertIn(
            self._remove_unused(source),
            (source, without_the_destructuring, without_either),
        )

    @opportunity
    def test_dead_destructuring_beside_a_for_of_goes_with_the_loop(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a, b;
              [a, b] = [1, 2];
              for (a of [7, 8]) {}
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual('console.log(3);', self._deobfuscate(source))

    def test_dead_destructuring_in_block_read_outside_preserved(self):
        source = inspect.cleandoc(
            """
            function f(cond) {
              if (cond) {
                var a;
                [a] = [1];
              }
              return a;
            }
            console.log(f(true));
            """
        )
        self.assertEqual(self._remove_unused(source), source)

    def test_dead_destructuring_in_block_with_surviving_outer_write_keeps_declarator(self):
        source = inspect.cleandoc(
            """
            function f(g, cond) {
              if (cond) {
                var a;
                [a] = [1];
              }
              [a] = [g()];
            }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function f(g, cond) {
                  if (cond) {
                    var a;
                  }
                  [a] = [g()];
                }
                console.log(f());
                """
            ),
        )

    def test_dead_destructuring_target_written_by_surviving_sibling_keeps_declarator(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a, b;
              [a] = [1];
              [a, b] = [2, 3];
              return b;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function f() {
                  var a, b;
                  [a, b] = [2, 3];
                  return b;
                }
                console.log(f());
                """
            ),
        )

    def test_dead_destructuring_object_getter_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a;
              ({x: a} = {get x() { return g(); }});
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(self._remove_unused_unwrapped(source), self._simplify(source))

    def test_dead_destructuring_object_computed_key_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a;
              ({x: a} = {[g()]: 1});
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(self._remove_unused_unwrapped(source), self._simplify(source))

    def test_dead_destructuring_plain_object_removed(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a;
              ({x: a} = {x: 1});
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused_unwrapped(source),
            inspect.cleandoc(
                """
                function f() {
                  return 3;
                }
                console.log(f());
                """
            ),
        )

    def test_dead_destructuring_target_read_by_computed_key_preserved(self):
        source = inspect.cleandoc(
            """
            function f(obj) {
              var a, b;
              [a] = ['k'];
              ({[a]: b} = obj);
              return b;
            }
            console.log(f({k: 42}));
            """
        )
        self.assertEqual(self._remove_unused_unwrapped(source), self._simplify(source))

    def test_dead_destructuring_object_proto_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            function f(p) {
              var a;
              ({y: a} = {__proto__: p});
              return 3;
            }
            console.log(f({}));
            """
        )
        self.assertEqual(self._remove_unused_unwrapped(source), self._simplify(source))

    def test_dead_destructuring_object_proto_method_rhs_removed(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a;
              ({y: a} = {__proto__() {}});
              return 3;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused_unwrapped(source),
            inspect.cleandoc(
                """
                function f() {
                  return 3;
                }
                console.log(f());
                """
            ),
        )

    def test_transitive_reachability(self):
        source = inspect.cleandoc(
            """
            function helper() { return 42; }
            function main() { return helper(); }
            function orphan() { return 99; }
            console.log(main());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function helper() {
                  return 42;
                }
                function main() {
                  return helper();
                }
                console.log(main());
                """
            ),
            self._remove_unused(source),
        )

    def test_identifier_as_value_makes_reachable(self):
        source = inspect.cleandoc(
            """
            function callback() { return 1; }
            function unused() { return 2; }
            var x = callback;
            console.log(x());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function callback() {
                  return 1;
                }
                var x = callback;
                console.log(x());
                """
            ),
            self._remove_unused(source),
        )

    def test_all_functions_unreachable_keeps_them(self):
        source = inspect.cleandoc(
            """
            function a() { return 1; }
            function b() { return 2; }
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function a() {
                  return 1;
                }
                function b() {
                  return 2;
                }
                """
            ),
        )

    def test_nested_dead_code_in_block(self):
        source = inspect.cleandoc(
            """
            function main(n) {
              if (n > 0) {
                function dead_inside() { return "sha256"; }
                return n * 2;
              }
              return 0;
            }
            console.log(main(5));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function main(n) {
                  if (n > 0) {
                    return n * 2;
                  }
                  return 0;
                }
                console.log(main(5));
                """
            ),
            self._remove_unused(source),
        )

    def test_dead_assignment_removed(self):
        source = inspect.cleandoc(
            """
            var x;
            x = {};
            console.log("hello");
            """
        )
        self.assertEqual(self._remove_unused(source), 'console.log("hello");')

    def test_cascading_dead_variables(self):
        source = inspect.cleandoc(
            """
            var alpha, beta, gamma;
            alpha = {};
            beta = alpha.foo;
            gamma = alpha.bar || beta;
            console.log("live");
            """
        )
        self.assertEqual(self._remove_unused(source), 'console.log("live");')

    def test_shadowed_param_does_not_prevent_removal(self):
        source = inspect.cleandoc(
            """
            var x;
            x = 42;
            function foo(x) { return x + 1; }
            console.log(foo(10));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function foo(x) {
                  return x + 1;
                }
                console.log(foo(10));
                """
            ),
            self._remove_unused(source),
        )

    def test_live_variable_preserved(self):
        source = inspect.cleandoc(
            """
            var x;
            x = 42;
            console.log(x);
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                var x;
                x = 42;
                console.log(x);
                """
            ),
        )

    def test_side_effect_rhs_preserved(self):
        source = inspect.cleandoc(
            """
            var x;
            x = sideEffect();
            console.log("done");
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                sideEffect();
                console.log("done");
                """
            ),
            self._remove_unused(source),
        )

    def test_forin_target_var_not_removed(self):
        source = inspect.cleandoc(
            """
            var x;
            for (x in obj) { console.log(x); }
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                var x;
                for (x in obj) {
                  console.log(x);
                }
                """
            ),
        )

    def test_forof_target_var_not_removed(self):
        source = inspect.cleandoc(
            """
            var x;
            for (x of arr) { console.log(x); }
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                var x;
                for (x of arr) {
                  console.log(x);
                }
                """
            ),
        )


class TestRegressionBugs(TestJsDeobfuscator):

    def test_dead_variable_preserves_external_property_access(self):
        source = inspect.cleandoc(
            """
            var x;
            x = externalObj.prop;
            """
        )
        result = self._run_transformer(source, JsUnusedCodeRemoval)
        self.assertEqual(result, 'externalObj.prop;')

    def test_delete_expression_not_removed(self):
        source = inspect.cleandoc(
            """
            var o = [1];
            delete o[0];
            console.log(o[0]);
            """
        )
        result = self._run_transformer(source, JsUnusedCodeRemoval)
        self.assertEqual(source, result)

    @opportunity
    def test_a_delete_of_a_declared_variable_goes(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            delete x;
            console.log('done');
            """
        )
        self.assertEqual("console.log('done');", self._run_transformer(source, JsUnusedCodeRemoval))

    def test_dead_binding_from_pure_call_removed(self):
        source = inspect.cleandoc(
            """
            function makeTag() {
              return "[x]";
            }
            var unused = makeTag();
            keep("y");
            """
        )
        self.assertEqual('keep("y");', self._run_transformer(source, JsUnusedCodeRemoval))

    def test_dead_binding_from_established_const_call_removed(self):
        source = inspect.cleandoc(
            """
            const makeTag = () => "[x]";
            var unused = makeTag();
            keep("y");
            """
        )
        self.assertEqual('keep("y");', self._run_transformer(source, JsUnusedCodeRemoval))

    def test_dead_binding_from_impure_call_keeps_the_call(self):
        source = inspect.cleandoc(
            """
            function sink() {
              notify();
              return 2;
            }
            var unused = sink();
            keep("y");
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            function sink() {
              notify();
              return 2;
            }
            sink();
            keep("y");
            """
        )
        without_the_binding_or_the_return = inspect.cleandoc(
            """
            function sink() {
              notify();
            }
            sink();
            keep("y");
            """
        )
        self.assertIn(
            self._run_transformer(source, JsUnusedCodeRemoval),
            (source, without_the_binding, without_the_binding_or_the_return),
        )

    @opportunity
    def test_dead_binding_from_an_effectful_initializer_leaves_the_initializer(self):
        source = inspect.cleandoc(
            """
            var unused = notify();
            keep("y");
            """
        )
        result = self._run_transformer(source, JsUnusedCodeRemoval)
        self.assertEqual(
            inspect.cleandoc(
                """
                notify();
                keep("y");
                """
            ),
            result,
        )

    def test_dead_binding_from_pure_inline_iife_removed(self):
        source = inspect.cleandoc(
            """
            var unused = function () {
              return [].slice;
            }();
            keep("y");
            """
        )
        self.assertEqual('keep("y");', self._run_transformer(source, JsUnusedCodeRemoval))

    def test_dead_binding_from_intrinsic_static_read_removed(self):
        source = inspect.cleandoc(
            """
            var unused = String.fromCodePoint;
            keep("y");
            """
        )
        self.assertEqual('keep("y");', self._run_transformer(source, JsUnusedCodeRemoval))

    def test_dead_binding_from_decoder_factory_iife_removed(self):
        source = inspect.cleandoc(
            """
            var unused = function (...A3LWTls) {
              A3LWTls.length = 0;
              A3LWTls.b = new Array(128);
              A3LWTls.d = [];
              return function (w) { return A3LWTls.d; };
            }();
            keep("y");
            """
        )
        self.assertEqual('keep("y");', self._run_transformer(source, JsUnusedCodeRemoval))

    def test_bare_decoder_factory_iife_removed_with_dead_sibling(self):
        source = inspect.cleandoc(
            """
            var dead;
            dead = 1;
            (function (...A3LWTls) {
              A3LWTls.length = 0;
              A3LWTls.d = [];
              return function (w) { return A3LWTls.d; };
            }());
            keep("y");
            """
        )
        self.assertEqual('keep("y");', self._run_transformer(source, JsUnusedCodeRemoval))

    def test_impure_orphan_function_kept_when_dead_store_preserves_call(self):
        source = inspect.cleandoc(
            """
            var SINK = [];
            function leak() { SINK.push("x"); }
            var dead;
            dead = leak();
            console.log(SINK.join(","));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var SINK = [];
                function leak() {
                  SINK.push("x");
                }
                leak();
                console.log(SINK.join(","));
                """
            ),
            self._run_transformer(source, JsUnusedCodeRemoval),
        )


class TestHostEntrypoints(TestJsDeobfuscator):

    def _remove_unused(self, source: str, *entrypoints: str) -> str:
        return self._run_transformer(
            source,
            JsUnusedCodeRemoval,
            DeobfuscationOptions(entrypoints=entrypoints),
        )

    def test_unreferenced_function_removed_when_no_entrypoint_is_named(self):
        source = inspect.cleandoc(
            """
            var config = 'x';
            function run() {
              return config;
            }
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_named_entrypoint_survives(self):
        source = inspect.cleandoc(
            """
            var config = 'x';
            function run() {
              return config;
            }
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, 'run'))

    def test_named_entrypoint_keeps_the_functions_it_calls(self):
        source = inspect.cleandoc(
            """
            function helper() {
              return 7;
            }
            function run() {
              return helper();
            }
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, 'run'))

    def test_unnamed_function_still_removed_beside_an_entrypoint(self):
        source = inspect.cleandoc(
            """
            function junk() {
              return 2;
            }
            function run() {
              return 1;
            }
            console.log(1);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function run() {
                  return 1;
                }
                console.log(1);
                """
            ),
            self._remove_unused(source, 'run'),
        )

    def test_non_matching_pattern_changes_nothing(self):
        source = inspect.cleandoc(
            """
            function run() {
              return 1;
            }
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source, 'doGet'))

    def test_wildcard_selects_a_family_of_handlers(self):
        source = inspect.cleandoc(
            """
            function OnStart() {
              return 1;
            }
            function OnStop() {
              return 2;
            }
            function junk() {
              return 3;
            }
            console.log(1);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function OnStart() {
                  return 1;
                }
                function OnStop() {
                  return 2;
                }
                console.log(1);
                """
            ),
            self._remove_unused(source, 'On*'),
        )

    def test_single_asterisk_keeps_every_top_level_function(self):
        source = inspect.cleandoc(
            """
            function a() {
              return 1;
            }
            function b() {
              return 2;
            }
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, '*'))

    def test_pattern_matching_is_case_sensitive(self):
        source = inspect.cleandoc(
            """
            function Run() {
              return 1;
            }
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source, 'run'))

    def test_nested_function_sharing_the_name_is_not_protected(self):
        source = inspect.cleandoc(
            """
            function outer() {
              function run() {
                return 1;
              }
              return 2;
            }
            console.log(outer());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  return 2;
                }
                console.log(outer());
                """
            ),
            self._remove_unused(source, 'run'),
        )

    def test_entrypoints_protect_nothing_under_the_module_model(self):
        source = inspect.cleandoc(
            """
            var config = 'x';
            function run() {
              return config;
            }
            console.log(1);
            """
        )
        self.assertEqual(
            'console.log(1);',
            self._run_transformer(
                source,
                JsUnusedCodeRemoval,
                DeobfuscationOptions(execution=ExecutionModel.module, entrypoints=('run',)),
            ),
        )

    def test_entrypoint_referenced_only_by_a_property_write_survives(self):
        source = inspect.cleandoc(
            """
            function run() {
              return 1;
            }
            run.version = 2;
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, 'run'))

    @todo
    def test_entrypoint_held_by_a_let_declarator_survives(self):
        """
        A top-level `let` of a script is not a property of the global object, but later scripts and
        the event handler attributes of the page look names up in the scope it binds, so a host can
        call the function it holds by name.
        """
        source = inspect.cleandoc(
            """
            let run = function() {
              return 1;
            };
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, 'run'))

    def test_entrypoint_held_by_a_var_declarator_survives(self):
        source = inspect.cleandoc(
            """
            var run = function() {
              return 1;
            };
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, 'run'))

    def test_entrypoint_var_store_survives(self):
        source = inspect.cleandoc(
            """
            var run;
            run = function() {
              return 1;
            };
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source, 'run'))

    def test_a_relocated_declaration_is_written_behind_the_directive(self):
        source = inspect.cleandoc(
            """
            var t;
            function f(n) {
              'use strict';
              t = n * 2;
              console.log(t);
            }
            f(3);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(n) {
                  'use strict';
                  var t;
                  t = n * 2;
                  console.log(t);
                }
                f(3);
                """
            ),
            self._remove_unused(source),
        )

    def test_a_directive_is_not_swept_with_the_binding_beside_it(self):
        source = inspect.cleandoc(
            """
            function f(a) {
              'use strict';
              var q;
              q = a;
              return 1;
            }
            console.log(f(1));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a) {
                  'use strict';
                  return 1;
                }
                console.log(f(1));
                """
            ),
            self._remove_unused(source),
        )

    def test_a_string_that_declares_no_mode_is_swept_with_it(self):
        source = inspect.cleandoc(
            """
            function f(a) {
              'use loose';
              var q;
              q = a;
              return 1;
            }
            console.log(f(1));
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a) {
                  return 1;
                }
                console.log(f(1));
                """
            ),
            self._remove_unused(source),
        )

    def test_a_dead_write_in_an_unbraced_branch_body_reports_a_change_only_when_it_goes(self):
        programs = [
            inspect.cleandoc(
                """
                if (Math.random() > 2) globalThis.x = 1;
                console.log(3);
                """
            ),
            inspect.cleandoc(
                """
                var y;
                if (Math.random() > 2) y = 1;
                console.log(3);
                """
            ),
            inspect.cleandoc(
                """
                var a, b;
                if (Math.random() > 2) [a, b] = [1, 2];
                console.log(3);
                """
            ),
        ]
        for source in programs:
            with self.subTest(source=source):
                ast = JsParser(source).parse()
                transformer = JsUnusedCodeRemoval()
                sweep = threading.Thread(target=transformer.visit, args=(ast,), daemon=True)
                sweep.start()
                sweep.join(60)
                # A change reported for a write the tree kept starts the sweep over without end.
                self.assertFalse(sweep.is_alive())
                rewritten = JsSynthesizer().convert(ast) != printed(source)
                self.assertEqual(transformer.changed, rewritten)

    def test_a_declaration_stays_while_its_write_stays_in_an_unbraced_branch_body(self):
        programs_and_their_text_without_the_write = [
            (
                inspect.cleandoc(
                    """
                    var y;
                    if (Math.random() > 2) y = 1;
                    console.log(3);
                    """
                ),
                inspect.cleandoc(
                    """
                    if (Math.random() > 2) {}
                    console.log(3);
                    """
                ),
            ),
            (
                inspect.cleandoc(
                    """
                    var a, b;
                    if (Math.random() > 2) [a, b] = [1, 2];
                    console.log(3);
                    """
                ),
                inspect.cleandoc(
                    """
                    if (Math.random() > 2) {}
                    console.log(3);
                    """
                ),
            ),
            (
                inspect.cleandoc(
                    """
                    'use strict';
                    var y;
                    if (Math.random() < 2) y = 1;
                    console.log(3);
                    """
                ),
                inspect.cleandoc(
                    """
                    'use strict';
                    if (Math.random() < 2) {}
                    console.log(3);
                    """
                ),
            ),
            (
                inspect.cleandoc(
                    """
                    function f() {
                      var location;
                      if (Math.random() < 2) location = 'http://x.test/';
                      return 3;
                    }
                    console.log(f());
                    """
                ),
                inspect.cleandoc(
                    """
                    function f() {
                      if (Math.random() < 2) {}
                      return 3;
                    }
                    console.log(f());
                    """
                ),
            ),
        ]
        for source, without_the_write in programs_and_their_text_without_the_write:
            with self.subTest(source=source):
                self.assertIn(self._remove_unused(source), (printed(source), without_the_write))

    @opportunity
    def test_a_dead_write_in_an_unbraced_branch_body_goes(self):
        programs = [
            'var y;\nif (Math.random() > 2) y = 1;\nconsole.log(3);',
            'var a, b;\nif (Math.random() > 2) [a, b] = [1, 2];\nconsole.log(3);',
        ]
        self.assertEqual(
            {source: self._deobfuscate(source) for source in programs},
            {source: 'console.log(3);' for source in programs},
        )

    def test_a_write_read_back_through_a_bracket_spelling_is_kept(self):
        source = "globalThis.x = 1;\nconsole.log(globalThis['x']);"
        self.assertEqual(source, self._remove_unused(source))


A_SLOPPY_REGION_ASSIGNING_TO_NO_BINDING: dict[str, str] = {
    'function f(b) { var q = b + 1; undeclared_e = 1; return q; } console.log(f(2));':
        'console.log(3);',
    'undeclared_f = 1; console.log(3);': 'console.log(3);',
}

A_STRICT_REGION_ASSIGNING_TO_A_NAME_IT_DECLARES: dict[str, str] = {
    "'use strict'; var declared_g; declared_g = 1; console.log(3);":
        "'use strict';\nconsole.log(3);",
}


class TestAWriteSloppyCodeAnswersIsADeadStore(TestJsDeobfuscator):

    def test_the_write_is_removed_where_nothing_makes_the_region_strict(self):
        rows = A_SLOPPY_REGION_ASSIGNING_TO_NO_BINDING
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_the_write_is_removed_where_the_strict_region_declares_the_name(self):
        rows = A_STRICT_REGION_ASSIGNING_TO_A_NAME_IT_DECLARES
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameOnceTheDeadStoreIsGone(TestJsDeobfuscator):

    def test_each_program_prints_what_it_printed_before_the_removal(self):
        rows = {
            **A_SLOPPY_REGION_ASSIGNING_TO_NO_BINDING,
            **A_STRICT_REGION_ASSIGNING_TO_A_NAME_IT_DECLARES,
        }
        self.assertEqual(
            {source: behavior(self._deobfuscate(source)) for source in rows},
            {source: behavior(source) for source in rows},
        )


def _a_property_written_on_a_local_object(name: str) -> str:
    return inspect.cleandoc(
        F"""
        var {name} = {{}};
        {name}.x = 1;
        console.log(JSON.stringify({name}));
        """
    )


A_PROPERTY_WRITTEN_ON_AN_OBJECT_A_LOCAL_NAME_HOLDS: dict[str, str] = {
    source: source
    for source in map(_a_property_written_on_a_local_object, [
        'globalThis',
        'global',
        'window',
        'self',
        'top',
        'frames',
        'obj',
    ])
}

A_GLOBAL_PROPERTY_WRITE_NOTHING_READS: dict[str, str] = {
    'globalThis.q = 1;\nconsole.log(3);': 'console.log(3);',
    "globalThis.x = 1;\nif (typeof window !== 'undefined') {\n  console.log(3);\n}":
        "if (typeof window !== 'undefined') {\n  console.log(3);\n}",
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAFunctionATaggedTemplateCalls(TestJsDeobfuscator):

    def test_the_write_of_a_tag_a_call_runs_still_prints(self):
        source = 'var x = 0; function t(s) { x = 1; } function g() { t`a`; } g(); console.log(x);'
        self.assertEqual(behavior(source), ('1\n', None))
        self.assertEqual(behavior(self._deobfuscate(source)), behavior(source))


class TestAPropertyWriteThroughAShadowedGlobalAliasSurvives(TestJsDeobfuscator):

    def test_the_write_is_kept_where_a_declaration_binds_the_alias_name(self):
        rows = A_PROPERTY_WRITTEN_ON_AN_OBJECT_A_LOCAL_NAME_HOLDS
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_the_write_is_removed_where_no_declaration_binds_the_alias(self):
        rows = A_GLOBAL_PROPERTY_WRITE_NOTHING_READS
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutTheObjectALocalAliasNameHolds(TestJsDeobfuscator):

    def test_each_object_program_prints_the_property_to_begin_with(self):
        rows = A_PROPERTY_WRITTEN_ON_AN_OBJECT_A_LOCAL_NAME_HOLDS
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: ('{"x":1}\n', None) for source in rows},
        )

    def test_each_program_prints_what_it_printed_before(self):
        rows = {
            **A_PROPERTY_WRITTEN_ON_AN_OBJECT_A_LOCAL_NAME_HOLDS,
            **A_GLOBAL_PROPERTY_WRITE_NOTHING_READS,
        }
        self.assertEqual(
            {source: behavior(self._deobfuscate(source)) for source in rows},
            {source: behavior(source) for source in rows},
        )


A_GLOBAL_PROPERTY_WRITE_AN_UNSPELLED_READ_OBSERVES: dict[str, str] = {
    source: source
    for source in [
        inspect.cleandoc(
            """
            globalThis.x = 1;
            console.log(Object.keys(globalThis).includes('x'));
            """
        ),
        inspect.cleandoc(
            """
            globalThis.x = 1;
            for (var k in globalThis) {
              console.log(k);
            }
            """
        ),
        inspect.cleandoc(
            """
            window.cfg = 1;
            (function(w) {
              console.log(w.cfg);
            })(window);
            """
        ),
        'globalThis.x = 1;\ndump(this);',
    ]
}

A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_CERTAIN_BASE: dict[str, str] = {
    'globalThis.q = 1;\nconsole.log(3);': 'console.log(3);',
}

A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_HOST_CONDITIONAL_BASE: dict[str, str] = {
    source: source
    for source in [
        'window.q = 1;\nconsole.log(3);',
        'self.q = 1;\nconsole.log(3);',
        'global.q = 1;\nconsole.log(3);',
    ]
}

A_DEAD_PROPERTY_WRITE_ON_ANOTHER_REALMS_GLOBAL: dict[str, str] = {
    source: source
    for source in [
        'top.q = 1;\nconsole.log(3);',
        'frames.q = 1;\nconsole.log(3);',
    ]
}


class TestAGlobalPropertyWriteSurvivesWhereTheGlobalObjectEscapes(TestJsDeobfuscator):

    def test_the_write_is_kept_where_a_position_reads_the_object_whole(self):
        rows = A_GLOBAL_PROPERTY_WRITE_AN_UNSPELLED_READ_OBSERVES
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_the_write_is_removed_through_a_base_that_resolves(self):
        rows = A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_CERTAIN_BASE
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_the_write_is_kept_through_a_host_conditional_base(self):
        rows = A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_HOST_CONDITIONAL_BASE
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_the_write_is_kept_under_a_spelling_of_another_realms_global(self):
        rows = A_DEAD_PROPERTY_WRITE_ON_ANOTHER_REALMS_GLOBAL
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)


class TestALexicalBindingThatStopsABlockFunctionEscapingIsKept(TestJsDeobfuscator):

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_name_the_suppressing_binding_keeps_from_escaping_stays_unbound(self):
        """
        The `let f` keeps Annex B from copying the inner `function f` into a `var` of `outer`, so
        `typeof f` finds no binding and the program prints `undefined`; without the `let` it prints
        `function`.
        """
        source = inspect.cleandoc(
            """
            function outer() {
              { let f = 1; { function f() { return 2; } } }
              console.log(typeof f);
            }
            outer();
            """
        )
        self.assertEqual(behavior(self._remove_unused(source)), ('undefined\n', None))

    def test_a_binding_no_block_function_shares_a_name_with_is_still_removed(self):
        source = inspect.cleandoc(
            """
            function outer() {
              { let d = 1; { function g() { return 2; } } }
              console.log(typeof g);
            }
            outer();
            """
        )
        expected = inspect.cleandoc(
            """
            function outer() {
              {
                {
                  function g() {
                    return 2;
                  }
                }
              }
              console.log(typeof g);
            }
            outer();
            """
        )
        self.assertEqual(self._remove_unused(source), expected)


A_BLOCK_FUNCTION_CALLED_FROM_OUTSIDE_ITS_BLOCK = {
    '{ let q = 1; function h() { return q; } } console.log(h());': '1\n',
    inspect.cleandoc("""
        function f() { { let q = 2; function h() { return q; } } return h(); }
        console.log(f());
    """): '2\n',
    'if (true) { let q = 3; function h() { return q; } } console.log(h());': '3\n',
    '{ let q = 4; function h() { return q; } } { console.log(h()); }': '4\n',
    inspect.cleandoc("""
        function f() { { function g() {} g.x = 1; } return g.x; }
        console.log(f());
    """): '1\n',
    inspect.cleandoc("""
        function f() { { function h() { return 7; } h.x = 1; } return h() + h.x; }
        console.log(f());
    """): '8\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutABlockFunctionCalledFromOutsideItsBlock(TestJsDeobfuscator):

    def test_the_call_outside_the_block_still_prints_what_it_printed(self):
        rows = A_BLOCK_FUNCTION_CALLED_FROM_OUTSIDE_ITS_BLOCK
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameWhereTheGlobalObjectEscapes(TestJsDeobfuscator):

    def test_each_program_prints_what_it_printed_before(self):
        rows = {
            **A_GLOBAL_PROPERTY_WRITE_AN_UNSPELLED_READ_OBSERVES,
            **A_DEAD_PROPERTY_WRITE_ON_ANOTHER_REALMS_GLOBAL,
            **A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_CERTAIN_BASE,
        }
        self.assertEqual(
            {source: behavior(self._deobfuscate(source)) for source in rows},
            {source: behavior(source) for source in rows},
        )


A_KEPT_READ_OF_A_NAME_NOTHING_BINDS: dict[str, str] = {
    'function f() { let v = zzz; }\nf();\nconsole.log(1);\n':
        'let v = zzz;\nconsole.log(1);',
    'function f() { var v = zzz; }\nf();\nconsole.log(1);\n':
        'var v = zzz;\nconsole.log(1);',
    'y = a;\nconsole.log(1);\n': 'a;\nconsole.log(1);',
    'var o = { p: g };\nconsole.log(1);\n': 'var o = { p: g };\nconsole.log(1);',
    'y = N();\nN = function () {};\nconsole.log(1);\n':
        'N();\nN = function() {};\nconsole.log(1);',
}

A_KEPT_READ_A_TRY_CATCHES: dict[str, str] = {
    'try {\n  var x = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {\n  var x = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
    'try {\n  let v = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {\n  let v = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
    'try {\n  y = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {\n  missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
    'try {\n  var o = { p: missing };\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {\n  var o = { p: missing };\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
    'try {\n  throw 1;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {\n  throw 1;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
    'try {\n  null.p;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {\n  null.p;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
}

A_KEPT_CALL_WHOSE_BODY_CANNOT_RETURN: dict[str, str] = {
    source: source.rstrip('\n')
    for source in [
        'function f() {\n  var x = missing;\n  return 7;\n}\nconsole.log(f());\n',
        'function f() {\n  var x = { p: missing };\n  return 7;\n}\nconsole.log(f());\n',
        'var f = () => {\n  var x = missing;\n  return 7;\n};\nconsole.log(f());\n',
        'function f() {\n  missing;\n  return 7;\n}\nconsole.log(f());\n',
        'function f() {\n  return missing;\n}\nconsole.log(f());\n',
    ]
}

AN_ESTABLISHED_STORE_STILL_REDUCES: dict[str, str] = {
    'X = 5;\ny = X;\nconsole.log(1);\n': 'console.log(1);',
    'function f() {\n  var x = 1;\n  return 7;\n}\nconsole.log(f());\n': 'console.log(7);',
    'try {\n  var x = 1;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n': 'console.log(3);',
    'N = function () {};\ny = N();\nconsole.log(1);\n': 'console.log(1);',
    'function N() {}\ny = N();\nconsole.log(1);\n': 'console.log(1);',
}

THE_CLEAN_TEXT_AROUND_WHAT_MAY_THROW: dict[str, str] = {
    'function f() { let v = zzz; }\nf();\nconsole.log(1);\n':
        inspect.cleandoc("""
            zzz;
            console.log(1);
        """),
    'function f() { var v = zzz; }\nf();\nconsole.log(1);\n':
        inspect.cleandoc("""
            zzz;
            console.log(1);
        """),
    'var o = { p: g };\nconsole.log(1);\n':
        inspect.cleandoc("""
            g;
            console.log(1);
        """),
    'y = N();\nN = function () {};\nconsole.log(1);\n':
        inspect.cleandoc("""
            N();
            console.log(1);
        """),
    'try {\n  var x = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        inspect.cleandoc("""
            try {
              missing;
            } catch (e) {
              console.log(2);
            }
            console.log(3);
        """),
    'try {\n  let v = missing;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        inspect.cleandoc("""
            try {
              missing;
            } catch (e) {
              console.log(2);
            }
            console.log(3);
        """),
    'try {\n  var o = { p: missing };\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        inspect.cleandoc("""
            try {
              missing;
            } catch (e) {
              console.log(2);
            }
            console.log(3);
        """),
    'try {\n  throw 1;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        inspect.cleandoc("""
            console.log(2);
            console.log(3);
        """),
    'try {\n  null.p;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        inspect.cleandoc("""
            console.log(2);
            console.log(3);
        """),
    'function f() {\n  var x = missing;\n  return 7;\n}\nconsole.log(f());\n':
        inspect.cleandoc("""
            function f() {
              missing;
              return 7;
            }
            console.log(f());
        """),
    'function f() {\n  var x = { p: missing };\n  return 7;\n}\nconsole.log(f());\n':
        inspect.cleandoc("""
            function f() {
              missing;
              return 7;
            }
            console.log(f());
        """),
    'var f = () => {\n  var x = missing;\n  return 7;\n};\nconsole.log(f());\n':
        inspect.cleandoc("""
            var f = () => {
              missing;
              return 7;
            };
            console.log(f());
        """),
    'if ([zzz]) console.log(1);\n':
        inspect.cleandoc("""
            zzz;
            console.log(1);
        """),
    'var o = { p: zzz, q: 1 };\nconsole.log(o.q);\n':
        inspect.cleandoc("""
            zzz;
            console.log(1);
        """),
    'var r = [1, zzz][0];\nconsole.log(r);\n':
        inspect.cleandoc("""
            zzz;
            console.log(1);
        """),
}


def _each_reads_as_kept_or_clean(test: TestJsDeobfuscator, rows: dict[str, str]):
    for source, kept in rows.items():
        clean = THE_CLEAN_TEXT_AROUND_WHAT_MAY_THROW.get(source, kept)
        with test.subTest(source=source):
            test.assertIn(test._deobfuscate(source), (kept, clean))


class TestAReadOfANameNothingBindsIsKept(TestJsDeobfuscator):

    def test_the_read_survives_where_its_expression_is_discarded(self):
        _each_reads_as_kept_or_clean(self, A_KEPT_READ_OF_A_NAME_NOTHING_BINDS)

    def test_the_read_survives_inside_a_try_so_the_catch_still_runs(self):
        _each_reads_as_kept_or_clean(self, A_KEPT_READ_A_TRY_CATCHES)

    def test_a_call_whose_body_cannot_return_is_not_replaced_by_its_value(self):
        _each_reads_as_kept_or_clean(self, A_KEPT_CALL_WHOSE_BODY_CANNOT_RETURN)

    @opportunity
    def test_what_nothing_reads_around_what_may_throw_goes(self):
        for source, clean in THE_CLEAN_TEXT_AROUND_WHAT_MAY_THROW.items():
            with self.subTest(source=source):
                self.assertEqual(self._deobfuscate(source), clean)

    def test_a_store_the_model_vouches_for_still_reduces(self):
        rows = AN_ESTABLISHED_STORE_STILL_REDUCES
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAReadOfANameNothingBinds(TestJsDeobfuscator):

    def test_each_free_reading_program_still_refuses_to_run(self):
        rows = {
            **A_KEPT_READ_OF_A_NAME_NOTHING_BINDS,
            **A_KEPT_CALL_WHOSE_BODY_CANNOT_RETURN,
        }
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: ('', 'ReferenceError') for source in rows},
        )

    def test_each_program_behaves_as_it_did_before(self):
        rows = {
            **A_KEPT_READ_OF_A_NAME_NOTHING_BINDS,
            **A_KEPT_READ_A_TRY_CATCHES,
            **A_KEPT_CALL_WHOSE_BODY_CANNOT_RETURN,
            **AN_ESTABLISHED_STORE_STILL_REDUCES,
        }
        self.assertEqual(
            {source: behavior(self._deobfuscate(source)) for source in rows},
            {source: behavior(source) for source in rows},
        )


A_KEPT_READ_A_DISCARDING_CONTEXT_FOLDS_AROUND: dict[str, str] = {
    'if ([zzz]) console.log(1);\n': '[zzz];\nconsole.log(1);',
    'var o = { p: zzz, q: 1 };\nconsole.log(o.q);\n':
        'var o = { p: zzz, q: 1 };\nconsole.log(1);',
    'console.log(function (a, b) { return a; }(7, zzz));\n':
        'console.log(function(a, b) {\n  return a;\n}(7, zzz));',
    'function w(a, b) {\n  return a;\n}\nconsole.log(w(7, zzz));\n':
        'function w(a, b) {\n  return a;\n}\nconsole.log(w(7, zzz));',
    'var r = [1, zzz][0];\nconsole.log(r);\n': 'var r = [1, zzz][0];\nconsole.log(r);',
}

A_KEPT_READ_UNDER_TYPEOF_STILL_THROWS: dict[str, str] = {
    'try {\n'
    '  console.log(function (a) { return typeof a; }(u));\n'
    '} catch (e) {\n'
    "  console.log('caught');\n"
    '}\n':
        'try {\n'
        '  console.log(function(a) {\n'
        '    return typeof a;\n'
        '  }(u));\n'
        '} catch (e) {\n'
        "  console.log('caught');\n"
        '}',
}

A_TYPEOF_OF_AN_ESTABLISHED_ARGUMENT_FOLDS: dict[str, str] = {
    'var u = 1;\n'
    'try {\n'
    '  console.log(function (a) { return typeof a; }(u));\n'
    '} catch (e) {\n'
    "  console.log('caught');\n"
    '}\n':
        'try {\n'
        "  console.log('number');\n"
        '} catch (e) {\n'
        "  console.log('caught');\n"
        '}',
}


class TestAReadOfANameNothingBindsSurvivesEveryDiscardingContext(TestJsDeobfuscator):

    def test_the_read_survives_where_a_context_folds_around_it(self):
        _each_reads_as_kept_or_clean(self, A_KEPT_READ_A_DISCARDING_CONTEXT_FOLDS_AROUND)

    def test_a_may_throw_argument_is_not_moved_under_typeof(self):
        rows = A_KEPT_READ_UNDER_TYPEOF_STILL_THROWS
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_an_established_argument_under_typeof_still_folds(self):
        rows = A_TYPEOF_OF_AN_ESTABLISHED_ARGUMENT_FOLDS
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAcrossEveryDiscardingContext(TestJsDeobfuscator):

    def test_each_discarded_reading_program_still_refuses_to_run(self):
        rows = A_KEPT_READ_A_DISCARDING_CONTEXT_FOLDS_AROUND
        self.assertEqual(
            {source: behavior(source) for source in rows},
            {source: ('', 'ReferenceError') for source in rows},
        )

    def test_each_program_behaves_as_it_did_before(self):
        rows = {
            **A_KEPT_READ_A_DISCARDING_CONTEXT_FOLDS_AROUND,
            **A_KEPT_READ_UNDER_TYPEOF_STILL_THROWS,
            **A_TYPEOF_OF_AN_ESTABLISHED_ARGUMENT_FOLDS,
        }
        self.assertEqual(
            {source: behavior(self._deobfuscate(source)) for source in rows},
            {source: behavior(source) for source in rows},
        )


class TestATypedLocalMemberReadIsRemovableUnderTrust(TestJsDeobfuscator):

    @staticmethod
    def _remove_unused(source: str, *, trust_eval: bool = False) -> str:
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsUnusedCodeRemoval()
            transform.options = DeobfuscationOptions(trust_eval=trust_eval)
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_a_dead_constructor_read_off_a_function_is_removed_under_trust(self):
        self.assertEqual(
            'function f() {\n  return 1;\n}',
            self._remove_unused(
                'function f() { return 1; } var x = f.constructor;', trust_eval=True),
        )

    @opportunity
    def test_a_dead_constructor_read_off_a_function_is_removed_without_trust(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  return 1;
                }
                """
            ),
            self._remove_unused('function f() { return 1; } var x = f.constructor;'),
        )

    def test_a_read_before_the_value_is_established_is_kept_under_trust(self):
        self.assertIn(
            self._remove_unused(
                'var x = f.constructor; var f = function () { return 1; };', trust_eval=True),
            (
                'var x = f.constructor;\nvar f = function() {\n  return 1;\n};',
                'f.constructor;\nvar f = function() {\n  return 1;\n};',
            ),
        )

    def test_an_accessor_installed_through_an_alias_is_kept_under_trust(self):
        source = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            var g = f;
            Object.defineProperty(g, 'constructor', { get: function () { return SINK(); } });
            var x = f.constructor;
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            var g = f;
            Object.defineProperty(g, 'constructor', { get: function () { return SINK(); } });
            f.constructor;
            """
        )
        self.assertIn(
            self._remove_unused(source, trust_eval=True),
            (printed(source), printed(without_the_binding)),
        )

    @opportunity
    def test_a_plain_value_written_through_an_alias_keeps_no_read_under_trust(self):
        source = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            var g = f;
            g.constructor = 5;
            var x = f.constructor;
            """
        )
        with_the_write = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            var g = f;
            g.constructor = 5;
            """
        )
        only_the_function = inspect.cleandoc(
            """
            function f() {
              return 1;
            }
            """
        )
        self.assertIn(
            self._remove_unused(source, trust_eval=True),
            (with_the_write, only_the_function, ''),
        )

    def test_a_poisoned_key_off_a_function_is_kept_under_trust(self):
        self.assertIn(
            self._remove_unused('function f() { return 1; } var x = f.caller;', trust_eval=True),
            (
                'function f() {\n  return 1;\n}\nvar x = f.caller;',
                'function f() {\n  return 1;\n}\nf.caller;',
            ),
        )

    def test_a_read_under_a_surviving_surface_is_kept_under_trust(self):
        source = inspect.cleandoc(
            """
            var e = eval;
            e(input);
            function f() {
              return 1;
            }
            var x = f.constructor;
            """
        )
        without_the_binding = inspect.cleandoc(
            """
            var e = eval;
            e(input);
            function f() {
              return 1;
            }
            f.constructor;
            """
        )
        self.assertIn(self._remove_unused(source, trust_eval=True), (source, without_the_binding))


class TestARedundantGlobalMemberStoreIsRemoved(TestJsDeobfuscator):

    @staticmethod
    def _remove_unused(source: str) -> str:
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsUnusedCodeRemoval()
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_the_interleaved_duplicate_stores_dedupe(self):
        self.assertEqual(
            'global.r = require;\nglobal.m = module;',
            self._remove_unused(
                'global.r = require; global.m = module; global.r = require; global.m = module;'),
        )

    def test_a_counting_setter_keeps_every_store_firing(self):
        source = inspect.cleandoc(
            """
            Object.defineProperty(globalThis, 'r', { set: function () {
              SINK();
            } });
            global.r = require;
            global.r = require;
            """
        )
        self.assertEqual(printed(source), self._remove_unused(source))

    def test_a_reflective_surface_keeps_the_stores(self):
        source = inspect.cleandoc(
            """
            eval(input);
            global.r = require;
            global.r = require;
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    @opportunity
    def test_a_reflective_surface_behind_the_stores_keeps_no_duplicate(self):
        source = inspect.cleandoc(
            """
            global.r = require;
            global.r = require;
            eval(input);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                global.r = require;
                eval(input);
                """
            ),
            self._remove_unused(source),
        )

    def test_a_statement_between_the_stores_keeps_them(self):
        source = 'global.r = require;\nSINK();\nglobal.r = require;'
        self.assertEqual(source, self._remove_unused(source))

    def test_a_different_value_stored_between_keeps_the_last(self):
        source = 'global.r = require;\nglobal.r = module;\nglobal.r = require;'
        self.assertEqual(source, self._remove_unused(source))

    def test_a_free_global_value_rewritten_between_the_stores_keeps_the_last(self):
        source = 'global.r = x;\nglobal.x = spoof;\nglobal.r = x;'
        self.assertEqual(source, self._remove_unused(source))

    def test_an_inherited_prototype_setter_keeps_the_stores(self):
        source = inspect.cleandoc(
            """
            Object.defineProperty(Object.prototype, 'r', { set: function () {
              SINK();
            } });
            global.r = require;
            global.r = require;
            """
        )
        self.assertEqual(printed(source), self._remove_unused(source))

    def test_a_setter_installed_through_the_global_proto_keeps_the_stores(self):
        source = inspect.cleandoc(
            """
            globalThis.__proto__ = { set r(v) {
              SINK();
            } };
            global.r = require;
            global.r = require;
            """
        )
        self.assertEqual(printed(source), self._remove_unused(source))

    def test_two_undecodable_string_literals_are_not_deduped(self):
        source = 'global.r = "\\xZZ";\nglobal.r = "\\xYY";'
        self.assertEqual(source, self._remove_unused(source))

    def test_a_duplicate_read_through_a_base_the_host_may_lack_is_kept(self):
        source = 'globalThis.r = require;\nwindow.r = require;\nSINK(r);'
        self.assertEqual(source, self._remove_unused(source))


class TestADestructuredImplicitGlobalIsReadByTheWholeScript(TestJsDeobfuscator):

    def test_a_read_outside_the_function_keeps_the_assignment(self):
        source = inspect.cleandoc(
            """
            function f() {
              [a] = [1];
            }
            f();
            console.log(a);
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsUnusedCodeRemoval))

    def test_an_assignment_nothing_reads_still_goes(self):
        source = inspect.cleandoc(
            """
            function f() {
              [a] = [1];
            }
            f();
            """
        )
        self.assertNotIn('[a]', self._run_transformer(source, JsUnusedCodeRemoval))


class TestADiscardedCompletionValueIsRemoved(TestJsDeobfuscator):

    @staticmethod
    def _remove_unused(source: str, options: DeobfuscationOptions | None = None) -> str:
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsUnusedCodeRemoval()
            transform.options = options
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_a_discarded_iife_completion_value_goes(self):
        self.assertEqual(
            '(function() {\n  SINK();\n})();\nSINK();',
            self._remove_unused('(function() { SINK(); return 5042; })(); SINK();'),
        )

    def test_a_completion_value_someone_reads_stays(self):
        source = 'var x = (function() {\n  return 5042;\n})();\nSINK(x);'
        self.assertEqual(source, self._remove_unused(source))

    def test_an_entrypoint_keeps_its_completion_value(self):
        source = inspect.cleandoc(
            """
            function f() {
              SINK();
              return 5042;
            }
            f();
            """
        )
        options = DeobfuscationOptions(entrypoints=('f',))
        self.assertEqual(source, self._remove_unused(source, options))

    @opportunity
    def test_a_top_level_function_no_host_calls_gives_up_its_completion_value(self):
        source = inspect.cleandoc(
            """
            function f() {
              SINK();
              return 5042;
            }
            f();
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  SINK();
                }
                f();
                """
            ),
            self._remove_unused(source),
        )

    def test_a_return_of_a_local_no_call_reads_goes(self):
        source = inspect.cleandoc(
            """
            (function() {
              var r = x;
              return r;
            })();
            """
        )
        without_the_return = inspect.cleandoc(
            """
            (function() {
              var r = x;
            })();
            """
        )
        without_the_return_or_the_binding = inspect.cleandoc(
            """
            (function() {
              x;
            })();
            """
        )
        self.assertIn(
            self._remove_unused(source),
            (without_the_return, without_the_return_or_the_binding),
        )


class TestLivenessIsHeldFromTheStartOfASweep(TestJsDeobfuscator):

    def test_liveness_first_read_after_a_removed_store(self):
        self.assertEqual(
            'globalThis.r = 1;\nSINK(r);',
            self._run_transformer(
                'globalThis.r = 1; globalThis.r = 1; SINK(r);', JsUnusedCodeRemoval
            ),
        )


class TestAStandAloneEmptyStatementIsRemoved(TestJsDeobfuscator):

    @staticmethod
    def _remove_unused(source: str) -> str:
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsUnusedCodeRemoval()
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_an_empty_statement_in_a_body_goes(self):
        self.assertEqual('a();\nb();', self._remove_unused('a();\n;\nb();'))

    def test_an_empty_statement_in_a_nested_block_goes(self):
        self.assertEqual(
            'if (x) {\n  a();\n}',
            self._remove_unused('if (x) {\n  a();\n  ;\n}'),
        )

    def test_an_empty_statement_as_a_branch_body_leaves_the_branch(self):
        self.assertIn(
            self._remove_unused('if (x);\na();'),
            ('if (x) {\n  ;\n}\na();', 'if (x) {}\na();'),
        )

    @opportunity
    def test_an_empty_statement_as_a_branch_body_goes(self):
        self.assertEqual(self._remove_unused('if (x);\na();'), 'if (x) {}\na();')

    def test_an_empty_statement_braced_into_a_block_goes(self):
        self.assertEqual(
            'if (x) {}\na();',
            self._remove_unused('if (x) {\n  ;\n}\na();'),
        )


class TestADebuggerStatementInAListIsRemoved(TestJsDeobfuscator):

    @staticmethod
    def _remove_unused(source: str) -> str:
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsUnusedCodeRemoval()
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_a_debugger_statement_in_a_body_goes(self):
        self.assertEqual(self._remove_unused('a();\ndebugger;\nb();'), 'a();\nb();')

    def test_a_debugger_statement_in_a_nested_block_goes(self):
        self.assertEqual(
            self._remove_unused('if (x) {\n  a();\n  debugger;\n}'),
            'if (x) {\n  a();\n}',
        )

    def test_a_debugger_statement_as_a_branch_body_leaves_the_branch(self):
        self.assertIn(
            self._remove_unused('if (x) debugger;\na();'),
            ('if (x) {\n  debugger;\n}\na();', 'if (x) {}\na();'),
        )

    @opportunity
    def test_a_debugger_statement_as_a_branch_body_goes(self):
        self.assertEqual(self._remove_unused('if (x) debugger;\na();'), 'if (x) {}\na();')

    def test_a_labeled_debugger_statement_stays_or_goes_with_its_label(self):
        source = 'L: debugger;\na();'
        self.assertIn(self._remove_unused(source), (source, 'a();'))

    @opportunity
    def test_a_labeled_debugger_statement_goes_with_its_label(self):
        self.assertEqual(self._remove_unused('L: debugger;\na();'), 'a();')


A_DEBUGGER_STATEMENT = {
    inspect.cleandoc("""
        function f(x) {
          debugger;
          if (x) {
            debugger;
            x++;
          }
          return x;
        }
        console.log(f(1));
    """): '2\n',
    inspect.cleandoc("""
        console.log(eval('1; debugger;'));
        console.log(eval('debugger;'));
        console.log(eval('2; if (true) { debugger; }'));
    """): '1\nundefined\nundefined\n',
    inspect.cleandoc("""
        function f(x) {
          L: debugger;
          if (x) debugger; else x = 3;
          return x;
        }
        console.log(f(0), f(1));
    """): '3 1\n',
    inspect.cleandoc("""
        function f(k) {
          switch (k) {
            case 1:
              debugger;
              return 'one';
            default:
              debugger;
          }
          return 'other';
        }
        console.log(f(1), f(2));
    """): 'one other\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutADebuggerStatement(TestJsDeobfuscator):

    def test_a_program_holding_debugger_statements_still_prints_the_same(self):
        rows = A_DEBUGGER_STATEMENT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAFunctionNothingReachesGoesFromAListOfNothingButFunctions(TestJsDeobfuscator):

    @staticmethod
    def _remove_unused(source: str, options: DeobfuscationOptions | None = None) -> str:
        ast = JsParser(source).parse()
        for _ in range(10):
            transform = JsUnusedCodeRemoval()
            transform.options = options
            transform.visit(ast)
            if not transform.changed:
                break
        return JsSynthesizer().convert(ast)

    def test_the_functions_of_a_function_body_of_nothing_but_functions_go(self):
        source = inspect.cleandoc(
            """
            function outer() { function a() { return 1; } function b() { return a(); } }
            console.log(outer());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function outer() {}
                console.log(outer());
                """
            ),
        )

    def test_a_function_in_the_block_of_a_loop_goes(self):
        source = inspect.cleandoc(
            """
            function f(c) { if (c) { while (true) { function dead() { return 1; } } } return c; }
            console.log(f(0));
            """
        )
        expected = inspect.cleandoc(
            """
            function f(c) {
              if (c) {
                while (true) {}
              }
              return c;
            }
            console.log(f(0));
            """
        )
        self.assertEqual(self._remove_unused(source), expected)

    def test_a_function_in_a_block_of_a_function_goes(self):
        source = inspect.cleandoc(
            """
            function f() { { function g() {} } }
            console.log(f());
            """
        )
        self.assertEqual(
            self._remove_unused(source),
            inspect.cleandoc(
                """
                function f() {}
                console.log(f());
                """
            ),
        )

    def test_a_file_of_nothing_but_functions_keeps_them(self):
        source = 'function a() {\n  return 1;\n}\nfunction b() {\n  return a();\n}'
        self.assertEqual(self._remove_unused(source), source)

    def test_a_block_function_a_script_may_take_for_its_value_is_kept_where_that_value_is(self):
        source = '1;\n{\n  function g() {}\n}'
        options = DeobfuscationOptions(preserve_script_return=True)
        self.assertEqual(self._remove_unused(source, options), source)

    @opportunity
    def test_a_block_function_the_script_ends_with_goes_where_its_value_is_not_kept(self):
        source = inspect.cleandoc(
            """
            SINK();
            {
              function g() {}
            }
            """
        )
        self.assertEqual(self._remove_unused(source), 'SINK();')

    def test_a_block_function_whose_body_alone_is_strict_is_kept_as_well(self):
        source = inspect.cleandoc(
            """
            1;
            {
              function g() {
                'use strict';
              }
            }
            """
        )
        options = DeobfuscationOptions(preserve_script_return=True)
        self.assertEqual(self._remove_unused(source, options), source)

    def test_a_block_function_followed_by_the_value_of_the_script_goes(self):
        options = DeobfuscationOptions(preserve_script_return=True)
        self.assertEqual(self._remove_unused('{ function g() {} }\n1;', options), '1;')

    def test_a_strict_block_function_goes_where_the_script_ends_with_it(self):
        source = "'use strict';\n1;\n{ function g() {} }"
        options = DeobfuscationOptions(preserve_script_return=True)
        self.assertEqual(self._remove_unused(source, options), "'use strict';\n1;")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeTakesASloppyBlockFunctionForTheValueOfAScript(TestBase):

    def test_a_block_function_is_the_value_of_the_script_whether_or_not_its_body_is_strict(self):
        programs = [
            inspect.cleandoc(
                """
                1;
                {
                  function g() {}
                }
                """
            ),
            inspect.cleandoc(
                """
                1;
                {
                  function g() {
                    'use strict';
                  }
                }
                """
            ),
        ]
        self.assertEqual(completion_values(programs, JsEvaluation.SCRIPT), ['function', 'function'])


A_LIST_OF_NOTHING_BUT_FUNCTIONS = {
    inspect.cleandoc("""
        if (Math.random() < 2) {
          function f() { return 1; }
        }
        console.log(f());
    """): '1\n',
    inspect.cleandoc("""
        function g() {
          {
            function f() { return 'via eval'; }
          }
          return eval('f()');
        }
        console.log(g());
    """): 'via eval\n',
    inspect.cleandoc("""
        function outer() {
          function a() { return 1; }
          function b() { return a(); }
        }
        console.log(outer(), typeof outer);
    """): 'undefined function\n',
    inspect.cleandoc("""
        function f(x) {
          if (Math.random() > 2) {
            while (true) {
              function dead() { return window.location; }
            }
          }
          return x + 1;
        }
        console.log(f(1));
    """): '2\n',
    inspect.cleandoc("""
        'use strict';
        {
          function f() { return 1; }
        }
        console.log(typeof f);
    """): 'undefined\n',
    inspect.cleandoc("""
        function g(k) {
          switch (k) {
            case 0:
              function f() { return 'f'; }
            case 1:
              return typeof f === 'function' ? f() : 'none';
          }
        }
        console.log(g(1), g(0));
    """): 'f f\n',
    inspect.cleandoc("""
        var o = {};
        function g() {
          with (o) {
            {
              function f() { return 'with'; }
            }
            return f();
          }
        }
        console.log(g());
    """): 'with\n',
    inspect.cleandoc("""
        {
          function f() { return 'exported'; }
        }
        module.exports = f;
        console.log(module.exports());
    """): 'exported\n',
    inspect.cleandoc("""
        function outer() {
          function a() { return 'a'; }
          function b() { return a(); }
        }
        Object.defineProperty(globalThis, 'peek', { get() { return outer.toString().length > 0; } });
        console.log(peek);
    """): 'true\n',
    inspect.cleandoc("""
        function g() {
          {
            function a() { return b(); }
            function b() { return 'b'; }
          }
          return a();
        }
        console.log(g());
    """): 'b\n',
    inspect.cleandoc("""
        function g(x) {
          {
            function* gen() { yield 1; }
          }
          return x * 2;
        }
        console.log(g(2));
    """): '4\n',
    inspect.cleandoc("""
        class C {
          static {
            {
              function f() { return 1; }
            }
            C.v = typeof f;
          }
        }
        console.log(C.v);
    """): 'undefined\n',
    inspect.cleandoc("""
        var r = eval("'a'; if (true) { function g() {} }");
        console.log(typeof r);
    """): 'undefined\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAListOfNothingButFunctions(TestJsDeobfuscator):

    def test_a_program_reaching_a_function_from_outside_its_list_still_prints_the_same(self):
        rows = A_LIST_OF_NOTHING_BUT_FUNCTIONS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAFunctionAnotherFunctionReadsIsKept(TestJsDeobfuscator):

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    def test_two_functions_only_each_other_read_are_removed(self):
        source = inspect.cleandoc(
            """
            function W(a) {
              return V.extra;
            }
            W.extra = 1;
            function V(a) {
              return W.extra;
            }
            V.extra = 2;
            console.log(3);
            """
        )
        self.assertEqual('console.log(3);', self._remove_unused(source))

    def test_a_function_only_a_removed_property_write_holds_is_removed(self):
        source = inspect.cleandoc(
            """
            function W(a) {
              return a + 1;
            }
            W.handler = g;
            function g() {
              return W.extra;
            }
            W.extra = 5;
            console.log(7);
            """
        )
        self.assertEqual('console.log(7);', self._remove_unused(source))

    def test_a_function_whose_property_another_function_reads_is_kept(self):
        source = inspect.cleandoc(
            """
            function W(a) {
              return a + 1;
            }
            W.extra = 1;
            function f() {
              return W.extra;
            }
            console.log(f());
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_a_function_only_its_property_writes_reference_is_removed(self):
        source = inspect.cleandoc(
            """
            function W(a) {
              return a + 1;
            }
            W.extra = 1;
            console.log(2);
            """
        )
        self.assertEqual('console.log(2);', self._remove_unused(source))


A_WRITE_TO_A_FUNCTION_NOTHING_READS_WITH_AN_EFFECT = {
    inspect.cleandoc("""
        function f() {}
        f.x = console.log(1);
    """): '1\n',
    inspect.cleandoc("""
        function f() {}
        f[console.log(2)] = 1;
    """): '2\n',
}


class TestAWriteToAFunctionNothingReadsKeepsItsEffect(TestJsDeobfuscator):

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    def test_the_effect_of_the_write_is_kept(self):
        value_source = inspect.cleandoc(
            """
            function f() {}
            f.x = console.log(1);
            """
        )
        key_source = inspect.cleandoc(
            """
            function f() {}
            f[console.log(2)] = 1;
            """
        )
        self.assertIn(self._remove_unused(value_source), (value_source, 'console.log(1);'))
        self.assertEqual(self._remove_unused(key_source), key_source)

    @opportunity
    def test_a_write_whose_value_has_an_effect_leaves_only_the_effect(self):
        source = inspect.cleandoc(
            """
            function f() {}
            f.x = console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_writes_without_an_effect_are_removed_with_the_function(self):
        source = inspect.cleandoc(
            """
            function f() {}
            f.x = 1;
            f.y = function () {
              return 2;
            };
            console.log(3);
            """
        )
        self.assertEqual('console.log(3);', self._remove_unused(source))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAWriteToAFunctionNothingReads(TestJsDeobfuscator):

    def test_each_deobfuscation_prints_what_the_program_prints(self):
        for source, prints in A_WRITE_TO_A_FUNCTION_NOTHING_READS_WITH_AN_EFFECT.items():
            for strict in (False, True):
                with self.subTest(source=source, strict=strict):
                    deobfuscated = source.encode('utf8') | djs(strict=strict) | str
                    self.assertEqual(
                        (behavior(source), behavior(deobfuscated)),
                        ((prints, None), (prints, None)),
                    )


A_FUNCTION_ANOTHER_FUNCTION_READS = {
    inspect.cleandoc("""
        function W(a) { return a + 1; }
        W.extra = 1;
        function f() { return W(1) + W.extra; }
        console.log(f());
    """): '3\n',
    inspect.cleandoc("""
        function W(a) { return a + 1; }
        W.extra = 2;
        function g() { return W.extra; }
        function f() { return g() * 3; }
        console.log(f());
    """): '6\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAFunctionAnotherFunctionReads(TestJsDeobfuscator):

    def test_the_function_reading_the_property_still_prints_it(self):
        rows = A_FUNCTION_ANOTHER_FUNCTION_READS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_FOR_LOOP_TESTING_A_NAME = {
    inspect.cleandoc("""
        function f(m) { var n = 0; for (var go = true; go; ) { n++; if (n > m) go = false; } return n; }
        console.log(f(Math.random() < 2 ? 2 : 3));
    """): '3\n',
    inspect.cleandoc("""
        function f(m) { var n = 0, go; for (go = 1; go; n++) { if (n > m) go = 0; } return n; }
        console.log(f(Math.random() < 2 ? 2 : 3));
    """): '4\n',
    inspect.cleandoc("""
        function f(m) { var n = 0, go = m; for (; go; ) { n++; go = 0; } return n; }
        console.log(f(Math.random() < 2 ? 1 : 0));
    """): '1\n',
    inspect.cleandoc("""
        function f(k) { var n = 0, i; for (i = k; i; ) { n++; i = 0; } return n; }
        console.log(f(Math.random() < 2 ? 1 : 0));
    """): '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAForLoopTestingAName(TestJsDeobfuscator):

    def test_a_loop_testing_a_name_still_prints_the_same(self):
        rows = A_FOR_LOOP_TESTING_A_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAStoreAForLoopTestsByNameIsKept(TestJsDeobfuscator):

    def test_the_loop_still_tests_the_name_its_body_clears(self):
        source = inspect.cleandoc(
            """
            function f(k) {
              var n = 0, i;
              for (i = k; i; ) {
                n++;
                i = 0;
              }
              return n;
            }
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsUnusedCodeRemoval))


A_STORE_IN_THE_SUBJECT_OF_A_LOOP = {
    inspect.cleandoc("""
        function f(arr) { var x = 0; for (var k of (x = 1, arr)) { console.log(x); x = 2; } }
        f([0, 0]);
    """): '1\n2\n',
    inspect.cleandoc("""
        function f(o) { var x = 0; for (var k in (x = 1, o)) { console.log(x); x = 2; } }
        f({ a: 1, b: 2 });
    """): '1\n2\n',
    inspect.cleandoc("""
        var x;
        function f(arr) { for (var k of (x = 1, arr)) { console.log(x); x = 2; } }
        f([0, 0]);
    """): '1\n2\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAStoreInTheSubjectOfALoop(TestJsDeobfuscator):

    def test_the_next_iteration_still_prints_the_store_of_the_body(self):
        rows = A_STORE_IN_THE_SUBJECT_OF_A_LOOP
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestALoopReadingOnlyItsOwnConstantIsUnused(TestJsDeobfuscator):

    def test_a_call_of_a_function_whose_loop_only_reads_its_constant_is_removed(self):
        source = inspect.cleandoc(
            """
            function g(o) { for (const k in o) { k; } }
            g({ a: 1 });
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._run_transformer(source, JsUnusedCodeRemoval))


A_STORE_A_STATEMENT_MAY_SKIP = {
    inspect.cleandoc("""
        function f(y) { var x = 1; y ||= (x = 2); return x; }
        console.log(f(Math.random() < 2 ? 1 : 0));
    """): '1\n',
    inspect.cleandoc("""
        function f(y) { var x = 1; y &&= (x = 2); return x; }
        console.log(f(Math.random() < 2 ? 0 : 1));
    """): '1\n',
    inspect.cleandoc("""
        function f(y) { var x = 1; y ??= (x = 2); return x; }
        console.log(f(Math.random() < 2 ? 1 : null));
    """): '1\n',
    inspect.cleandoc("""
        function f(y) { var x = 1; y && (x = 2); return x; }
        console.log(f(Math.random() < 2 ? 0 : 1));
    """): '1\n',
    inspect.cleandoc("""
        function f(o) { var x = 1; o?.g(x = 2); return x; }
        console.log(f(Math.random() < 2 ? null : {}));
    """): '1\n',
    inspect.cleandoc("""
        function f(o) { var x = 1; o?.[x = 2]; return x; }
        console.log(f(Math.random() < 2 ? null : {}));
    """): '1\n',
    inspect.cleandoc("""
        function f(o) { var x = 1; o?.a.b(x = 2); return x; }
        console.log(f(Math.random() < 2 ? null : {}));
    """): '1\n',
    inspect.cleandoc("""
        function f(o) { var x = 1; o?.()(x = 2); return x; }
        console.log(f(Math.random() < 2 ? null : function () { return function () {}; }));
    """): '1\n',
    inspect.cleandoc("""
        function f(v) { var x = 1; switch (v) { case 0: break; case (x = 2): break; } return x; }
        console.log(f(Math.random() < 2 ? 0 : 1));
    """): '1\n',
    inspect.cleandoc("""
        function f(o) { var x = 1, a; ({ a = (x = 2) } = o); return x; }
        console.log(f(Math.random() < 2 ? { a: 3 } : {}));
    """): '1\n',
    inspect.cleandoc("""
        function f() { var x = 1; class A { y = (x = 2); } return x; }
        console.log(f());
    """): '1\n',
    inspect.cleandoc("""
        function f() { var x = 1; class A { static y = (x = 2); } return x; }
        console.log(f());
    """): '2\n',
    inspect.cleandoc("""
        var x;
        function f(y) { y ||= (x = 2); return x; }
        console.log(f(0), f(1));
    """): '2 2\n',
    inspect.cleandoc("""
        var x;
        function f(o) { o?.g(x = 2); return x; }
        console.log(f({ g() {} }), f(null));
    """): '2 2\n',
    inspect.cleandoc("""
        var x;
        function f(v) { switch (v) { case 0: break; case (x = 2): break; } return x; }
        console.log(f(1), f(0));
    """): '2 2\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAStoreAStatementMaySkip(TestJsDeobfuscator):

    def test_the_earlier_store_still_prints_where_the_later_one_is_skipped(self):
        rows = A_STORE_A_STATEMENT_MAY_SKIP
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestDeadDeclarationsInOneBodyLeaveItInOneEdit(TestJsDeobfuscator):

    @staticmethod
    def _edits_and_output(count: int) -> tuple[int, str]:
        lines = ['(function () {']
        lines.extend(F'var t{i}; SINK({i});' for i in range(count))
        lines.append('})();')
        ast = JsParser('\n'.join(lines)).parse()
        before = tree_version(ast)
        JsUnusedCodeRemoval().visit(ast)
        return tree_version(ast) - before, JsSynthesizer().convert(ast)

    def test_sixteen_dead_declarations_cost_as_many_edits_as_two(self):
        few_edits, few_output = self._edits_and_output(2)
        many_edits, many_output = self._edits_and_output(16)
        self.assertNotIn('var', few_output)
        self.assertNotIn('var', many_output)
        self.assertEqual(few_edits, many_edits)


class TestUnusedCodeRemovalTakesTimeThatGrowsWithTheProgram(TestJsDeobfuscator):

    @staticmethod
    def _cost_ratio(small: str, large: str) -> tuple[float, str]:
        small_asts = [JsParser(small).parse() for _ in range(3)]
        large_asts = [JsParser(large).parse() for _ in range(3)]
        large_time = fastest_processor_time(functools.partial(JsUnusedCodeRemoval().visit, ast) for ast in large_asts)
        small_time = fastest_processor_time(functools.partial(JsUnusedCodeRemoval().visit, ast) for ast in small_asts)
        return processor_time_ratio(large_time, small_time), JsSynthesizer().convert(large_asts[0])

    def test_live_stores_to_two_reused_names_are_kept_in_time_that_grows_with_the_program(self):
        def source(count: int) -> str:
            lines = ['var o = {};', 'var a, b;']
            lines.extend(F'a = "p{i}"; b = a; o[b] = {i};' for i in range(count))
            lines.append('console.log(o);')
            return '\n'.join(lines)

        small, large = source(1000), source(8000)
        ratio, output = self._cost_ratio(small, large)
        self.assertEqual(output, JsSynthesizer().convert(JsParser(large).parse()))
        self.assertLess(ratio, 2 * len(large) / len(small))

    def test_dead_stores_between_calls_are_removed_in_time_that_grows_with_the_function(self):
        def source(count: int) -> str:
            lines = ['(function () {', 'var x;']
            lines.extend(F'SINK({i}); x = {i};' for i in range(count))
            lines.append('})();')
            return '\n'.join(lines)

        small, large = source(1000), source(8000)
        ratio, output = self._cost_ratio(small, large)
        calls = ''.join(F'  SINK({i});\n' for i in range(8000))
        self.assertEqual(output, F'(function() {{\n{calls}}})();')
        self.assertLess(ratio, 2 * len(large) / len(small))
