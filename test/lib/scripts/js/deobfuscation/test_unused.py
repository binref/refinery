from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import (
    JsUnusedCodeRemoval,
    _destructuring_target_safe,
)
from refinery.lib.scripts.js.model import JsAssignmentExpression
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


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
        """
        `acc` and `i` are script-scope `var`s referenced only inside `build`, which overwrites each
        before reading it, so they behave as locals of `build` and are relocated there, tightening
        globals the obfuscator hoisted. The move observes no value carried across calls or from load, so
        behaviour is unchanged. `push` (never referenced) and `dead` (a dead store) are removed.
        """
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
        """
        `counter` is read before it is written inside `next`, so a value carried across calls is
        observed; relocating it into `next` would give each call a fresh local and change behaviour. It
        stays at script scope unchanged.
        """
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
        self.assertEqual(source, self._remove_unused(source))

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
            eval();
            """
        )
        expected = inspect.cleandoc(
            """
            function eval() {
              return 0;
            }
            eval();
            """
        )
        self.assertEqual(expected, self._remove_unused(source))

    def test_strip_globals_removes_dead_global_declaration(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            console.log(2);
            """
        )
        ast = JsParser(source).parse()
        JsUnusedCodeRemoval(preserve_globals=False).visit(ast)
        self.assertEqual('console.log(2);', JsSynthesizer().convert(ast))

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
        """
        `x` has no static reference — `eval('x')` names it only at runtime — but the eval lies inside
        `f`, so it could read the local. The declaration and its store must both be kept.
        """
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
        left, right = self._destructuring_parts('({k: a} = {get x(){}});')
        self.assertFalse(_destructuring_target_safe(left, right))

    def test_destructuring_object_spread_source_is_unsafe(self):
        left, right = self._destructuring_parts('({k: a} = {...o});')
        self.assertFalse(_destructuring_target_safe(left, right))

    def test_function_local_read_in_a_with_block_is_kept(self):
        """
        Inside `with (o)` the name `x` may resolve to `o.x` or, failing that, the local, so removing the
        local would change which it binds. The `with` makes the function dynamic, and `x` is kept.
        """
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
            uses();
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
            f();
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def _remove_unused_unwrapped(self, source: str) -> str:
        """
        Statement-level object-pattern destructuring is parenthesized by the parser; the
        deobfuscation pipeline strips that wrapper before unused-code removal runs. Mirror that by
        simplifying first so the object-pattern path is actually exercised.
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

    def test_dead_destructuring_compound_assignment_target_preserved(self):
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
        self.assertEqual(self._remove_unused(source), source)

    def test_dead_destructuring_for_of_target_preserved(self):
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
        self.assertEqual(self._remove_unused(source), source)

    def test_dead_destructuring_in_block_read_outside_preserved(self):
        """
        The `var a` is function-scoped, so the destructuring inside the `if` block is read by the
        `return a` that follows the block; removal must account for the whole function scope, not
        just the immediate block.
        """
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
        """
        A computed property key in a surviving destructuring pattern reads its identifier, so the
        plain `[a] = ...` that feeds it must not be treated as dead.
        """
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
            var x = 1;
            delete x;
            console.log('done');
            """
        )
        result = self._run_transformer(source, JsUnusedCodeRemoval)
        self.assertEqual(source, result)

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

    def test_dead_binding_from_impure_call_kept(self):
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
        self.assertEqual(source, self._run_transformer(source, JsUnusedCodeRemoval))

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
