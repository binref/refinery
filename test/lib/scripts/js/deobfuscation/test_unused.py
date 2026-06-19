from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestUnusedCodeRemoval(TestJsDeobfuscator):

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

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

    def test_script_scope_declarations_kept_when_written_in_function(self):
        """
        A top-level declaration whose global is written inside `build` is kept: flow-insensitively the
        write cannot be proven to precede every read, so dropping the declaration could leave a read of
        an undeclared name. Only `push` (never referenced) and `dead` (a dead store) are removed.
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
                var acc, i;
                function build(n) {
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

    def test_reflection_surface_preserves_dead_init_global(self):
        source = inspect.cleandoc(
            """
            var deadGlobal = 1;
            eval('deadGlobal');
            """
        )
        self.assertEqual(source, self._remove_unused(source))

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
