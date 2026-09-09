from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.options import DeobfuscationOptions
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
        """
        A read of a trusted data-property global off `globalThis` runs no getter, so an unused binding
        initialized from one is a pure dead store the removal drops.
        """
        source = inspect.cleandoc(
            """
            var d = globalThis.TextDecoder;
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_dead_non_data_property_global_read_preserved(self):
        """
        `location` is not among the trusted global data properties, so `globalThis.location` may run an
        accessor; the unused binding is kept rather than dropped as a pure read.
        """
        source = inspect.cleandoc(
            """
            var d = globalThis.location;
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_strict_function_caller_read_preserved(self):
        """
        Reading `.caller` on a strict-mode function throws a `TypeError`, so the read is not
        side-effect-free even off a fresh function literal; the unused binding is kept, not dropped.
        """
        source = inspect.cleandoc(
            """
            var x = function() {
              'use strict';
            }.caller;
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_strict_function_computed_caller_read_preserved(self):
        """
        The poison-pill gate also covers the string-computed form `['caller']`, which names the same
        throwing accessor as the dotted `.caller`.
        """
        source = inspect.cleandoc(
            """
            var x = function() {
              'use strict';
            }['caller'];
            console.log(1);
            """
        )
        self.assertEqual(source, self._remove_unused(source))

    def test_dead_global_alias_data_property_read_removed(self):
        """
        A local single-assigned to the global object is a global-object alias, so a data-property read
        through it runs no getter; the dead read and the now-unreferenced alias are both dropped.
        """
        source = inspect.cleandoc(
            """
            var g = globalThis || {};
            var d = g.TextDecoder;
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source))

    def test_dead_global_alias_read_before_establishment_preserved(self):
        """
        The alias is read before its establishing assignment runs, where it is still the hoisted
        `undefined`, so the read throws; dropping it would discard the throw, so it is kept.
        """
        source = inspect.cleandoc(
            """
            var d = g.TextDecoder;
            var g = globalThis || {};
            console.log(1);
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

    def test_dead_store_calling_a_dead_zone_reader_is_kept(self):
        """
        A dead store holding a call to a function that reads an outer `let` in that binding's dead
        zone throws a `ReferenceError` at the call, so the store is not removable. The reformatted
        program is returned unchanged.
        """
        source = 'function f() { return q; }\nvar dead = f();\nlet q = 1;\nconsole.log(2);\n'
        self.assertEqual(self._run_transformers(source), self._remove_unused(source))

    def test_dead_store_calling_an_established_reader_is_removed(self):
        """
        The same reader called after its `let` declaration reads no dead zone, so the discarded call
        is pure and the store, the now-uncalled function, and the unread binding all go. This is the
        control the dead-zone case is refused against: identical but for declaration order, it must
        still reduce.
        """
        source = 'function f() { return q; }\nlet q = 1;\nvar dead = f();\nconsole.log(2);\n'
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_dead_store_calling_a_generator_dead_zone_reader_is_removed(self):
        """
        Calling a generator returns an iterator without running its body, so a dead-zone read in the
        body never executes and the discarded call throws nothing. The dead store is removed even
        though the body would read `q` before its declaration.
        """
        source = 'function* gen() { return q; }\nvar dead = gen();\nlet q = 1;\nconsole.log(2);\n'
        self.assertEqual('console.log(2);', self._remove_unused(source))

    def test_dead_store_calling_a_reader_of_its_own_dead_zone_local_is_removed(self):
        """
        A function reading a `let` it declares itself orders that read against the declaration
        in its own body, so a call to it is safe with respect to the binding. The owned binding
        is filtered out of the deferred dead-zone set and the discarded call is removed.
        """
        source = 'function f() { let x = 1; return x; }\nvar dead = f();\nconsole.log(2);\n'
        self.assertEqual('console.log(2);', self._remove_unused(source))

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

    def test_strip_globals_keeps_reflection_reachable_global(self):
        """
        With preserve_globals=False the blunt script-scope bail is disabled, yet a global that a
        reflection surface can reach must still be preserved by the fine-grained reachability check;
        dropping it would be unsound.
        """
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

    def test_dead_binding_from_established_const_call_removed(self):
        source = inspect.cleandoc(
            """
            const makeTag = () => "[x]";
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
    """
    A top-level function a host invokes by name has no caller inside the file, so reachability computed
    over the file alone judges it dead — and removing it also strands everything only it reached. Which
    names a host calls is not derivable from the file, so the caller declares them and they seed the
    reachability roots.
    """

    def _remove_unused(self, source: str, *entrypoints: str) -> str:
        return self._run_transformer(
            source,
            JsUnusedCodeRemoval,
            DeobfuscationOptions(entrypoints=entrypoints),
        )

    def test_unreferenced_function_removed_when_no_entrypoint_is_named(self):
        """
        The default is unchanged: with nothing declared, an unreferenced top-level function is dead.
        """
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
        """
        The declaration seeds a reachability root rather than exempting one function from removal, so
        the entrypoint's callees are reachable through it and survive without being named themselves.
        """
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
        """
        Only a declaration a host can actually reach is protected, which `reaches_global_object` decides.
        A same-named function inside another body is a distinct binding no host can name.
        """
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
        """
        A top-level declaration in a module never becomes a property of the global object, so no host can
        call it by name and naming it cannot make it live.
        """
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
                DeobfuscationOptions(module=True, entrypoints=('run',)),
            ),
        )

    def test_entrypoint_referenced_only_by_a_property_write_survives(self):
        """
        A function whose only reference is `f.prop = ...` is normally reclaimed as write-only. A host
        calls the entrypoint regardless of how the file references it, so that demotion must not apply.
        """
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

    def test_declared_name_that_is_not_a_top_level_function_is_inert(self):
        """
        A pattern names a callable a host reaches, so it protects a top-level function declaration. A name
        the script never declares that way — here only a `let` binding exists — is left to the ordinary
        reachability rules.
        """
        source = inspect.cleandoc(
            """
            let run = function() {
              return 1;
            };
            console.log(1);
            """
        )
        self.assertEqual('console.log(1);', self._remove_unused(source, 'run'))

    def test_entrypoint_held_by_a_var_declarator_survives(self):
        """
        `var run = function(){}` puts `run` on the global object just as a declaration does, so a host can
        call it. This binding is swept by the dead-variable path rather than the dead-function path, which
        is why the declaration is protected per binding and not only where function reachability is
        computed.
        """
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
        """
        The same binding in its split form, where the declaration and the assignment are separate
        statements and the assignment is what the sweep would drop.
        """
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
        """
        The pseudo-global `t` is relocated into the one function that uses it, and the declaration
        goes below the `'use strict'` that opens that body rather than above it. Written above, it
        would end the Directive Prologue before the directive is reached, and the assignment below
        would create a global instead of throwing.
        """
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
        """
        Nothing reads `q`, so the declaration and the store both go, and the sweep that removes them
        passes over every statement of the body which only evaluates a literal. The directive is
        written in that shape and is not one of those statements: dropping it would leave the body
        running under the other mode.
        """
        source = inspect.cleandoc(
            """
            function f(a) {
              'use strict';
              var q;
              q = a;
              return 1;
            }
            f(1);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a) {
                  'use strict';
                  return 1;
                }
                f(1);
                """
            ),
            self._remove_unused(source),
        )

    def test_a_string_that_declares_no_mode_is_swept_with_it(self):
        """
        The same body with a directive the language does not recognize. It declares nothing, so
        nothing turns on whether it stands there, and it goes the way every other statement that
        only evaluates a literal goes.
        """
        source = inspect.cleandoc(
            """
            function f(a) {
              'use loose';
              var q;
              q = a;
              return 1;
            }
            f(1);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a) {
                  return 1;
                }
                f(1);
                """
            ),
            self._remove_unused(source),
        )

    def test_a_dead_write_standing_as_an_unbraced_branch_body_is_kept_and_the_pass_ends(self):
        """
        `_remove_from_parent` cannot take a statement out of a single-node field, so a removal the
        tree refuses must not report the pass as changed: each of these programs used to spin the
        fixpoint forever, one per removal arm — global property, dead variable, destructuring.
        """
        rows = {
            'if (Math.random() > 2) window.x = 1;\nconsole.log(3);':
                'if (Math.random() > 2) {\n  window.x = 1;\n}\nconsole.log(3);',
            'var y;\nif (Math.random() > 2) y = 1;\nconsole.log(3);':
                'var y;\nif (Math.random() > 2) {\n  y = 1;\n}\nconsole.log(3);',
            'var a, b;\nif (Math.random() > 2) [a, b] = [1, 2];\nconsole.log(3);':
                'var a, b;\nif (Math.random() > 2) {\n  [a, b] = [1, 2];\n}\nconsole.log(3);',
        }
        self.assertEqual({source: self._remove_unused(source) for source in rows}, rows)

    def test_a_write_read_back_through_a_bracket_spelling_is_kept(self):
        source = "globalThis.x = 1;\nconsole.log(globalThis['x']);"
        self.assertEqual(source, self._remove_unused(source))


#: An assignment to a name no declaration binds, standing where nothing makes the region strict,
#: mapped to the text the deobfuscation writes for it. Sloppy code answers such a write by creating
#: a property of the global object, so a write nothing reads back really is a dead store and the
#: text records that it is gone.
A_SLOPPY_REGION_ASSIGNING_TO_NO_BINDING: dict[str, str] = {
    'function f(b) { var q = b + 1; undeclared_e = 1; return q; } console.log(f(2));':
        'console.log(3);',
    'undeclared_f = 1; console.log(3);': 'console.log(3);',
}

#: A region that runs strict, assigning to a name it declares itself, mapped to the text the
#: deobfuscation writes for it. Strictness refuses only the write that resolves to no binding, so a
#: declared name leaves the store as dead here as it is anywhere, and the mode is no reason to keep
#: it.
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
    """
    A program that declares *name* as a local object, writes a property on it, and prints the object
    as JSON, so that a write that went missing is a line of output and not an error.
    """
    return inspect.cleandoc(
        F"""
        var {name} = {{}};
        {name}.x = 1;
        console.log(JSON.stringify({name}));
        """
    )


#: A program whose object is named by a local declaration, mapped to the text the deobfuscation
#: writes for it — the program itself. A declaration of a global-object alias name binds it, so the
#: write puts a property on an ordinary object the `JSON.stringify` read prints whole, never on the
#: global object, and the write is kept however dead its property name looks. The name is spelled
#: seven ways: the four the removal's same-realm set holds, the two alias spellings outside it, and
#: one that is no spelling of the global object at all.
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

#: The same write through an alias no declaration binds, beside a program that never reads the
#: name, mapped to the text the deobfuscation writes for it. This is the control: here the write
#: really puts a property on the global object and nothing reads it, so the sweep removes it, and a
#: fix that kept every write spelled through an alias would fail this row. The second row stands a
#: spelling in a `typeof` guard, which observes no property, so it does not veto the sweep either.
A_GLOBAL_PROPERTY_WRITE_NOTHING_READS: dict[str, str] = {
    'globalThis.q = 1;\nconsole.log(3);': 'console.log(3);',
    "globalThis.x = 1;\nif (typeof window !== 'undefined') {\n  console.log(3);\n}":
        "if (typeof window !== 'undefined') {\n  console.log(3);\n}",
}


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


#: The same dead-looking write beside a position that hands the global object itself onward — a
#: call argument, a `for-in` subject, the `this` of the top level — mapped to the program itself.
#: From such a position every property is readable without its name being spelled, so nothing may
#: be removed: `Object.keys` would hold one name fewer and the `w` parameter would print
#: `undefined` if the write went.
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

#: A dead write whose base resolves in every host, mapped to the text the deobfuscation writes for
#: it: `globalThis` is the one same-realm spelling the language mandates, so its read cannot throw and
#: a store to a property nothing reads is a dead store to remove. The row joins the Node twin, since it
#: runs and prints the same before and after.
A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_CERTAIN_BASE: dict[str, str] = {
    'globalThis.q = 1;\nconsole.log(3);': 'console.log(3);',
}

#: The same dead write through a host-conditional spelling, mapped to the program itself. A bare
#: `window`/`self`/`global` read may not resolve — under Node it throws a `ReferenceError` — so
#: removing the store would drop the throw the base raises where the host lacks the name, and the write
#: is kept. These rows pin the text only and stay out of the Node twin, whose host lacks the names.
A_DEAD_GLOBAL_PROPERTY_WRITE_THROUGH_A_HOST_CONDITIONAL_BASE: dict[str, str] = {
    source: source
    for source in [
        'window.q = 1;\nconsole.log(3);',
        'self.q = 1;\nconsole.log(3);',
        'global.q = 1;\nconsole.log(3);',
    ]
}

#: The same dead write through the two spellings the removal set leaves out, mapped to the program
#: itself: `top` and `frames` are not trusted to denote this document's global object, so their
#: writes are not this sweep's to remove.
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
    """
    A `let` between a block-scoped function declaration and the `var` scope around it keeps §B.3.3.1
    from copying the function out, so the name means nothing after the block. Reading the `let` is
    the whole of what it is for, which the reference-counting removal does not see: the binding has
    no reference, and removing it lets the copy run and the name reach the enclosing scope.
    """

    def _remove_unused(self, source: str) -> str:
        return self._run_transformer(source, JsUnusedCodeRemoval)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_suppressing_binding_is_kept_so_the_name_stays_unbound(self):
        """
        Node prints `undefined` for this program: `let f` stops the inner `function f` from being
        given a `var` in `outer`, so `typeof f` finds no binding. Removing the `let` as unreferenced
        makes the program print `function` instead.
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
        """
        The guard keys on the name a block function is declared with, not on any `let` standing in a
        block: where the `let` binds a name no block-scoped function shares, it suppresses no copy
        and the unreferenced binding is removed as before.
        """
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


#: A program whose one failure is a read of a name nothing binds, standing where nothing uses the
#: value around it, mapped to the text the deobfuscation writes for it. Reading such a name throws a
#: `ReferenceError`, so the read survives every discarding context: the store around it may go — the
#: third row keeps its right-hand side as a bare expression — but the read itself stays and the
#: program still refuses to run.
A_KEPT_READ_OF_A_NAME_NOTHING_BINDS: dict[str, str] = {
    'function f() { let v = zzz; }\nf();\nconsole.log(1);\n':
        'function f() {\n  let v = zzz;\n}\nf();\nconsole.log(1);',
    'function f() { var v = zzz; }\nf();\nconsole.log(1);\n':
        'function f() {\n  var v = zzz;\n}\nf();\nconsole.log(1);',
    'y = a;\nconsole.log(1);\n': 'a;\nconsole.log(1);',
    'var o = { p: g };\nconsole.log(1);\n': 'var o = { p: g };\nconsole.log(1);',
    'y = N();\nN = function () {};\nconsole.log(1);\n':
        'N();\nN = function() {};\nconsole.log(1);',
}

#: The same read standing inside a `try`, mapped to the text the deobfuscation writes for it. The
#: read throws, the `catch` clause runs and prints, and the program carries on, so both sides run
#: to the end and only the first line of output tells them apart; emptying the block would take the
#: clause's run away. The store around the read may still go — the third row keeps the read as a
#: bare expression — and the last two rows are the controls: a `throw` and a member read on `null`
#: reach the same clause from the same block and are not reads of a name.
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

#: A program that calls a function whose body reads a name nothing binds and prints the result,
#: mapped to the text the deobfuscation writes for it — the program itself. Evaluating the body
#: throws, so the call is not a call that may be written as the value it would have returned, and
#: neither the store holding the read nor the call goes. The last two rows are the controls: the
#: same read written as a statement of its own and as the returned expression.
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

#: The same shapes with every read established or resolved, mapped to the text the deobfuscation
#: writes for them. These are the controls against over-refusal: a read the definite-assignment
#: model vouches a completed creating write for is droppable with its store, so the first program
#: still reduces to its print, the call whose body cannot throw is still written as its value, and
#: the `try` around a store that cannot throw still empties.
AN_ESTABLISHED_STORE_STILL_REDUCES: dict[str, str] = {
    'X = 5;\ny = X;\nconsole.log(1);\n': 'console.log(1);',
    'function f() {\n  var x = 1;\n  return 7;\n}\nconsole.log(f());\n': 'console.log(7);',
    'try {\n  var x = 1;\n} catch (e) {\n  console.log(2);\n}\nconsole.log(3);\n':
        'try {} catch (e) {\n  console.log(2);\n}\nconsole.log(3);',
    'N = function () {};\ny = N();\nconsole.log(1);\n': 'console.log(1);',
    'function N() {}\ny = N();\nconsole.log(1);\n': 'console.log(1);',
}


class TestAReadOfANameNothingBindsIsKept(TestJsDeobfuscator):
    """
    The removal contexts ask the throw half of the read contract and take the establishment answer
    from `refinery.lib.scripts.js.analysis.assignment.DefiniteAssignmentModel`, so a read of a name
    no completed write establishes keeps its `ReferenceError` wherever its expression is discarded.
    """

    def test_the_read_survives_where_its_expression_is_discarded(self):
        rows = A_KEPT_READ_OF_A_NAME_NOTHING_BINDS
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_the_read_survives_inside_a_try_so_the_catch_still_runs(self):
        rows = A_KEPT_READ_A_TRY_CATCHES
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

    def test_a_call_whose_body_cannot_return_is_not_replaced_by_its_value(self):
        rows = A_KEPT_CALL_WHOSE_BODY_CANNOT_RETURN
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

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


#: A program whose one failure is a read of a name nothing binds, standing where a discarding
#: context other than the store-removal sweep folds the expression around it, mapped to the text the
#: deobfuscation writes for it. The dead-branch fold takes the truthy `if` but keeps `[zzz]` as a
#: bare expression, the object fold inlines `o.q` to its value but keeps the declaration whose
#: construction reads the unaccessed `zzz`, and the IIFE inliner declines to substitute a may-throw
#: argument bound to a parameter its body drops. The last two rows are the controls a named-wrapper
#: inline and an array-index fold already kept. Every row throws where it threw, so the read survives
#: each context the way the sweep keeps it.
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

#: A wrapper reading its parameter under `typeof` handed a name nothing binds, mapped to the text the
#: deobfuscation writes for it. `typeof` is the one operand position where reading a free name does
#: not throw, so substituting the call-site argument into it would erase the `ReferenceError` the
#: call raised even though the argument is used once and in order; the IIFE inliner refuses the
#: position and the call stands.
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

#: The control: the same wrapper handed an established name, mapped to the text the deobfuscation
#: writes for it. The argument does not throw, so the inline proceeds and `typeof 1` folds to its
#: answer where the throwing argument's would have stood.
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
    """
    Every pass that drops or reorders an expression asks the throw half of the read contract with the
    establishment answer `refinery.lib.scripts.js.analysis.assignment.DefiniteAssignmentModel` gives,
    so a read of a name no completed write establishes survives the dead-branch fold, the object fold,
    and the IIFE inliner the way the store-removal sweep already keeps it. The IIFE inliner further
    refuses to move a may-throw argument into a `typeof` operand, the one position that would mute the
    throw the ordering rules keep.
    """

    def test_the_read_survives_where_a_context_folds_around_it(self):
        rows = A_KEPT_READ_A_DISCARDING_CONTEXT_FOLDS_AROUND
        self.assertEqual({source: self._deobfuscate(source) for source in rows}, rows)

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
