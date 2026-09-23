from __future__ import annotations

import inspect
import unittest

from test import TestBase, a_property_of_the_batch_itself
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    before_and_after,
    each_program_still_prints,
    folded,
)

from refinery.lib.scripts.js.deobfuscation.constants import JsConstantInlining
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestConstantInlining(TestJsDeobfuscator):

    def test_literal_string_inlined(self):
        self.assertEqual("console.log('hello');", self._inline("var x = 'hello'; console.log(x);"))

    def test_literal_number_inlined(self):
        self.assertEqual('console.log(42);', self._inline('var x = 42; console.log(x);'))

    def test_literal_boolean_inlined(self):
        self.assertEqual('console.log(true);', self._inline('var x = true; console.log(x);'))

    def test_delete_initializer_is_not_relocated(self):
        """
        Deleting a binding is observable, so an initializer spelled as a `delete` is not pure and its
        single use does not take it: the move would put the delete past the intervening call, moving
        the moment the binding disappears. The pure arithmetic control beside it still moves.
        """
        self.assertEqual(
            'var x = 5;\nvar t = delete x;\ng();\nf(t);',
            self._inline('var x = 5; var t = delete x; g(); f(t);'))
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

    def test_read_before_mutating_call_inlines_read_after_does_not(self):
        """
        `f` reassigns the captured `x`, so the read before the call still sees `5` and is inlined, while
        the read after the call sees `9` and must be left alone — the value holds up to the barrier only.
        """
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
        """
        `f` mutates the captured `x` at the end of each iteration, so a later iteration reads `9`. The
        do-while whose body opens with a `try` must order that call before the reads on the loop's
        back-edge, leaving `SINK.push(x)` alone.
        """
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
        """
        The same loop-carried mutation through a `for (;;)` whose body opens with a `try`: the back-edge
        must reach the guarded reads, so `SINK.push(x)` is not inlined to `5`.
        """
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
        """
        Declarators run left to right, so `y = (SINK(x), 0)` reads `x` while it is still undefined; the
        later `x = 5` must not fold into that read. Statement granularity cannot order the two, so a
        constant is not inlined into a use that shares its defining statement.
        """
        source = inspect.cleandoc(
            """
            var y = (SINK(x), 0), x = 5;
            DONE(y);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_expression_not_inlined_past_free_variable_mutation(self):
        """
        `x = a + 5` captures `a` at entry; `g()` reassigns the captured `a` before each `SINK(x)`.
        Relocating `a + 5` into the loop would recompute it with the mutated `a`, so the single-use
        expression stays at its definition even though `x` itself is never mutated.
        """
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

    def test_constant_mutated_through_with_not_inlined(self):
        """
        A write inside a `with` body resolves to no binding — it could hit the outer `x` or a property
        of the `with` object — so the constant is not stable and must not be inlined.
        """
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
        """
        The `with` body names `z`, not `x`, so the local constant is not reflectively reachable and folds
        — the same-scope precision the re-expressed `reflection_can_reach` unmasks; a coarse
        any-`with`-in-the-function guard would have refused it.
        """
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
        """
        The `with` body's write to `arr[0]` resolves to no binding, but it is attributed to `arr` as a
        dynamic reference, so the container is not immutable and the cross-function `arr[0]` read is not
        inlined into `get`.
        """
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
        """
        The `with` body's `x = 2` resolves to no binding but is attributed to the script `x`, so the
        candidate is rejected and the cross-function read in `f` is not inlined — it must observe the
        reassignment.
        """
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
        """
        The `with` body's `x = 2` is attributed to `g`'s parameter `x`, which shadows the script `x`, so
        the script constant stays stable and the cross-function read folds — the binding-attributed gain
        over a name-based scan, which would reject any candidate merely named `x`.
        """
        self.assertEqual(
            inspect.cleandoc(
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
            ),
            self._inline('var x = 1; function g(x) { with (q) { x = 2; } } function f() { return x; } SINK(f());'),
        )

    def test_cross_function_local_reassignable_by_direct_eval_not_inlined(self):
        """
        A direct `eval` in `outer` can rebind its local `x` through an opaque string that carries no
        referencing identifier, so `x` is not a stable constant: the cross-function read in `f` must
        not be inlined. Unlike a `with` body, the reassignment leaves no unresolved-write node to
        reject on, so the candidate is rejected on `local_reachable_by_direct_eval`. `x` is a
        function-local, not the script-scope opaque-`eval` residual.
        """
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
        """
        The `eval` can rebind the local, but only at the statement spelling the call, so the read
        before it is inlined and the read after it is not. The declaration stays: the later read
        still names it.
        """
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
        """
        The read folds — it stands before the `eval` — but the payload could read `x` by name,
        so the declaration stays: removing it would turn the value the eval reads into a
        `ReferenceError`.
        """
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
        """
        The callback is invoked whenever the host fires it, a point no ordering pins down, so the
        `eval` ahead of it could have rebound `x` by the time the read runs — the cross-function
        inliner refuses the candidate a dynamic scope could rewrite, whatever reader shape holds it.
        """
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
        """
        The `with` body invokes `evil` by name; if `o` lacks a property `evil` the call runs the local
        `evil`, which writes `b`. That invocation is a call site no static reasoning can pin down, so a
        function named inside a `with` escapes and `b` is volatile — the constant must not be folded.
        """
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
        """
        The `with` body reassigns `n` to `evil` (a mutator of `b`); if `o` lacks a property `n` the later
        `n()` runs `evil` and sets `b` to 99. The alias resolves to no binding statically, so `evil`
        escapes through its `with`-body reference and `b`'s constant must not be folded.
        """
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
        """
        `f` is invoked inside the `with` body, before `const c` initializes, so that call reads `c` in
        its temporal dead zone. The invocation is a call site no static reference records, so ordering
        the constant against `f`'s static references alone judges it to run before every call and folds
        `c` into `f` — turning the `ReferenceError` the early call throws into a silent `5`. The
        with-body reference must keep `f`'s invocation points unorderable, mirroring `function_escapes`.
        """
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
        """
        `probe` is invoked only through the opaque `eval(payload)`, a call site no static reference
        records; it could run `probe` before `const c` initializes, reading `c` in its temporal dead
        zone. Ordering the constant against `probe`'s static references alone would find none and fold
        `c` into the body, turning the `ReferenceError` the early call throws into a silent `5`, so the
        opaque reflective surface must keep `probe`'s invocation points unorderable.
        """
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
        """
        `globalThis.x = 2` writes the script-level `x` through a member expression the effect model's
        per-binding accounting does not see, so the constant is rejected directly.
        """
        source = inspect.cleandoc(
            """
            var x = 1;
            globalThis.x = 2;
            SINK.push(x);
            """
        )
        self.assertEqual(source, self._inline(source))

    def test_constant_mutated_by_transitively_called_function_not_inlined(self):
        """
        `outer` does not write `x` itself but calls `inner`, which does; the effect model rolls the
        transitive write into `outer`'s summary, so the call to `outer` seals the constant.
        """
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
        """
        The escaping closure mutates `make`'s local `x`, a different binding from the script-level
        constant `x`; the name-based predecessor rejected every `x` on the shared name, but the
        binding-resolved analysis sees the mutated binding is not the constant and inlines it.
        """
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
        self.assertEqual(
            inspect.cleandoc(
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
            ),
            self._inline(source),
        )

    def test_constant_mutated_in_function_with_confined_reads_not_inlined(self):
        """
        Every read of `x` is confined to `f`, which reassigns it between two of them. The write is
        unobservable outside `f`, so `f` is pure, but it still changes `x` between the reads, so the
        constant is not stable inside `f` and neither read may be inlined.
        """
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
        self.assertEqual(source, self._inline(source))

    def test_constant_mutated_by_redeclared_function_not_inlined(self):
        """
        `f` is declared twice; the later definition wins at runtime and reassigns `x`. A redeclared name
        cannot be pinned to one body, so the mutating call cannot be sealed and the constant is rejected.
        """
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
        """
        `c` is read in the temporal dead zone, before its own `const` declaration runs, so the read
        throws. The cross-function pass must leave a reference in the declaring function's own body to
        the in-scope domination pass, which already declines this pre-declaration read, rather than
        inlining the value and replacing the throw with it.
        """
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
        """
        `x` is read before its hoisted `var` is assigned, so the read sees `undefined`. Promoting `x`
        to its eventual constant and inlining that read in the same function would turn `undefined`
        into the value.
        """
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
        """
        `read` returns a free `v` that resolves to no local binding; the only `v` is a block-scoped
        `const` invisible to the function. Matching by name alone would inline the const into a
        reference that never reads it, so the inline is gated on the reference resolving to the
        candidate binding.
        """
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

    def test_member_array_element_increment_not_inlined(self):
        """
        `X.Y[0]++` mutates the member-array element, so the array is not immutable and its elements
        must not be inlined — a hand-rolled assignment-only write check judged the array safe and folded
        `X.Y[0]` to the literal (emitting invalid `5++`).
        """
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

    def test_member_array_read_only_element_inlined(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var X = {};
                SINK(6);
                """
            ),
            self._inline('var X = {}; X.Y = [5, 6]; SINK(X.Y[1]);'),
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

    def test_var_array_inlined_into_called_function_after_definition(self):
        """
        `f` is called after `p` is assigned, so every read of `p[0]` inside it sees the literal array;
        the runs-before check orders the call against the definition where statement position could not.
        """
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
        """
        The reader is an anonymous function invoked immediately — the shape every packed payload
        uses. Its single reference point is the function expression itself, which the initializer
        precedes, so the read folds and the declaration, with nothing left reading it, goes too.
        """
        self.assertEqual(
            "(function() {\n  SINK('abc');\n})();",
            self._inline("var k = 'abc'; (function () { SINK(k); })();"),
        )

    def test_var_inlined_into_a_stored_function_reader_after_definition(self):
        """
        The reader is stored in a binding and invoked through it; the read of the name is the one
        point the invocation cannot precede, and the initializer precedes it.
        """
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
        """
        The computed-member arm admits the same reader shapes the plain-identifier arm does: the
        index read folds inside an immediately invoked function.
        """
        self.assertEqual(
            "(function() {\n  SINK('a');\n})();",
            self._inline("var p = ['a']; (function () { SINK(p[0]); })();"),
        )

    def test_var_not_inlined_into_an_iife_reader_that_runs_too_early(self):
        """
        The expression statement that invokes the reader stands before the initializer's statement,
        so a read inside it may observe the stale value and is left standing.
        """
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
        """
        `!a` consumes the value the binding holds as a verdict and forwards nothing, so it is no
        escape from the container and the index read beside it folds. An empty array is truthy, so
        the guard itself folds nowhere here — it is not this pass's question.
        """
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

    def test_a_loose_equality_operand_still_blocks_index_inlining(self):
        """
        A loose equality runs `ToPrimitive` on the object, a method the prototype chain chooses, so
        it forwards and stays an escape: the index read is left standing.
        """
        source = inspect.cleandoc(
            """
            var a = ['x'];
            if (a == 1) {
              return;
            }
            f(a[0]);
            """
        )
        self.assertEqual(source, self._inline(source))

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
        """
        The guard's read stands inside a `with` body, where the bare name consults the `with`
        object first and a getter there runs code that can mutate the container, so the verdict
        position does not clear it and the index read is left standing.
        """
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

    def _inline_one_plan_at_a_time(self, source: str) -> str:
        """
        The pass's sequential self: each decided plan applies at the moment it is decided, against
        the tree the previous plans already changed. Its output must equal the batched run's.
        """
        ast = JsParser(source).parse()
        instance = JsConstantInlining()
        instance.options = None
        instance.batching = False
        instance.visit(ast)
        return JsSynthesizer().convert(ast)

    def test_a_substitution_that_clones_a_read_keeps_the_binding_it_was_cloned_from(self):
        """
        Substituting `b` at `b.floor` writes a clone of `a`, the only read that keeps `var a`
        alive once its own read in `var b = a` has folded, so the declarator of `a` must survive
        the round that folded it.
        """
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
        """
        The inner plan's relocation detaches the outer plan's target — the `K` inside the
        initializer — so the outer plan declines and the next round folds the read the relocation
        cloned.
        """
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
        """
        The two rows above are the shapes where the order of plan application matters, and the
        sequential self agrees with the batched run on both.
        """
        rows = AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND
        self.assertEqual(
            {source: self._inline_one_plan_at_a_time(source) for source in rows},
            {source: self._inline(source) for source in rows},
        )

    def test_a_shadowing_declaration_folds_its_outer_name_away_in_the_same_round(self):
        """
        The nested scope substitutes its own `K` in the same round the outer plan substitutes the
        outer `K`, so the outer declarator's liveness can only be judged on the tree the inner plan
        leaves behind.
        """
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
        """
        The same shape with the shadowing declaration one scope further in: the plans of `g`, `f`,
        and the script all apply in one round.
        """
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
        """
        The sequential self decides the outer removal after the nested plans have applied; the
        batched self decides it before and counts at apply time instead, and the two agree.
        """
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


#: A program whose object literal names a property by its shorthand, mapped to the text a correct
#: deobfuscation writes for it. The one identifier of a shorthand is both the name of the property
#: and a read of the binding, so a constant reaches it the way it reaches any other read, and the
#: property still needs a name once the value is there. The last three rows are the controls, each
#: of them a substitution that lands where it belongs: into a key that is spelled out, into the
#: object a destructuring pattern takes apart, and into the default a shorthand in such a pattern
#: carries.
A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY = {
    'var q = 1;\nconsole.log(JSON.stringify({ q }));\n':
        'console.log(JSON.stringify({ q: 1 }));',
    'var q = "a";\nconsole.log(JSON.stringify({ q }));\n':
        'console.log(JSON.stringify({ q: "a" }));',
    'var q = 1;\nvar w = 2;\nconsole.log(JSON.stringify({ q, w }));\n':
        'console.log(JSON.stringify({ q: 1, w: 2 }));',
    'var q = 1;\nvar o = { q, r: 2 };\nconsole.log(JSON.stringify(o));\n':
        'var o = { q: 1, r: 2 };\nconsole.log(JSON.stringify(o));',
    'var q = 1;\nconsole.log(JSON.stringify({ q: q }));\n':
        'console.log(JSON.stringify({ q: 1 }));',
    'var p = 5;\nvar o = { q: p };\nvar { q } = o;\nconsole.log(q);\n':
        'var o = { q: 5 };\nvar { q } = o;\nconsole.log(q);',
    'var d = 5;\nvar o = {};\nvar { q = d } = o;\nconsole.log(q);\n':
        'var o = {};\nvar { q = 5 } = o;\nconsole.log(q);',
}


class TestAConstantSubstitutedIntoAShorthandPropertyKeepsItsName(TestBase):
    """
    `{ q }` means `{ q: q }`, and what parts the two spellings is that the shorthand writes one
    identifier where the other writes two: the name of the property and the read of the binding are
    the same word. Node prints `{"q":1}` for

        var q = 1; console.log(JSON.stringify({ q }));

    and prints `{"q":1}` for `{ q: 1 }` written out in full, which is where the value of that read
    has to go. A property named by nothing is not a property, so the one thing a substitution here
    may not do is put the value where the name stood.

    `refinery.lib.scripts.js.deobfuscation.helpers.substitute_use_position` is where that is
    decided, for this pass and for every other one that puts a value where a name stood: it asks
    `refinery.lib.scripts.js.model.names_a_property` which positions spell a name, and writes a
    shorthand out in full so that only its value half is replaced.

    The entry is stated over the text the tool writes rather than over what running it prints,
    because the corrupt rows are not programs and cannot be run at all: Node answers `SyntaxError`
    for each of them, and answers it just as readily for any other way of breaking a file, so
    running them can say that something is wrong but never which value went where. The controls are
    the second reason. A fix that stopped substituting into an object literal altogether would leave
    every program here printing what it printed before, since refusing to touch a program cannot
    change what it does, and a behavior comparison would then report this entry as an unexpected
    success on the day the defect was covered over instead of fixed.

    Those controls are the last three rows, and each is the text the tool writes today. The first
    takes the same constant into a key that is spelled out and keeps the name beside it. The other
    two are the destructuring pattern, which was measured rather than assumed: a shorthand there
    names the binding the pattern writes and not one it reads, nothing is substituted over it, and a
    constant reaching the same statement lands on the object being taken apart in one row and on the
    default the shorthand carries in the other.
    """

    def test_a_constant_substituted_into_a_shorthand_property_is_written_under_its_name(self):
        """
        Node prints `{"q":1}`, `{"q":"a"}`, `{"q":1,"w":2}`, `{"q":1,"r":2}`, `{"q":1}`, `5` and `5`
        for the seven programs of `A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY`, and prints those same
        seven lines for the seven texts they are mapped to.
        """
        rows = A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY
        self.assertEqual({source: folded(source) for source in rows}, rows)


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


#: A program binding a name to `eval` and calling through it, mapped to the text a correct
#: deobfuscation writes for it under the module reading `before_and_after` takes. Only a call
#: written as the name `eval` is a direct eval, so the one thing substituting the alias's value may
#: not write for such a call is that name in the callee position. The last two rows are the
#: controls: a use no call applies takes the bare name, and a name bound to any other global calls
#: bare as well.
A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL = {
    AN_ALIAS_CALL_READING_A_LOCAL_OF_ITS_CALLER: (
        'function f() {\n'
        '  try {\n'
        "    return (0, eval)('loc');\n"
        '  } catch (e) {\n'
        '    return e.constructor.name;\n'
        '  }\n'
        '}\n'
        'console.log(f());'
    ),
    AN_ALIAS_CALL_UNDER_A_TYPEOF_GUARD: (
        'function f() {\n'
        "  return typeof (0, eval)('typeof loc');\n"
        '}\n'
        'console.log(f());'
    ),
    AN_ALIAS_OF_EVAL_READ_WITHOUT_A_CALL: (
        'function f() {\n'
        '  return typeof eval;\n'
        '}\n'
        'console.log(f());'
    ),
    AN_ALIAS_OF_ANOTHER_GLOBAL_CALLED: (
        'console.log(7);'
    ),
}

#: What Node prints for each program of `A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL` — and for the text
#: it is mapped to, which is the agreement the entry exists for.
WHAT_A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL_PRINTS = {
    AN_ALIAS_CALL_READING_A_LOCAL_OF_ITS_CALLER: 'ReferenceError\n',
    AN_ALIAS_CALL_UNDER_A_TYPEOF_GUARD: 'string\n',
    AN_ALIAS_OF_EVAL_READ_WITHOUT_A_CALL: 'function\n',
    AN_ALIAS_OF_ANOTHER_GLOBAL_CALLED: '7\n',
}


class TestACallThroughANameBoundToEvalStaysIndirect(TestJsDeobfuscator):
    """
    `eval` is the one function the language treats differently depending on how the call was
    written. A call whose callee is the name `eval` runs its text in the calling scope; a call
    reaching the same function any other way runs it in the global scope, where the caller's
    locals are not. `var g = eval; g(s)` is the second kind, so substituting the value of `g` may
    bind the call to any spelling but that name, and
    `refinery.lib.scripts.js.deobfuscation.helpers.substitute_use_position` writes `(0, eval)`
    into a callee position instead — the spelling for the call the alias made, and one
    `test.lib.scripts.js.deobfuscation.test_simplify` pins as a sequence no collapse takes apart.

    The texts are the module reading. The script reading hands the same programs to
    `refinery.lib.scripts.js.deobfuscation.reflection`, which resolves the indirect eval against
    the global scope itself, and the text it writes witnesses that pass instead of this rule.
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
        """
        Node prints `ReferenceError` for the first program of
        `A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL`, whose payload reads a local of the calling
        function, and `string` for the second, where a `typeof` guard makes the same read safe. A
        rewrite binding the call to the name `eval` prints `7` for the first instead.
        """
        rows = WHAT_A_CALL_THROUGH_A_NAME_BOUND_TO_EVAL_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs whose inlining has to survive an edit an earlier plan of the same round makes. The
#: first holds a two-hop intrinsic alias, the second an outer constant's read inside the
#: initializer a nested scope's plan relocates; both hold back one round and the next one folds
#: them.
AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND = {
    'a two-hop intrinsic alias': (
        'var a = Math; var b = a; b.floor = function () { return 1; };'
        ' console.log(String(Math.floor(1.7)));'
    ),
    'a constant read inside a relocated initializer': (
        'const K = 5; function inner() { var t = K + 1; console.log(t); } inner();'
    ),
}

#: Programs where a nested scope declares a name the outer round inlines under, its own
#: substitution and removal landing in the same round as the outer one.
A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE = {
    'a shadowing declaration in a nested scope': (
        'var K = 5; function f() { var K = 9; console.log(K); } f(); console.log(K);'
    ),
    'a shadowing declaration two scopes deep': (
        'var K = 5; function f() { function g() { var K = 9; console.log(K); } g(); }'
        ' f(); console.log(K);'
    ),
}

#: What Node prints for each program of `A_DECLARATION_THAT_SHARES_ITS_ROUND_WITH_A_SHADOWING_ONE`
#: — and for the text it is deobfuscated to, which is the agreement the entry exists for.
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
        """
        Node prints `9` then `5` for both programs — the nested read folds to the shadowing value
        and the outer read to the outer one — and prints the same two lines for the texts they are
        deobfuscated to.
        """
        rows = WHAT_A_DECLARATION_THAT_SHARES_ITS_ROUND_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: What Node prints for each program of `AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_OF_ITS_ROUND`
#: — and for the text it is deobfuscated to, which is the agreement the entry exists for.
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
        """
        Node prints `1` for the two-hop alias program, whose patch of `Math.floor` has to survive
        both rounds, and `6` for the relocated initializer, and prints the same two lines for the
        texts they are deobfuscated to.
        """
        rows = WHAT_AN_INLINE_THAT_HAS_TO_SURVIVE_AN_EARLIER_PLAN_PRINTS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
