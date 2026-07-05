from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationDifferential(TestBase):
    """
    Each case runs a benign snippet and its deobfuscation through Node.js and asserts they behave
    identically. These guard the semantics-preservation invariant against the substrate migration.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_closure_counter(self):
        self._check(
            'function mk(){ var c = 0; return function(){ return ++c; }; }'
            ' var f = mk(); console.log(f(), f(), f());')

    def test_function_and_var_hoisting(self):
        self._check('console.log(g()); function g(){ var r = 41; return r + 1; }')

    def test_dead_variable_and_constant_folding(self):
        self._check('var a = 1 + 2; var unused = 5; console.log(a * 2);')

    def test_constant_not_substituted_into_member_property_name(self):
        """
        The constant `g` appears both as a value (`+ g`, which folds to `5`) and as the property name
        of a non-computed member access (`o.g`). Only the value position is a substitutable use of the
        binding; inlining the constant into the property name would produce `o.5`, a SyntaxError.
        """
        self._check(
            'function f(o){ var g = 5; return o.g + g; } console.log(f({ g: 9 }));')

    def test_with_scoped_throwing_iife_argument_not_dropped(self):
        """
        Inside a `with` body a bare name whose property was deleted throws when read. Passing it as an
        unused IIFE argument must not inline the body and drop the argument, which would discard the
        throwing read: the argument can throw, so it is effectful and the call is left in place.
        """
        self._check(
            'var SINK = [];'
            ' var o = { p0: 1 };'
            " with (o) { delete p0; SINK.push((function(a){ return 'x'; })(p0)); }"
            " console.log(SINK.join('|'));")

    def test_dead_store_overwritten_before_read(self):
        self._check('function f(){ var x = 1; x = 5; return x; } console.log(f());')

    def test_dead_store_effectful_rhs_preserved(self):
        self._check(
            'var log = [];'
            ' function f(){ var x; x = (log.push("a"), 1); x = 2; return x; }'
            ' console.log(f(), log.length);')

    def test_dead_store_in_loop_function(self):
        self._check(
            'function f(n){ var s = 0; s = []; for (var i = 0; i < n; i++) { s.push(i * i); }'
            ' return s.join(","); } console.log(f(4));')

    def test_pseudo_global_localized_into_function(self):
        self._check(
            'var acc, i;'
            ' function build(n){ acc = []; for (i = 1; i <= n; i++) { acc.push(i * i); } return acc; }'
            ' console.log(build(4).join(","));')

    def test_pseudo_global_with_cross_call_state_preserved(self):
        self._check(
            'var n;'
            ' function tick(){ n = (n || 0) + 1; return n; }'
            ' console.log(tick(), tick(), tick());')

    def test_dead_store_removed_with_reflection_outside_its_function(self):
        self._check(
            'function f(){ var x = 1; x = 2; return x; }'
            " var t = eval('6 * 7'); console.log(f(), t);")

    def test_local_read_only_by_in_function_eval_preserved(self):
        self._check(
            'function f(){ var x; x = 41; return eval("x + 1"); } console.log(f());')

    def test_outer_local_read_by_eval_in_nested_function_preserved(self):
        self._check(
            'function f(){ var x; x = 41; function g(){ return eval("x"); } return g(); }'
            ' console.log(f());')

    def test_block_scoped_for_let(self):
        self._check('var out = []; for (let i = 0; i < 3; i++) { out.push(i); }'
                    ' console.log(out.join(","));')

    def test_try_catch_error_name(self):
        self._check('try { null.x; } catch (e) { console.log(e.name, e instanceof TypeError); }')

    def test_iife(self):
        self._check('console.log((function(x){ return x * x; })(7));')

    def test_parameter_shadows_outer(self):
        self._check('var x = 1; function f(x){ return x + 1; } console.log(f(10), x);')

    def test_module_pattern_private_state(self):
        self._check(
            'var C = (function(){ var n = 0; return { inc: function(){ return ++n; } }; })();'
            ' console.log(C.inc(), C.inc());')

    def test_dynamic_eval_reading_global_preserved(self):
        self._check(
            'var data; data = 123;'
            ' var name = String.fromCharCode(100, 97, 116, 97);'
            ' console.log(eval(name));')

    def test_function_called_only_through_eval_preserved(self):
        self._check("function greet(){ return 'hi'; } console.log(eval('greet()'));")

    def test_global_alias_not_collapsed_into_catch_binding(self):
        """
        `globalThis.X` inside a `catch (X)` names the global property, not the caught exception, so
        simplification must keep the alias rather than collapse it to the catch-bound `X`.
        """
        self._check(
            "globalThis.X = 'global';"
            ' function probe(){ try { throw "caught"; } catch (X) { return globalThis.X; } }'
            ' console.log(probe());')

    def test_namespace_flatten_preserves_block_scoped_shadow(self):
        """
        Flattening `NS.x` to a script-level `var x` must respect a `let x` that block-scopes a
        different value: the inner read stays bound to the block's `x`, the outer read to the
        flattened one, so the observed sequence is unchanged.
        """
        self._check(
            'var NS = {}; NS.x = 1; var r = [];'
            ' { let x = 9; r.push(x); } r.push(NS.x); console.log(r.join(","));')

    def test_const_not_inlined_past_inherited_param_shadow(self):
        """
        `B` reads `k` through the parameter of its enclosing `A`, not the outer `const k`. Constant
        inlining must respect that inherited shadow rather than substituting the constant's value, so
        `A(9)` keeps returning the argument.
        """
        self._check(
            'const k = 5; function A(k) { function B() { return k; } return B(); }'
            ' console.log(A(9));')

    def test_dead_const_removed_only_when_truly_unreferenced(self):
        """
        Inside `wrap` the `var x` hoists over `g`'s read, so the outer `const x` is referenced only by
        `f`. Removing `f` and the now-dead `const x` must not disturb `wrap`'s own `x`, so both reads
        keep their values.
        """
        self._check(
            "const x = 'outer';"
            ' const f = () => x;'
            ' function wrap(){ const g = () => x; if (true) { var x = "inner"; } return g(); }'
            ' console.log(f(), wrap());')

    def test_nested_closures_share_binding(self):
        """
        `outer` calls a nested `add` that mutates the captured `s`. A nested call runs in an isolated
        child interpreter with no write-back, so the evaluator refuses to fold `outer` rather than
        dropping the mutation — the call is left for the engine and the behavior ("ab") is preserved.
        """
        self._check(
            'function outer(){ var s = ""; function add(x){ s += x; } add("a"); add("b");'
            ' return s; } console.log(outer());')

    def test_function_constructor_return_this_is_global_object(self):
        """
        `new Function("return this")()` yields the global object (a Function-constructed function is
        sloppy and called with no receiver), so reflection inlining must resolve it to `globalThis`
        rather than the caller's `this`, which under Node is the empty module export object.
        """
        self._check(
            'var g = new Function("return this")();'
            ' console.log(g === globalThis, typeof g.Array);')

    def test_function_constructor_body_var_does_not_capture_caller_scope(self):
        """
        A `Function`-constructed body runs in its own scope, so its `var x` is local to the constructed
        function and never reaches the caller; inlining it must not redeclare the caller's `x`, which
        would change the value observed after the call.
        """
        self._check('var x = 1; new Function("var x = 2;")(); console.log(x);')

    def test_function_constructor_body_lexical_does_not_redeclare_caller_block(self):
        """
        A `let` in a `Function`-constructed body is local to it; inlining it into the caller's block
        where a same-named `let` already lives would be a duplicate-declaration SyntaxError rather than
        the original's two independent bindings.
        """
        self._check(
            '{ let y = 1; new Function("let y = 2; console.log(y);")(); console.log(y); }')

    def test_function_constructor_body_var_does_not_cross_block_let(self):
        """
        A `Function`-constructed body's `var x` is local to the constructed function; a `var` spliced
        into a block that already lexically binds `x` would hoist across that `let`, a redeclaration
        SyntaxError rather than the original's two independent bindings.
        """
        self._check('{ let x = 9; new Function("var x = 2;")(); console.log(x); }')

    def test_function_constructor_in_strict_caller_not_inlined(self):
        """
        A `Function`-constructed body is always sloppy, so its octal literal is legal; splicing the
        body into a strict-mode caller would subject the octal to strict mode, a SyntaxError. The body
        must stay an un-inlined call so the caller's strictness never reaches it.
        """
        self._check('function f(){ "use strict"; return new Function("return 010")(); } console.log(f());')

    def test_dead_pure_call_binding_removal_preserves_behavior(self):
        """
        `tag` is pure and its result is unused, so dropping the dead binding and the now-uncalled `tag`
        changes nothing observable; only the surviving `console.log` is what the run prints.
        """
        self._check(
            'function tag(x){ return "<" + x + ">"; }'
            ' var dead = tag("a");'
            ' console.log("result");')

    def test_constant_if_preserves_effectful_test(self):
        """
        An `if` whose test has statically-known truthiness is pruned to the taken branch, but the
        test still runs for its side effects: `[v6(), false]` is truthy, so the empty branches
        collapse, yet the call `v6()` it evaluates must survive.
        """
        self._check(
            'function v6(){ console.log(-1); }'
            ' if ([v6(), false]) {} else {}')

    def test_unary_minus_preserves_negative_zero(self):
        """
        Negating a value that coerces to zero yields IEEE-754 negative zero, observable as `[ -0 ]`.
        The evaluator must not collapse it to a positive-zero literal when it inlines the function.
        """
        self._check(
            'function f(){ var x = -false; return x; } console.log([f()]);')

    def test_multiplication_preserves_negative_zero(self):
        """
        `0 * -5` is negative zero, so `1 / (0 * -5)` is `-Infinity`. Folding the product must keep
        the sign of the zero rather than collapse it to a positive zero.
        """
        self._check(
            'function f(){ return 0 * -5; } console.log(1 / f());')

    def test_dead_store_effectful_call_keeps_orphan_function(self):
        """
        `leak` mutates the observed `SINK` and is reached only through a dead store, whose removal
        preserves the call as a bare statement. Dropping the now-orphan `leak` and that call would
        discard the push, so the printed `SINK` must still contain it.
        """
        self._check(
            'var SINK = [];'
            ' function leak() { SINK.push("x"); }'
            ' var dead;'
            ' dead = leak();'
            ' console.log(SINK.join(","));')

    def test_relational_comparison_of_non_numeric_strings(self):
        """
        Relational operators ToPrimitive both operands first and compare as strings when both results
        are strings: `[false] <= "op7"` is `"false" <= "op7"` (true), not a numeric `NaN <= NaN`
        (false). Folding the comparison must not numerically coerce an array operand that stringifies.
        """
        self._check('console.log([false] <= ("op" + 7), (["ef", true] >= "cd") + 4);')

    def test_nested_implicit_global_write_read_elsewhere_is_kept(self):
        """
        `v1` calls a nested `v2` that writes the implicit global `v0`, which `v5` later reads. The
        evaluator must not fold `v1()` to its `undefined` result while dropping the nested write, or
        the later read throws instead of seeing 12.
        """
        self._check(
            'var SINK = [];'
            ' function v1() { function v2() { v0 = 12; } return v2(); }'
            ' function v5() { for (let i = 0; i < 1; i++) { SINK.push(v1()); } return v0; }'
            ' SINK.push(v5());'
            ' console.log(SINK.join(","));')

    def test_reassigned_global_not_inlined_as_initial_value(self):
        """
        `v0` starts at 7 but is reassigned to an array before `v3` (which reads `-v0`) ever runs, so
        inlining the initial 7 into `v3` is unsound: the real reads must see the array (`-['ij']` is
        NaN), not -7.
        """
        self._check(
            'var SINK = [];'
            ' var v0 = 7;'
            ' function v3(v4) { return [-5, -v0, ["ij", "gh"]]; }'
            ' function v6() { v0 = ["ij"]; return v3(true ? v0 : v0); }'
            ' SINK.push(v6());'
            ' SINK.push((!v0) === v3(3));'
            ' console.log(SINK.join("|"));')

    def test_escaping_global_temp_write_is_preserved(self):
        """
        The function `dec` writes the implicit global `rr` and returns a constant. Because `rr` is read
        after the call, folding `dec("hi")` to its constant result would drop the write and the later
        read would see `undefined`; the effect model marks the escaping write observable, so the call
        is kept and the read still sees "hi".
        """
        self._check(
            'const dec = function(s){ rr = s; return "x"; };'
            ' var y = dec("hi");'
            ' console.log(y, rr);')

    def test_uninitialized_var_promoted_constant_not_inlined_before_assignment(self):
        """
        `g` reads the outer `x`, which is `undefined` until a later `x = 5`. The first `g()` runs
        before that assignment, so promoting `x` to the constant `5` and inlining it into `g` would
        change the first call's result from `undefined` to `5`. Cross-function inlining must keep the
        value un-inlined where a call can observe it before the assignment establishes it.
        """
        self._check(
            'var SINK = [];'
            ' var x;'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_var_initializer_declared_after_call_not_inlined(self):
        """
        `var x = 5` hoists as `undefined` and is assigned only when its declaration runs, after the
        first `g()`. Inlining the constant into `g` would make the first call return 5 instead of the
        undefined the hoisted-but-unassigned binding holds.
        """
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' var x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_const_declared_after_call_not_inlined_past_tdz(self):
        """
        `g` reads `const x` from the temporal dead zone at the first `g()`, which throws; only after
        the declaration does it read 5. Inlining the constant into `g` would replace the throw with a
        value, so the const must not be substituted into a function a visible call reaches before the
        declaration.
        """
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' try { SINK.push(g()); } catch (e) { SINK.push(e.name); }'
            ' const x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_redeclared_wrapper_is_not_inlined(self):
        """
        The first `v` is a trivial constant wrapper, but `v` is redeclared, so a call runs the second
        body (which pushes to `SINK` and returns 2). Wrapper inlining resolves the call through the
        binding and must refuse to substitute the first body, or the push is dropped and the value is
        wrong.
        """
        self._check(
            'var SINK = [];'
            ' function v(){ return 1; }'
            ' function v(){ SINK.push("x"); return 2; }'
            ' SINK.push(v());'
            " console.log(SINK.join('|'));")

    def test_uninitialized_var_assigned_in_block_not_inlined_before_call(self):
        """
        `x = 5` sits in a nested block, so it does not share a statement list with the first `g()`,
        yet that call still runs before the assignment and reads the hoisted `undefined`. The ordering
        check must compare the call against the value at their common ancestor body, not only within
        the value's own block, or the first call's result changes from `undefined` to `5`.
        """
        self._check(
            'var SINK = [];'
            ' var x;'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' { x = 5; }'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_var_initializer_in_block_not_inlined_before_call(self):
        """
        `var x = 5` is nested in a `try`, so its assignment runs after the first `g()`, which reads the
        hoisted-but-unassigned `x`. Inlining the constant into `g` would make that first call return 5
        instead of `undefined`, so the value nested in the block must still be ordered after the call.
        """
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' try { var x = 5; } catch (e) {}'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_array_index_not_inlined_before_assignment(self):
        """
        `A` holds its array only after the first `read()`, so `A[0]` is an access on `undefined` at
        that call — a TypeError. Inlining the element into `read` would replace the throw with 1, so
        the index access must not be substituted where a call observes it before the array is set.
        """
        self._check(
            'var SINK = [];'
            ' var A;'
            ' function read(){ return A[0]; }'
            ' try { SINK.push(read()); } catch (e) { SINK.push(e.name); }'
            ' A = [1, 2, 3];'
            ' SINK.push(read());'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_escaping_function_before_value(self):
        """
        `g` escapes — it is passed to `forEach`, not called directly — so it can run before `const x`
        is established. That invocation is not among g's resolvable direct call sites, so the ordering
        check cannot see it; the const must not be inlined into g, or the temporal-dead-zone throw at
        the first call becomes the value 5.
        """
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' try { [g].forEach(function(h){ SINK.push(h()); }); } catch (e) { SINK.push(e.name); }'
            ' const x = 5;'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_aliased_function_before_value(self):
        """
        `g` is aliased to `p` and called through the alias before `const x` exists, so that call is not
        among g's resolvable direct call sites. Inlining the const into g would turn the alias call's
        temporal-dead-zone throw into a value.
        """
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' var p = g;'
            ' try { SINK.push(p()); } catch (e) { SINK.push(e.name); }'
            ' const x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_wrapper_referenced_only_inside_surviving_wrapper_is_kept(self):
        """
        `u` is a wrapper called only from inside `v`, which survives un-inlined (its call is
        arity-mismatched). After `c` inlines and triggers wrapper removal, `u` must be kept — removing
        it would leave `v`'s body calling a missing function. The keep-set is grown to a fixpoint so a
        wrapper reached only through another surviving wrapper is retained.
        """
        self._check(
            'var SINK = [];'
            ' function ext(z){ SINK.push("e"); return z; }'
            ' function u(x){ return ext(x); }'
            ' function v(x){ return u(x, x); }'
            ' SINK.push(v(3, 4));'
            ' function c(){ return 0; }'
            ' SINK.push(c());'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_own_function_before_declaration(self):
        """
        `f` reads `c` in its own body before the `const c` declaration runs — the temporal dead zone,
        which throws. The cross-function pass walks the whole subtree, including `f`'s own body, but a
        reference in the declaring function itself belongs to the domination-aware in-scope pass;
        inlining it here would replace the dead-zone throw with the value.
        """
        self._check(
            'var SINK = [];'
            ' function f(){ try { SINK.push(c); } catch (e) { SINK.push(e.name); } const c = 5;'
            ' SINK.push(c); }'
            ' f();'
            " console.log(SINK.join('|'));")

    def test_uninitialized_var_not_inlined_into_own_function_before_assignment(self):
        """
        `f` reads its hoisted `var x` before the assignment runs, so the read sees `undefined`.
        Inlining the eventual constant into that same-function read would change the first push from
        `undefined` to the value.
        """
        self._check(
            'var SINK = [];'
            ' function f(){ SINK.push(x); var x; x = 5; SINK.push(x); }'
            ' f();'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_same_named_free_reference(self):
        """
        `read` returns a free `secret` that resolves to no local binding (a reference error), while
        the only `secret` is a block-scoped `const` invisible to `read`. Inlining by name alone would
        turn the reference error into the const's value; the inline must require the reference to
        resolve to the candidate binding.
        """
        self._check(
            'var SINK = [];'
            ' { const secret = "X"; SINK.push(secret); }'
            ' function read(){ try { return secret; } catch (e) { return e.name; } }'
            ' SINK.push(read());'
            " console.log(SINK.join('|'));")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationWithScope(TestBase):
    """
    Semantics preservation for a read that resolves through a `with` body's dynamic scope. A bare name
    inside a `with` body is resolved against the `with` object first, so reading it is not a pure,
    droppable, or reorderable operand: a matching property fires the object's getter — an observable
    side effect — a deleted or absent one falls through to a lexical binding or, failing that, throws a
    `ReferenceError`, and the reference keeps its lexical target alive. Each case is a regression the
    deobfuscator once mishandled by treating such a read as a pure operand or an absent use; the Node
    oracle confirms the observable behavior is unchanged.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_with_scoped_getter_read_in_sequence_not_dropped(self):
        """
        Reading the bare name `x` inside `with (o)` fires `o`'s getter for `x` before the lexical
        `var x` is consulted. Folding the sequence `(x, 'y')` to its last value would drop the read and
        skip the getter, so the sequence must be kept.
        """
        self._check(
            'var SINK = [];'
            ' var x = 1;'
            " var o = { get x() { SINK.push('g'); return 2; } };"
            " with (o) { SINK.push((x, 'y')); }"
            " console.log(SINK.join('|'));")

    def test_with_scoped_getter_read_as_iife_argument_not_dropped(self):
        """
        The bare read `x` inside `with (o)` fires `o`'s getter; passed as an unused IIFE argument it
        must not be inlined away, which would drop the argument and skip the getter.
        """
        self._check(
            'var SINK = [];'
            ' var x = 1;'
            " var o = { get x() { SINK.push('g'); return 2; } };"
            " with (o) { SINK.push((function(a){ return 'y'; })(x)); }"
            " console.log(SINK.join('|'));")

    def test_with_scoped_getter_read_in_pruned_if_test_not_dropped(self):
        """
        Reading the bare name `x` inside `with (o)` fires `o`'s getter. The `if ([x])` test is statically
        truthy, so the branch is taken and the array test discarded — but discarding it must not skip the
        getter, so the test is kept as an expression statement rather than dropped.
        """
        self._check(
            'var SINK = [];'
            ' var x = 1;'
            " var o = { get x() { SINK.push('g'); return 2; } };"
            " with (o) { if ([x]) SINK.push('t'); }"
            " console.log(SINK.join('|'));")

    def test_with_scoped_throwing_operand_not_dropped(self):
        """
        Inside a `with` body a bare name resolves through the dynamic scope, so reading one whose
        property was just deleted throws a `ReferenceError`. Folding the sequence `(p0, 'x')` to its
        last value drops the `p0` read, discarding that throw — the deobfuscator treats a dynamic-scope
        operand as a pure, droppable read when it can in fact throw.
        """
        self._check(
            'var SINK = [];'
            ' var o = { p0: 1 };'
            " with (o) { delete p0; SINK.push((p0, 'x')); }"
            " console.log(SINK.join('|'));")

    def test_function_called_only_in_with_body_not_removed(self):
        """
        `f` is called directly (foldable to its constant result) and also by bare name inside a `with`
        body, where the call resolves to the lexical `f` because the object lacks the property. After
        folding the direct call, unused-removal drops `f` — ignoring the `with`-body dynamic reference
        — so the surviving dynamic call throws a `ReferenceError`. A dead local in `f` is what routes it
        through this fold-then-remove path.
        """
        self._check(
            'var SINK = [];'
            " function f() { var dead = 1; return 'z'; }"
            ' var o = { p0: f() };'
            ' with (o) { SINK.push(f()); }'
            " console.log(SINK.join('|'));")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationModuleScope(TestBase):
    """
    Semantics preservation for the module execution model. The oracle runs each snippet as a CommonJS
    module (`node <file>`), so a scope-sensitive snippet is deobfuscated with `module=True` to match.
    """

    def _check(self, source: str, *, module: bool = False):
        deobfuscated = deobfuscate_source(source, module=module)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_indirect_eval_global_declaration_preserved_in_module_scope(self):
        """
        Indirect eval runs its code in the global scope, so `(0, eval)("var g = 7;")` creates a global
        that `globalThis.g` reads back as `7`. Rewriting it into a bare top-level `var g = 7;` is
        faithful only under the script model; under the module model the oracle runs, a top-level `var`
        is scoped to the module and never reaches the global object. Deobfuscated in module mode, the
        inliner declines the rewrite (leaving the reflective call intact) so the observable output is
        preserved.
        """
        self._check(
            'var SINK = [];'
            ' (0, eval)("var g = 7;");'
            ' SINK.push(globalThis.g);'
            " console.log(SINK.join('|'));",
            module=True)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationExpressionOpenBugs(TestBase):
    """
    Known-open soundness bugs the interpreter/expression fuzzer grammar surfaced, captured as expected
    failures pending the same batched fix session as the other open-bug classes. No deobfuscator change
    accompanies these tests; a fix turns the matching test into an unexpected success.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_math_sign_of_nan_folds_to_nan_not_zero(self):
        """
        `Math.sign(NaN)` is `NaN`, but the constant folder computes the sign as a difference of
        comparisons (`(x > 0) - (x < 0)`), which is `0` for a `NaN` argument. Folding `Math.sign('ab')`
        must yield `NaN`, not `0`.
        """
        self._check(
            'var SINK = [];'
            " SINK.push(Math.sign('ab'));"
            " console.log(SINK.join('|'));")

    def test_delete_parameter_not_substituted_when_inlined(self):
        """
        `delete p` for a parameter `p` returns false — a binding is not a deletable reference — but
        inlining the function substitutes `p` with its argument, turning `delete p` into `delete
        <literal>`, which returns true. The `instanceof` keeps the disjunction from being simplified
        away, so the inliner takes the parameter-substitution path and the observed value flips from
        false to true. A parameter that is the operand of `delete` must not be inlined.
        """
        self._check(
            'var SINK = [];'
            ' function f(p) { return ((p instanceof Array) || (delete p)); }'
            " SINK.push(f('ef'));"
            " console.log(SINK.join('|'));")

    def test_typeof_of_unfoldable_builtin_not_folded_to_undefined(self):
        """
        `Math.max('mn', 4)` is `NaN`, so `typeof` of it is `'number'`. While inlining a function the
        interpreter cannot fold `Math.max` on a non-numeric argument and yields a couldn't-fold
        sentinel; `typeof` of that sentinel is wrongly folded to `'undefined'` rather than left
        unevaluated. The same shape at the top level is not folded and stays `'number'`.
        """
        self._check(
            'var SINK = [];'
            " function m0() { return (typeof Math.max('mn', 4)); }"
            ' SINK.push(m0());'
            " console.log(SINK.join('|'));")

    def test_function_local_not_dropped_when_body_is_inlined(self):
        """
        `g` returns `x[0] instanceof Object`, an expression over its own local `x`. Because `instanceof`
        cannot be folded, the inliner substitutes the body into the caller — but drops the `var x`
        declaration, so the substituted `x` is a dangling reference that throws. Inlining a body that
        reads a function-local must not discard that local's declaration. (`return x[0]` folds to the
        value and is unaffected; the unfoldable operator is what forces textual substitution.)
        """
        self._check(
            'var SINK = [];'
            ' function g() { var x = [5]; return (x[0] instanceof Object); }'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_assignment_target_parameter_not_substituted_when_inlined(self):
        """
        The same inliner fragility as the `delete` case, in an assignment target: `(p = 5)` assigns the
        parameter `p`, but inlining substitutes `p` with its argument, producing `(3 = 5)` — an invalid
        assignment target, a SyntaxError. The `instanceof` keeps the expression from being simplified so
        the parameter-substitution path is taken. A parameter used as an assignment target must not be
        inlined.
        """
        self._check(
            'var SINK = [];'
            ' function f(p) { return ((p = 5) instanceof Object); }'
            ' SINK.push(f(3));'
            " console.log(SINK.join('|'));")

    def test_math_round_of_negative_zero_preserves_sign(self):
        """
        `Math.round(-0)` and `Math.floor(-0)` are `-0`, observable as `1 / -0 === -Infinity`. The
        constant folder rounds through an integer conversion that yields `+0`, dropping the sign, so
        `1 / Math.round(-0)` folds to `Infinity`. `Math.max`/`min`/`abs` keep the sign correctly;
        rounding a negative zero must too.
        """
        self._check(
            'var SINK = [];'
            ' SINK.push(1 / Math.round(-0));'
            " console.log(SINK.join('|'));")
