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
