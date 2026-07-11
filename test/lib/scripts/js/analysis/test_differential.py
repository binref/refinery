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

    def test_dead_global_read_with_installed_getter_preserved(self):
        """
        Installing an accessor with `Object.defineProperty` makes the global no longer pristine, so a
        read of a trusted data-property name may now run that getter. An unused read of it must be kept,
        or the getter's observable push is dropped.
        """
        self._check(
            'var SINK = [];'
            " Object.defineProperty(globalThis, 'TextDecoder',"
            " { configurable: true, get: function () { SINK.push('read'); return 1; } });"
            ' var dead = globalThis.TextDecoder;'
            " console.log(SINK.join('|'));")

    def test_dead_global_alias_read_with_installed_getter_preserved(self):
        """
        The read is through a local global-object alias, but an accessor installed with
        `Object.defineProperty` makes the global no longer pristine, so the alias read is no longer
        trusted as getter-free and the unused binding is kept, preserving the getter's observable push.
        """
        self._check(
            'var SINK = [];'
            " Object.defineProperty(globalThis, 'TextDecoder',"
            " { configurable: true, get: function () { SINK.push('read'); return 1; } });"
            ' var g = globalThis || {};'
            ' var dead = g.TextDecoder;'
            " console.log(SINK.join('|'));")

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

    def test_indirect_eval_block_hoisted_var_creates_observable_global(self):
        """
        The `var g` inside the block of the indirect-eval body hoists to the eval's global scope, so
        calling `f` creates a global `g` observable afterwards. Inlining the call into `f` would hoist
        `g` into the function and leave the global undefined, so the call must be kept.
        """
        self._check(
            "function f(){ (0, eval)('{ var g = 1; }'); }"
            ' f();'
            ' console.log(typeof g);')

    def test_indirect_eval_implicit_global_write_not_captured_by_local(self):
        """
        The unqualified `g = 5` in the indirect-eval body runs in the global scope, writing the global
        `g` rather than the function-local `g`. Inlining the call into `f` would capture the write with
        the local, so the call must be kept: `f` returns the untouched local and the global is set.
        """
        self._check(
            "function f(){ var g; (0, eval)('g = 5;'); return g; }"
            ' console.log(f(), typeof g);')

    def test_objectfold_parenthesized_function_value_folds_soundly(self):
        """
        A parenthesized function property value folds the same as the bare form: the immediately-called
        read inlines to its body while the identity-compared read is preserved as a distinct function,
        both without changing observable behavior.
        """
        self._check(
            'var o = { f: (function(a){ return a + 1; }) };'
            ' console.log(o.f(2), o.f === o.f);')

    def test_function_constructor_this_resolves_to_global_object(self):
        """
        A `Function`-constructed function invoked with no receiver has `this` bound to the global
        object, so `this.marker` reads the global set beforehand. Rewriting it to `globalThis.marker`
        when inlining must read the same global.
        """
        self._check(
            "globalThis.marker = 'G';"
            " var out = new Function('return this.marker')();"
            ' console.log(out);')

    def test_sequence_callee_preserves_indirect_this_binding(self):
        """
        `(0, o.m)()` calls `o.m` with no receiver, so `this` is not `o`. Collapsing the callee sequence
        to `o.m()` would bind `this` to `o`, changing the result, so the sequence must be kept.
        """
        self._check(
            "var o = { tag: 'self', m: function(){ return this === o ? this.tag : 'detached'; } };"
            ' console.log((0, o.m)());')

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

    def test_const_not_inlined_into_function_reachable_only_through_eval(self):
        """
        `probe` has no static reference — it is invoked only through the opaque `eval`, which runs it
        while `const c` is still in its temporal dead zone — so inlining `c`'s value into the body would
        replace the original `ReferenceError` with a silent read.
        """
        self._check(
            'function probe(){ return c; }'
            ' var call = String.fromCharCode(112, 114, 111, 98, 101, 40, 41);'
            ' eval(call); const c = 5;')

    def test_global_alias_not_collapsed_into_catch_binding(self):
        """
        `globalThis.X` inside a `catch (X)` names the global property, not the caught exception, so
        simplification must keep the alias rather than collapse it to the catch-bound `X`.
        """
        self._check(
            "globalThis.X = 'global';"
            ' function probe(){ try { throw "caught"; } catch (X) { return globalThis.X; } }'
            ' console.log(probe());')

    def test_free_global_alias_member_read_preserved(self):
        """
        `globalThis.X` for a free `X` yields `undefined`; collapsing it to a bare `X` would throw a
        ReferenceError, so the member read must be preserved.
        """
        self._check('console.log(globalThis.notDeclaredAnywhere);')

    def test_non_universal_global_alias_member_read_preserved(self):
        """
        `execScript` exists in no mainstream host: `globalThis.execScript` is `undefined` while a bare
        read throws, so a spec-existence tier that wrongly admitted it would diverge here.
        """
        self._check('console.log(globalThis.execScript);')

    def test_shadowed_alias_base_member_read_preserved(self):
        """
        `self` is a parameter holding an ordinary object, not the global object, so `self.Array` reads
        that object's property; collapsing it to the global `Array` would corrupt the value.
        """
        self._check('console.log((function (self) { return self.Array; })({ Array: 7 }));')

    def test_implicit_global_alias_read_before_write_preserved(self):
        """
        `globalThis.X` is read before the write that makes `X` an implicit global, so it is `undefined`;
        collapsing to a bare `X` read there would throw before the assignment runs.
        """
        self._check(
            'function f(v) { return v; } var y = f(globalThis.X); X = 5; console.log(y, X);')

    def test_namespace_flatten_preserves_block_scoped_shadow(self):
        """
        Flattening `NS.x` to a script-level `var x` must respect a `let x` that block-scopes a
        different value: the inner read stays bound to the block's `x`, the outer read to the
        flattened one, so the observed sequence is unchanged.
        """
        self._check(
            'var NS = {}; NS.x = 1; var r = [];'
            ' { let x = 9; r.push(x); } r.push(NS.x); console.log(r.join(","));')

    def test_namespace_function_not_hoisted_before_early_read(self):
        """
        `early()` runs before `NS.greet` is assigned, so `NS.greet` is `undefined` there. Flattening
        the assignment to a hoisted `function greet(){}` would make the early call see the function;
        the assignment must stay in place so the early read still observes `undefined`.
        """
        self._check(
            'var NS = {};'
            ' function early() { return NS.greet; }'
            ' var probe = early();'
            ' NS.greet = function () { return 42; };'
            ' console.log(typeof probe, typeof early());')

    def test_namespace_object_init_not_hoisted_before_early_read(self):
        self._check(
            'var NS = {};'
            ' function early() { return NS.config; }'
            ' var before = early();'
            ' NS.config = {};'
            ' console.log(typeof before, typeof early());')

    def test_namespace_named_function_expression_keeps_inner_name(self):
        """
        Flattening `NS.factorial` must not rebuild it as `function factorial(){}` — that would drop the
        expression's own name `fact`, leaving the recursive call unbound.
        """
        self._check(
            'var NS = {};'
            ' NS.factorial = function fact(n) { return n <= 1 ? 1 : n * fact(n - 1); };'
            ' console.log(NS.factorial(5));')

    def test_namespace_deleted_property_not_flattened(self):
        self._check(
            'var NS = {};'
            ' NS.flag = 1;'
            ' delete NS.flag;'
            ' console.log(NS.flag);')

    def test_argwrap_non_statement_call_preserves_evaluation_order(self):
        """
        `f()` is evaluated before the wrapper call's argument in the original; lowering the call to a
        comma sequence in place keeps that order, where hoisting the argument ahead of the statement
        would run it first.
        """
        self._check(
            'function W() { W = function () {}; }'
            ' var log = [];'
            ' function f() { log.push("f"); return 0; }'
            ' function a() { log.push("a"); return 0; }'
            ' var x = f() + W(a());'
            ' console.log(log.join(","), x);')

    def test_argwrap_non_statement_call_preserves_short_circuit(self):
        self._check(
            'function W() { W = function () {}; }'
            ' var log = [];'
            ' function a() { log.push("a"); return 0; }'
            ' var y = false && W(a());'
            ' console.log(log.join(","), y);')

    def test_argwrap_second_declarator_not_reordered(self):
        self._check(
            'function W() { W = function () {}; }'
            ' var log = [];'
            ' function g() { log.push("g"); return 1; }'
            ' function a() { log.push("a"); return 2; }'
            ' var p = g(), y = W(a());'
            ' console.log(log.join(","), p, y);')

    def test_argwrap_spread_argument_call_left_intact(self):
        self._check(
            'function W() { W = function () {}; }'
            ' var arr = [1, 2];'
            ' var y = W(...arr);'
            ' console.log(typeof y);')

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

    def test_call_mutating_container_before_reassignment_not_inlined(self):
        """
        `bump(o)` runs the original body, which sets `o.v` to 9, before `bump` is reassigned; judging `o`
        immutable and inlining `o.v` as its initial 1 drops the mutation.
        """
        self._check(
            'var o = { v: 1 };'
            ' function bump(x) { x.v = 9; }'
            ' bump(o);'
            ' bump = function(x) {};'
            ' console.log(o.v);')

    def test_call_before_function_reassignment_keeps_side_effect(self):
        """
        `v0(true)` runs the original side-effecting body before the reassignment; resolving `v0` to the
        later empty function and dropping the call as pure would lose the `SINK.push`. The unused `v6` is
        the dead binding that lets the removal pass reach the call.
        """
        self._check(
            'var SINK = [];'
            ' function v0(v1) { SINK.push(v1); }'
            ' v0(true);'
            ' function v6() {}'
            ' v0 = function(){};'
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

    def test_reflection_alias_eval_shadowed_base_not_inlined(self):
        """
        `window` is a parameter holding an ordinary object, so `window.eval` is that object's method,
        not the global eval; inlining its string argument would discard the real call and yield the
        evaluated code instead of the method's result.
        """
        self._check(
            'function f(window){ return window.eval("1"); }'
            ' console.log(f({ eval: function(){ return 99; } }));')

    def test_reflection_alias_timer_shadowed_base_not_lowered(self):
        """
        A local `window`'s `setTimeout` receives the code as a string; lowering it to a function wrapper
        would hand the local method a function instead, changing what it observes.
        """
        self._check(
            'function f(window){ window.setTimeout("console.log(0)", 0); }'
            ' f({ setTimeout: function(c){ console.log(typeof c); } });')

    def test_reflection_computed_alias_eval_inlined(self):
        """
        `globalThis['eval']("1")` reaches the same intrinsic as `globalThis.eval("1")`, so the computed
        alias member is inlined identically without changing behavior.
        """
        self._check('console.log(globalThis["eval"]("1"));')

    def test_reflection_bare_eval_shadowed_not_inlined(self):
        """
        `eval` is a parameter holding a plain function, so `eval("1")` calls it and returns 99; inlining
        the string as direct eval would yield 1 instead.
        """
        self._check(
            'function f(eval){ return eval("1"); }'
            ' console.log(f(function(){ return 99; }));')

    def test_reflection_sequence_eval_shadowed_not_inlined(self):
        """
        `(0, eval)` yields the local parameter `eval`, not the global; its call returns 99, where
        inlining the indirect eval would return 1.
        """
        self._check(
            'function f(eval){ return (0, eval)("1"); }'
            ' console.log(f(function(){ return 99; }));')

    def test_reflection_bare_timer_shadowed_not_lowered(self):
        """
        A local `setTimeout` receives its code as a string; lowering it to a function wrapper would hand
        the local a function argument instead, changing what it observes.
        """
        self._check(
            'function f(setTimeout){ setTimeout("console.log(0)", 0); }'
            ' f(function(c){ console.log(typeof c); });')

    def test_reflection_function_constructor_shadowed_not_inlined(self):
        """
        `Function` is a local parameter, so `Function("return 1")()` calls it and returns 99; treating it
        as the global constructor would inline the body and yield 1.
        """
        self._check(
            'function f(Function){ return Function("return 1")(); }'
            ' console.log(f(function(){ return function(){ return 99; }; }));')

    def test_private_class_fields_and_methods(self):
        """
        A class using private fields, a private method, a static private field, and the `#x in o`
        brand check must round-trip through parse/deob/synth with identical observable behavior.
        """
        self._check(
            'class A {'
            ' static #count = 0;'
            ' #x = 0;'
            ' constructor() { A.#count++; }'
            ' inc() { return ++this.#x; }'
            ' has(o) { return #x in o; }'
            ' static total() { return A.#count; }'
            ' }'
            ' var a = new A();'
            ' console.log(a.inc(), a.inc(), a.has(a), a.has({}), A.total());')

    def test_static_block_runs_at_class_definition(self):
        """
        A static block runs once, when the class is defined, and can read and write the class's private
        state; its observable effects must survive parse/deob/synth.
        """
        self._check(
            'var log = [];'
            ' class C { static #n = 0; static { log.push("sb"); C.#n = 7; } static n() { return C.#n; } }'
            ' console.log(log.join(","), C.n());')

    def test_static_block_var_does_not_leak_to_enclosing_function(self):
        """
        A `var` declared inside a static block is scoped to that block, not the enclosing function, so
        the function's own same-named binding is unaffected — no pass may conflate the two.
        """
        self._check(
            'function f() { var x = "outer"; class C { static { var x = "inner"; } } return x; }'
            ' console.log(f());')

    def test_dynamic_import_of_data_url(self):
        self._check(
            "import('data:text/javascript,export const v = 5').then(m => console.log(m.v));")

    def test_dynamic_import_side_effect_preserved(self):
        """
        import() runs the imported module's top-level code, so an unused dynamic import must not be
        dropped as if it were pure — its observable side effect has to survive.
        """
        self._check(
            "import('data:text/javascript,globalThis.SIDE = 9')"
            '.then(() => console.log(globalThis.SIDE));')

    def test_global_read_by_dynamic_import_kept_alive(self):
        """
        The imported module reads a global assigned before the import, so a dead-global pass must keep
        that write while a dynamic import (a reflective surface) is present.
        """
        self._check(
            'globalThis.CFG = 3;'
            " import('data:text/javascript,console.log(globalThis.CFG)').then(() => {});")

    def test_yield_as_identifier_multiplied_in_sloppy_function(self):
        """
        Outside a generator, `yield` is an ordinary identifier, so `yield * 2` is a multiplication, not
        a delegating yield — the parser must not reinterpret it.
        """
        self._check('function h(){ var yield = 3; return yield * 2; } console.log(h());')

    def test_await_as_identifier_at_top_level(self):
        self._check('var await = 5; function f(){ return await + 1; } console.log(f(), await);')

    def test_async_arrow_await_operator_preserved(self):
        self._check(
            'var f = async () => await Promise.resolve(7); f().then(v => console.log(v));')

    def test_generator_yield_and_delegate_preserved(self):
        self._check(
            'function* g(){ yield 1; yield* [2, 3]; } console.log([...g()].join(","));')


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

    def test_with_scoped_indirect_eval_prefix_read_not_dropped(self):
        """
        The bare name `e` in the comma-sequence prefix of `(e, eval)(...)` inside `with (o)` fires `o`'s
        getter before `eval` resolves. Inlining the indirect eval drops the prefix and skips the getter,
        so the site must be kept.
        """
        self._check(
            'var SINK = [];'
            ' var e = 0;'
            " var o = { get e() { SINK.push('g'); return 0; } };"
            ' with (o) { (e, eval)("1"); }'
            " console.log(SINK.join('|'));")

    def test_with_scoped_constructor_chain_base_read_not_dropped(self):
        """
        The bare base `s` of `s.constructor.constructor(...)()` inside `with (o)` fires `o`'s getter
        before the chain resolves to `Function`. Inlining the chain drops the base read and skips the
        getter, so the site must be kept.
        """
        self._check(
            'var SINK = [];'
            " var s = '';"
            " var o = { get s() { SINK.push('g'); return ''; } };"
            ' with (o) { s.constructor.constructor("return 1")(); }'
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

    def test_with_scoped_alias_eval_member_not_inlined(self):
        """
        Inside `with (o)` the base `window` resolves against `o` first, so `window.eval` need not be the
        global eval; `o.window` supplies a custom `eval`, so inlining the member's argument would drop
        that dynamic resolution and return the evaluated code instead of the custom method's result.
        """
        self._check(
            'var o = { window: { eval: function(){ return 99; } } };'
            ' var r;'
            ' with (o) { r = window.eval("1"); }'
            ' console.log(r);')

    def test_with_scoped_bare_eval_not_inlined(self):
        """
        Inside `with (o)` a bare `eval` resolves against `o` first, so it need not be the global eval;
        `o.eval` supplies a custom function, so inlining the call as direct eval would drop that dynamic
        resolution and return the evaluated code instead of the custom function's result.
        """
        self._check(
            'var o = { eval: function(){ return 99; } };'
            ' var r;'
            ' with (o) { r = eval("1"); }'
            ' console.log(r);')


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
class TestDeobfuscationExpressionRegressions(TestBase):
    """
    Interpreter and constant-folding cases the expression fuzzer grammar surfaced, each of which once
    changed observable behavior and is now fixed; they guard against a regression.
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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationReflectionScope(TestBase):
    """
    Reflected code — indirect `eval`, a string timer, a `Function`-constructor chain — runs in the
    global sloppy scope, and every inlining path holds it to that scope through the shared
    `_resolve_reflected_body` gate: a free name is inlined only when it still denotes the same global at
    the call site, a receiver `this` is rewritten to `globalThis`, a transient lexical declaration is
    declined, an expression-position IIFE/eval value is never fabricated, and a body is not inlined into
    a `with`. Each case changed observable behavior before the gate was unified; they guard the fix.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_indirect_eval_lexical_declaration_is_transient(self):
        """
        An indirect `eval` runs in the global scope, but a top-level `let`/`const`/`class` in its code
        is instantiated in a fresh declarative environment discarded when `eval` returns — so
        `(0, eval)('let g = 1;')` leaves no `g` afterward and `typeof g` is `'undefined'`. Inlining the
        declaration as a persistent top-level `let g = 1;` makes it `'number'`. Only a `var`/function
        declaration reaches the global object and may be inlined at global script scope; a lexical one
        must be declined.
        """
        self._check(
            "(0, eval)('let g = 1;');"
            ' console.log(typeof g);')

    def test_indirect_eval_in_expression_position_not_scope_checked(self):
        """
        An indirect `eval` in expression position is inlined with none of the global-scope safety
        checks the statement path and the `Function`-constructor path apply. Here `(0, eval)('g = 7')`
        runs in the global scope and writes the global `g`, leaving the function-local `g` at `0`;
        inlining it to `var x = (g = 7)` writes the local instead, so `f()` changes from `'0|7'` to
        `'7|7'`.
        """
        self._check(
            "function f() { var g = 0; var x = (0, eval)('g = 7'); return g + '|' + x; }"
            ' console.log(f());')

    def test_indirect_eval_free_name_recaptured_by_local(self):
        """
        An indirect `eval` reads its free names in the global scope, so `(0, eval)('g')` reads the
        global `g` (`1`); inlining `return g` into `f`, whose local `g` is `100`, recaptures the name
        and returns `100`. The eval/timer inlining path checks only the names the body binds, not the
        names it reads, so a free read that resolves to a shadowing local at the inline site is dropped
        in.
        """
        self._check(
            'globalThis.g = 1;'
            " function f() { var g = 100; return (0, eval)('g'); }"
            ' console.log(f());')

    def test_indirect_eval_this_rebinds_to_receiver(self):
        """
        An indirect `eval` body's `this` is the global object, so `(0, eval)('this.tag')` reads the
        global `tag`. Inlining `return this.tag` into the method `o.f` would rebind `this` to `o`,
        changing `'global'` to `'obj'`. The gate rewrites such a `this` to `globalThis` before inlining,
        so the global `tag` is still read.
        """
        self._check(
            "globalThis.tag = 'global';"
            " var o = { tag: 'obj', f: function() { return (0, eval)('this.tag'); } };"
            ' console.log(o.f());')

    def test_constructor_iife_without_return_yields_undefined(self):
        """
        A `Function`-constructed IIFE whose body is a bare expression runs it for effect and returns
        `undefined`; `Function("x")()` is not `x`. Inlining it in expression position must not lift the
        expression as the value, so `var y = Function("x")()` is left intact and `y` stays `undefined`.
        """
        self._check(
            'globalThis.x = 5;'
            ' var y = Function("x")();'
            ' console.log(typeof y);')

    def test_indirect_eval_top_level_return_is_a_syntax_error(self):
        """
        A `return` at the top level of evaluated code is a SyntaxError, so `(0, eval)("return 1")`
        throws; inlining it as the value `1` would turn the throw into a number. The body is left intact
        so the error is preserved.
        """
        self._check(
            'var y = (0, eval)("return 1");'
            ' console.log(y);')

    def test_indirect_eval_free_name_not_inlined_into_with_body(self):
        """
        An indirect `eval` resolves its free names in the global scope, but a `with` on the path to the
        call site binds them dynamically. Inlining `foo()` from `(0, eval)('foo()')` into a `with (obj)`
        body would call `obj.foo` when the object has that property; the body is left intact so the
        global `foo` runs.
        """
        self._check(
            'var out = [];'
            " globalThis.foo = function(){ out.push('global'); };"
            " var obj = { foo: function(){ out.push('obj'); } };"
            ' function f(){ with (obj) { (0, eval)("foo()"); } }'
            " f(); console.log(out.join('|'));")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationInlinerScope(TestBase):
    """
    When a folded call leaves an irreducible body expression, the evaluator splices it into the call
    site. The substitution-safety gate resolves every spliced reference at the call site: a name that
    binds outside the inlined function, or to no binding at all, is inlined only when it still resolves
    to the same declaration there, so a same-named local at the call site that would recapture it
    declines the substitution. Both cases changed observable behavior before the gate consulted the
    call-site scope; they guard the fix.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_substitution_recaptures_outer_binding_shadowed_at_call_site(self):
        """
        Folding `f(5)` substitutes the irreducible body expression `g` into the call site inside
        `caller`. `g` resolves to the outer `g` (`1`) in `f`'s scope, but `caller` has a local `g` of
        `100` that would recapture the spliced name, changing `caller()` from `1` to `100`. Resolving
        `g` at the call site sees the shadowing local and declines the substitution.
        """
        self._check(
            'var g = 1;'
            ' function f(n) { switch (n) { case 5: return g; } }'
            ' function caller() { var g = 100; return f(5); }'
            ' console.log(caller());')

    def test_substitution_recaptures_free_name_shadowed_at_call_site(self):
        """
        `f`'s body reads `externalThing`, a name it never binds, so in `f` it is a free global whose read
        throws when it is undeclared. Folding `f(5)` would splice `externalThing` into `caller`, whose
        local `externalThing` of `100` recaptures it — turning the throw into `100`. A free name is
        treated like an outer binding: it is inlined only when the call site resolves it the same way, so
        the shadowing local declines it.
        """
        self._check(
            'function f(n) { switch (n) { case 5: return externalThing; } }'
            ' function caller() { var externalThing = 100; return f(5); }'
            ' console.log(caller());')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationDirectEvalScope(TestBase):
    """
    A direct `eval` runs in the caller's scope, so its references and `this` inline unchanged, but only a
    sloppy `var` or function actually declares in the caller: a top-level `let`/`const`/`class`, and a
    `var` under strict mode, live in the eval's own environment and leave nothing behind, while a `var`
    that does persist is inlined only where the eval site dominates every reference to the name —
    hoisting it past an earlier reference would rebind that reference. Each case changed observable
    behavior before the gate modeled direct-eval declaration scope; they guard the fix.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_direct_eval_lexical_declaration_is_transient(self):
        """
        A direct `eval`'s top-level `let` lives in the eval's own environment, discarded when it returns,
        so `eval("let x = 1;")` leaves no `x` and `typeof x` is `'undefined'`. Inlining it as a
        persistent `let x = 1;` would make it `'number'`; the read of `x` outside the body declines it.
        """
        self._check(
            'function f(){ eval("let x = 1;"); return typeof x; }'
            ' console.log(f());')

    def test_direct_eval_var_in_strict_context_is_eval_local(self):
        """
        A strict direct `eval` has its own variable environment, so `eval("var x = 1;")` under
        `"use strict"` does not leak `x` to the caller and `typeof x` is `'undefined'`. Only a sloppy
        direct eval's `var` leaks; the strict context declines the inlining.
        """
        self._check(
            'function f(){ "use strict"; eval("var x = 1;"); return typeof x; }'
            ' console.log(f());')

    def test_direct_eval_var_not_inlined_past_earlier_reference(self):
        """
        A direct `eval`'s `var` is added to the caller only when the eval runs, so `var out = x` before
        `eval("var x = 1;")` reads the global `x` (`5`). Inlining the `var x` would hoist it above the
        read, rebinding `out` to the still-unassigned local; the earlier reference the eval does not
        dominate declines the inlining.
        """
        self._check(
            'globalThis.x = 5;'
            ' function f(){ var out = x; eval("var x = 1;"); return out; }'
            ' console.log(f());')
