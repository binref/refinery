from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    host_behavior,
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

    def test_dead_store_effectful_inline_iife_initializer_kept(self):
        """
        The dead `x` binds an inline IIFE whose body writes a global; the callee is a bare function
        expression, so clearing the call from its arguments alone would discard the write.
        """
        self._check(
            'var x = function(){ globalThis.g = 9; }();'
            ' console.log(globalThis.g);')

    def test_effectful_inline_iife_argument_to_inlined_iife_kept(self):
        """
        The bare-IIFE argument writes a global and the outer IIFE ignores its parameter; treating the
        argument as side-effect-free would let inlining elide the unused parameter and drop the write.
        """
        self._check(
            'console.log((function(unused){ return 7; })(function(){ globalThis.g = 9; }()));'
            ' console.log(globalThis.g);')

    def test_new_array_invalid_length_throw_preserved(self):
        """
        `new Array(-1)` throws a RangeError; recognizing `new Array` pure must exclude a bad length, so
        the dead store is kept and the throw survives.
        """
        self._check('var x = new Array(-1); console.log("after");')

    def test_new_array_pure_length_drop_preserves_behavior(self):
        self._check('var x = new Array(128); console.log("after");')

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

    def test_premature_bare_assignment_call_keeps_throw(self):
        """
        `f()` runs while `f` is the hoisted `undefined` (real: TypeError), before the assignment; dropping
        the call as pure discards the throw. The unused `dead` lets the removal pass reach the call.
        """
        self._check(
            'var f;'
            ' f();'
            ' function dead(){}'
            ' f = function(){ return 1; };'
            ' console.log("after");')

    def test_premature_const_call_keeps_throw(self):
        """
        `foo()` runs in the temporal dead zone of the later `const foo` (real: ReferenceError); dropping
        the call as pure discards the throw.
        """
        self._check(
            'foo();'
            ' function dead(){}'
            ' const foo = () => 1;'
            ' console.log("after");')

    def test_premature_iife_argument_call_keeps_throw(self):
        """
        The IIFE argument `f()` runs while `f` is the hoisted `undefined` (real: TypeError); inlining the
        IIFE and dropping the unused argument would discard the throw.
        """
        self._check(
            'var f;'
            ' console.log((function(p){ return 7; })(f()));'
            ' f = function(){ return 1; };')

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

    def test_method_value_read_is_not_invoked(self):
        """
        Reading a method without calling it yields the function, so `typeof 'abc'.charAt` is
        `'function'`. Folding the read as a zero-argument call would make it `'string'`.
        """
        self._check("console.log(typeof 'abc'.charAt, typeof 'abc'.toUpperCase, typeof 'abc'.split);")

    def test_length_is_not_callable(self):
        """
        `length` is a number, so calling it is a `TypeError`. Treating the call as a second application
        of the registry entry would fold it to the length and erase the throw.
        """
        self._check("console.log((function(){ return [1, 2].length(); })());")

    def test_string_length_is_not_callable(self):
        self._check("console.log((function(){ return 'hello'.length(); })());")

    def test_astral_split_by_code_unit(self):
        """
        `split('')` splits by UTF-16 code unit, so an astral character yields its two surrogate halves.
        """
        self._check(R"console.log('\u{1F600}x'.split('').length);")

    def test_astral_split_yields_lone_surrogates(self):
        """
        Each half of the split is a lone surrogate, so its code unit is in the D800-DFFF range. Splitting
        by code point instead would make the first element the whole astral character.
        """
        self._check(R"console.log('\u{1F600}x'.split('')[0].charCodeAt(0));")

    def test_unimplemented_method_read_is_not_undefined(self):
        """
        `normalize` and `sort` are real prototype methods this package does not implement. Membership in
        the language and evaluability here are different questions, so an unmodeled method must not read
        as `undefined`; using the builtin registry as a membership oracle made `typeof` answer
        `'undefined'` where Node says `'function'`.
        """
        self._check("console.log(typeof 'abc'.normalize, typeof [1, 2].sort, typeof [1, 2].map);")

    def test_inherited_object_member_read_is_not_undefined(self):
        """
        Strings, arrays, and plain objects all inherit from `Object.prototype`, so `hasOwnProperty` and
        `constructor` exist on every one of them.
        """
        self._check(
            "console.log(typeof 'abc'.hasOwnProperty, typeof [1, 2].constructor,"
            ' typeof ({ a: 1 }).toString);')

    def test_absent_member_read_is_still_undefined(self):
        """
        The companion case: a name on no prototype genuinely is `undefined`, so declining method reads
        must not degrade into declining every miss.
        """
        self._check("console.log(typeof 'abc'.nosuch, typeof ({ a: 1 }).nosuch);")

    def test_own_property_shadows_inherited_member(self):
        """
        An own property wins over the inherited one, so `({toString: 1}).toString` is the number `1`.
        A prototype-membership check applied before the own-property lookup would refuse or mis-answer.
        """
        self._check('console.log(({ toString: 1 }).toString, ({ map: 7 }).map, ({ length: 5 }).length);')

    def test_non_canonical_index_key_is_not_an_index(self):
        """
        A property key indexes only in its canonical decimal spelling, so `'+1'` and `'01'` are ordinary
        property names that read as `undefined`. Python's `int` accepts both, which would invent the
        element at index 1.
        """
        self._check("console.log('abc'['1'], typeof 'abc'['+1'], typeof 'abc'['01']);")

    def test_in_operator_sees_whole_prototype_chain(self):
        """
        `in` asks whether a property exists anywhere on the chain, so it is `true` for an unimplemented
        method and `false` for a non-canonical index key.
        """
        self._check(
            "console.log('sort' in [1, 2], 'map' in [1, 2], 'nosuch' in [1, 2],"
            " '0' in [1, 2], '2' in [1, 2], '+1' in [1, 2]);")

    def test_arguments_evaluate_before_non_callable_throws(self):
        """
        A call evaluates its arguments before checking that the callee is callable, so the push inside the
        argument is observable even though `length` is not a function. Throwing before evaluating them
        would lose the side effect.
        """
        self._check(
            'var log = [];'
            " try { 'hello'.length(log.push('arg')); } catch (e) { log.push('threw'); }"
            " console.log(log.join('|'));")

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

    def test_json_parsed_proto_key_survives_the_fold(self):
        """
        `JSON.parse` creates a real own `__proto__` property. Rendering the parsed object back with a
        plain `__proto__:` key installs a prototype instead, so the property disappears and the object
        stringifies as `{}`. Only the computed key form round-trips.
        """
        self._check(R"console.log(JSON.stringify(JSON.parse('{\"__proto__\":{\"x\":1}}')));")

    def test_json_parsed_proto_key_stays_enumerable(self):
        self._check(R"console.log(Object.keys(JSON.parse('{\"__proto__\":{\"x\":1}}')).length);")

    def test_nested_json_parsed_proto_key_survives_the_fold(self):
        self._check(R"console.log(JSON.stringify(JSON.parse('{\"a\":{\"__proto__\":{\"x\":1}}}')));")

    def test_proto_literal_installs_prototype_rather_than_property(self):
        """
        The inverse direction: a plain `__proto__:` key in the source installs a prototype and creates no
        own property, so reading it back as an ordinary key invents a property Node does not have and
        hides the inherited one.
        """
        self._check(
            'function f() { return Object.keys({ __proto__: { x: 1 } }).length; }'
            ' console.log(f());')

    def test_proto_literal_member_is_inherited(self):
        self._check(
            'function f() { var o = { __proto__: { x: 1 } }; return o.x; }'
            ' console.log(f());')

    def test_computed_proto_literal_is_an_own_property(self):
        """
        The companion positive case: the computed form really does create an own property, and must keep
        folding, so refusing the prototype-installing forms does not degrade into refusing all of them.
        """
        self._check(
            "function f() { var o = { ['__proto__']: { x: 1 } };"
            ' return Object.keys(o).length + (o.x === undefined); }'
            ' console.log(f());')

    def test_proto_assignment_installs_prototype(self):
        self._check(
            "function f() { var o = {}; o['__proto__'] = { x: 1 };"
            ' return Object.keys(o).length + (o.x === 1); }'
            ' console.log(f());')

    def test_buffer_survives_the_fold(self):
        """
        A Buffer has no literal form; emitting its bytes as an array would change its type, so
        `Buffer.isBuffer` and `.toString('hex')` would answer differently after the fold.
        """
        self._check(
            "function f() { return Buffer.from([65, 66]); }"
            " console.log(Buffer.isBuffer(f()), f().toString('hex'));")

    def test_buffer_decoded_to_string_still_folds(self):
        """
        The capability that must not be lost: when the chain ends in a string, the Buffer stays inside the
        interpreter and the base64 decoding still resolves.
        """
        self._check(R"console.log((function(){ return Buffer.from('QUJD', 'base64').toString('utf8'); })());")


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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestModelBlindFoldRegressions(TestBase):
    """
    Constant folding must consult the semantic model, not the spelling of a name. `String` and `parseInt`
    are only the built-ins when nothing shadows them at the use site, and a callback that writes an outer
    binding is not pure however literal its arguments are. Each case below currently changes observable
    behavior; they are the specification for routing every fold through one model-aware admission gate.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_shadowed_string_from_char_code_is_not_the_builtin(self):
        """
        A local `String` shadows the global, so `String.fromCharCode(65)` calls the local and yields `'X'`.
        Folding on the *name* `String` emits `'A'`. The fold must resolve the receiver through the model's
        per-use-site intrinsic lookup instead of comparing the identifier text.
        """
        self._check(
            "var String = { fromCharCode: function(){ return 'X'; } };"
            ' console.log(String.fromCharCode(65));')

    def test_shadowed_string_in_function_scope_is_not_the_builtin(self):
        self._check(
            "(function(){ var String = { fromCharCode: function(){ return 'X'; } };"
            ' console.log(String.fromCharCode(65)); })();')

    def test_shadowed_parse_int_is_not_the_builtin(self):
        """
        The same fault for a free function: a local `parseInt` makes both calls yield `99`, but folding by
        name emits `10` and `12`. Both the dedicated `parseInt` fold and the general registry fold are
        affected.
        """
        self._check(
            'var parseInt = function(){ return 99; };'
            " console.log(parseInt('10'), parseInt('12', 10));")

    def test_callback_writing_outer_binding_is_not_pure(self):
        """
        The callback writes the outer `n`, so evaluating the chain for its value must also keep that write.
        Folding the call to its result alone reports `n` as still `0` where Node says `3`. A callback is
        admissible only when it writes no binding outside itself, which purity alone does not establish —
        a write to a script-scope `var` is not *captured* from the callback's perspective.
        """
        self._check(
            'var n = 0;'
            " console.log((function(a){ return a.map(function(x){ n += x; return x; }).join(''); })([1, 2]), n);")

    def test_foreach_callback_write_survives(self):
        self._check(
            'var n = 0;'
            ' (function(a){ a.forEach(function(x){ n += x; }); })([1, 2]);'
            ' console.log(n);')

    def test_patched_string_method_is_not_the_builtin(self):
        """
        A method call on a literal receiver names no global at the call site, so per-name trust on the
        callee cannot see that the method itself was replaced. `String.prototype.toUpperCase = ...` makes
        `'ab'.toUpperCase()` yield `'X'`; folding it as the built-in emits `'AB'`. The gate must ask
        whether the *receiver's prototype* is intact, not only whether a named global is.
        """
        self._check(
            "String.prototype.toUpperCase = function () { return 'X'; };"
            " console.log('ab'.toUpperCase());")

    def test_patched_string_indexof_is_not_the_builtin(self):
        self._check(
            "String.prototype.indexOf = function () { return 99; };"
            " console.log('abc'.indexOf('b'));")

    def test_patched_string_split_is_not_the_builtin(self):
        self._check(
            "String.prototype.split = function () { return ['X']; };"
            " function f() { return 'a-b'.split('-').length; } console.log(f());")

    def test_patched_array_join_is_not_the_builtin(self):
        """
        The same fault for arrays. It survives at the top level only because the dedicated `join` fold
        needs an array-literal receiver that reaches it; inside a function the evaluator path folds and
        emits `'1-2'` where Node says `'X'`.
        """
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            ' function f() { return [1, 2].join(\'-\'); } console.log(f());')

    def test_patched_array_method_via_define_property_is_not_the_builtin(self):
        self._check(
            "Object.defineProperty(Array.prototype, 'join', { value: function () { return 'X'; } });"
            ' function f() { return [1, 2].join(\'-\'); } console.log(f());')

    def test_unpatched_prototype_methods_still_fold(self):
        """
        The companion control: with no prototype write anywhere, every one of these must still fold, so
        the receiver-prototype gate does not degrade into refusing all instance methods.
        """
        self._check(
            "function f() { return [1, 2].join('-') + 'ab'.toUpperCase() + 'abc'.indexOf('b'); }"
            ' console.log(f());')

    def test_patched_static_method_is_not_the_builtin_in_a_function(self):
        """
        The interpreter resolves a static method by name independently of the syntactic folds, so patching
        `Math.floor` must stop the interpreted path too. Inside a function body that path is the one taken.
        """
        self._check(
            'Math.floor = function () { return 99; };'
            ' function f() { return Math.floor(1.7); } console.log(f());')

    def test_patched_array_hof_is_not_the_builtin_in_a_function(self):
        """
        A higher-order method reaches the interpreter's own callback machinery rather than a registry entry,
        so it needs the receiver-prototype question asked separately at that site.
        """
        self._check(
            "Array.prototype.map = function () { return ['X']; };"
            ' function f() { return [1, 2].map(function (x) { return x + 1; }).length; }'
            ' console.log(f());')

    def test_patched_join_on_a_string_array_is_not_the_builtin(self):
        """
        The dedicated `join` fold only accepts string elements, so it is this shape rather than a numeric
        array that reaches it, and it needs its own receiver-prototype check.
        """
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            " console.log(['a', 'b'].join('-'));")

    def test_patched_join_after_split_is_not_the_builtin(self):
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            " console.log('a-b'.split('-').join('+'));")


class TestMemberCalleeChainFolds(TestBase):
    """
    A method-call chain on a literal receiver (`[66, 79].map(f).join('')`) is the decoder shape obfuscators
    emit most, and evaluating it is the whole point of having an interpreter. Behavior on these is already
    correct — the chain is simply left standing — so what these cases pin is that admitting them does not
    trade coverage for a wrong answer: every hazard below must survive the widening intact.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def _folds_to(self, source: str, expected: str):
        """
        Assert *source* deobfuscates to exactly *expected* and that both agree with Node. The literal form
        is asserted, not merely that behavior is preserved: leaving the chain untouched also preserves
        behavior, so only the exact output distinguishes a fold from a refusal.
        """
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(expected, deobfuscated.strip())
        self.assertEqual(behavior(source), behavior(deobfuscated))

    def test_map_join_xor_decoder_folds(self):
        self._folds_to(
            '[66, 79, 70, 70, 69].map(function (c) { return String.fromCharCode(c ^ 42); }).join(\'\');',
            "'hello';")

    def test_map_join_on_empty_array_folds(self):
        self._folds_to(
            "[].map(function (c) { return String.fromCharCode(c ^ 42); }).join('');",
            "'';")

    def test_filter_join_folds(self):
        self._folds_to(
            "['a', '', 'b'].filter(function (s) { return s; }).join('|');",
            "'a|b';")

    def test_slice_join_folds(self):
        self._folds_to("[1, 2, 3, 4].slice(1, 3).join('+');", "'2+3';")

    def test_concat_join_folds(self):
        self._folds_to("[1, 2].concat([3]).join('-');", "'1-2-3';")

    def test_reduce_decoder_folds(self):
        self._folds_to(
            "[72, 73].reduce(function (a, c) { return a + String.fromCharCode(c); }, '');",
            "'HI';")

    def test_callback_writing_outer_binding_blocks_the_chain(self):
        """
        The write to `n` is observable after the chain returns, so folding the chain to its value alone
        loses it. This is the hazard the widening must not admit.
        """
        self._check(
            'var n = 0;'
            " console.log([1, 2].map(function (x) { n += x; return x; }).join(''), n);")

    def test_effectful_receiver_blocks_the_chain(self):
        """
        A user function as the chain's innermost receiver is one the interpreter can resolve and run, so
        without a gate its write would be dropped while the chain folded. Only a literal receiver has a
        type the syntax fixes and a value with no effect to lose.
        """
        self._check(
            'var n = 0;'
            ' function mk() { n += 1; return [1, 2]; }'
            " console.log(mk().join('-'), n);")

    def test_effectful_argument_to_an_inner_chain_link_blocks_the_chain(self):
        """
        The effectful call is an argument to `Buffer.from`, the *inner* link, whose result is the receiver
        of `.toString`. Admitting the outer call must therefore re-ask the whole admission question of the
        inner one and not merely whether its callee is trusted, or the write to `n` is folded away.
        """
        self._check(
            'var n = 0;'
            " function h() { n += 1; return 'aa'; }"
            " console.log(Buffer.from(h(), 'hex').toString('hex'), n);")

    def test_patched_prototype_blocks_the_chain_at_every_link(self):
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            " console.log([66, 79].map(function (c) { return c; }).join(''));")

    def test_patched_string_prototype_blocks_a_string_seeded_chain(self):
        self._check(
            "String.prototype.split = function () { return ['X']; };"
            " console.log('a-b'.split('-').join('+'));")

    def test_identifier_receiver_still_refused(self):
        """
        A named receiver may be mutated through an alias between its definition and the chain, which no
        syntactic check on the chain can see. It stays refused; only literal receivers are admitted here.
        """
        self._check(
            'var a = [66, 79];'
            " console.log(a.map(function (x) { return x; }).join(''));")

    def test_throwing_callback_blocks_the_chain(self):
        self._check(
            "try { console.log([1, 2].map(function (x) { throw new Error('boom'); }).join('')); }"
            " catch (e) { console.log('caught'); }")

    def test_data_property_call_on_a_chain_still_throws(self):
        """
        `length` is a data property, so calling it is a `TypeError` rather than a value. A chain ending in
        one must not fold to the property's value.
        """
        self._check(
            'try { console.log([1, 2].concat([3]).length()); }'
            ' catch (e) { console.log(e.constructor.name); }')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMemberBaseSafety(TestBase):
    """
    A member read whose base is a literal was cleared as effect-free on the strength of the base's syntax
    alone, and three distinct holes in that reasoning let a real effect be deleted: an object literal
    carrying a getter still runs it, `null` is a literal whose every property read throws, and a chain is
    not safe merely because its root is — `root.a` may be `undefined`, so `root.a.b` throws.

    Each case pairs the hazard with the control it must not cost, since refusing everything would also make
    the behavior agree.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_getter_on_object_literal_base_still_runs(self):
        """
        The read is dead — nothing uses `t` — but the getter is observable, so the statement must stay.
        """
        self._check(
            "function f() { var t = { get k() { console.log('getter'); return 1; } }.k; }"
            " f();"
            " console.log('done');")

    def test_getter_on_object_literal_base_still_runs_through_a_computed_key(self):
        self._check(
            "function f() { var t = { get k() { console.log('getter'); return 1; } }['k']; }"
            " f();"
            " console.log('done');")

    def test_reading_a_property_of_null_still_throws(self):
        self._check(
            'function f() { var t = null.k; }'
            " try { f(); } catch (e) { console.log('caught ' + e.constructor.name); }"
            " console.log('done');")

    def test_reading_a_property_of_null_still_throws_uncaught(self):
        """
        Uncaught, the throw is the program's whole observable outcome: dropping the read turned a
        `TypeError` exit into a clean one that went on to print.
        """
        self._check(
            'function f() { var t = null.k; }'
            ' f();'
            " console.log('unreachable');")

    def test_chain_through_an_undefined_link_on_a_string_still_throws(self):
        self._check(
            'function f() { var t = "s".nope.deeper; }'
            " try { f(); } catch (e) { console.log('caught ' + e.constructor.name); }"
            " console.log('done');")

    def test_chain_through_an_undefined_link_on_an_array_still_throws(self):
        self._check(
            'function f() { var t = [1, 2].nope.deeper; }'
            " try { f(); } catch (e) { console.log('caught ' + e.constructor.name); }"
            " console.log('done');")

    def test_chain_through_an_undefined_link_on_an_object_still_throws(self):
        self._check(
            'function f() { var t = { a: 1 }.nope.deeper; }'
            " try { f(); } catch (e) { console.log('caught ' + e.constructor.name); }"
            " console.log('done');")

    def test_getter_reached_at_chain_depth_two_still_runs(self):
        """
        The root is a plain literal and only the second link carries the accessor, so a rule that judges
        the chain by its root alone clears this one.
        """
        self._check(
            "function f() { var t = { a: { get k() { console.log('getter'); return 1; } } }.a.k; }"
            ' f();'
            " console.log('done');")

    def test_setter_on_object_literal_base_is_not_run_by_a_read(self):
        """
        The control for the accessor cases: a literal carrying only a *setter* runs nothing on a read, so
        the conservative answer must not be reached through the setter's mere presence.
        """
        self._check(
            "function f() { var t = { set k(v) { console.log('setter'); } }.k; }"
            ' f();'
            " console.log('done');")

    def test_plain_literal_base_read_still_folds(self):
        self._check("function f() { console.log({ k: 7 }.k); } f(); console.log('done');")

    def test_valid_two_link_chain_still_folds(self):
        self._check("function f() { console.log({ a: { k: 5 } }.a.k); } f(); console.log('done');")

    def test_primitive_base_property_read_still_folds(self):
        self._check("function f() { console.log('abc'.length); } f(); console.log('done');")

    def test_function_literal_base_property_read_still_folds(self):
        self._check("function f() { console.log((function (a, b) {}).length); } f();")

    def test_arrow_literal_base_property_read_still_folds(self):
        self._check('function f() { console.log((() => 1).length); } f();')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestPrototypeChainTrust(TestBase):
    """
    A property read walks a prototype chain the program can patch, so what a literal base's syntax settles
    is its *type* and not its behaviour. A read cleared on syntax alone dropped a getter installed on the
    corresponding prototype, and the interpreter separately answered `undefined` for a name its own tables
    call absent from the chain — an absence claim that only holds while the chain is intact.

    Every prototype in the chain matters, not just the one owning the type's methods: `Object.prototype`
    roots the chain of an array literal, of a primitive, and of `Math` alike. Each patched case is paired
    with the pristine control it must not cost, since refusing every literal base would also make the
    behavior agree while undoing the folds these tests exist to protect.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def _getter(self, owner: str) -> str:
        return (
            F"Object.defineProperty({owner}.prototype, 'zz',"
            " { get: function () { console.log('getter'); return 1; } });"
        )

    def test_getter_on_array_prototype_is_reached_by_an_array_literal_read(self):
        self._check(
            self._getter('Array')
            + ' function f() { var t = [1, 2].zz; }'
            " f(); console.log('done');")

    def test_getter_on_string_prototype_is_reached_by_a_string_literal_read(self):
        self._check(
            self._getter('String')
            + " function f() { var t = 'ab'.zz; }"
            " f(); console.log('done');")

    def test_getter_on_number_prototype_is_reached_by_a_number_literal_read(self):
        self._check(
            self._getter('Number')
            + ' function f() { var t = 7 .zz; }'
            " f(); console.log('done');")

    def test_getter_on_boolean_prototype_is_reached_by_a_boolean_literal_read(self):
        self._check(
            self._getter('Boolean')
            + ' function f() { var t = true.zz; }'
            " f(); console.log('done');")

    def test_getter_on_function_prototype_is_reached_by_a_function_literal_read(self):
        self._check(
            self._getter('Function')
            + ' function f() { var t = (function () {}).zz; }'
            " f(); console.log('done');")

    def test_getter_on_function_prototype_is_reached_by_an_arrow_literal_read(self):
        self._check(
            self._getter('Function')
            + ' function f() { var t = (() => 1).zz; }'
            " f(); console.log('done');")

    def test_getter_on_object_prototype_is_reached_by_an_array_literal_read(self):
        """
        `Object.prototype` owns none of an array's methods, so a rule asking only about `Array` clears
        this. It is nonetheless in the chain a read walks.
        """
        self._check(
            self._getter('Object')
            + ' function f() { var t = [1, 2].zz; }'
            " f(); console.log('done');")

    def test_getter_on_object_prototype_is_reached_by_an_object_literal_read(self):
        self._check(
            self._getter('Object')
            + ' function f() { var t = ({ a: 1 }).zz; }'
            " f(); console.log('done');")

    def test_getter_on_object_prototype_is_reached_by_an_intrinsic_root_read(self):
        """
        `Math` names an intrinsic the program never touches, so trusting it by name says pristine while the
        read still walks the patched `Object.prototype`.
        """
        self._check(
            self._getter('Object')
            + ' function f() { var t = Math.zz; }'
            " f(); console.log('done');")

    def test_throwing_getter_on_a_patched_prototype_still_throws(self):
        """
        Uncaught, the throw is the program's whole observable outcome, so dropping the read turns a failing
        exit into a clean one — a divergence no amount of value agreement covers.
        """
        self._check(
            "Object.defineProperty(Array.prototype, 'zz',"
            " { get: function () { throw new Error('boom'); } });"
            ' function f() { var t = [1].zz; }'
            " f(); console.log('unreachable');")

    def test_value_read_through_a_patched_prototype_is_not_folded_to_undefined(self):
        """
        The interpreter's own tables do not list `zz` on `Array.prototype` and concluded the read was
        `undefined`. Here the value is used, so a wrong fold is observable even with no getter involved.
        """
        self._check(
            "Array.prototype.zz = 7;"
            ' function f() { return [1, 2].zz; }'
            ' console.log(String(f()));')

    def test_patched_prototype_method_is_not_folded_to_the_builtin(self):
        self._check(
            "Array.prototype.join = function () { return 'PATCHED'; };"
            " console.log([1, 2].join('-'));")

    def test_pristine_array_literal_read_still_folds(self):
        self._check("function f() { console.log([1, 2].length); } f(); console.log('done');")

    def test_pristine_intrinsic_root_read_still_folds(self):
        self._check("function f() { console.log(Math.PI); } f(); console.log('done');")

    def test_object_prototype_patch_does_not_block_an_owned_method_call(self):
        """
        The control that keeps the read rule from being copied onto the call rule: a method resolves on the
        prototype that owns it, so `Array.prototype.join` shadows anything installed on `Object.prototype`
        and the fold must survive.
        """
        self._check(
            "Object.prototype.join = function () { return 'PATCHED'; };"
            " console.log([1, 2].join('-'));")

    def test_object_prototype_patch_does_not_block_an_owned_string_method_call(self):
        self._check(
            "Object.prototype.toUpperCase = function () { return 'PATCHED'; };"
            " console.log('ab'.toUpperCase());")

    def test_patched_function_apply_is_not_dispatched_as_the_builtin(self):
        """
        `.apply` on a function receiver is dispatched by name like any other method, so a patched
        `Function.prototype.apply` redirects the call. The receiver has to be a function-local for the
        evaluator to reach that dispatch at all — a parenthesized literal receiver is refused earlier as an
        untrusted callee — which is why this shape and not the shorter one exercises the guard.
        """
        self._check(
            "Function.prototype.apply = function () { return 'PATCHED'; };"
            ' function f() { var g = function (a) { return a * 3; }; return g.apply(null, [3]); }'
            ' console.log(String(f()));')

    def test_patched_function_call_is_not_dispatched_as_the_builtin(self):
        self._check(
            "Function.prototype.call = function () { return 'PATCHED'; };"
            ' function f() { var g = function (a) { return a + 1; }; return g.call(null, 2); }'
            ' console.log(String(f()));')

    def test_pristine_function_apply_still_folds(self):
        self._check(
            ' function f() { var g = function (a) { return a * 3; }; return g.apply(null, [3]); }'
            ' console.log(String(f()));')

    def test_pristine_function_call_still_folds(self):
        self._check(
            ' function f() { var g = function (a) { return a + 1; }; return g.call(null, 2); }'
            ' console.log(String(f()));')


class TestHostEntrypointPreservation(TestBase):
    """
    Under the script execution model a top-level `var`/`function` is a property of the global object, so
    a host — a JXA runner, Windows Script Host, a browser event dispatch — calls into the file by a name
    the file itself never mentions. Reachability computed over the file alone therefore judges such a
    function dead.

    These cases are the reason `host_behavior` exists. Running the file and comparing stdout cannot see
    the difference, because nothing inside the file reads the deleted name; only calling it afterwards
    through `globalThis` makes the loss observable, with Node deciding what was lost.
    """

    def _check_host(self, source: str, *, calls: tuple[str, ...], entrypoints: tuple[str, ...]):
        deobfuscated = deobfuscate_source(source, entrypoints=entrypoints)
        self.assertEqual(
            host_behavior(source, calls=calls),
            host_behavior(deobfuscated, calls=calls),
            F'deobfuscation changed what a host observes; result was:\n{deobfuscated}',
        )

    def test_named_entrypoint_is_still_callable_by_the_host(self):
        self._check_host(
            "var config = 'hi';"
            ' function run() { return config; }',
            calls=('run',),
            entrypoints=('run',))

    def test_entrypoint_callees_survive_so_it_still_returns_the_same_value(self):
        """
        Preserving the entrypoint alone is not enough: everything it calls has to survive too, or the
        host's call throws instead of returning. Node arbitrates which.
        """
        self._check_host(
            "function decode(n) { return 'v' + n; }"
            ' function helper() { return decode(7); }'
            ' function run() { return helper(); }',
            calls=('run',),
            entrypoints=('run',))

    def test_several_handlers_survive_a_wildcard(self):
        self._check_host(
            "function OnStart() { return 'a'; }"
            " function OnStop() { return 'b'; }",
            calls=('OnStart', 'OnStop'),
            entrypoints=('On*',))

    def test_entrypoint_survives_beside_a_self_driving_top_level(self):
        """
        The realistic shape: the file both runs code of its own on load and exposes an entrypoint. Both
        the load-time output and the host call must be preserved.
        """
        self._check_host(
            "var log = [];"
            " function record(x) { log.push(x); return x; }"
            " function run() { return record('called'); }"
            " console.log(record('loaded'));",
            calls=('run',),
            entrypoints=('run',))

    def test_unnamed_dead_function_removal_is_unobservable_to_the_host(self):
        """
        The companion control. A function the host does not call may still be removed, and doing so
        changes nothing a host can observe — so declaring one entrypoint does not freeze the file.
        """
        self._check_host(
            "function junk() { return 'unused'; }"
            " function run() { return 'kept'; }",
            calls=('run', 'junk'),
            entrypoints=('run',))

    def test_entrypoint_held_by_a_var_is_still_callable_by_the_host(self):
        """
        `var run = function(){}` reaches the global object exactly as a declaration does, so a host calls
        it the same way. It is removed by a different sweep than a function declaration, and Node confirms
        the host observes no difference either way.
        """
        self._check_host(
            "var run = function() { return 'from-var'; };",
            calls=('run',),
            entrypoints=('run',))

