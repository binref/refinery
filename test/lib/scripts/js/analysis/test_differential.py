from __future__ import annotations

import inspect
import json
import unicodedata
import unittest

from test import TestBase

from refinery.lib.scripts import canonical
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.interpreter import BUILTIN_REGISTRY, InterpreterError
from refinery.lib.scripts.js.lexer import JsLexer
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.token import JsTokenKind

from test.lib.scripts.js.analysis.differential import (
    DeobfuscationFailed,
    behavior,
    deobfuscate_source,
    deobfuscate_within,
    host_behavior,
    node_executable,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationDifferential(TestBase):
    """
    Each case runs a benign snippet and its deobfuscation through Node.js and asserts they behave
    identically.
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
class TestGuaranteedGlobalNamesInWithScope(TestBase):
    """
    `undefined`, `NaN` and `Infinity` are the three names whose value the language guarantees, and
    that guarantee is what makes an expression over them foldable at all. It is a guarantee about
    the global binding, not about the spelling: inside a `with` body the name is looked up on the
    object first, so it denotes whatever the object supplies — through its prototype as well, and
    through a property added after the body starts running — and an accessor makes the read itself
    observable.

    Every case pins the emitted text rather than only the behavior, because comparing behavior is
    blind in both directions here: an untouched program behaves like itself, so refusing every fold
    would satisfy it, and the controls below would still pass with the whole feature deleted.
    """

    def _unchanged(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(deobfuscate_source(source), source)

    def _folds_to(self, source: str, folded: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(folded), (output, None))
        self.assertEqual(deobfuscate_source(source), folded)

    def test_typeof_undefined_is_not_folded_where_the_with_object_supplies_the_name(self):
        """
        Node: `number`. The bare `undefined` denotes `o.undefined`, the number one, so `typeof`
        answers for that value; the global's answer would be `'undefined'`.
        """
        self._unchanged(
            inspect.cleandoc("""
                var o = { undefined: 1 };
                with (o) {
                  console.log(typeof undefined);
                }
            """),
            'number\n',
        )

    def test_bitwise_complement_of_nan_is_not_folded_where_the_with_object_supplies_the_name(self):
        """
        Node: `-6`. The bare `NaN` denotes `o.NaN`, which is five, so the complement is minus six;
        the global's answer would be minus one, since ToInt32 maps a NaN to zero.
        """
        self._unchanged(
            inspect.cleandoc("""
                var o = { NaN: 5 };
                with (o) {
                  console.log(String(~NaN));
                }
            """),
            '-6\n',
        )

    def test_logical_not_of_infinity_is_not_folded_where_the_with_object_supplies_the_name(self):
        """
        Node: `true`. The bare `Infinity` denotes `o.Infinity`, which is zero and therefore falsy;
        the global's answer would be `false`.
        """
        self._unchanged(
            inspect.cleandoc("""
                var o = { Infinity: 0 };
                with (o) {
                  console.log(String(!Infinity));
                }
            """),
            'true\n',
        )

    def test_undefined_is_not_folded_in_a_with_body_whose_object_gains_the_name(self):
        """
        Node: `undefined|number`. The object supplies nothing when the body starts, so the first
        read is the global one, and it supplies the name by the time of the second. The two reads
        are spelled identically and mean different things, so neither is decided by the spelling.
        """
        self._unchanged(
            inspect.cleandoc("""
                var SINK = [];
                var o = {};
                with (o) {
                  SINK.push(typeof undefined);
                  o.undefined = 1;
                  SINK.push(typeof undefined);
                }
                console.log(SINK.join('|'));
            """),
            'undefined|number\n',
        )

    def test_nan_is_not_folded_where_only_the_prototype_of_the_with_object_supplies_the_name(self):
        """
        Node: `-10`. A `with` scope resolves a name by asking the object whether it has the
        property, which walks the prototype chain, so the inherited nine answers although `o`
        itself has no such property.
        """
        self._unchanged(
            inspect.cleandoc("""
                var proto = { NaN: 9 };
                var o = Object.create(proto);
                with (o) {
                  console.log(String(~NaN));
                }
            """),
            '-10\n',
        )

    def test_infinity_read_in_a_with_body_is_not_folded_past_the_objects_getter(self):
        """
        Node: `read|true`. Reading the bare name runs the accessor, so the read is observable even
        before its value is used; folding it would drop the push as well as answer `false`.
        """
        self._unchanged(
            inspect.cleandoc("""
                var SINK = [];
                var o = { get Infinity() {
                  SINK.push('read');
                  return 0;
                } };
                with (o) {
                  SINK.push(String(!Infinity));
                }
                console.log(SINK.join('|'));
            """),
            'read|true\n',
        )

    def test_typeof_undefined_outside_any_with_body_folds(self):
        self._folds_to(
            'console.log(typeof undefined);',
            "console.log('undefined');",
            'undefined\n',
        )

    def test_bitwise_complement_of_nan_outside_any_with_body_folds(self):
        self._folds_to(
            'console.log(String(~NaN));',
            "console.log('-1');",
            '-1\n',
        )

    def test_logical_not_of_infinity_outside_any_with_body_folds(self):
        self._folds_to(
            'console.log(String(!Infinity));',
            "console.log('false');",
            'false\n',
        )

    def test_nan_folds_in_a_statement_that_follows_a_with_body(self):
        """
        The dynamic scope ends with the body, so the trailing statement is an ordinary one and its
        `NaN` is the global. Containing a `with` anywhere does not disqualify a program from this
        fold.
        """
        self._folds_to(
            inspect.cleandoc("""
                var o = { NaN: 5 };
                with (o) {
                  console.log(o.NaN);
                }
                console.log(String(~NaN));
            """),
            inspect.cleandoc("""
                var o = { NaN: 5 };
                with (o) {
                  console.log(o.NaN);
                }
                console.log(String(-1));
            """),
            '5\n-1\n',
        )

    def test_undefined_folds_in_a_function_declared_outside_the_with_body_that_calls_it(self):
        """
        Node: `undefined`. A function's scope chain is the one it was created in, so the body of `f`
        never sees `o` however `f` is called, and `o.undefined` does not reach the name it reads.
        """
        self._folds_to(
            inspect.cleandoc("""
                function f() {
                  return typeof undefined;
                }
                var o = { undefined: 1 };
                with (o) {
                  console.log(f());
                }
            """),
            inspect.cleandoc("""
                function f() {
                  return 'undefined';
                }
                var o = { undefined: 1 };
                with (o) {
                  console.log(f());
                }
            """),
            'undefined\n',
        )


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
    a `with`.
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
    declines the substitution.
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
    hoisting it past an earlier reference would rebind that reference.
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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestBuiltinNameBoundByAnEnclosingParameter(TestBase):
    """
    A parameter binds its name for the whole of the function it belongs to, and a nested function is
    part of that function. A parameter named `parseInt` or `String` is therefore what the name denotes
    in a nested body exactly as it is in the outer body, and reading it as the built-in there computes
    with a function the program never calls.

    Node decides. Each case names the program a fold that missed the binding would produce and requires
    Node to print something else for it, so a replacement that answers the call the way the built-in
    does cannot pass for a proof. The controls put the same replacement where resolving it was never in
    doubt — at the top level, and in the very function the read is written in — so that a fix which
    works by refusing to fold anything at all does not pass either.
    """

    def _shadowed(self, source: str, misfolded: str):
        self.assertNotEqual(
            behavior(source),
            behavior(misfolded),
            'the program does not discriminate: the replacement answers as the built-in does',
        )
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_top_level_binding_shadows_a_called_builtin(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                var parseInt = function (text) { return 'r' + text; };
                function inner() {
                  return parseInt('10');
                }
                console.log(inner());
            """),
            inspect.cleandoc("""
                var parseInt = function (text) { return 'r' + text; };
                function inner() {
                  return 10;
                }
                console.log(inner());
            """),
        )

    def test_a_parameter_of_the_reading_function_shadows_a_called_builtin(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer(parseInt) {
                  return parseInt('10');
                }
                console.log(outer(function (text) { return 'r' + text; }));
            """),
            inspect.cleandoc("""
                function outer(parseInt) {
                  return 10;
                }
                console.log(outer(function (text) { return 'r' + text; }));
            """),
        )

    def test_a_parameter_of_an_enclosing_function_shadows_a_called_builtin(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in. The parameter is
        the only meaning `parseInt` has anywhere inside `outer`, and `inner` is inside `outer`.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer(parseInt) {
                  function inner() {
                    return parseInt('10');
                  }
                  return inner();
                }
                console.log(outer(function (text) { return 'r' + text; }));
            """),
            inspect.cleandoc("""
                function outer(parseInt) {
                  function inner() {
                    return 10;
                  }
                  return inner();
                }
                console.log(outer(function (text) { return 'r' + text; }));
            """),
        )

    def test_a_parameter_of_an_enclosing_function_shadows_a_called_builtin_constructor(self):
        """
        Node: `r7`, and `7` for the program that read the name as the built-in. A constructor
        called as a function is folded by the same reading of the name.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer(String) {
                  function inner() {
                    return String(7);
                  }
                  return inner();
                }
                console.log(outer(function (value) { return 'r' + value; }));
            """),
            inspect.cleandoc("""
                function outer(String) {
                  function inner() {
                    return '7';
                  }
                  return inner();
                }
                console.log(outer(function (value) { return 'r' + value; }));
            """),
        )

    def test_both_reads_of_an_enclosing_parameter_denote_it(self):
        """
        Node: `r10/r12`, and `10/r12` for the program that read only the nested occurrence as the
        built-in. One binding, two reads, and the function boundary is the whole difference
        between them.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer(parseInt) {
                  function inner() {
                    return parseInt('10');
                  }
                  return inner() + '/' + parseInt('12');
                }
                console.log(outer(function (text) { return 'r' + text; }));
            """),
            inspect.cleandoc("""
                function outer(parseInt) {
                  return 10 + '/' + parseInt('12');
                }
                console.log(outer(function (text) { return 'r' + text; }));
            """),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestBuiltinNameBoundByACatchClause(TestBase):
    """
    A catch clause binds its name for the block it heads, so a catch binding named `parseInt` is what
    that name denotes there, and reading it as the built-in computes with a function the program never
    calls. It is a class of its own rather than another case of the one above because the binder is
    what is under test: a catch clause reaches a read written directly in its own block, where a
    parameter's reach is what carries it into a nested function.

    Node decides, and each case names the program a fold that missed the binding would produce and
    requires Node to print something else for it. The control binds the replacement with a `var` in
    the very same block, so what the block is and where the read sits are held fixed and the binder is
    the only thing that differs.
    """

    def _shadowed(self, source: str, misfolded: str):
        self.assertNotEqual(
            behavior(source),
            behavior(misfolded),
            'the program does not discriminate: the replacement answers as the built-in does',
        )
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_var_in_the_catch_block_shadows_a_called_builtin(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw 0;
                  } catch (error) {
                    var parseInt = function (text) { return 'r' + text; };
                    return parseInt('10');
                  }
                }
                console.log(outer());
            """),
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw 0;
                  } catch (error) {
                    var parseInt = function (text) { return 'r' + text; };
                    return 10;
                  }
                }
                console.log(outer());
            """),
        )

    def test_a_catch_binding_shadows_a_called_builtin_read_in_its_own_block(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in. The thrown
        function is the only thing `parseInt` names in the handler.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw function (text) { return 'r' + text; };
                  } catch (parseInt) {
                    return parseInt('10');
                  }
                }
                console.log(outer());
            """),
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw function (text) { return 'r' + text; };
                  } catch (parseInt) {
                    return 10;
                  }
                }
                console.log(outer());
            """),
        )

    def test_a_catch_binding_shadows_a_called_builtin_read_in_a_nested_function(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw function (text) { return 'r' + text; };
                  } catch (parseInt) {
                    var inner = function () { return parseInt('10'); };
                    return inner();
                  }
                }
                console.log(outer());
            """),
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw function (text) { return 'r' + text; };
                  } catch (parseInt) {
                    var inner = function () { return 10; };
                    return inner();
                  }
                }
                console.log(outer());
            """),
        )

    def test_a_destructured_catch_binding_shadows_a_called_builtin(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in. A pattern is a
        second way a catch clause names a binding, and the same pattern in a `var` declaration is
        read correctly, so it can be missed here on its own.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw { parseInt: function (text) { return 'r' + text; } };
                  } catch ({ parseInt }) {
                    return parseInt('10');
                  }
                }
                console.log(outer());
            """),
            inspect.cleandoc("""
                function outer() {
                  try {
                    throw { parseInt: function (text) { return 'r' + text; } };
                  } catch ({ parseInt }) {
                    return 10;
                  }
                }
                console.log(outer());
            """),
        )


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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAliasedIntrinsicPatches(TestBase):
    """
    A property write patches the intrinsic its target denotes, which need not be the name it is spelled with:
    `var m = Math; m.floor = f` replaces `Math.floor` while mentioning `Math` nowhere in the assignment.
    Attributing the write to the syntactic root left the built-in looking pristine, so every later
    `Math.floor(…)` folded to the original.

    Each patched form is paired with the control it must not cost — above all a bare alias with no write
    through it, which is ordinary minifier output and must keep folding.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_patch_through_a_plain_alias_is_honored(self):
        self._check(
            "var m = Math; m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_guarded_alias_is_honored(self):
        self._check(
            "var m = Math || {}; m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_sequence_alias_is_honored(self):
        self._check(
            "var m = (0, Math); m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_conditional_alias_is_honored(self):
        self._check(
            "var m = 1 ? Math : {}; m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_alias_assigned_after_declaration_is_honored(self):
        self._check(
            "var m; m = Math; m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_two_hop_alias_is_honored(self):
        self._check(
            "var a = Math; var b = a; b.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_computed_key_on_an_alias_is_honored(self):
        self._check(
            "var m = Math; m['fl' + 'oor'] = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_descriptor_install_through_an_alias_is_honored(self):
        self._check(
            "var m = Math; Object.defineProperty(m, 'floor',"
            " { value: function () { return 'PATCHED'; } });"
            ' console.log(String(Math.floor(1.7)));')

    def test_prototype_patch_through_a_constructor_alias_is_honored(self):
        self._check(
            "var A = Array; A.prototype.join = function () { return 'PATCHED'; };"
            " console.log([1, 2].join('-'));")

    def test_prototype_patch_through_a_prototype_alias_is_honored(self):
        self._check(
            "var p = Array.prototype; p.join = function () { return 'PATCHED'; };"
            " console.log([1, 2].join('-'));")

    def test_string_patch_through_an_alias_is_honored(self):
        self._check(
            "var S = String; S.fromCharCode = function () { return 'PATCHED'; };"
            ' console.log(String(String.fromCharCode(65)));')

    def test_bare_alias_without_a_write_still_folds(self):
        self._check('var m = Math; console.log(String(m.floor(1.7)));')

    def test_write_on_an_unrelated_local_still_folds(self):
        self._check('var m = {}; m.floor = 1; console.log(String(Math.floor(1.7)));')

    def test_write_on_the_result_of_an_intrinsic_call_still_folds(self):
        """
        The local holds the string the call returned, not `String`, so treating it as an alias would refuse
        every `String.fromCharCode` fold in a file that ever stores one of its results.
        """
        self._check(
            "var s = String.fromCharCode(65); s.x = 1;"
            ' console.log(String(String.fromCharCode(66)));')

    def test_write_on_the_result_of_a_method_call_still_folds(self):
        self._check(
            "var s = 'ab'.toUpperCase(); s.x = 1;"
            ' console.log(String(String.fromCharCode(66)));')


class TestEscapedIntrinsicPatches(TestBase):
    """
    An intrinsic handed to a function is patched by a write that names it nowhere:
    `function p(o) { o.floor = f; } p(Math)` replaces `Math.floor` while the assignment mentions only a
    parameter. Scanning for write targets left the built-in pristine, so every later `Math.floor(…)` folded
    to the original.

    One case per *route* rather than per form, because the routes are what a forward argument-to-parameter
    binder cannot follow: it reaches the first of these and none of the rest — a callback, a returned value,
    `arguments`, spread, rest, a method on an object literal, a container. Asking instead whether the value
    escapes a position whose effect is known covers them together.

    The controls are the point of the chosen posture, not an afterthought. A call whose callee provably
    writes nothing keeps folding, so passing an intrinsic to a function that merely reads from it — ordinary
    code — costs nothing.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_patch_through_a_positional_argument_is_honored(self):
        self._check(
            "function p(o) { o.floor = function () { return 'PATCHED'; }; } p(Math);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_guarded_argument_is_honored(self):
        self._check(
            "function p(o) { o.floor = function () { return 'PATCHED'; }; } p(Math || {});"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_alias_argument_is_honored(self):
        self._check(
            "function p(o) { o.floor = function () { return 'PATCHED'; }; } var m = Math; p(m);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_spread_argument_is_honored(self):
        self._check(
            "function p(o) { o.floor = function () { return 'PATCHED'; }; } p(...[Math]);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_rest_parameter_is_honored(self):
        self._check(
            "function p() { arguments[0].floor = function () { return 'PATCHED'; }; } p(Math);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_the_arguments_object_is_honored(self):
        self._check(
            "function p(...r) { r[0].floor = function () { return 'PATCHED'; }; } p(Math);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_callback_is_honored(self):
        """
        The callee is a parameter, so resolving it demands the ordering-free answer. A resolver that fell
        back to a binding's declaration parent named `each` here — the function that declares `f`, not the
        one it holds — and reported it write-free, losing the callback's write entirely.
        """
        self._check(
            'function each(f) { f(Math); }'
            " each(function (o) { o.floor = function () { return 'PATCHED'; }; });"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_returned_intrinsic_is_honored(self):
        self._check(
            "function get() { return Math; } get().floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_intrinsic_a_callee_returns_is_honored(self):
        """
        Not reachable through aliasing: the alias walk stops at a call, so `m` does not denote `Math`. The
        write is only attributed because letting a callee return its parameter counts as an escape.
        """
        self._check(
            'function get(o) { return o; } var m = get(Math);'
            " m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_unknown_computed_key_is_honored(self):
        """
        `Array[k]` may be `Array.prototype`, so an unresolvable key has to reach the surface. Node decides
        what the program does with whichever key it turns out to be.
        """
        self._check(
            "var k = 'prototype'; function p(o) { o.join = function () { return 'PATCHED'; }; }"
            " p(Array[k]); console.log([1, 2].join('-'));")

    def test_patch_along_a_chain_past_the_depth_limit_is_honored(self):
        self._check(
            'function f0(o) { f1(o); } function f1(o) { f2(o); } function f2(o) { f3(o); }'
            ' function f3(o) { f4(o); }'
            " function f4(o) { f5(o); } function f5(o) { o.floor = function () { return 'PATCHED'; }; }"
            ' f0(Math); console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_method_of_an_object_literal_is_honored(self):
        self._check(
            "var h = { p: function (o) { o.floor = function () { return 'PATCHED'; }; } }; h.p(Math);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_intrinsic_stored_in_a_container_is_honored(self):
        self._check(
            "var a = [Math]; a[0].floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_prototype_argument_is_honored(self):
        self._check(
            "function p(o) { o.join = function () { return 'PATCHED'; }; } p(Array.prototype);"
            " console.log([1, 2].join('-'));")

    def test_patch_through_a_call_two_hops_deep_is_honored(self):
        self._check(
            "function q(o) { o.floor = function () { return 'PATCHED'; }; }"
            ' function p(o) { q(o); } p(Math);'
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_by_a_callee_that_saves_the_parameter_is_honored(self):
        self._check(
            'var save; function p(o) { save = o; } p(Math);'
            " save.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_argument_to_a_reading_callee_still_folds(self):
        self._check(
            'function log(o) { return o.PI; } log(Math); console.log(String(Math.floor(1.7)));')

    def test_argument_to_a_callee_that_ignores_it_still_folds(self):
        self._check(
            'function ignore(o) { return 1; } ignore(Math); console.log(String(Math.floor(1.7)));')

    def test_argument_to_a_reading_callee_two_hops_deep_still_folds(self):
        self._check(
            'function inner(o) { return o.PI; } function outer(o) { return inner(o); } outer(Math);'
            ' console.log(String(Math.floor(1.7)));')

    def test_method_called_on_a_parameter_still_folds(self):
        self._check(
            'function use(o) { return o.floor(1.7); } console.log(String(use(Math)));')

    def test_write_on_a_constant_read_off_an_intrinsic_still_folds(self):
        """
        Node decides this: a property written on the number `Math.PI` is invisible to `Math.floor`, so the
        walk must stop at a non-surface key. Continuing through every member access instead would refuse
        every file that hands out a constant.
        """
        self._check(
            'function p(v) { v.x = 1; } p(Math.PI); console.log(String(Math.floor(1.7)));')

    def test_write_on_a_method_read_off_an_intrinsic_still_folds(self):
        self._check(
            'function p(v) { v.x = 1; } p(Math.floor); console.log(String(Math.floor(1.7)));')


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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNumericLiteralsAreDoubles(TestBase):
    """
    A JavaScript Number is an IEEE-754 double. Every case here asks whether the tool computes in that
    domain, and asserts the deobfuscated program *text* rather than only its behavior: a comparison of
    behavior alone is satisfied by declining to fold, so it cannot tell a correct implementation from
    one that does nothing at all.

    Node decides what each program means. Every expected value is what a real engine produces, and
    `_folds_to` re-derives that claim by running both programs, so an expectation that is merely
    plausible fails as loudly as a wrong fold does.
    """

    def _folds_to(self, source: str, expected: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(deobfuscated, expected)
        self.assertEqual(behavior(deobfuscated), behavior(source))

    def _prints(self, source: str, output: str):
        """
        For a case whose correct answer does not determine a spelling. The engine's output is asserted of
        the input first, which is the oracle, and then required of the deobfuscation, which leaves the
        tool free either to fold or to decline.
        """
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_large_integer_a_double_represents_exactly_folds_to_that_integer(self):
        self._folds_to(
            'console.log(4503599627370496 * 2);',
            'console.log(9007199254740992);')

    def test_integer_literal_too_precise_for_a_double_folds_to_the_double_it_denotes(self):
        """
        `9007199254740993` has no double of its own and the nearest one is `9007199254740992`, so the
        digits this program prints are not the digits it was written with.
        """
        self._folds_to(
            'console.log(String(9007199254740993));',
            "console.log('9007199254740992');")

    def test_two_spellings_of_one_double_are_equal_and_differ_by_zero(self):
        self._folds_to(
            'console.log(9007199254740993 === 9007199254740992, 9007199254740993 - 9007199254740992);',
            'console.log(true, 0);')

    def test_product_of_two_over_precise_literals_folds_to_the_double_product(self):
        """
        Each operand denotes `2**53`, so the product denotes `2**106`. Multiplying the written digits
        exactly gives `81129638414606699710187514626049`, which is a different double.
        """
        self._folds_to(
            'console.log(String(9007199254740993 * 9007199254740993));',
            "console.log('8.112963841460668e+31');")

    def test_sum_of_exact_operands_whose_result_is_inexact_folds_to_the_double_sum(self):
        self._folds_to(
            'console.log(String(9007199254740992 + 1));',
            "console.log('9007199254740992');")

    def test_arithmetic_that_overflows_the_double_range_still_means_infinity(self):
        """
        Both operands are ordinary doubles and only the product leaves the range. Any finite spelling of
        the result is wrong, and `Infinity` has no literal spelling at all, so this pins the meaning and
        leaves the tool free to decline.
        """
        self._prints('console.log(String(1.7976931348623157e308 * 2));', 'Infinity\n')

    def test_literal_outside_the_double_range_and_its_negation_fold_to_the_infinities(self):
        self._folds_to(
            'console.log(String(1e400), String(-1e400));',
            "console.log('Infinity', '-Infinity');")

    def test_decimal_integer_outside_the_double_range_and_its_negation_fold_to_the_infinities(self):
        """
        The same magnitude written in digits rather than with an exponent, which is the spelling an exact
        integer parse accepts without complaint.
        """
        self._folds_to(
            F'console.log(String({10 ** 400}), String(-{10 ** 400}));',
            "console.log('Infinity', '-Infinity');")

    def test_negative_zero_survives_a_fold(self):
        """
        Negative zero prints as `0` and is `=== 0`, so neither witnesses it. Its reciprocal does:
        `1 / -0` is `-Infinity` where `1 / 0` is `Infinity`.
        """
        self._folds_to('console.log(1 / (0 * -1));', 'console.log(-1e999);')

    def test_bitwise_operators_coerce_an_over_precise_literal_through_its_double(self):
        """
        ToInt32 of `2**53` is `0`, while ToInt32 of the exact integer `2**53 + 1` is `1`. It is the one
        case here whose wrong answer a reader has no way to recognize by inspection.
        """
        self._folds_to(
            'console.log(9007199254740993 | 0, 9007199254740993 >>> 0);',
            'console.log(0, 0);')

    def test_every_radix_spells_the_same_over_precise_integer(self):
        """
        Each line subtracts `2**53` from `2**53 + 1` written in a different base, and all four differences
        are zero because the left operand has no double of its own in any spelling.
        """
        self._folds_to(
            inspect.cleandoc("""
                console.log(0x20000000000001 - 0x20000000000000);
                console.log(0o400000000000000001 - 0o400000000000000000);
                console.log(0400000000000000001 - 0400000000000000000);
                console.log(
                    0b100000000000000000000000000000000000000000000000000001
                    - 0b100000000000000000000000000000000000000000000000000000);
            """),
            inspect.cleandoc("""
                console.log(0);
                console.log(0);
                console.log(0);
                console.log(0);
            """),
        )

    def test_radix_spellings_the_deobfuscator_has_no_reason_to_rewrite_are_left_alone(self):
        self._folds_to(
            'console.log(0xFF, 0o17, 0b1010, 017, 1_000, 1 + 1);',
            'console.log(0xFF, 0o17, 0b1010, 017, 1_000, 2);')

    def test_bigint_arithmetic_is_exact_where_the_same_number_arithmetic_rounds(self):
        self._folds_to(
            'console.log(String(9007199254740993n + 1n), String(9007199254740993 + 1));',
            "console.log(String(9007199254740993n + 1n), '9007199254740992');")

    def test_bigint_beyond_the_double_range_keeps_every_digit(self):
        self._folds_to(
            'console.log(String(2n ** 70n), 1 + 1);',
            'console.log(String(2n ** 70n), 2);')

    def test_a_bigint_added_to_a_number_is_not_folded(self):
        """
        Mixing the two is a `TypeError` in JavaScript, which is what makes a fold that treats a BigInt as
        a Number observable rather than merely imprecise.
        """
        self._folds_to('console.log(1n + 1);', 'console.log(1n + 1);')

    def test_parse_int_yields_the_double_its_digits_denote(self):
        self._folds_to(
            "console.log(String(parseInt('9007199254740993')), String(parseInt('123456789012345678901234567890')));",
            "console.log('9007199254740992', '1.2345678901234568e+29');")

    def test_a_folded_number_is_spelled_the_way_javascript_prints_it(self):
        """
        Node prints these three as `1e+21`, `1e-7` and `0.30000000000000004`. A spelling that denotes the
        same double but is not the one the language produces makes the deobfuscated program harder to
        read than the one it replaced.
        """
        self._folds_to(
            'console.log(1e21 + 0, 1e-7 + 0, 0.1 + 0.2);',
            'console.log(1e+21, 1e-7, 0.30000000000000004);')

    def test_a_byte_array_keeps_its_grid_and_its_values(self):
        """
        The synthesizer lays a long byte array out as a grid of hex bytes, which it decides on from each
        element's value; folding the index is what shows the gridded values are still the array's own.
        """
        self._folds_to(
            inspect.cleandoc("""
                var key = [
                    15, 216, 150, 85, 200, 21, 150, 34, 117, 192, 188, 159, 55, 161, 212,
                    83, 194, 215, 4, 31, 78, 146, 105, 234, 185, 106, 130, 223, 47, 187
                ];
                console.log(key[3 + 4], key.length);
            """),
            inspect.cleandoc("""
                var key = [
                  0x0F, 0xD8, 0x96, 0x55, 0xC8, 0x15, 0x96, 0x22, 0x75, 0xC0, 0xBC, 0x9F, 0x37, 0xA1, 0xD4,
                  0x53, 0xC2, 0xD7, 0x04, 0x1F, 0x4E, 0x92, 0x69, 0xEA, 0xB9, 0x6A, 0x82, 0xDF, 0x2F, 0xBB
                ];
                console.log(34, key.length);
            """),
        )

    def test_an_array_index_folds_only_when_the_folded_number_is_an_integer(self):
        self._folds_to(
            'console.log([10, 20, 30][1 + 1], [10, 20, 30][0.5 + 1]);',
            'console.log(30, [10, 20, 30][1.5]);')

    def test_exponentiation_with_a_large_integer_exponent_terminates(self):
        """
        One double operation answers `Infinity`. Raising an exact integer to the same power instead builds
        a number of half a billion digits, so the property under test is termination and the assertion has
        to bound it in time rather than wait for an answer.
        """
        source = 'console.log(3 ** 1000000000);'
        deobfuscated = deobfuscate_within(source, seconds=20)
        if deobfuscated is None:
            self.fail('the fold did not terminate')
        self.assertEqual(behavior(deobfuscated), ('Infinity\n', None))

    def test_an_integral_double_is_spelled_with_the_digits_an_engine_prints(self):
        """
        Above `2**53` the exact value of a double and the digits JavaScript prints for it part
        ways: node prints `2**64` as `18446744073709552000`, while its exact value is
        `18446744073709551616`. The smaller operands are controls: for them the two readings
        agree, so nothing about them may change.
        """
        self._folds_to(
            inspect.cleandoc("""
                console.log(65536 * 65536, 67108864 * 67108864, 4294967296 * 2097152);
                console.log(4294967296 * 4294967296, 4294967296 * 2147483648, 1e20 + 0);
            """),
            inspect.cleandoc("""
                console.log(4294967296, 4503599627370496, 9007199254740992);
                console.log(18446744073709552000, 9223372036854776000, 100000000000000000000);
            """),
        )

    def test_parse_int_reads_a_base_prefix_only_when_no_radix_contradicts_it(self):
        """
        Node: `31 31 0 77 63`. Without a radix `parseInt` honours the `0x` prefix, an explicit
        radix of 16 accepts it as well, and radix 10 stops the parse at the `x`. A leading zero
        is not a prefix at all, so `'077'` is seventy-seven unless base 8 is asked for.
        """
        self._folds_to(
            "console.log(parseInt('0x1F'), parseInt('0x1F', 16), parseInt('0x1F', 10),"
            " parseInt('077'), parseInt('077', 8));",
            'console.log(31, 31, 0, 77, 63);')

    def test_parse_int_of_a_digit_string_beyond_double_precision_keeps_the_printed_digits(self):
        """
        Node prints these two as `11111111111111110000` and `1.111111111111111e+29`. Neither is
        the digit string it was handed, and the first is not the exact value of its double
        either — that value is `11111111111111110656`, which JavaScript never prints.
        """
        self._folds_to(
            "console.log(String(parseInt('11111111111111111111')),"
            " String(parseInt('111111111111111111111111111111')));",
            "console.log('11111111111111110000', '1.111111111111111e+29');")

    def test_numeric_coercion_declines_a_string_only_python_reads_as_a_number(self):
        """
        Node: the first six are all `NaN`. JavaScript spells an infinity exactly `Infinity` and
        knows no numeric separator inside a string, where Python's own float parser reads `inf`,
        `infinity` and `1_0` happily. The last two are controls: the spellings JavaScript really
        does accept.
        """
        self._folds_to(
            "console.log(Number('inf'), Number('infinity'), Number('-inf'), Number('1_0'),"
            " Math.abs('inf'), Math.round('infinity'), Number('Infinity'), Number('0x1F'));",
            'console.log(0 / 0, 0 / 0, 0 / 0, 0 / 0, 0 / 0, 0 / 0, 1e999, 31);')

    def test_an_integer_literal_beyond_the_double_range_is_neither_an_index_nor_a_radix(self):
        """
        Node: `undefined 10`. The literal denotes `Infinity`, which indexes no array, and which
        `parseInt` reads as radix zero and therefore as its default of ten.
        """
        self._prints(
            F"console.log(String([10, 20, 30][{10 ** 400}]), String(parseInt('10', {10 ** 400})));",
            'undefined 10\n')

    def test_an_integer_literal_beyond_the_double_range_is_not_a_rotation_count(self):
        """
        The literal denotes `Infinity`, so the rotation is a loop no engine ever leaves and the
        program cannot be run. What is left to assert is that the tool hands it back untouched
        rather than rotating the array by some count of its own.
        """
        source = inspect.cleandoc(F"""
            function rot(arr, n) {{
              for (var i = 0; i < n; i++) {{
                arr.push(arr.shift());
              }}
              return arr;
            }}
            console.log(rot(
              ['b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'a'],
              {10 ** 400}
            ).join(''));
        """)
        self.assertEqual(deobfuscate_source(source), source)

    def test_a_folded_negative_number_keeps_the_negation_bound_to_it(self):
        """
        A negation binds more loosely than `**`, than a member access and than a call, so a
        folded negative number needs a parenthesis in each of those positions: `-2 ** e` does
        not parse at all, `-2[k]` negates the element rather than indexing `-2`, and `-2(k)`
        calls `2`. The exponent, key and argument are read from `process.argv`, which no fold
        can know, so the negative number has to survive into the output. Node prints `4`,
        `string`, `undefined` and `TypeError`.
        """
        self._folds_to(
            inspect.cleandoc("""
                console.log((0 - 2) ** process.argv.length);
                console.log(typeof (0 - 2).toString(process.argv.length));
                console.log(String((0 - 2)[process.argv.length]));
                try { (0 - 2)(process.argv.length); } catch (e) { console.log(e.constructor.name); }
            """),
            inspect.cleandoc("""
                console.log((-2) ** process.argv.length);
                console.log(typeof (-2).toString(process.argv.length));
                console.log(String((-2)[process.argv.length]));
                try {
                  (-2)(process.argv.length);
                } catch (e) {
                  console.log(e.constructor.name);
                }
            """),
        )

    def test_negative_zero_survives_the_reformatting_of_a_long_array(self):
        """
        Node: `true` and `-Infinity`. Negative zero prints as `0` and is `=== 0`, so only
        `Object.is` and the reciprocal witness it. The index comes from `process.argv` so that
        the element is fetched from the emitted array at run time rather than folded out of the
        program.
        """
        self._prints(
            inspect.cleandoc("""
                var a = [
                    0 * -1, 216, 150, 85, 200, 21, 150, 34, 117, 192, 188, 159, 55, 161, 212,
                    83, 194, 215, 4, 31, 78, 146, 105, 234, 185, 106, 130, 223, 47, 187
                ];
                console.log(Object.is(a[process.argv.length - 2], -0));
                console.log(1 / a[process.argv.length - 2]);
            """),
            'true\n-Infinity\n',
        )

    def test_a_negative_base_raised_to_an_infinity_is_what_the_engine_says(self):
        """
        Node: `Infinity 0`, then `NaN NaN`, then `0 Infinity`. A magnitude above one and one
        below it answer opposite ways for the two signs of exponent, and a base of exactly `-1`
        is `NaN` for either sign — where Python's own power operator answers `1.0`.
        """
        self._prints(
            inspect.cleandoc("""
                console.log(String(Math.pow(0 - 2, 1e400)), String(Math.pow(0 - 2, -1e400)));
                console.log(String(Math.pow(0 - 1, 1e400)), String(Math.pow(0 - 1, -1e400)));
                console.log(String(Math.pow(0 - 0.5, 1e400)), String(Math.pow(0 - 0.5, -1e400)));
            """),
            'Infinity 0\nNaN NaN\n0 Infinity\n',
        )

    def test_rest_parameter_unpacking_of_an_implausible_length_terminates(self):
        """
        The `length` truncation of a rest array names how many parameters the function was
        written with. A count of a million is no parameter list, and the property under test is
        that deciding so takes bounded time rather than one parameter per counted element.
        """
        source = (
            'var f = function (...s) { s.length = 1000000; return s[0]; };'
            ' console.log(f(1));'
        )
        deobfuscated = deobfuscate_within(source, seconds=20)
        if deobfuscated is None:
            self.fail('the rest parameter unpacking did not terminate')
        self.assertEqual(behavior(deobfuscated), ('1\n', None))

    def test_a_string_that_names_negative_zero_folds_to_negative_zero(self):
        """
        Node: `-Infinity true -Infinity true`. `Number('-0')` and `parseInt('-0')` are both negative
        zero, which prints as `0` and is `=== 0`, so only the reciprocal and `Object.is` witness it.
        A sign carried through a Python integer is lost, because that type has a single zero.
        """
        self._folds_to(
            "console.log(1 / Number('-0'), Object.is(Number('-0'), -0),"
            " 1 / parseInt('-0'), Object.is(parseInt('-0'), -0));",
            'console.log(-1e999, Object.is(-0, -0), -1e999, Object.is(-0, -0));')

    def test_unary_plus_on_a_string_that_names_negative_zero_folds_to_negative_zero(self):
        """
        Node: `-Infinity true`. The same coercion reached through the operator rather than through
        the call.
        """
        self._folds_to(
            "var f = function () { return +'-0'; };"
            ' console.log(1 / f(), Object.is(f(), -0));',
            'console.log(-1e999, Object.is(-0, -0));')

    def test_numeric_coercion_refuses_the_decimal_digits_only_python_reads(self):
        """
        Node: `NaN NaN NaN`. The Arabic-Indic, fullwidth and Devanagari digit strings each name one
        hundred and twenty-three to Python's `int` and `float`. The language's numeric grammar has
        no digit outside `0` through `9`, so none of them names a number at all.
        """
        self._folds_to(
            R"console.log(Number('\u0661\u0662\u0663'), Number('\uFF11\uFF12\uFF13'),"
            R" Number('\u0967\u0968\u0969'));",
            'console.log(0 / 0, 0 / 0, 0 / 0);')

    def test_numeric_coercion_refuses_the_padding_only_python_strips(self):
        """
        Node: `NaN NaN NaN NaN`. `U+001C` through `U+001F` are removed by Python's `str.strip` and
        are not ECMAScript WhiteSpace, so every string here carries a leading character the grammar
        does not allow before a digit.
        """
        self._folds_to(
            R"console.log(Number('\u001C5'), Number('\u001D5'), Number('\u001E5'),"
            R" Number('\u001F5'));",
            'console.log(0 / 0, 0 / 0, 0 / 0, 0 / 0);')

    def test_parse_int_refuses_the_padding_only_python_strips(self):
        """
        Node: `NaN NaN NaN NaN`. `parseInt` skips leading whitespace and then reads digits, so a
        leading character that is not whitespace ends the parse before any digit is seen.
        """
        self._prints(
            R"console.log(String(parseInt('\u001C5')), String(parseInt('\u001D5')),"
            R" String(parseInt('\u001E5')), String(parseInt('\u001F5')));",
            'NaN NaN NaN NaN\n')

    def test_numeric_coercion_accepts_the_byte_order_mark_as_whitespace(self):
        """
        Node: `5 5 5 12`. `U+FEFF` is ECMAScript WhiteSpace and Python's `str.strip` leaves it in
        place, so it pads a number on either side exactly as a space does.
        """
        self._folds_to(
            R"console.log(Number('\uFEFF5'), Number('5\uFEFF'), parseInt('\uFEFF5'),"
            R" Number('\uFEFF\uFEFF12\uFEFF'));",
            'console.log(5, 5, 5, 12);')

    def test_unary_plus_reads_the_padding_and_digits_the_engine_reads(self):
        """
        Node: `NaN NaN 5`. The three classes of string above reached through the operator, whose
        coercion is written once for `Number`, once for `parseInt` and once for `+`.
        """
        self._prints(
            R"var f = function () { return +'\u0661\u0662\u0663'; };"
            R" var g = function () { return +'\u001C5'; };"
            R" var h = function () { return +'\uFEFF5'; };"
            ' console.log(String(f()), String(g()), String(h()));',
            'NaN NaN 5\n')

    def test_arithmetic_on_a_string_reads_the_number_the_language_reads(self):
        """
        Node: `1000 42 NaN NaN -Infinity 32 12`. Every operator coerces its string operand through
        the same grammar the `Number` call uses, which reads an exponent, refuses one it does not
        finish, refuses the numeric separator, and keeps the sign of a zero.
        """
        self._prints(
            "console.log(+'1e3', +' 42 ', String(+'1e'), String(+'1_0'), 1 / +'-0',"
            " String(+'0x10' * 2), String('3' * '4'));",
            '1000 42 NaN NaN -Infinity 32 12\n')

    def test_a_string_coerced_behind_a_function_reads_the_same_grammar(self):
        """
        Node: `1000 NaN Infinity 16`. The same coercion where the string arrives as an argument
        rather than standing beside the operator.
        """
        self._prints(
            'var f = function (s) { return s * 1; };'
            " console.log(f('1e3'), String(f('1e')), String(f('Infinity')), f('0x10'));",
            '1000 NaN Infinity 16\n')

    def test_parse_int_reads_its_radix_through_the_signed_32_bit_wrap(self):
        """
        Node: `16 10 255`. The radix is coerced with ToInt32, so `2**32 + 16` selects base sixteen,
        `2**32` selects nothing and leaves the default of ten, and a negative value wraps the same
        way. Truncating instead names a radix outside 2 to 36, which is `NaN` for every string.
        """
        self._folds_to(
            "var f = function () { return parseInt('10', 4294967312); };"
            " var g = function () { return parseInt('10', 4294967296); };"
            " var h = function () { return parseInt('ff', -4294967280); };"
            ' console.log(f(), g(), h());',
            'console.log(16, 10, 255);')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestParseFloatGrammar(TestBase):
    """
    `parseFloat` reads the longest prefix of its argument that spells a decimal literal, and that
    grammar is wider than a run of digits and a point: it admits an exponent, and it admits the word
    `Infinity` behind an optional sign. Node says what number each string names, and the emitted
    program has to name the same one whether the tool folds the call or leaves it standing.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_the_grammar_without_an_exponent_or_an_infinity_folds_to_its_numbers(self):
        """
        Node: `3.14 42 2.5 0 1 1.2 NaN NaN`. Padding is skipped, the parse stops at the first
        character that cannot continue the literal, and a prefix of `Infinity` is not one.
        """
        source = (
            "console.log(parseFloat('3.14'), parseFloat(' 42 '), parseFloat('2.5abc'),"
            " parseFloat('0x10'), parseFloat('1e'), parseFloat('1.2.3'), parseFloat('Infinit'),"
            " parseFloat('nope'));")
        self._prints(source, '3.14 42 2.5 0 1 1.2 NaN NaN\n')
        self.assertEqual(
            deobfuscate_source(source),
            'console.log(3.14, 42, 2.5, 0, 1, 1.2, 0 / 0, 0 / 0);')

    def test_an_exponent_belongs_to_the_literal_parse_float_reads(self):
        """
        Node: `1000 1000 1000 0.001 50 -150`. Stopping at the `e` reads a mantissa the string never
        names on its own, so every one of these is off by a factor the exponent decides.
        """
        self._prints(
            "console.log(parseFloat('1e3'), parseFloat('1E3'), parseFloat('1e+3'),"
            " parseFloat('1e-3'), parseFloat('.5e2'), parseFloat('-1.5e2'));",
            '1000 1000 1000 0.001 50 -150\n')

    def test_the_word_infinity_is_a_literal_parse_float_reads(self):
        """
        Node: `Infinity -Infinity Infinity Infinity`. The word carries an optional sign and, like
        every other parse here, ends wherever the literal does rather than at the end of the string.
        """
        self._prints(
            "console.log(parseFloat('Infinity'), parseFloat('-Infinity'),"
            " parseFloat('+Infinity'), parseFloat('Infinityabc'));",
            'Infinity -Infinity Infinity Infinity\n')

    def test_an_exponent_that_is_begun_and_never_finished_shortens_the_literal(self):
        """
        Node: `1 1 1 1 1.2 100 1 1000`. An exponent the string does not complete is not an error but
        a shorter literal, so each of these names the mantissa alone — and `1e2.5` names a hundred,
        the point ending an exponent that was completed by the digit ahead of it.
        """
        self._prints(
            "console.log(parseFloat('1e'), parseFloat('1E'), parseFloat('1e+'), parseFloat('1e-'),"
            " parseFloat('1.2e'), parseFloat('1e2.5'), parseFloat('1ee3'), parseFloat('1e+3e4'));",
            '1 1 1 1 1.2 100 1 1000\n')

    def test_an_exponent_with_no_digits_ahead_of_it_names_no_number(self):
        """
        Node: `NaN NaN 50`. A mantissa may be written as a bare fraction but never omitted.
        """
        self._prints(
            "console.log(String(parseFloat('e3')), String(parseFloat('.e3')),"
            " parseFloat('.5e2'));",
            'NaN NaN 50\n')

    def test_a_sign_is_read_where_the_literal_begins_and_nowhere_else(self):
        """
        Node: `1 -0.5 NaN NaN 1 NaN`. A sign belongs to the literal only where it is adjacent to
        one, so a space behind it or a second sign ahead of it leaves a string naming nothing, while
        a sign behind the digits is merely where the parse stops.
        """
        self._prints(
            "console.log(parseFloat('+1'), parseFloat('-.5'), String(parseFloat('- 1')),"
            " String(parseFloat('+-1')), parseFloat('1-'), String(parseFloat('-')));",
            '1 -0.5 NaN NaN 1 NaN\n')

    def test_an_infinity_by_overflow_and_a_zero_by_underflow_keep_their_signs(self):
        """
        Node: `Infinity -Infinity true false 5e-324`. A magnitude the double range cannot hold
        becomes an infinity and one below its smallest subnormal becomes a zero, and both keep the
        sign the string was written with. `Object.is` is the only witness of the negative zero,
        which prints as `0` and is `=== 0`.
        """
        self._prints(
            "console.log(String(parseFloat('1e999')), String(parseFloat('-1e999')),"
            " Object.is(parseFloat('-1e-999'), -0), Object.is(parseFloat('1e-999'), -0),"
            " String(parseFloat('5e-324')));",
            'Infinity -Infinity true false 5e-324\n')

    def test_a_parse_that_stops_at_a_base_prefix_keeps_the_sign_of_its_zero(self):
        """
        Node: `true true true false`. `parseFloat` reads no base other than ten, so it stops at the
        letter and answers the signed zero the two characters ahead of it name.
        """
        self._prints(
            "console.log(Object.is(parseFloat('-0'), -0), Object.is(parseFloat('-0x10'), -0),"
            " Object.is(parseFloat('-0b101'), -0), Object.is(parseFloat('+0x10'), -0));",
            'true true true false\n')

    def test_padding_is_what_the_language_calls_whitespace_and_nothing_else(self):
        """
        Node: `2.5 -150 NaN NaN 5 NaN`. `U+FEFF`, `U+00A0` and `U+3000` are whitespace to the
        language, two of which Python's `str.strip` also removes and one of which it leaves.
        `U+0085` and `U+001C` are the reverse, removed by `str.strip` and not whitespace here, and
        `U+200B` is neither.
        """
        self._prints(
            R"console.log(parseFloat('\uFEFF 2.5'), parseFloat('\u00A0-1.5e2\u3000'),"
            R" String(parseFloat('\u00855')), String(parseFloat('\u001C5')),"
            R" parseFloat('5\u0085'), String(parseFloat('\u200B5')));",
            '2.5 -150 NaN NaN 5 NaN\n')

    def test_digits_of_another_script_and_characters_that_look_like_digits_are_not_digits(self):
        """
        Node: `NaN 1 NaN 2 NaN`. The Arabic-Indic digits, the superscript two and the Roman numeral
        all satisfy one of Python's `isdigit` or `isnumeric`; the language's decimal digits are `0`
        through `9` and nothing else, so each of them is only where a parse stops.
        """
        self._prints(
            R"console.log(String(parseFloat('\u0661\u0662\u0663')), parseFloat('1\u0661'),"
            R" String(parseFloat('\u00B2')), parseFloat('2\u00B2'),"
            R" String(parseFloat('\u216B')));",
            'NaN 1 NaN 2 NaN\n')

    def test_a_base_other_than_ten_is_read_no_further_than_its_prefix(self):
        """
        Node: `0 0 0 1 777 10`. A leading zero selects no base at all, so `0777` is read in full.
        """
        self._prints(
            "console.log(parseFloat('0x10'), parseFloat('0b101'), parseFloat('0o17'),"
            " parseFloat('1_0'), parseFloat('0777'), parseFloat('10n'));",
            '0 0 0 1 777 10\n')

    def test_an_empty_string_names_no_number_here_and_zero_to_the_whole_string_reader(self):
        """
        Node: `NaN NaN NaN 0 0 0`. This is the one place the two readings of a string differ on text
        that contains no digit at all.
        """
        self._prints(
            R"console.log(String(parseFloat('')), String(parseFloat('   ')),"
            R" String(parseFloat('\uFEFF')), Number(''), Number('   '), Number('\uFEFF'));",
            'NaN NaN NaN 0 0 0\n')

    def test_a_very_long_run_of_digits_names_the_infinity_it_denotes(self):
        """
        Node: `Infinity Infinity Infinity NaN`. Four hundred digits are a number the double range
        cannot hold, whether written out or reached through an exponent of four hundred digits.
        """
        digits = '1' * 400
        self._prints(
            F"console.log(String(parseFloat('{digits}')), String(parseFloat('1e{'9' * 400}')),"
            F" String(parseFloat('{digits}x')), String(Number('{digits}x')));",
            'Infinity Infinity Infinity NaN\n')

    def test_parse_float_reached_through_a_name_reads_the_same_grammar(self):
        """
        Node: `2.5 1 NaN`.
        """
        self._prints(
            "var read = parseFloat;"
            " console.log(read('2.5abc'), read('1e'), String(read('nope')));",
            '2.5 1 NaN\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestStringTrimReadsTheWhitespaceOfTheLanguage(TestBase):
    """
    `trim`, `trimStart` and `trimEnd` remove ECMAScript WhiteSpace together with the line
    terminators, which is not the set Python's `str.strip` removes without an argument: the two
    disagree in both directions, so a trim written with Python's default keeps a character the engine
    takes off and takes off five the engine keeps.

    Each case compares the trimmed string with the exact string the language leaves it as, so every
    boolean Node prints is `true` and a trim that removed one character too many or too few prints
    `false`. One case additionally asserts the emitted text, because a comparison of behavior alone
    is satisfied by declining to fold and cannot tell a correct trim from an absent one.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_the_padding_only_python_strips_survives_a_trim(self):
        """
        Node: `true true true true true`. `U+001C` through `U+001F` and `U+0085` are all removed by
        `str.strip` and none of them is ECMAScript WhiteSpace, so `trim` leaves each string whole.
        """
        self._prints(
            R"console.log('\u001CX\u001C'.trim() === '\u001CX\u001C',"
            R" '\u001DX\u001D'.trim() === '\u001DX\u001D',"
            R" '\u001EX\u001E'.trim() === '\u001EX\u001E',"
            R" '\u001FX\u001F'.trim() === '\u001FX\u001F',"
            R" '\u0085X\u0085'.trim() === '\u0085X\u0085');",
            'true true true true true\n')

    def test_the_byte_order_mark_python_leaves_in_place_is_taken_off_by_all_three(self):
        """
        Node: `true true true`. `U+FEFF` is ECMAScript WhiteSpace and `str.strip` keeps it, so it is
        the one character each of the three methods removes that Python's default does not.
        """
        source = (
            R"console.log('\uFEFFX\uFEFF'.trim() === 'X', '\uFEFFX'.trimStart() === 'X',"
            R" 'X\uFEFF'.trimEnd() === 'X');")
        self._prints(source, 'true true true\n')
        self.assertEqual(deobfuscate_source(source), 'console.log(true, true, true);')

    def test_one_end_is_trimmed_with_the_set_that_trims_both(self):
        """
        Node: `true true`. A character the language keeps is kept by `trimStart` and by `trimEnd` as
        well, so the three methods cannot be read as three different sets.
        """
        self._prints(
            R"console.log('\u001CX'.trimStart() === '\u001CX', 'X\u0085'.trimEnd() === 'X\u0085');",
            'true true\n')

    def test_every_whitespace_character_is_taken_off_and_a_look_alike_is_not(self):
        """
        Node: `true true`. The first string is padded with every character the WhiteSpace and the
        LineTerminator productions name, and the second with the zero width space, which is a `Cf`
        character the productions do not name however much it reads like one.
        """
        self._prints(
            R"console.log('\u0009\u000A\u000B\u000C\u000D\u0020\u00A0\u1680\u2000"
            R"\u200A\u2028\u2029\u202F\u205F\u3000\uFEFFX'.trimStart() === 'X',"
            R" '\u200BX\u200B'.trim() === '\u200BX\u200B');",
            'true true\n')

    def test_a_trim_stops_at_the_first_character_the_language_keeps(self):
        """
        Node: `true`. Each side is padded with a mark and a space and then a character that stops
        the trim, so what is left begins and ends with one `str.strip` would have removed.
        """
        self._prints(
            R"console.log('\uFEFF \u001CX\u0085 \uFEFF'.trim() === '\u001CX\u0085');",
            'true\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestParseIntEvaluatesEveryArgumentItIsWrittenWith(TestBase):
    """
    A call evaluates each argument it is written with, and how many of them the function reads has
    nothing to do with it. `parseInt` reads two, so replacing a call of it with the number those two
    name is only the same program while everything else the call was written with still runs: an
    argument can throw, and an argument can write.
    """

    def _preserves(self, source: str, expected: tuple[str, str | None]):
        self.assertEqual(expected, behavior(source))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            expected,
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_third_argument_that_names_nothing_throws_before_parse_int_is_reached(self):
        """
        Node prints nothing and exits with an uncaught `ReferenceError`: the arguments are evaluated
        before the call and `nowhere` is declared in no scope. A rewrite that keeps only the two
        arguments the function reads turns a program that throws into one that prints `2`.
        """
        self._preserves("console.log(parseInt('10', 2, nowhere));", ('', 'ReferenceError'))

    def test_a_third_argument_that_increments_is_evaluated(self):
        """
        Node: `2 1`. The string and the radix decide the result and the third argument decides `x`,
        so one program witnesses both the number the call names and the write a fold must not drop.
        """
        self._preserves("var x = 0; console.log(parseInt('10', 2, x++), x);", ('2 1\n', None))

    def test_a_third_argument_that_calls_is_evaluated(self):
        """
        Node: `2 third`. The same argument list where the effect is a call rather than a write.
        """
        self._preserves(
            "var sink = []; var n = parseInt('10', 2, sink.push('third'));"
            " console.log(n, sink.join('|'));",
            ('2 third\n', None))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestUnaryOperatorFoldCoverage(TestBase):
    """
    Every unary operator whose result is decided by its operand, asserted to be folded away. Each case is
    written as an assertion about the emitted text rather than about behavior, because a deobfuscator that
    declined every one of these folds would still preserve behavior: an untouched program behaves like
    itself, so `behavior(input) == behavior(output)` cannot tell a fold from a refusal.

    The behavioral control is kept as its own test at the end, over the same sources, so a fold that
    silently changes what a case computes fails there rather than passing here.
    """

    def _folds(self, source: str, token: str):
        """
        Assert the deobfuscated output no longer contains *token*, i.e. the operator was folded away.
        """
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            token in deobfuscated,
            False,
            F'{token!r} was not folded; result was:\n{deobfuscated}',
        )

    def _preserves(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_bitwise_not_of_nan_folds(self):
        """
        Node: `~NaN` is `-1`, since ToInt32 maps every non-finite value to zero.
        """
        self._folds('console.log(String(~NaN));', '~')

    def test_bitwise_not_of_infinity_folds(self):
        """
        Node: `~Infinity` is `-1`, since ToInt32 maps every non-finite value to zero.
        """
        self._folds('console.log(String(~Infinity));', '~')

    def test_bitwise_not_of_negative_infinity_folds(self):
        self._folds('console.log(String(~(-Infinity)));', '~')

    def test_typeof_null_folds(self):
        """
        Node: `'object'`, the answer `typeof` has given for `null` since the first edition.
        """
        self._folds('console.log(typeof null);', 'typeof')

    def test_typeof_undefined_folds(self):
        self._folds('console.log(typeof undefined);', 'typeof')

    def test_typeof_an_object_literal_folds(self):
        self._folds('console.log(typeof {});', 'typeof')

    def test_typeof_an_array_literal_folds(self):
        self._folds('console.log(typeof []);', 'typeof')

    def test_typeof_a_function_expression_folds(self):
        """
        Node: `'function'`. Worth folding because an obfuscator uses exactly this to test for a callable.
        """
        self._folds('console.log(typeof function () {});', 'typeof')

    def test_unary_plus_on_a_string_literal_folds(self):
        """
        Node: `+'12'` is `12`. Numeric coercion of a string literal is decided by the syntax alone.
        """
        self._folds("console.log(String(+'12'));", '+')

    def test_unary_plus_on_null_folds(self):
        self._folds('console.log(String(+null));', '+')

    def test_logical_not_of_an_object_literal_folds(self):
        """
        Node: `false`. Every object is truthy, whichever literal form creates it.
        """
        self._folds('console.log(String(!{}));', '!')

    def test_delete_of_a_property_of_a_local_object_literal_folds(self):
        """
        Node: `true`, and the property is gone. `delete` mutates, so folding it away is only sound when the
        mutation cannot be observed — which is what this source arranges by never reading `o.a` again.
        """
        self._folds("var o = { a: 1 }; console.log(String(delete o.a));", 'delete')

    def test_typeof_a_numeric_literal_already_folds(self):
        """
        The controls: three `typeof` operands are already handled, and a consolidation must not lose them.
        """
        self._folds('console.log(typeof 1);', 'typeof')

    def test_typeof_a_string_literal_already_folds(self):
        self._folds("console.log(typeof 'a');", 'typeof')

    def test_typeof_a_boolean_literal_already_folds(self):
        self._folds('console.log(typeof true);', 'typeof')

    def test_void_already_folds(self):
        self._folds('console.log(String(void 7));', 'void')

    def test_logical_not_of_null_already_folds(self):
        self._folds('console.log(String(!null));', '!')

    def test_bitwise_not_of_a_finite_number_already_folds(self):
        self._folds('console.log(String(~1e21));', '~')

    def test_every_folded_unary_still_behaves_correctly(self):
        """
        The load-bearing control for this whole class: none of the folds above is a miscompile. The tests
        above assert only that the operator disappeared, which a fold to the wrong value satisfies too.
        """
        for source in (
            'console.log(String(~NaN));',
            'console.log(String(~Infinity));',
            'console.log(String(~(-Infinity)));',
            'console.log(typeof null);',
            'console.log(typeof undefined);',
            'console.log(typeof {});',
            'console.log(typeof []);',
            'console.log(typeof function () {});',
            "console.log(String(+'12'));",
            'console.log(String(+null));',
            'console.log(String(!{}));',
            'var o = { a: 1 }; console.log(String(delete o.a));',
        ):
            with self.subTest(source=source):
                self._preserves(source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNegatedInfinityTermination(TestBase):
    """
    An infinity is a Number that no numeric literal spells: `Infinity` is a global binding,
    `-Infinity` is an operator applied to that binding, and a literal large enough to denote one is
    a spelling of digits rather than of the value they overflow to. A pass that folds such an
    expression and writes the answer back has nothing to write but an expression of the shape it
    just consumed, and a pass that keeps consuming its own output never settles.

    Each case is a small, ordinary program whose deobfuscation has to finish in bounded time. What
    it finishes as is deliberately left open, because declining a fold is always allowed and looping
    on one never is; only Node's verdict on the program is required to survive.
    """

    def _terminates_and_prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        try:
            deobfuscated = deobfuscate_within(source, seconds=20)
        except DeobfuscationFailed as failure:
            self.fail(F'the deobfuscation did not run to completion:\n{failure}')
        if deobfuscated is None:
            self.fail('the deobfuscation did not terminate')
        self.assertEqual(behavior(deobfuscated), (output, None))

    def test_negative_infinity_terminates(self):
        self._terminates_and_prints('console.log(String(-Infinity));', '-Infinity\n')

    def test_unary_plus_applied_to_negative_infinity_terminates(self):
        self._terminates_and_prints('console.log(String(+(-Infinity)));', '-Infinity\n')

    def test_negation_of_a_string_naming_infinity_terminates(self):
        self._terminates_and_prints("console.log(String(-('Infinity')));", '-Infinity\n')

    def test_negation_of_a_literal_that_overflows_to_infinity_terminates(self):
        self._terminates_and_prints('console.log(String(-(2e308)));', '-Infinity\n')

    def test_negative_infinity_consumed_by_arithmetic_terminates(self):
        self._terminates_and_prints(
            'console.log(String(-Infinity + 1), 1 / -Infinity);', '-Infinity -0\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestFoldedNegativeNumbers(TestBase):
    """
    JavaScript has no negative numeric literal: `-5` is the negation operator applied to `5`. A fold
    that arrives at a negative number therefore has two ways to record it that print the same text,
    and a consumer that reads only one of them stops folding exactly where the other carries on.

    Every case computes negative five a different way, hands it to the same four consumers, and has
    to end at the program the written `-5` ends at. Node decides what all of them mean: each source
    here prints one and the same line.
    """

    _FOLDED = "console.log(-10, 20, '-5', 'bcdef');"
    _OUTPUT = '-10 20 -5 bcdef\n'

    def _folds_like_a_written_negative(self, source: str):
        self.assertEqual(behavior(source), (self._OUTPUT, None))
        self.assertEqual(deobfuscate_source(source), self._FOLDED)

    def test_a_written_negative_is_consumed_by_every_fold(self):
        self.assertEqual(behavior(self._FOLDED), (self._OUTPUT, None))
        self._folds_like_a_written_negative(
            "console.log(-5 * 2, [10, 20, 30][-5 + 6], String(-5), 'abcdef'.slice(-5));")

    def test_a_negative_difference_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            'console.log((0 - 5) * 2, [10, 20, 30][(0 - 5) + 6], String(0 - 5),'
            " 'abcdef'.slice(0 - 5));")

    def test_a_negated_sum_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            'console.log(-(2 + 3) * 2, [10, 20, 30][-(2 + 3) + 6], String(-(2 + 3)),'
            " 'abcdef'.slice(-(2 + 3)));")

    def test_a_bitwise_complement_that_is_negative_is_consumed_by_every_fold(self):
        """
        `~4` is negative five and nothing in the source is written with a sign at all, so the
        negation can only have been introduced by the fold.
        """
        self._folds_like_a_written_negative(
            "console.log(~4 * 2, [10, 20, 30][~4 + 6], String(~4), 'abcdef'.slice(~4));")

    def test_a_negated_numeric_string_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            "console.log(-'5' * 2, [10, 20, 30][-'5' + 6], String(-'5'), 'abcdef'.slice(-'5'));")

    def test_a_negative_carried_through_unary_plus_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            'console.log(+(-5) * 2, [10, 20, 30][+(-5) + 6], String(+(-5)),'
            " 'abcdef'.slice(+(-5)));")

    def test_a_negative_from_string_coercion_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            "console.log(Number('-5') * 2, [10, 20, 30][Number('-5') + 6], String(Number('-5')),"
            " 'abcdef'.slice(Number('-5')));")

    def test_a_negative_rounded_by_math_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            'console.log(Math.round(-4.6) * 2, [10, 20, 30][Math.round(-4.6) + 6],'
            " String(Math.round(-4.6)), 'abcdef'.slice(Math.round(-4.6)));")

    def test_a_negative_bound_to_a_variable_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            'var n = ~4;'
            " console.log(n * 2, [10, 20, 30][n + 6], String(n), 'abcdef'.slice(n));")

    def test_a_negative_returned_by_a_function_is_consumed_by_every_fold(self):
        self._folds_like_a_written_negative(
            'var f = function () { return 0 - 5; };'
            " console.log(f() * 2, [10, 20, 30][f() + 6], String(f()), 'abcdef'.slice(f()));")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestClassMemberNamesArePropertyKeys(TestBase):
    """
    The name of a class field or method is a property key, exactly as the `foo` in `obj.foo` and in
    `{ foo: 1 }` is, and never a read of a binding that happens to be spelled the same. Every case
    declares a variable under the member's name, so reading the member name as a use of that binding
    renames the member: the field then answers `undefined` under the name it was written with, and
    the method is no longer there to be called. Node says what each program prints.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_computed_class_member_name_is_a_variable_read(self):
        """
        The control for the four cases below: in brackets the name really is an expression, so the
        binding must be substituted there and the key the class ends up with is its value.
        """
        source = (
            "var k = 'a'; class C { [k] = 1; }"
            " console.log(new C().a, Object.keys(new C()).join('|'));")
        self._prints(source, '1 a\n')
        self.assertEqual(
            deobfuscate_source(source),
            inspect.cleandoc(
                """
                class C {
                  ['a'] = 1;
                }
                console.log(new C().a, Object.keys(new C()).join('|'));
                """
            ),
        )

    def test_an_instance_field_name_is_not_a_variable_read(self):
        """
        Node: `1 label X`. The instance carries one property and it is named `label`, so a rewritten
        key is observable both through the access and through the list of keys.
        """
        self._prints(
            "var label = 'X'; class C { label = 1; }"
            " console.log(new C().label, Object.keys(new C()).join('|'), label);",
            '1 label X\n')

    def test_an_instance_method_name_is_not_a_variable_read(self):
        """
        Node: `5 hi`. A renamed method leaves `new C().greet` undefined, so the call is a `TypeError`
        and not merely a wrong value.
        """
        self._prints(
            "var greet = 'hi'; class C { greet() { return 5; } }"
            ' console.log(new C().greet(), greet);',
            '5 hi\n')

    def test_a_static_field_name_is_not_a_variable_read(self):
        """
        Node: `7 T`. The property belongs to the constructor rather than to an instance, which is a
        second place a member name is written.
        """
        self._prints(
            "var tag = 'T'; class C { static tag = 7; } console.log(C.tag, tag);",
            '7 T\n')

    def test_a_static_method_name_is_not_a_variable_read(self):
        """
        Node: `9 R`.
        """
        self._prints(
            "var run = 'R'; class C { static run() { return 9; } } console.log(C.run(), run);",
            '9 R\n')


class TestANamedEntrypointIsKeptInTheEmittedText(TestBase):
    """
    The `entrypoints` option is a promise about the output: a host reaches each named binding once
    the file has loaded, so under the script execution model the binding, everything it reaches, and
    every read of it survive in the emitted text. A host that can reach a name can also have
    rewritten it, so a folded copy of its value is a value the host never gets to replace. Each case
    drives the file with an outer call so the library rule that keeps a file of only declarations
    does not apply, and pairs the kept output against the control that removes or folds the same
    binding when no entrypoint names it, so the entrypoint is shown to be what keeps it.

    The data global is the shape the release was held for: `refinery.lib.scripts.js.deobfuscation`
    folded `var VERSION = 3` into its readers and dropped the declaration, so a host reading
    `globalThis.VERSION` after load got `undefined` where the source gave it `3`. The module model
    protects nothing here, which the sibling class below pins.

    A constant object and a built-up namespace object are the same data global in the two other
    shapes: the object folder inlines `CFG.v` and the namespace flattener splits `NS` into loose
    globals, and each drops the `var` a host reaches by name unless the same predicate stops it.
    """

    def test_a_declared_function_named_as_an_entrypoint_is_kept(self):
        source = 'function handler() { return 5; } run();'
        self.assertEqual(deobfuscate_source(source), 'run();')
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('handler',)),
            'function handler() {\n  return 5;\n}\nrun();',
        )

    def test_a_helper_an_entrypoint_reaches_is_kept(self):
        source = (
            'function help() { console.log("hi!"); return 7; }'
            ' function handler() { return help(); } run();'
        )
        self.assertEqual(deobfuscate_source(source), 'run();')
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('handler',)),
            'function help() {\n  console.log("hi!");\n  return 7;\n}\n'
            'function handler() {\n  return help();\n}\nrun();',
        )

    def test_a_data_global_named_as_an_entrypoint_survives_unfolded(self):
        source = 'var VERSION = 3; console.log(VERSION);'
        self.assertEqual(deobfuscate_source(source), 'console.log(3);')
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('VERSION',)),
            'var VERSION = 3;\nconsole.log(VERSION);',
        )

    def test_an_object_global_named_as_an_entrypoint_survives_unfolded(self):
        source = 'var CFG = { v: 3 }; console.log(CFG.v);'
        self.assertEqual(deobfuscate_source(source), 'console.log(3);')
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('CFG',)),
            'var CFG = { v: 3 };\nconsole.log(CFG.v);',
        )

    def test_a_namespace_object_named_as_an_entrypoint_survives_unflattened(self):
        source = 'var NS = {}; NS.greet = function () { return 7; }; console.log(NS.greet());'
        self.assertEqual(deobfuscate_source(source), 'console.log(7);')
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('NS',)),
            'var NS = {};\nNS.greet = function() {\n  return 7;\n};\nconsole.log(NS.greet());',
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestUndeclaredHostObservableGlobals(TestBase):
    def assertSameBehavior(self, source: str, *, calls: tuple[str, ...], entrypoints: tuple[str, ...] = ()):
        deobfuscated = deobfuscate_source(source, entrypoints=entrypoints)
        self.assertEqual(
            host_behavior(source, calls=calls),
            host_behavior(deobfuscated, calls=calls),
            F'deobfuscation changed what a host observes; result was:\n{deobfuscated}',
        )

    def test_handler_held_by_var_01(self):
        source = 'var handler = function () { return 5; };'
        self.assertEqual(deobfuscate_source(source), '')
        self.assertSameBehavior(source, calls=('handler',), entrypoints=('handler',))

    def test_handler_held_by_var_02(self):
        source = 'var handler = () => 5;'
        self.assertEqual(deobfuscate_source(source), '')
        self.assertSameBehavior(source, calls=('handler',), entrypoints=('handler',))

    def test_unexported_global_folds(self):
        self.assertEqual(
            deobfuscate_source('var VERSION = 3; console.log(VERSION);'),
            'console.log(3);')

    def test_module_scoped_var_is_removed_even_when_exported(self):
        """
        Under the module model a top-level binding is scoped to the module and never becomes a property
        of the global object — Node reports `typeof globalThis.handler` as `undefined` for this source
        run as CommonJS — so no host can reach it by name and removing it is sound however it is named.
        These assertions read the emitted text because `host_behavior` observes the global object, which
        the binding never joins, and would compare `undefined` against `undefined`.
        """
        source = 'var handler = function () { return 5; };'
        self.assertEqual(deobfuscate_source(source, module=True, entrypoints=('handler',)), '')

    def test_module_scoped_global_still_folds_when_exported(self):
        source = 'var VERSION = 3; console.log(VERSION);'
        self.assertEqual(
            deobfuscate_source(source, module=True, entrypoints=('VERSION',)),
            'console.log(3);')

    @unittest.expectedFailure
    def test_module_scoped_dead_function_is_removed_even_when_exported(self):
        source = 'function handler() { return 5; }'
        self.assertEqual(deobfuscate_source(source, module=True, entrypoints=('handler',)), '')


class TestDeobfuscateWithin(TestBase):
    """
    The timeout helper is an oracle in its own right: every test that reads its `None` as "the
    fold did not terminate" is only as trustworthy as the helper's ability to tell that verdict
    apart from any other way a child process can fail to hand its answer back.
    """

    def test_a_deobfuscation_whose_program_is_not_ascii_is_reported_as_finished(self):
        """
        The result crosses a process boundary, and the console codec of the machine running the
        tests has no say in what a JavaScript program may contain. A program those characters
        cannot be spelled in must come back as itself, not as a timeout and not as a failed
        child.
        """
        source = "console.log('日本語');"
        self.assertEqual(deobfuscate_within(source, seconds=20), source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDecidedTestsKeepTheirEffects(TestBase):
    """
    A conditional, `&&`, `||` and `??` whose test is decidable folds to the operand that runs.
    Evaluating the test remains part of what the program does: it can call a function, or read a
    property whose getter runs. Which operand the fold discards is not the same for all four — the
    conditional discards the test and the untaken branch, `&&` with a truthy test discards the
    test, and `||` and `??` keep the test as their result and discard the right-hand side instead —
    so each shape is written out.

    Every test here allocates an array, which is truthy whatever it contains: that is what makes a
    test decidable while it still runs a call or an accessor. Each case names the program a fold
    that lost the effect would produce and requires it to behave differently, so that a case whose
    discarded operand printed nothing cannot pass for a proof.
    """

    _CALL = inspect.cleandoc("""
        var SINK = [];
        function t(v) {
          SINK.push(v);
          return v;
        }
    """)

    _GETTER = inspect.cleandoc("""
        var SINK = [];
        var o = { get p() {
          SINK.push('g');
          return 1;
        } };
    """)

    def _preserves(self, preamble: str, source: str, misfolded: str):
        program = F'{preamble}\n{source}'
        self.assertNotEqual(
            behavior(program),
            behavior(F'{preamble}\n{misfolded}'),
            'the program does not discriminate: it behaves the same with and without the effect',
        )
        deobfuscated = deobfuscate_source(program)
        self.assertEqual(
            behavior(program),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_conditional_keeps_the_call_in_its_decided_test(self):
        """
        Node: `a t`.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                var r = [t('t')] ? 'a' : 'b';
                console.log(r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = 'a';
                console.log(r, SINK.join('|'));
            """),
        )

    def test_conditional_keeps_the_getter_in_its_decided_test(self):
        """
        Node: `a g`.
        """
        self._preserves(
            self._GETTER,
            inspect.cleandoc("""
                var r = [o.p] ? 'a' : 'b';
                console.log(r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = 'a';
                console.log(r, SINK.join('|'));
            """),
        )

    def test_conditional_keeps_the_test_and_runs_only_the_taken_branch(self):
        """
        Node: `a t|a`. The order matters as much as the set: the test runs before the branch it
        selects.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                var r = [t('t')] ? t('a') : t('b');
                console.log(r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = t('a');
                console.log(r, SINK.join('|'));
            """),
        )

    def test_conditional_statement_keeps_its_test_when_the_whole_value_is_discarded(self):
        """
        Node: `t|a`.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                [t('t')] ? t('a') : t('b');
                console.log(SINK.join('|'));
            """),
            inspect.cleandoc("""
                t('a');
                console.log(SINK.join('|'));
            """),
        )

    def test_logical_and_keeps_the_call_in_its_decided_test(self):
        """
        Node: `x t`. A truthy test makes the right-hand side the result, so the test is what the
        fold discards.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                var r = [t('t')] && 'x';
                console.log(r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = 'x';
                console.log(r, SINK.join('|'));
            """),
        )

    def test_logical_and_keeps_the_getter_in_its_decided_test(self):
        """
        Node: `x g`.
        """
        self._preserves(
            self._GETTER,
            inspect.cleandoc("""
                var r = [o.p] && 'x';
                console.log(r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = 'x';
                console.log(r, SINK.join('|'));
            """),
        )

    def test_logical_and_statement_keeps_its_test_before_the_right_hand_side(self):
        """
        Node: `t|u`.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                [t('t')] && t('u');
                console.log(SINK.join('|'));
            """),
            inspect.cleandoc("""
                t('u');
                console.log(SINK.join('|'));
            """),
        )

    def test_logical_and_with_a_falsy_test_discards_the_right_hand_side(self):
        """
        Node: `0` and an empty sink. This is the other shape: the test is the result and the
        right-hand side is what goes, so the call it holds must never run.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                var r = 0 && t('u');
                console.log(r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = t('u');
                console.log(r, SINK.join('|'));
            """),
        )

    def test_logical_or_keeps_its_test_and_discards_the_right_hand_side(self):
        """
        Node: `object t`. A truthy test is the result of `||`, so the discarded operand is the
        right-hand side and its call must not run — while the test's own call must.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                var r = [t('t')] || t('u');
                console.log(typeof r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = [];
                console.log(typeof r, SINK.join('|'));
            """),
        )

    def test_logical_or_statement_keeps_the_call_in_its_discarded_test(self):
        """
        Node: `t`. Nothing of the expression is used, so both operands are discarded as values and
        only the test's effect survives.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                [t('t')] || t('u');
                console.log(SINK.join('|'));
            """),
            inspect.cleandoc("""
                console.log(SINK.join('|'));
            """),
        )

    def test_nullish_keeps_its_test_and_discards_the_right_hand_side(self):
        """
        Node: `object t`. An array is not nullish, so `??` answers with the test and discards the
        right-hand side.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                var r = [t('t')] ?? t('u');
                console.log(typeof r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = t('u');
                console.log(typeof r, SINK.join('|'));
            """),
        )

    def test_nullish_statement_keeps_the_call_in_its_discarded_test(self):
        """
        Node: `t`.
        """
        self._preserves(
            self._CALL,
            inspect.cleandoc("""
                [t('t')] ?? t('u');
                console.log(SINK.join('|'));
            """),
            inspect.cleandoc("""
                console.log(SINK.join('|'));
            """),
        )

    def test_nullish_keeps_the_getter_in_its_test(self):
        """
        Node: `object g`.
        """
        self._preserves(
            self._GETTER,
            inspect.cleandoc("""
                var r = [o.p] ?? 'x';
                console.log(typeof r, SINK.join('|'));
            """),
            inspect.cleandoc("""
                var r = [];
                console.log(typeof r, SINK.join('|'));
            """),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestFoldsIntoScopesThatRebindAGlobalName(TestBase):
    """
    A value computed at analysis time is written back into the program as source text, and some
    values are spelled by a global name — `undefined`, `NaN`, `Infinity`, `globalThis` — because
    the language has no literal for them. Such a name is an ordinary binding, so a parameter, a
    `var`, a `let`, a `catch` binding, a function declaration, or a `with` object can rebind it in
    any enclosing scope. The text written back therefore has to denote the computed value in the
    scope it lands in, not merely in a scope where nothing was rebound.

    Node decides and behavior is the criterion: no case asserts the emitted text, which would pin
    today's choice of spelling rather than the property that must not regress. Every program
    observes its rebinding alongside the folded value, so spelling that value with the bare global
    name changes what the program prints.
    """

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_undefined_folded_into_a_function_whose_parameter_rebinds_the_name(self):
        """
        Node: `undefined/shadow`. `u` is never assigned and so holds `undefined`, but inside `f`
        that name is the parameter, which the call binds to `'shadow'`.
        """
        self._check(inspect.cleandoc("""
            var u;
            function f(undefined) {
              return String(u) + '/' + String(undefined);
            }
            console.log(f('shadow'));
        """))

    def test_nan_folded_into_a_function_whose_parameter_rebinds_the_name(self):
        """
        Node: `NaN/3`. The quotient is a NaN, while the name inside `f` is the parameter, which
        holds three.
        """
        self._check(inspect.cleandoc("""
            var n = 0 / 0;
            function f(NaN) {
              return String(n) + '/' + String(NaN);
            }
            console.log(f(3));
        """))

    def test_infinity_folded_into_a_function_whose_parameter_rebinds_the_name(self):
        """
        Node: `Infinity/shadow`.
        """
        self._check(inspect.cleandoc("""
            var big = 1 / 0;
            function f(Infinity) {
              return String(big) + '/' + String(Infinity);
            }
            console.log(f('shadow'));
        """))

    def test_negative_infinity_folded_into_a_function_whose_parameter_rebinds_the_name(self):
        """
        Node: `-Infinity/shadow`. A negated bare name would be the negation of the parameter's
        string, which is a NaN.
        """
        self._check(inspect.cleandoc("""
            var small = -1 / 0;
            function f(Infinity) {
              return String(small) + '/' + String(Infinity);
            }
            console.log(f('shadow'));
        """))

    def test_nan_folded_in_a_function_whose_var_rebinds_the_name(self):
        """
        Node: `NaN/shadow`.
        """
        self._check(inspect.cleandoc("""
            function f() {
              var NaN = 'shadow';
              return String(0 / 0) + '/' + String(NaN);
            }
            console.log(f());
        """))

    def test_infinity_folded_above_the_var_that_rebinds_the_name_later_in_the_body(self):
        """
        Node: `Infinity/shadow`. The rebinding `var` is written below the fold site but hoists over
        it, so the bare name there is the local, still holding the `undefined` it hoisted with.
        """
        self._check(inspect.cleandoc("""
            function f() {
              var head = String(1 / 0);
              var Infinity = 'shadow';
              return head + '/' + String(Infinity);
            }
            console.log(f());
        """))

    def test_nan_folded_in_a_function_whose_function_declaration_rebinds_the_name(self):
        """
        Node: `NaN/function`. The declaration hoists to the top of the body, so the bare name is
        that function everywhere in it.
        """
        self._check(inspect.cleandoc("""
            function f() {
              var head = String(0 / 0);
              function NaN() {}
              return head + '/' + typeof NaN;
            }
            console.log(f());
        """))

    def test_infinity_folded_in_a_function_whose_let_rebinds_the_name(self):
        """
        Node: `Infinity/shadow`.
        """
        self._check(inspect.cleandoc("""
            function f() {
              let Infinity = 'shadow';
              return String(1 / 0) + '/' + String(Infinity);
            }
            console.log(f());
        """))

    def test_undefined_folded_in_a_block_whose_let_rebinds_the_name(self):
        """
        Node: `undefined|shadow`. A function that returns nothing yields `undefined`, a name the
        block's `let` binds to `'shadow'`.
        """
        self._check(inspect.cleandoc("""
            var SINK = [];
            function nothing() {}
            {
              let undefined = 'shadow';
              SINK.push(String(nothing()));
              SINK.push(String(undefined));
            }
            console.log(SINK.join('|'));
        """))

    def test_undefined_folded_in_a_catch_block_whose_binding_rebinds_the_name(self):
        """
        Node: `undefined|caught`. The catch parameter is an ordinary binding of the name for the
        whole handler.
        """
        self._check(inspect.cleandoc("""
            var SINK = [];
            var u;
            try {
              throw 'caught';
            } catch (undefined) {
              SINK.push(String(u));
              SINK.push(String(undefined));
            }
            console.log(SINK.join('|'));
        """))

    def test_nan_folded_in_a_with_body_whose_object_supplies_the_name(self):
        """
        Node: `NaN|shadow`. The body resolves the name against the object first, so it denotes the
        object's property there.
        """
        self._check(inspect.cleandoc("""
            var SINK = [];
            var n = 0 / 0;
            var o = { NaN: 'shadow' };
            with (o) {
              SINK.push(String(n));
              SINK.push(String(NaN));
            }
            console.log(SINK.join('|'));
        """))

    def test_undefined_folded_in_a_with_body_whose_object_supplies_the_name(self):
        """
        Node: `undefined|shadow`.
        """
        self._check(inspect.cleandoc("""
            var SINK = [];
            var u;
            var o = { undefined: 'shadow' };
            with (o) {
              SINK.push(String(u));
              SINK.push(String(undefined));
            }
            console.log(SINK.join('|'));
        """))

    def test_nan_folded_into_a_nested_function_that_inherits_the_parameter_rebinding(self):
        """
        Node: `NaN/3`. The fold site is a scope that rebinds nothing itself; the name it would use
        resolves through the enclosing function's parameter.
        """
        self._check(inspect.cleandoc("""
            function outer(NaN) {
              function inner() {
                return String(0 / 0);
              }
              return inner() + '/' + String(NaN);
            }
            console.log(outer(3));
        """))

    def test_constructed_receiver_read_where_a_parameter_rebinds_the_global_object_name(self):
        """
        Node: `G/X`. A `Function`-constructed function called with no receiver has `this` bound to
        the global object, so it reads the global marker; the name for that object is the parameter
        here, which holds an ordinary object carrying a different marker.
        """
        self._check(inspect.cleandoc("""
            globalThis.marker = 'G';
            function f(globalThis) {
              return new Function('return this.marker')() + '/' + globalThis.marker;
            }
            console.log(f({ marker: 'X' }));
        """))

    def test_constructed_this_compared_where_a_parameter_rebinds_the_global_object_name(self):
        """
        Node: `true/false`. The constructed function returns the global object itself, while the name
        for it inside `f` is the parameter, which is a different object.
        """
        self._check(inspect.cleandoc("""
            var REAL = globalThis;
            function f(globalThis) {
              var constructed = new Function('return this')();
              return String(constructed === REAL) + '/' + String(globalThis === REAL);
            }
            console.log(f({}));
        """))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestGuaranteedGlobalNamesAreOrdinaryBindings(TestBase):
    """
    `undefined`, `NaN` and `Infinity` denote the values the language guarantees only where the
    program has not given the name another meaning, and there are several ways it can. A
    declaration in the scope of the read or any scope enclosing it does it — a parameter, a `var`,
    a `let`, a `const`, a catch binding, a function. So does a `with` object that carries the
    property, where reading the name may additionally run an accessor. So does a direct `eval`,
    which can declare the name with no declaration appearing anywhere in the source.

    Each rebinding case names the program the unsound fold would produce and requires it to behave
    differently from the original before requiring the deobfuscation to behave like the original.
    Without that pairing the case would be blind: a rebound value that answers the tested operation
    the same way the global does passes whether the fold was refused or not.

    The three converse cases carry a rebinding that is not positioned to reach the read, so the
    fold is owed. Comparing behavior cannot see that one was refused — refusing every fold
    preserves behavior — so they count the referencing occurrences of the name that survive.
    """

    @staticmethod
    def _references(source: str, name: str) -> int:
        ast = JsParser(source).parse()
        model = build_semantic_model(ast)
        seen: set[int] = set()
        count = 0
        for node in ast.walk_in_order():
            if not isinstance(node, JsIdentifier) or node.name != name or id(node) in seen:
                continue
            seen.add(id(node))
            if model.is_reference(node):
                count += 1
        return count

    def _rebound(self, source: str, misfolded: str):
        self.assertNotEqual(
            behavior(source),
            behavior(misfolded),
            'the program does not discriminate: it behaves the same folded and unfolded',
        )
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def _folds(self, source: str, name: str):
        self.assertEqual(self._references(source, name), 1)
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        self.assertEqual(
            self._references(deobfuscated, name),
            0,
            F'the name was still read, so it was not folded; result was:\n{deobfuscated}',
        )

    def test_typeof_undefined_is_not_folded_where_a_parameter_binds_the_name(self):
        """
        Node: `number`. The parameter holds one, so `typeof` answers for that; the global's answer
        would be `'undefined'`.
        """
        self._rebound(
            inspect.cleandoc("""
                function f(undefined) {
                  return typeof undefined;
                }
                console.log(f(1));
            """),
            inspect.cleandoc("""
                function f(undefined) {
                  return 'undefined';
                }
                console.log(f(1));
            """),
        )

    def test_bitwise_complement_of_nan_is_not_folded_where_an_enclosing_function_binds_it(self):
        """
        Node: `-6`. The read is in a nested function and the `var` is in the one enclosing it, so
        the name is five and its complement minus six; the global's answer would be minus one,
        since ToInt32 maps a NaN to zero.
        """
        self._rebound(
            inspect.cleandoc("""
                function outer() {
                  var NaN = 5;
                  function inner() {
                    return ~NaN;
                  }
                  return inner();
                }
                console.log(String(outer()));
            """),
            inspect.cleandoc("""
                function outer() {
                  var NaN = 5;
                  function inner() {
                    return -1;
                  }
                  return inner();
                }
                console.log(String(outer()));
            """),
        )

    def test_logical_not_of_infinity_is_not_folded_where_a_block_lets_the_name(self):
        """
        Node: `true`. The `let` holds zero, which is falsy; the global's answer would be `false`.
        """
        self._rebound(
            inspect.cleandoc("""
                {
                  let Infinity = 0;
                  console.log(String(!Infinity));
                }
            """),
            inspect.cleandoc("""
                {
                  let Infinity = 0;
                  console.log(String(false));
                }
            """),
        )

    def test_typeof_undefined_is_not_folded_where_a_const_binds_the_name(self):
        """
        Node: `number`.
        """
        self._rebound(
            inspect.cleandoc("""
                const undefined = 1;
                console.log(typeof undefined);
            """),
            inspect.cleandoc("""
                const undefined = 1;
                console.log('undefined');
            """),
        )

    def test_bitwise_complement_of_nan_is_not_folded_where_a_catch_clause_binds_the_name(self):
        """
        Node: `-6`. The caught value is five, so the complement is minus six.
        """
        self._rebound(
            inspect.cleandoc("""
                try {
                  throw 5;
                } catch (NaN) {
                  console.log(String(~NaN));
                }
            """),
            inspect.cleandoc("""
                try {
                  throw 5;
                } catch (NaN) {
                  console.log(String(-1));
                }
            """),
        )

    def test_typeof_infinity_is_not_folded_where_a_function_declaration_binds_the_name(self):
        """
        Node: `function`. Truthiness could not tell the two apart — a function and the global
        infinity are both truthy — so the operation is `typeof`, where the global answers
        `'number'`.
        """
        self._rebound(
            inspect.cleandoc("""
                function Infinity() {}
                console.log(typeof Infinity);
            """),
            inspect.cleandoc("""
                function Infinity() {}
                console.log('number');
            """),
        )

    def test_typeof_undefined_is_not_folded_where_a_top_level_var_binds_the_name(self):
        """
        Node: `number`. The oracle runs a snippet as a module, whose top level is a function scope,
        so the declaration binds the name there; at the top level of a classic script the same
        `var` would be a no-op, the global property being neither writable nor configurable.
        """
        self._rebound(
            inspect.cleandoc("""
                var undefined = 1;
                console.log(typeof undefined);
            """),
            inspect.cleandoc("""
                var undefined = 1;
                console.log('undefined');
            """),
        )

    def test_bitwise_complement_of_nan_is_not_folded_where_the_with_object_carries_the_name(self):
        """
        Node: `-6`.
        """
        self._rebound(
            inspect.cleandoc("""
                var o = { NaN: 5 };
                with (o) {
                  console.log(String(~NaN));
                }
            """),
            inspect.cleandoc("""
                var o = { NaN: 5 };
                with (o) {
                  console.log(String(-1));
                }
            """),
        )

    def test_logical_not_of_infinity_is_not_folded_where_the_with_object_runs_a_getter(self):
        """
        Node: `g|true`. Reading the name runs the accessor, so the read is observable before its
        value is ever used: a fold loses the push as well as answering `false`.
        """
        self._rebound(
            inspect.cleandoc("""
                var SINK = [];
                var o = { get Infinity() {
                  SINK.push('g');
                  return 0;
                } };
                with (o) {
                  SINK.push(String(!Infinity));
                }
                console.log(SINK.join('|'));
            """),
            inspect.cleandoc("""
                var SINK = [];
                var o = { get Infinity() {
                  SINK.push('g');
                  return 0;
                } };
                with (o) {
                  SINK.push(String(false));
                }
                console.log(SINK.join('|'));
            """),
        )

    def test_typeof_undefined_is_not_folded_where_a_direct_eval_declares_the_name(self):
        """
        Node: `number`. A `var` declared by a direct `eval` lands in the var scope the call stands
        in and outlives it, so the name is bound although no declaration of it is in the source.
        """
        self._rebound(
            inspect.cleandoc("""
                eval('var undefined = 1;');
                console.log(typeof undefined);
            """),
            inspect.cleandoc("""
                eval('var undefined = 1;');
                console.log('undefined');
            """),
        )

    def test_bitwise_complement_of_nan_is_not_folded_where_a_direct_eval_in_it_declares_it(self):
        """
        Node: `-6`.
        """
        self._rebound(
            inspect.cleandoc("""
                function f() {
                  eval('var NaN = 5;');
                  return ~NaN;
                }
                console.log(String(f()));
            """),
            inspect.cleandoc("""
                function f() {
                  eval('var NaN = 5;');
                  return -1;
                }
                console.log(String(f()));
            """),
        )

    def test_bitwise_complement_of_nan_is_not_folded_in_a_function_below_the_direct_eval(self):
        """
        Node: `-6`. The binding lands in `f`, and a function nested inside `f` inherits its scope,
        so the read there sees it too.
        """
        self._rebound(
            inspect.cleandoc("""
                function f() {
                  eval('var NaN = 5;');
                  function g() {
                    return ~NaN;
                  }
                  return g();
                }
                console.log(String(f()));
            """),
            inspect.cleandoc("""
                function f() {
                  eval('var NaN = 5;');
                  function g() {
                    return -1;
                  }
                  return g();
                }
                console.log(String(f()));
            """),
        )

    def test_typeof_undefined_is_not_folded_where_the_direct_eval_follows_the_reader(self):
        """
        Node: `number`. The `eval` is written after the function that reads the name and runs
        before it is called, so what decides the read is the scope the `eval` stands in, not where
        it stands within it.
        """
        self._rebound(
            inspect.cleandoc("""
                function g() {
                  return typeof undefined;
                }
                eval('var undefined = 1;');
                console.log(g());
            """),
            inspect.cleandoc("""
                function g() {
                  return 'undefined';
                }
                eval('var undefined = 1;');
                console.log(g());
            """),
        )

    def test_typeof_undefined_folds_where_the_direct_eval_is_in_an_unrelated_function(self):
        """
        Node: `ran undefined`. The `eval` declares into `unrelated`, a scope that does not contain
        the read, so the read is the global one and owes its fold.
        """
        self._folds(
            inspect.cleandoc("""
                var SINK = [];
                function unrelated() {
                  eval('var undefined = 1;');
                  SINK.push('ran');
                }
                unrelated();
                console.log(SINK.join('|'), typeof undefined);
            """),
            'undefined',
        )

    def test_bitwise_complement_of_nan_folds_where_an_unrelated_function_parameter_binds_it(self):
        """
        Node: `1 -1`.
        """
        self._folds(
            inspect.cleandoc("""
                var SINK = [];
                function unrelated(NaN) {
                  SINK.push(arguments.length);
                }
                unrelated(5);
                console.log(SINK.join('|'), String(~NaN));
            """),
            'NaN',
        )

    def test_bitwise_complement_of_nan_folds_where_a_sibling_block_lets_the_name(self):
        """
        Node: `-1`. A `let` is scoped to its block, which the read is not in.
        """
        self._folds(
            inspect.cleandoc("""
                {
                  let NaN = 5;
                }
                console.log(String(~NaN));
            """),
            'NaN',
        )


class TestValueNameClobberedThroughTheGlobalObject(TestBase):
    """
    The top-level `this` of a script is the global object, so `this.NaN = 5` writes the property
    that `globalThis.NaN = 5` and a bare `NaN = 5` write, and all three are one clobber written
    three ways. Where a clobber can land, the name no longer denotes the value the language
    guarantees, and folding it to that value is wrong.

    The oracle for whether it lands is Windows Script Host's JScript, the engine these programs are
    deobfuscated for and the one whose scripts this tool is aimed at. There `NaN`, `Infinity` and
    `undefined` are writable, and the three programs below print `5`, `5` and `number`. It is not
    run: nothing in this suite executes a JScript engine. Node cannot stand in for it, because Node
    implements a later language in which those three properties are not writable, so the assignment
    silently does nothing there and a tool that saw the write and one that did not emit programs
    Node cannot tell apart.

    Each case therefore asserts the deobfuscation rather than a behavior: a clobber the tool cannot
    rule out leaves the name standing, and the two controls are the same clobber under the two
    spellings for which it already does.
    """

    def _keeps_the_name(self, source: str):
        self.assertEqual(deobfuscate_source(source), source)

    def test_a_bare_assignment_to_nan_stops_the_fold(self):
        self._keeps_the_name(inspect.cleandoc("""
            NaN = 5;
            console.log(String(NaN));
        """))

    def test_an_assignment_to_nan_through_global_this_stops_the_fold(self):
        self._keeps_the_name(inspect.cleandoc("""
            globalThis.NaN = 5;
            console.log(String(NaN));
        """))

    def test_an_assignment_to_nan_through_this_stops_the_fold(self):
        self._keeps_the_name(inspect.cleandoc("""
            this.NaN = 5;
            console.log(String(NaN));
        """))

    def test_an_assignment_to_infinity_through_this_stops_the_fold(self):
        self._keeps_the_name(inspect.cleandoc("""
            this.Infinity = 5;
            console.log(String(Infinity));
        """))

    def test_an_assignment_to_undefined_through_this_stops_the_fold(self):
        self._keeps_the_name(inspect.cleandoc("""
            this.undefined = 5;
            console.log(typeof undefined);
        """))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestFoldedCalleeKeepsHowTheFunctionIsReached(TestBase):
    """
    How a call reaches its function is part of what the call means, and not a detour on the way
    to the same result. `o.m()` passes `o` as the receiver while a callee spelled as any other
    expression passes none, and `eval(s)` runs `s` in the scope of the caller while any other
    spelling of that same function runs it in the global scope. A conditional, `&&`, `||` or `??`
    whose test is decidable folds to the operand that survives; when such an expression is what a
    call invokes, putting the surviving operand in its place hands the call a callee of a
    different kind.

    Which operand survives is not the same for the four: the conditional keeps the branch its test
    selects, whereas `&&`, `||` and `??` keep their right-hand side only for a truthy, a falsy and
    a nullish test respectively, so each is written with the test value that leaves the callee
    standing. Node decides and no case asserts the emitted text, because a callee reached without
    a receiver has more than one correct spelling. Each case also names the program a fold that
    lost the distinction would produce and requires Node to print something else for it, so a call
    whose function cannot tell how it was reached cannot pass for a proof.
    """

    def _receiver_program(self, callee: str) -> str:
        return '\n'.join([
            "var o = { tag: 'self', m: function () {",
            "  return this === o ? this.tag : 'detached';",
            '} };',
            F'console.log({callee}());',
        ])

    def _direct_eval_program(self, callee: str) -> str:
        return '\n'.join([
            'function reach() {',
            "  var secret = 'local';",
            F"  return {callee}('typeof secret');",
            '}',
            'console.log(reach());',
        ])

    def _preserves(self, source: str, misfolded: str):
        self.assertNotEqual(
            behavior(source),
            behavior(misfolded),
            'the program does not discriminate: it behaves the same however its callee is reached',
        )
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_conditional_taking_its_consequent_calls_without_a_receiver(self):
        """
        Node prints `detached`, and `self` once the callee is spelled `o.m`.
        """
        self._preserves(
            self._receiver_program('(1 ? o.m : null)'),
            self._receiver_program('o.m'),
        )

    def test_conditional_taking_its_alternate_calls_without_a_receiver(self):
        """
        Node prints `detached`, and `self` once the callee is spelled `o.m`.
        """
        self._preserves(
            self._receiver_program('(0 ? null : o.m)'),
            self._receiver_program('o.m'),
        )

    def test_logical_and_with_a_truthy_test_calls_its_right_hand_side_without_a_receiver(self):
        """
        Node prints `detached`, and `self` once the callee is spelled `o.m`.
        """
        self._preserves(
            self._receiver_program('(1 && o.m)'),
            self._receiver_program('o.m'),
        )

    def test_logical_or_with_a_falsy_test_calls_its_right_hand_side_without_a_receiver(self):
        """
        Node prints `detached`, and `self` once the callee is spelled `o.m`.
        """
        self._preserves(
            self._receiver_program('(0 || o.m)'),
            self._receiver_program('o.m'),
        )

    def test_nullish_with_a_nullish_test_calls_its_right_hand_side_without_a_receiver(self):
        """
        Node prints `detached`, and `self` once the callee is spelled `o.m`.
        """
        self._preserves(
            self._receiver_program('(null ?? o.m)'),
            self._receiver_program('o.m'),
        )

    def test_conditional_taking_its_consequent_leaves_its_eval_indirect(self):
        """
        Node prints `undefined`, and `string` once the callee is spelled `eval`, which then reads
        the local of the function the call is written in.
        """
        self._preserves(
            self._direct_eval_program('(1 ? eval : null)'),
            self._direct_eval_program('eval'),
        )

    def test_logical_and_with_a_truthy_test_leaves_its_eval_indirect(self):
        """
        Node prints `undefined`, and `string` once the callee is spelled `eval`.
        """
        self._preserves(
            self._direct_eval_program('(1 && eval)'),
            self._direct_eval_program('eval'),
        )

    def test_logical_or_with_a_falsy_test_leaves_its_eval_indirect(self):
        """
        Node prints `undefined`, and `string` once the callee is spelled `eval`.
        """
        self._preserves(
            self._direct_eval_program('(0 || eval)'),
            self._direct_eval_program('eval'),
        )

    def test_nullish_with_a_nullish_test_leaves_its_eval_indirect(self):
        """
        Node prints `undefined`, and `string` once the callee is spelled `eval`.
        """
        self._preserves(
            self._direct_eval_program('(null ?? eval)'),
            self._direct_eval_program('eval'),
        )


_SPACE_LIKE_CATEGORIES = frozenset({'Cc', 'Cf', 'Zl', 'Zp', 'Zs'})
"""
The Unicode general categories a character that could be mistaken for a space belongs to: the
controls, the format characters, and the three kinds of separator.
"""

SPACE_LIKE_CODE_POINTS = sorted(
    cp for cp in range(0x110000)
    if unicodedata.category(chr(cp)) in _SPACE_LIKE_CATEGORIES or chr(cp).isspace()
)
"""
Every code point that could be mistaken for a space: the categories above together with everything
Python's `str.isspace` accepts, which is the notion a reader written in Python reaches for by
default. Offering the engine this whole set rather than a list of characters is what finds a
character a reader invented, and not merely one it forgot.
"""

_ASK_WHICH_CHARACTERS_STAND_BETWEEN_TOKENS = R'''
const separates = [];
const ends = [];
for (const cp of CANDIDATES) {
    const c = String.fromCodePoint(cp);
    const name = 'q' + cp;
    try {
        if (eval('(function(){ var' + c + name + ' = 7; return ' + name + '; })()') === 7) {
            separates.push(cp);
        }
    } catch (error) {}
    try {
        if (eval('(function(){ return' + c + '42; })()') === undefined) {
            ends.push(cp);
        }
    } catch (error) {}
}
console.log(JSON.stringify(separates));
console.log(JSON.stringify(ends));
'''
"""
A program that reports, for each candidate character, whether it may stand between `var` and the
name it declares, and whether it ends the statement a `return` begins. The first is what separates
two tokens at all and the second is what ends a line, so the difference of the two is the
whitespace of the language as the engine reads it. Each declaration is given a name of its own
because a direct `eval` puts a `var` into the enclosing scope, where the next round would find it.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTokensAreSeparatedByTheWhitespaceOfTheLanguage(TestBase):
    """
    Whitespace between two tokens is the whole ECMA-262 WhiteSpace production and not the space and
    the tab alone. A character of it that the lexer does not skip becomes a token of its own, which
    splits one statement into two; a character the lexer skips that is not in it merges two programs
    that the engine says are different. Node names the set, and the lexer has to answer with it.
    """

    def _node_reading(self) -> tuple[list[int], list[int]]:
        source = F'const CANDIDATES = {json.dumps(SPACE_LIKE_CODE_POINTS)};'
        output, error = behavior(source + _ASK_WHICH_CHARACTERS_STAND_BETWEEN_TOKENS)
        self.assertIsNone(error)
        separates, ends = (json.loads(line) for line in output.splitlines())
        return separates, ends

    def _between_two_names(self, code_point: int) -> list[JsTokenKind]:
        return [token.kind for token in JsLexer(F'a{chr(code_point)}b').tokenize()]

    def _skipped_by_the_lexer(self) -> list[int]:
        two_names = [JsTokenKind.IDENTIFIER, JsTokenKind.IDENTIFIER, JsTokenKind.EOF]
        return [
            cp for cp in SPACE_LIKE_CODE_POINTS if self._between_two_names(cp) == two_names
        ]

    def _read_as_a_line_ending(self) -> list[int]:
        a_broken_line = [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.NEWLINE,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.EOF,
        ]
        return [
            cp for cp in SPACE_LIKE_CODE_POINTS if self._between_two_names(cp) == a_broken_line
        ]

    def test_the_lexer_skips_the_characters_that_separate_tokens_without_ending_a_line(self):
        separates, ends = self._node_reading()
        self.assertEqual([cp for cp in separates if cp not in ends], self._skipped_by_the_lexer())

    def test_the_lexer_ends_a_line_at_the_characters_that_end_a_statement(self):
        """
        A line ending is where a semicolon may be inserted, so the characters the lexer reports as
        one have to be the characters the engine inserts a semicolon at, no more and no fewer.
        """
        _, ends = self._node_reading()
        self.assertEqual(ends, self._read_as_a_line_ending())

    def test_a_program_woven_with_every_whitespace_character_is_the_spaced_program(self):
        """
        Node prints `3`. The same tokens separated by each character of the set in turn are the same
        program as the one separated by spaces: the same tree, and the same deobfuscated text.
        """
        separates, ends = self._node_reading()
        whitespace = [cp for cp in separates if cp not in ends]
        spaced = 'var a = 1 ; var b = 2 ; console . log ( a + b ) ;'
        words = spaced.split(' ')
        woven = words[0] + ''.join(
            chr(whitespace[index % len(whitespace)]) + word
            for index, word in enumerate(words[1:])
        )
        self.assertEqual(behavior(woven), ('3\n', None))
        self.assertEqual(canonical(JsParser(woven).parse()), canonical(JsParser(spaced).parse()))
        self.assertEqual(deobfuscate_source(woven), 'console.log(3);')
        self.assertEqual(deobfuscate_source(woven), deobfuscate_source(spaced))

    def test_a_file_that_begins_with_a_byte_order_mark_is_the_file_without_it(self):
        """
        Node prints `3` for both. A byte order mark is whitespace, so a file that opens with one
        opens with the token behind it; reading the mark as a token of its own would make the first
        statement of every such file a statement no grammar admits.
        """
        program = 'var greeting = 1 + 2;\nconsole.log(greeting);'
        marked = chr(0xFEFF) + program
        self.assertEqual(behavior(marked), ('3\n', None))
        self.assertEqual(canonical(JsParser(marked).parse()), canonical(JsParser(program).parse()))
        self.assertEqual(deobfuscate_source(marked), 'console.log(3);')

    def test_a_character_python_calls_a_space_and_the_language_does_not_separates_nothing(self):
        """
        Node refuses every one of these programs and runs the one written with a space. `U+001C`
        through `U+001F` and `U+0085` are removed by Python's `str.strip` and are whitespace to
        nothing in the language, so each is a character no grammar admits between two tokens.
        """
        not_a_separator = [
            JsTokenKind.IDENTIFIER,
            JsTokenKind.ERROR,
            JsTokenKind.IDENTIFIER,
            JsTokenKind.EOF,
        ]
        for cp in [0x001C, 0x001D, 0x001E, 0x001F, 0x0085]:
            with self.subTest(character=F'U+{cp:04X}'):
                self.assertEqual(
                    behavior(F'var{chr(cp)}x = 1; console.log(x);'), ('', 'SyntaxError'))
                self.assertEqual(self._between_two_names(cp), not_a_separator)
        self.assertEqual(behavior('var x = 1; console.log(x);'), ('1\n', None))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAutomaticSemicolonInsertionIsWhereTheLineEnds(TestBase):
    """
    A semicolon is inserted where a line ends and nowhere else. Widening the set of characters that
    separate two tokens must therefore not widen the set that ends a line: a character read as both
    would end statements that were never over, and one read as neither would join statements the
    engine keeps apart. Every expected value is what Node prints for the program as written.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_line_feed_after_return_ends_the_return_statement(self):
        self._prints('function f() {\n  return\n  42;\n}\nconsole.log(f());', 'undefined\n')

    def test_carriage_return_line_feed_endings_end_a_line_where_a_line_feed_does(self):
        self._prints('function f() {\r\n  return\r\n  42;\r\n}\r\nconsole.log(f());', 'undefined\n')
        self._prints('var a = 1\r\nvar b = 2\r\nconsole.log(a + b)', '3\n')

    def test_statements_separated_only_by_newlines_are_separate_statements(self):
        self._prints('var a = 1\nvar b = 2\nconsole.log(a + b)', '3\n')

    def test_a_newline_ahead_of_a_prefix_increment_ends_the_previous_statement(self):
        """
        Node prints `2 1`: the line ending closes `var y = x`, so `++x` is a statement of its own
        and `y` holds the value `x` had before it. Joined into one line the two read as `x ++ x`,
        which is no program at all.
        """
        self._prints('var x = 1\nvar y = x\n++x\nconsole.log(x, y)', '2 1\n')
        self._prints('var x = 1\r\nvar y = x\r\n++x\r\nconsole.log(x, y)', '2 1\n')

    def test_whitespace_that_ends_no_line_does_not_end_a_return_statement(self):
        """
        Node prints `42` for each. The tab, the vertical tab, the form feed, the no-break space, the
        ideographic space and the byte order mark all separate two tokens and none of them ends a
        line, so the `return` reads the number written behind it.
        """
        for cp in [0x0009, 0x000B, 0x000C, 0x00A0, 0x3000, 0xFEFF]:
            with self.subTest(character=F'U+{cp:04X}'):
                self._prints(F'function f() {{ return{chr(cp)}42; }} console.log(f());', '42\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheLineSeparatorsEndALineRatherThanSeparateLikeASpace(TestBase):
    """
    `U+2028` and `U+2029` are line terminators of the language, which is a different thing from
    whitespace: they separate two tokens as a space does, and they additionally end a line, where a
    comment stops and a semicolon may be inserted. Node was asked what each program below does
    before any of them was written down.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_line_separator_ends_a_single_line_comment(self):
        """
        Node prints `1` and then `2`: the comment ends at the separator, so the call written behind
        it is code. A separator that ends no line leaves that call inside the comment, where it is
        deleted along with it.
        """
        self._prints(F'console.log(1); // done{chr(0x2028)}console.log(2);', '1\n2\n')
        self._prints(F'console.log(1); // done{chr(0x2029)}console.log(2);', '1\n2\n')

    def test_a_line_separator_between_two_operands_is_no_token_of_its_own(self):
        """
        Node prints `3`: the call has the one argument `1 + 2`, the separator being only where the
        line ends. A separator that is a token of its own splits the sum into two arguments, and the
        call then prints `1 2`.
        """
        self._prints(F'console.log(1{chr(0x2028)}+ 2);', '3\n')
        self._prints(F'console.log(1{chr(0x2029)}+ 2);', '3\n')

    def test_a_line_separator_inside_an_expression_leaves_the_expression_whole(self):
        """
        Node prints `3`: an expression continues across the end of a line, so a `+` still waiting
        for its right operand finds the number written on the next one.
        """
        self._prints(F'var x = 1 +{chr(0x2028)}2; console.log(x);', '3\n')
        self._prints(F'var x = 1 +{chr(0x2029)}2; console.log(x);', '3\n')

    def test_a_line_separator_after_return_ends_the_return_statement(self):
        """
        Node prints `undefined`: a semicolon is inserted at the end of the line exactly as a line
        feed would have it inserted.
        """
        self._prints(F'function f() {{ return{chr(0x2028)}42; }} console.log(f());', 'undefined\n')
        self._prints(F'function f() {{ return{chr(0x2029)}42; }} console.log(f());', 'undefined\n')

    def test_a_line_separator_inside_a_string_literal_is_a_character_of_the_string(self):
        """
        Node prints the two letters with the separator between them: a line terminator is an
        ordinary character of a string literal and ends no line there.
        """
        self._prints(
            F"console.log(JSON.stringify('a{chr(0x2028)}b'));", F'"a{chr(0x2028)}b"\n')
        self._prints(
            F"console.log(JSON.stringify('a{chr(0x2029)}b'));", F'"a{chr(0x2029)}b"\n')


_ASK_WHICH_CHARACTERS_A_FORGIVING_DECODE_REMOVES = R'''
const removed = [];
for (const cp of CANDIDATES) {
    const c = String.fromCodePoint(cp);
    try {
        if (atob('QUJ' + c + 'D') === 'ABC') removed.push(cp);
    } catch (error) {}
}
console.log(JSON.stringify(removed));
'''
"""
A program that reports which candidate characters a forgiving base64 decode removes from its
argument. A character it does not remove is one the decode refuses the whole argument over, so the
same experiment names both the padding a call may be folded through and the throw a call is.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAtobRemovesTheWhitespaceOfAForgivingBase64Decode(TestBase):
    """
    `atob` removes a set of characters from its argument before it decodes, and refuses the argument
    over any character outside that set. The set therefore decides both what a call computes and
    whether it computes anything at all, so reading it too widely turns a program that throws into
    one that has a value. Node names the set.
    """

    def _folded(self, code_point: int) -> str:
        """
        The escape is the braced form rather than the four digit one, because the four digit form
        takes exactly four and a code point above `U+FFFF` spells five: `\\u110BD` is `U+110B`
        followed by a `D`, so half the candidates were offered a character nobody was asking about.
        """
        return deobfuscate_source(RF"SINK(atob('QUJ\u{{{code_point:X}}}D'));")

    def _catching_program(self, escape: str) -> str:
        return (
            F"try {{ console.log(atob('QUJ{escape}D')); }}"
            F' catch (error) {{ console.log(error.name); }}')

    def test_the_characters_a_decode_removes_are_the_ones_node_removes_and_no_others(self):
        """
        Every character that could be mistaken for a space is offered to a decode in Node, and only
        the ones it removes may be folded away: for every other character the call is a throw.
        """
        source = F'const CANDIDATES = {json.dumps(SPACE_LIKE_CODE_POINTS)};'
        output, error = behavior(source + _ASK_WHICH_CHARACTERS_A_FORGIVING_DECODE_REMOVES)
        self.assertIsNone(error)
        self.assertEqual(
            json.loads(output),
            [cp for cp in SPACE_LIKE_CODE_POINTS if self._folded(cp) == "SINK('ABC');"],
        )

    def test_an_argument_padded_with_them_decodes_to_the_text_it_names(self):
        """
        Node prints `ABC` and then `Hello, world`: the removal happens before the decode and does
        not care where in the argument the characters sit.
        """
        padded = R"console.log(atob('\t\n\f\r QUJD \r\f\n\t'));"
        self.assertEqual(behavior(padded), ('ABC\n', None))
        self.assertEqual(deobfuscate_source(padded), "console.log('ABC');")
        interior = R"console.log(atob('SGVs\nbG8s\tIHdv\rcmxk'));"
        self.assertEqual(behavior(interior), ('Hello, world\n', None))
        self.assertEqual(deobfuscate_source(interior), "console.log('Hello, world');")

    def test_an_argument_holding_a_character_it_does_not_remove_is_refused(self):
        """
        Node prints `InvalidCharacterError` for each. The vertical tab, the no-break space, the em
        space, the byte order mark and the line separator are each whitespace of one kind or
        another, and none of them is whitespace to a forgiving decode.
        """
        for escape in [
            R'\u000B',
            R'\u00A0',
            R'\u2003',
            R'\uFEFF',
            R'\u2028',
            '!',
        ]:
            with self.subTest(escape=escape):
                source = self._catching_program(escape)
                self.assertEqual(behavior(source), ('InvalidCharacterError\n', None))
                self.assertEqual(
                    behavior(deobfuscate_source(source)), ('InvalidCharacterError\n', None))

    def test_a_refused_argument_is_not_folded_to_a_value(self):
        """
        Node prints nothing and exits with the refusal uncaught. It is a `DOMException` rather than
        an `Error`, which is why the type is reported as the bare `ERROR`; what the case pins is
        that neither program prints, where a folded call would print `ABC`.
        """
        source = R"console.log(atob('QUJ\u000BD'));"
        self.assertEqual(behavior(source), ('', 'ERROR'))
        self.assertEqual(behavior(deobfuscate_source(source)), ('', 'ERROR'))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNumberParseIntAndParseFloatAreTheGlobalFunctions(TestBase):
    """
    `Number.parseInt` and `parseInt` are one function object, and so are `Number.parseFloat` and
    `parseFloat`. A call therefore names the same number whichever way it is written, and the two
    programs deobfuscate to the same text.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def _parse_int_calls(self, spelling: str) -> str:
        return (
            F"console.log({spelling}('101', 2), {spelling}('ff', 16), {spelling}('0x1f'),"
            F" {spelling}('1e3'), {spelling}(' 42abc'), String({spelling}('nope')));")

    def _parse_float_calls(self, spelling: str) -> str:
        return (
            F"console.log({spelling}('2.5abc'), {spelling}('1e3'), {spelling}('-1.5e2'),"
            F" {spelling}('0x10'), String({spelling}('Infinity')), String({spelling}('nope')));")

    def test_each_spelling_names_one_and_the_same_function(self):
        self._prints(
            'console.log(Number.parseInt === parseInt, Number.parseFloat === parseFloat);',
            'true true\n')

    def test_parse_int_reached_through_number_folds_as_the_global_one_does(self):
        """
        Node prints `5 255 31 1 42 NaN` for both. A radix is read where one is given, a `0x` prefix
        selects sixteen where none is, an exponent is no part of an integer, padding is skipped, and
        a string naming no number is not a number.
        """
        through_number = self._parse_int_calls('Number.parseInt')
        through_global = self._parse_int_calls('parseInt')
        self._prints(through_number, '5 255 31 1 42 NaN\n')
        self._prints(through_global, '5 255 31 1 42 NaN\n')
        self.assertEqual(
            deobfuscate_source(through_number), "console.log(5, 255, 31, 1, 42, 'NaN');")
        self.assertEqual(deobfuscate_source(through_number), deobfuscate_source(through_global))

    def test_parse_float_reached_through_number_folds_as_the_global_one_does(self):
        """
        Node prints `2.5 1000 -150 0 Infinity NaN` for both. The parse ends where the decimal
        literal does, an exponent belongs to that literal, a base prefix does not, and the word
        `Infinity` is a literal of its own.
        """
        through_number = self._parse_float_calls('Number.parseFloat')
        through_global = self._parse_float_calls('parseFloat')
        self._prints(through_number, '2.5 1000 -150 0 Infinity NaN\n')
        self._prints(through_global, '2.5 1000 -150 0 Infinity NaN\n')
        self.assertEqual(
            deobfuscate_source(through_number),
            "console.log(2.5, 1000, -150, 0, 'Infinity', 'NaN');")
        self.assertEqual(deobfuscate_source(through_number), deobfuscate_source(through_global))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANumberWrittenInABaseOtherThanTenIsReadAtAnyLength(TestBase):
    """
    `Number` reads a base prefix and then every digit written behind it, and how many digits that is
    is not bounded by what a double can hold. Node says what each of these strings names.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_run_of_digits_a_double_holds_names_the_integer_it_spells(self):
        """
        Node prints `255 9007199254740991 9007199254740992`. The last string has no double of its
        own, so the digits it names are not the digits it was written with.
        """
        source = (
            "console.log(Number('0xff'), Number('0x1fffffffffffff'),"
            " Number('0x20000000000001'));")
        self._prints(source, '255 9007199254740991 9007199254740992\n')
        self.assertEqual(
            deobfuscate_source(source),
            'console.log(255, 9007199254740991, 9007199254740992);')

    def test_a_run_of_digits_past_the_double_range_names_an_infinity(self):
        """
        Node prints `Infinity` for each. The count of digits decides this and their values do not,
        so a string far longer than any number has to be answered as quickly as one that merely
        overflows.
        """
        for prefix, digit, count in [('0x', 'f', 300), ('0b', '1', 1100), ('0o', '7', 400)]:
            with self.subTest(prefix=prefix):
                source = F"console.log(String(Number('{prefix}{digit * count}')));"
                self._prints(source, 'Infinity\n')
                self.assertEqual(deobfuscate_source(source), "console.log('Infinity');")

    def test_leading_zeros_are_not_digits_of_the_number_they_precede(self):
        """
        Node prints `16`: five thousand zeros behind the prefix change neither what the string names
        nor how long it takes to name it.
        """
        source = F"console.log(Number('0x{'0' * 5000}10'));"
        self._prints(source, '16\n')
        self.assertEqual(deobfuscate_source(source), 'console.log(16);')


_BACKSLASH = '\\'
"""
A single backslash. In an identifier it begins a unicode escape, and outside a string literal it has
no other meaning at all.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABackslashThatBeginsNoEscapeDoesNotStallTheReader(TestBase):
    """
    Node refuses every program below, so none of them names anything and there is no answer to
    compare against. What these pin is that there is an answer at all: a backslash the scan did not
    consume yielded tokens without end, and a reader that never returns is a defect no comparison of
    results can express, because the comparison is never reached. Only a bound on the time can.
    """

    def _answered_within(self, source: str):
        self.assertEqual(behavior(source), ('', 'SyntaxError'))
        self.assertIsNotNone(deobfuscate_within(source, 30.0))

    def test_a_backslash_standing_between_two_statements_is_answered(self):
        self._answered_within(F'console.log(1); {_BACKSLASH} console.log(2);')

    def test_a_backslash_between_two_identifier_characters_is_answered(self):
        self._answered_within(F'var a{_BACKSLASH}b = 1; console.log(a{_BACKSLASH}b);')

    def test_a_backslash_at_the_end_of_the_input_is_answered(self):
        self._answered_within(F'console.log(1); {_BACKSLASH}')

    def test_two_backslashes_in_a_row_are_answered(self):
        self._answered_within(F'var a{_BACKSLASH}{_BACKSLASH}b = 1; console.log(1);')


_ATOB_ARGUMENTS = [
    'QUJD',
    'QQ==',
    'QQ=',
    'QQ',
    'Q',
    'QUJDRA==',
    'QUJDRA=',
    'QUJDRA',
    'QUJDR',
    'QQ===',
    'QUJD=',
    'QQ=A',
    'QUJ=D',
    '=',
    '==',
    '====',
    '',
    ' QQ== ',
    ' QQ= ',
    'QR',
    'QR==',
]
"""
Arguments for a forgiving base64 decode: every length modulo four, each offered with a trailing `=`
and without one, so that the padding and the length are asked about separately. `QR` is there
because the bits a decode has left over are not required to be zero, the padded whitespace because
the removal happens before the length is read, and the empty argument because it is the one that
decodes to nothing rather than to a refusal.
"""

_ASK_WHAT_A_FORGIVING_DECODE_ANSWERS = R'''
const answers = [];
for (const argument of ARGUMENTS) {
    try {
        answers.push(atob(argument));
    } catch (error) {
        answers.push(null);
    }
}
console.log(JSON.stringify(answers));
'''
"""
A program that reports what a forgiving base64 decode answers for each argument, and a null for
each argument it refuses. A decode answers a string and never a null, so the two cannot be
confused for one another.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAForgivingDecodeReadsTheLengthOfItsArgumentBeforeItsPadding(TestBase):
    """
    A forgiving base64 decode removes the padding of its argument only where what is left of the
    argument has a length a group ends on: `atob('QQ==')` is the letter `A` and `atob('QQ=')` is a
    refusal, because three characters are no whole number of groups and the `=` is then simply a
    character the base64 alphabet does not hold. Completing that group instead of refusing it is how
    a call the program never returns from becomes a value.

    Node is asked what each argument answers, and the builtin has to answer the same — on its own,
    and again through a program deobfuscated whole.
    """

    def _node_answers(self) -> list[str | None]:
        source = F'const ARGUMENTS = {json.dumps(_ATOB_ARGUMENTS)};'
        output, error = behavior(source + _ASK_WHAT_A_FORGIVING_DECODE_ANSWERS)
        self.assertIsNone(error)
        return json.loads(output)

    def _builtin_answers(self) -> list[str | None]:
        decode = BUILTIN_REGISTRY[None, 'atob']
        answers = []
        for argument in _ATOB_ARGUMENTS:
            try:
                answers.append(decode([argument]))
            except InterpreterError:
                answers.append(None)
        return answers

    def test_the_builtin_answers_every_argument_the_way_node_answers_it(self):
        self.assertEqual(self._node_answers(), self._builtin_answers())

    def test_a_trailing_equals_short_of_a_whole_group_is_a_refusal_and_not_a_value(self):
        """
        Node prints nothing and exits with the refusal uncaught. It is a `DOMException` rather than
        an `Error`, which is why the type is reported as the bare `ERROR`; what the case pins is
        that the program still refuses, where a folded call would have printed `A`.
        """
        source = "console.log(atob('QQ='));"
        self.assertEqual(behavior(source), ('', 'ERROR'))
        self.assertEqual(deobfuscate_source(source), source)
        self.assertEqual(behavior(deobfuscate_source(source)), ('', 'ERROR'))

    def test_the_refusal_a_program_catches_is_the_one_node_raises(self):
        """
        Node prints `InvalidCharacterError` for each: an argument three characters long, one seven
        characters long, one padded to a length no group ends on, and one padded past the group it
        completes.
        """
        for argument in ['QQ=', 'QUJDRA=', 'QUJD=', 'QQ===']:
            with self.subTest(argument=argument):
                source = (
                    F"try {{ console.log(atob('{argument}')); }}"
                    F' catch (error) {{ console.log(error.name); }}')
                self.assertEqual(behavior(source), ('InvalidCharacterError\n', None))
                self.assertEqual(
                    behavior(deobfuscate_source(source)), ('InvalidCharacterError\n', None))

    def test_a_dead_binding_whose_decode_is_refused_keeps_the_refusal(self):
        """
        Node prints nothing for the first program and `after` for the second. Nothing reads either
        binding, and only the one whose decode has a value may be removed along with it.
        """
        refused = "var value = atob('QQ='); console.log('after');"
        self.assertEqual(behavior(refused), ('', 'ERROR'))
        self.assertEqual(behavior(deobfuscate_source(refused)), ('', 'ERROR'))
        decoded = "var value = atob('QQ=='); console.log('after');"
        self.assertEqual(behavior(decoded), ('after\n', None))
        self.assertEqual(deobfuscate_source(decoded), "console.log('after');")

    def test_the_same_text_decodes_where_its_group_is_whole_or_its_padding_is_absent(self):
        """
        Node prints `A A` and `ABCD ABCD`. What the refusal above is about is the trailing `=` and
        not the text it pads, so both spellings of the same bytes still fold to the string they
        name — a decode that refused everything would satisfy the cases above and fail these.
        """
        two_letters = "console.log(atob('QQ=='), atob('QQ'));"
        self.assertEqual(behavior(two_letters), ('A A\n', None))
        self.assertEqual(deobfuscate_source(two_letters), "console.log('A', 'A');")
        four_letters = "console.log(atob('QUJDRA'), atob('QUJDRA=='));"
        self.assertEqual(behavior(four_letters), ('ABCD ABCD\n', None))
        self.assertEqual(deobfuscate_source(four_letters), "console.log('ABCD', 'ABCD');")


_URI_FUNCTIONS = (
    'decodeURIComponent',
    'encodeURIComponent',
    'unescape',
)


_URI_ARGUMENTS = [
    '',
    'abc',
    "-_.!~*'()",
    'a b',
    '+',
    'a+b',
    '/?:@&=$,#[]',
    '"<>\\^`{|}',
    'é',
    '€',
    '%',
    '100%',
    'a%',
    '%A',
    '%4',
    '%GG',
    '%G0',
    '%0G',
    '%%41',
    '%u0041',
    '%uD83D',
    '%41',
    '%41%42',
    '%4a',
    '%25',
    '%2541',
    '%20',
    '%2F',
    '%23',
    '%C3%A9',
    '%c3%a9',
    '%E2%82%AC',
    '%F0%9F%98%80',
    '%F4%8F%BF%BF',
    '%80',
    '%BF',
    '%C2',
    '%E2%82',
    '%41%C0',
    '%C3%28',
    '%C0%80',
    '%C1%BF',
    '%E0%80%AF',
    '%F0%82%82%AC',
    '%ED%A0%80',
    '%ED%BF%BF',
    '%F4%90%80%80',
    '%F5%80%80%80',
    '%FE',
    '%FF',
]
"""
Arguments for the three functions that read and write percent escapes, chosen so that each of the
two questions a decode asks its argument is asked on its own.

The first question is about the text: a `%` is the start of an escape and two hexadecimal digits
have to follow it, so the argument is asked with a `%` at its end, alone, one digit short, followed
by characters that are not hexadecimal, followed by another `%`, and followed by the `u` a
`%uXXXX` escape is written with.

The second is about the bytes the escapes name, which have to be a UTF-8 encoding of a character:
the argument is asked with a continuation byte standing alone, with a sequence cut short, with the
overlong encodings of a character that has a shorter one, with the encodings of a surrogate, and
with the encodings of a number above the last code point. `%F4%8F%BF%BF` is the last code point
itself and `%F4%90%80%80` is the first number past it, so the two sit either side of that edge.

The rest are arguments a decode reads: the empty text, letters, the characters no encode escapes,
the reserved characters an encode escapes and a decode of a component gives back, an escape written
in lowercase, and the `+` that is a plus here and not the space a form encoding reads it as.

No argument here is written with a code unit in the surrogate range, which is a third question and
not a third answer to these two. An encode is asked it below, a surrogate no partner completes
being the one thing an encode refuses. A decode is not: Node hands such an argument straight back,
there being no escape in it to read, and the fold refuses it instead — a defect
`test.lib.scripts.js.test_unfixed_defects` holds, and these arguments join the corpus the day it
comes off.
"""


_ASK_WHAT_THE_URI_FUNCTIONS_ANSWER = R'''
const answers = [];
for (const argument of ARGUMENTS) {
    const row = [];
    for (const fn of FUNCTIONS) {
        try {
            const value = fn(argument);
            const units = [];
            for (let index = 0; index < value.length; index++) {
                units.push(value.charCodeAt(index));
            }
            row.push(units);
        } catch (error) {
            row.push(null);
        }
    }
    answers.push(row);
}
console.log(JSON.stringify(answers));
'''
"""
A program that reports what each function answers for each argument, and a null for each argument it
refuses. An answer crosses as the numbers of its UTF-16 code units rather than as text, so that a
unit naming no character on its own — which `unescape('%uD83D')` is — arrives as the unit it is
instead of as whatever an encoding of the output stream would put in its place. A list of numbers is
never a null, so an answer and a refusal cannot be confused for one another.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheUriFunctionsAnswerEveryArgumentTheWayNodeDoes(TestBase):
    """
    `decodeURIComponent`, `encodeURIComponent` and `unescape` are the functions this project models
    for percent escapes, and they are asked one corpus of arguments together. Two of them are
    partial — an argument they cannot read is a `URIError` and not a value — so the corpus decides
    both what a call computes and whether it computes anything at all, and reading either function's
    domain too widely turns a program that throws into one that has a value. Node names every answer
    and every refusal.
    """

    def _node_answers(self) -> list[list[list[int] | None]]:
        source = (
            F'const ARGUMENTS = {json.dumps(_URI_ARGUMENTS)};'
            F'const FUNCTIONS = [{", ".join(_URI_FUNCTIONS)}];'
        )
        output, error = behavior(source + _ASK_WHAT_THE_URI_FUNCTIONS_ANSWER)
        self.assertIsNone(error)
        return json.loads(output)

    def _builtin_answers(self) -> list[list[list[int] | None]]:
        answers: list[list[list[int] | None]] = []
        for argument in _URI_ARGUMENTS:
            row: list[list[int] | None] = []
            for name in _URI_FUNCTIONS:
                try:
                    row.append([ord(unit) for unit in BUILTIN_REGISTRY[None, name]([argument])])
                except InterpreterError:
                    row.append(None)
            answers.append(row)
        return answers

    def test_the_builtins_answer_every_argument_the_way_node_answers_it(self):
        self.assertEqual(self._node_answers(), self._builtin_answers())


_ARGUMENTS_NO_DECODE_READS = [
    '%',
    '100%',
    'a%',
    '%A',
    '%4',
    '%GG',
    '%G0',
    '%0G',
    '%%41',
    '%u0041',
    '%80',
    '%BF',
    '%C2',
    '%E2%82',
    '%41%C0',
    '%C3%28',
    '%C0%80',
    '%C1%BF',
    '%E0%80%AF',
    '%F0%82%82%AC',
    '%ED%A0%80',
    '%ED%BF%BF',
    '%F4%90%80%80',
    '%F5%80%80%80',
    '%FE',
    '%FF',
]
"""
The arguments of `_URI_ARGUMENTS` that `decodeURIComponent` throws a `URIError` on, the ones whose
text no escape can be read out of first and the ones whose escapes name bytes that are no UTF-8
encoding of a character second.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADecodeThatRefusesItsArgumentIsNotFoldedToAString(TestBase):
    """
    `decodeURIComponent` produces no value for an argument it refuses: the call throws and the
    program aborts there. A fold that answers such a call with a string invents a value for a file
    that has none, and the program it hands back runs to completion where the file it came from
    stopped.
    """

    def _calls_that_catch(self, arguments: list[str]) -> str:
        return ''.join(
            F'try {{ console.log(decodeURIComponent({json.dumps(argument)})); }}'
            F' catch (error) {{ console.log(error.name); }}\n'
            for argument in arguments
        )

    def test_every_argument_no_decode_reads_raises_the_error_node_raises(self):
        """
        Node prints `URIError` once for each argument and nothing else, so no call among them is one
        that has a string. The deobfuscation of the same file has to print the same lines: a fold
        that answered any of these calls would print what it decided the call was worth in place of
        the error the line reports.
        """
        source = self._calls_that_catch(_ARGUMENTS_NO_DECODE_READS)
        refused = ('URIError\n' * len(_ARGUMENTS_NO_DECODE_READS), None)
        self.assertEqual(behavior(source), refused)
        self.assertEqual(behavior(deobfuscate_source(source)), refused)

    def test_a_refused_call_is_left_standing_and_the_program_still_aborts(self):
        """
        Node prints nothing and exits with the `URIError` uncaught, for a `%` no digits follow and
        for an escape sequence naming the bytes of a surrogate. Nothing catches either one, so the
        `console.log` around it is never reached and the call has to still be there afterwards.
        """
        for argument in ('100%', '%ED%A0%80'):
            with self.subTest(argument=argument):
                source = F'console.log(decodeURIComponent({json.dumps(argument)}));'
                self.assertEqual(behavior(source), ('', 'URIError'))
                self.assertEqual(deobfuscate_source(source), source)
                self.assertEqual(behavior(deobfuscate_source(source)), ('', 'URIError'))

    def test_a_dead_binding_whose_decode_is_refused_keeps_the_refusal(self):
        """
        Node prints nothing for the first program and `after` for the second. Nothing reads either
        binding, and only the one whose decode has a value may be removed along with it.
        """
        refused = 'var value = decodeURIComponent("100%"); console.log("after");'
        self.assertEqual(behavior(refused), ('', 'URIError'))
        self.assertEqual(behavior(deobfuscate_source(refused)), ('', 'URIError'))
        decoded = 'var value = decodeURIComponent("%41"); console.log("after");'
        self.assertEqual(behavior(decoded), ('after\n', None))
        self.assertEqual(deobfuscate_source(decoded), 'console.log("after");')

    def test_an_argument_whose_escapes_are_whole_folds_to_the_text_it_names(self):
        """
        Node prints each of these, and a decode that refused everything would satisfy the cases
        above and fail this one. The escapes are read whichever case their digits are written in,
        `%25` is the `%` that stands for itself, a `+` is a plus and not a space, `%2F` is the
        reserved character a decode of a component gives back, and the last two escape sequences
        name characters above the basic plane, the second of them the last code point there is.
        """
        for argument, folded, printed in [
            ('%41', "console.log('A');", 'A\n'),
            ('100%25', "console.log('100%');", '100%\n'),
            ('+', "console.log('+');", '+\n'),
            ('%2F', "console.log('/');", '/\n'),
            ('%c3%a9', "console.log('é');", 'é\n'),
            ('%E2%82%AC', "console.log('€');", '€\n'),
            ('%F0%9F%98%80', "console.log('\U0001F600');", '\U0001F600\n'),
            ('%F4%8F%BF%BF', "console.log('\U0010FFFF');", '\U0010FFFF\n'),
        ]:
            with self.subTest(argument=argument):
                source = F'console.log(decodeURIComponent({json.dumps(argument)}));'
                self.assertEqual(behavior(source), (printed, None))
                self.assertEqual(deobfuscate_source(source), folded)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestUnescapeReadsEveryArgumentNoDecodeReads(TestBase):
    """
    `unescape` is total where `decodeURIComponent` is partial: it reads a `%` that introduces no
    escape as the character it is and never asks whether the bytes an escape names encode anything,
    so no argument is a refusal. The two functions therefore do not share a contract, and the corpus
    that decides one says nothing about the other.
    """

    def test_every_argument_a_decode_refuses_is_one_unescape_reads(self):
        """
        Node prints `URIError` and then `unescaped` for each argument: the same text that no decode
        reads is one `unescape` hands a string back for. Both lines have to survive the
        deobfuscation — the first because the throw is not a value to fold the call to, the second
        because there is nothing there to throw.
        """
        source = ''.join(
            F'try {{ decodeURIComponent({json.dumps(argument)}); console.log("decoded"); }}'
            F' catch (error) {{ console.log(error.name); }}\n'
            F'try {{ unescape({json.dumps(argument)}); console.log("unescaped"); }}'
            F' catch (error) {{ console.log(error.name); }}\n'
            for argument in _ARGUMENTS_NO_DECODE_READS
        )
        both = ('URIError\nunescaped\n' * len(_ARGUMENTS_NO_DECODE_READS), None)
        self.assertEqual(behavior(source), both)
        self.assertEqual(behavior(deobfuscate_source(source)), both)

    def test_each_argument_folds_to_the_text_unescape_answers_with(self):
        """
        Node prints each of these. A `%` no pair of hexadecimal digits follows stands for itself,
        `%41` and `%u0041` are both the letter `A`, and the bytes of an escape are code units and
        not UTF-8: `%C3%A9` is two characters here where a decode of it is the one character those
        two bytes encode.
        """
        for argument, folded, printed in [
            ('100%', "console.log('100%');", '100%\n'),
            ('%', "console.log('%');", '%\n'),
            ('a%', "console.log('a%');", 'a%\n'),
            ('%GG', "console.log('%GG');", '%GG\n'),
            ('%%41', "console.log('%A');", '%A\n'),
            ('%41', "console.log('A');", 'A\n'),
            ('%u0041', "console.log('A');", 'A\n'),
            ('%80', "console.log('\x80');", '\x80\n'),
            ('%C3%A9', "console.log('\xc3\xa9');", '\xc3\xa9\n'),
            ('%ED%A0%80', "console.log('\xed\xa0\x80');", '\xed\xa0\x80\n'),
        ]:
            with self.subTest(argument=argument):
                source = F'console.log(unescape({json.dumps(argument)}));'
                self.assertEqual(behavior(source), (printed, None))
                self.assertEqual(deobfuscate_source(source), folded)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnEncodeRefusesASurrogateThatNamesNoCharacter(TestBase):
    """
    `encodeURIComponent` writes the UTF-8 of the characters its argument names, so it is refused by
    an argument that names none: a code unit in the surrogate range that no partner completes is a
    `URIError` wherever it stands. A pair that is whole names one character and is encoded, which is
    the same question answered the other way.
    """

    def test_a_surrogate_no_partner_completes_is_refused(self):
        """
        Node prints nothing and exits with the `URIError` uncaught for a high surrogate alone, a low
        surrogate alone, one standing between two letters, and a low surrogate written before a high
        one — an order no pair is written in, so neither of the two completes the other.
        """
        for spelling in (R'\uD800', R'\uDFFF', R'a\uD83Db', R'\uDC00\uD800'):
            with self.subTest(spelling=spelling):
                source = F'console.log(encodeURIComponent("{spelling}"));'
                self.assertEqual(behavior(source), ('', 'URIError'))
                self.assertEqual(behavior(deobfuscate_source(source)), ('', 'URIError'))

    def test_a_pair_that_is_whole_is_encoded_as_the_utf8_of_the_character_it_names(self):
        """
        Node prints `a%F0%9F%98%80b`, those four bytes being the UTF-8 of U+1F600, which the two
        code units of the argument name together.
        """
        source = R'console.log(encodeURIComponent("a😀b"));'
        self.assertEqual(behavior(source), ('a%F0%9F%98%80b\n', None))
        self.assertEqual(deobfuscate_source(source), "console.log('a%F0%9F%98%80b');")

    def test_the_characters_an_encode_writes_as_themselves_are_the_unreserved_ones(self):
        """
        Node prints the nine characters unchanged and then escapes every character of the second
        argument that is not a letter, so the reserved characters a URI is punctuated with are
        escaped by an encode of a component and are not the same set the letters and the nine are.
        """
        source = (
            'console.log(encodeURIComponent("-_.!~*\'()"),'
            ' encodeURIComponent("a b/c?d=e&f#g"));'
        )
        self.assertEqual(behavior(source), ("-_.!~*'() a%20b%2Fc%3Fd%3De%26f%23g\n", None))
        self.assertEqual(
            deobfuscate_source(source),
            "console.log('-_.!~*\\'()', 'a%20b%2Fc%3Fd%3De%26f%23g');",
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWellKnownObjectNameThatABindingHasClaimed(TestBase):
    """
    `Math`, `Number` and `String` are ordinary global bindings, and a program is free to name a
    local one the same. Where it does, a member call written on that name is a call on the object
    the program made, and answering it as the built-in computes with a function the program never
    calls.

    A call written inside a string that a direct `eval` runs is the same question asked where there
    is nothing yet to ask it of: the call site is code that exists only once the eval has been
    inlined, so what the name denotes there is decided by where that code lands rather than by an
    effect model consulted beforehand.

    Node decides. Each case names the program a fold that missed the binding would produce and
    requires Node to print something else for it, so a replacement that answers the way the built-in
    does cannot pass for a proof.
    """

    def _shadowed(self, source: str, misfolded: str):
        self.assertNotEqual(
            behavior(source),
            behavior(misfolded),
            'the program does not discriminate: the replacement answers as the built-in does',
        )
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_local_variable_named_math_is_what_a_floor_call_reaches(self):
        """
        Node: `r1.5`, and `1` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f() {
                  var Math = { floor: function (x) { return 'r' + x; } };
                  return Math.floor(1.5);
                }
                console.log(f());
            """),
            inspect.cleandoc("""
                function f() {
                  var Math = { floor: function (x) { return 'r' + x; } };
                  return 1;
                }
                console.log(f());
            """),
        )

    def test_a_parameter_named_math_is_what_a_floor_call_reaches(self):
        """
        Node: `r1.5`, and `1` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f(Math) {
                  return Math.floor(1.5);
                }
                console.log(f({ floor: function (x) { return 'r' + x; } }));
            """),
            inspect.cleandoc("""
                function f(Math) {
                  return 1;
                }
                console.log(f({ floor: function (x) { return 'r' + x; } }));
            """),
        )

    def test_a_catch_binding_named_math_is_what_a_floor_call_reaches(self):
        """
        Node: `r1.5`, and `1` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f() {
                  try {
                    throw { floor: function (x) { return 'r' + x; } };
                  } catch (Math) {
                    return Math.floor(1.5);
                  }
                }
                console.log(f());
            """),
            inspect.cleandoc("""
                function f() {
                  try {
                    throw { floor: function (x) { return 'r' + x; } };
                  } catch (Math) {
                    return 1;
                  }
                }
                console.log(f());
            """),
        )

    def test_a_local_variable_named_number_is_what_a_parse_int_call_reaches(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f() {
                  var Number = { parseInt: function (text) { return 'r' + text; } };
                  return Number.parseInt('10');
                }
                console.log(f());
            """),
            inspect.cleandoc("""
                function f() {
                  var Number = { parseInt: function (text) { return 'r' + text; } };
                  return 10;
                }
                console.log(f());
            """),
        )

    def test_a_local_variable_named_string_is_what_a_from_char_code_call_reaches(self):
        """
        Node: `r65`, and `A` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f() {
                  var String = { fromCharCode: function (code) { return 'r' + code; } };
                  return String.fromCharCode(65);
                }
                console.log(f());
            """),
            inspect.cleandoc("""
                function f() {
                  var String = { fromCharCode: function (code) { return 'r' + code; } };
                  return 'A';
                }
                console.log(f());
            """),
        )

    def test_a_local_variable_named_math_is_what_a_call_inside_a_direct_eval_reaches(self):
        """
        Node: `r1.5`, and `1` for the program that read the name as the built-in. A direct eval runs
        its argument in the scope of the call, which is the scope the local was declared in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f() {
                  var Math = { floor: function (x) { return 'r' + x; } };
                  return eval("Math.floor(1.5)");
                }
                console.log(f());
            """),
            inspect.cleandoc("""
                function f() {
                  var Math = { floor: function (x) { return 'r' + x; } };
                  return 1;
                }
                console.log(f());
            """),
        )

    def test_a_parameter_named_math_is_what_a_call_inside_a_direct_eval_reaches(self):
        """
        Node: `r1.5`, and `1` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f(Math) {
                  return eval("Math.floor(1.5)");
                }
                console.log(f({ floor: function (x) { return 'r' + x; } }));
            """),
            inspect.cleandoc("""
                function f(Math) {
                  return 1;
                }
                console.log(f({ floor: function (x) { return 'r' + x; } }));
            """),
        )

    def test_a_catch_binding_named_number_is_what_a_call_inside_a_direct_eval_reaches(self):
        """
        Node: `r10`, and `10` for the program that read the name as the built-in.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f() {
                  try {
                    throw { parseInt: function (text) { return 'r' + text; } };
                  } catch (Number) {
                    return eval("Number.parseInt('10')");
                  }
                }
                console.log(f());
            """),
            inspect.cleandoc("""
                function f() {
                  try {
                    throw { parseInt: function (text) { return 'r' + text; } };
                  } catch (Number) {
                    return 10;
                  }
                }
                console.log(f());
            """),
        )

    def test_a_parameter_named_math_is_what_a_call_inside_a_nested_functions_eval_reaches(self):
        """
        Node: `r1.5`, and `1` for the program that read the name as the built-in. The parameter is
        the only meaning `Math` has anywhere inside `outer`, and the eval runs inside `inner`, which
        is inside `outer`.
        """
        self._shadowed(
            inspect.cleandoc("""
                function outer(Math) {
                  function inner() {
                    return eval("Math.floor(1.5)");
                  }
                  return inner();
                }
                console.log(outer({ floor: function (x) { return 'r' + x; } }));
            """),
            inspect.cleandoc("""
                function outer(Math) {
                  function inner() {
                    return 1;
                  }
                  return inner();
                }
                console.log(outer({ floor: function (x) { return 'r' + x; } }));
            """),
        )

    def test_a_parameter_named_string_is_what_a_call_inside_an_eval_of_a_built_string_reaches(self):
        """
        Node: `r65`, and `A` for the program that read the name as the built-in. The code the eval
        runs is not written anywhere in the program; it is the value of an expression.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f(String) {
                  return eval("Stri" + "ng.fromCharCode(65)");
                }
                console.log(f({ fromCharCode: function (code) { return 'r' + code; } }));
            """),
            inspect.cleandoc("""
                function f(String) {
                  return 'A';
                }
                console.log(f({ fromCharCode: function (code) { return 'r' + code; } }));
            """),
        )

    def test_a_parameter_named_math_without_that_method_throws_where_the_builtin_answers(self):
        """
        Node: `TypeError`, and `1` for the program that read the name as the built-in. The object
        the program passes has no `floor` at all, so answering the call with a number replaces a
        throw with a value.
        """
        self._shadowed(
            inspect.cleandoc("""
                function f(Math) {
                  try {
                    return eval("Math.floor(1.5)");
                  } catch (error) {
                    return error.name;
                  }
                }
                console.log(f({}));
            """),
            inspect.cleandoc("""
                function f(Math) {
                  try {
                    return 1;
                  } catch (error) {
                    return error.name;
                  }
                }
                console.log(f({}));
            """),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANumberParseCallWrittenWhereNothingReadsItsValue(TestBase):
    """
    `Number.parseInt` and `Number.parseFloat` are the global functions of those names, so a call of
    one names a number wherever it is written. A statement that is nothing but such a call has a
    value nothing reads, and what decides whether the statement may go is not the call but the
    arguments it was written with: an argument can throw, and an argument can write.

    Node says what each program prints, and the program it deobfuscates to has to print the same.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_discarded_call_prints_what_the_program_around_it_prints(self):
        """
        Node prints `after` for each: the call names a number and the statement it is drops it, so
        the only thing the run prints is what the statement behind it prints.
        """
        self._prints("Number.parseInt('42'); console.log('after');", 'after\n')
        self._prints("Number.parseFloat('2.5'); console.log('after');", 'after\n')
        self._prints("Number.parseInt('nope'); console.log('after');", 'after\n')
        self._prints("Number.parseFloat('Infinity'); console.log('after');", 'after\n')
        self._prints("Number.parseInt('42', 10); console.log('after');", 'after\n')

    def test_a_call_whose_value_is_read_is_the_number_it_names(self):
        """
        Node prints `42` and `2.5`. The emitted text is pinned as well, because a program that
        printed the right number by leaving the call where it stood would satisfy the comparison of
        behavior and tell nothing about whether the call was read at all.
        """
        integer = "console.log(Number.parseInt('42'));"
        self._prints(integer, '42\n')
        self.assertEqual(deobfuscate_source(integer), 'console.log(42);')
        decimal = "console.log(Number.parseFloat('2.5'));"
        self._prints(decimal, '2.5\n')
        self.assertEqual(deobfuscate_source(decimal), 'console.log(2.5);')

    def test_a_discarded_call_whose_argument_names_nothing_still_throws(self):
        """
        Node prints nothing and exits with an uncaught `ReferenceError`: the argument is evaluated
        before the call, and `nowhere` is declared in no scope. Dropping the statement because its
        value is unread turns a program that throws into one that prints `after`.
        """
        source = "Number.parseInt(nowhere); console.log('after');"
        self.assertEqual(behavior(source), ('', 'ReferenceError'))
        self.assertEqual(behavior(deobfuscate_source(source)), ('', 'ReferenceError'))

    def test_a_discarded_call_whose_argument_writes_still_writes(self):
        """
        Node prints `1`. The third argument is one `parseInt` never reads, and the increment it
        performs outlives the statement whose value nothing reads.
        """
        self._prints("var x = 0; Number.parseInt('10', 2, x++); console.log(x);", '1\n')

    def test_a_discarded_call_whose_argument_calls_still_calls(self):
        """
        Node prints `a`: the same argument list where the effect is a call rather than a write.
        """
        self._prints(
            "var sink = []; Number.parseFloat(sink.push('a')); console.log(sink.join('|'));",
            'a\n')


_JOINERS = [chr(0x200C), chr(0x200D)]
"""
The zero width non-joiner and the zero width joiner. Both are IdentifierPart and neither is
IdentifierStart, so a name may hold one anywhere but its beginning.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAJoinerInsideANameIsPartOfTheNameItStandsIn(TestBase):
    """
    A name that holds a zero width joiner or non-joiner is that name and not the name spelled
    without it. Neither character has any width, so the two spellings are indistinguishable on the
    page while denoting different bindings, and a reader that dropped one or refused it would either
    conflate two names or lose one. Node says what each program prints.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_binding_whose_name_holds_a_joiner_is_read_by_that_name(self):
        """
        Node prints `7`. The emitted text is pinned as well: the value reaches the call only because
        the declaration and the read are one name, so a program that still prints `7` while leaving
        the two standing tells nothing.
        """
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                source = F'var a{joiner}b = 7; console.log(a{joiner}b);'
                self._prints(source, '7\n')
                self.assertEqual(deobfuscate_source(source), 'console.log(7);')

    def test_two_names_that_differ_only_by_a_joiner_are_two_names(self):
        """
        Node prints `1 2`. A reader that dropped the joiner would declare `ab` twice and print the
        second value for both reads.
        """
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                self._prints(
                    F'var ab = 1; var a{joiner}b = 2; console.log(ab, a{joiner}b);', '1 2\n')

    def test_the_two_joiners_name_two_different_bindings(self):
        """
        Node prints `1 2`. The two characters are not one another, so the names they stand in are
        not one name either.
        """
        non_joiner, joiner = _JOINERS
        self._prints(
            F'var a{non_joiner}b = 1; var a{joiner}b = 2;'
            F' console.log(a{non_joiner}b, a{joiner}b);',
            '1 2\n')

    def test_a_name_spelled_without_the_joiner_reaches_no_binding(self):
        """
        Node prints `ReferenceError`: the program declares one name and reads another, however alike
        the two look. A reader that dropped the joiner would print `7`.
        """
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                self._prints(
                    F'var a{joiner}b = 7;'
                    ' try { console.log(ab); } catch (error) { console.log(error.name); }',
                    'ReferenceError\n')

    def test_a_parameter_whose_name_holds_a_joiner_is_read_in_the_body(self):
        """
        Node prints `7`.
        """
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                self._prints(
                    F'function f(a{joiner}b) {{ return a{joiner}b + 1; }} console.log(f(6));',
                    '7\n')


_LINE_ENDINGS = [chr(0x000A), chr(0x000D), chr(0x000D) + chr(0x000A), chr(0x2028), chr(0x2029)]
"""
Every spelling of a line ending: the line feed, the carriage return, the pair of the two, which is
one ending and not two, and the line separator and the paragraph separator.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileThatOpensWithAHashBangLine(TestBase):
    """
    A file may open with a `#!` line, which is a comment: nothing it says is code, and it is over at
    the first line terminator, of which the language has four. Node runs every program below, and
    the deobfuscation of each has to run the same way — a line ending the reader does not know ends
    the comment swallows the program written behind it, which prints nothing at all.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_file_is_read_the_same_whichever_terminator_ends_its_hash_bang_line(self):
        """
        Node prints `1` for each of the five spellings, and each deobfuscates to the one program
        they all are, the `#!` line kept at its head and ended by the line feed the printer writes.
        """
        for ending in _LINE_ENDINGS:
            with self.subTest(ending=' '.join(F'U+{ord(c):04X}' for c in ending)):
                source = F'#!/usr/bin/env node{ending}console.log(1);'
                self._prints(source, '1\n')
                self.assertEqual(deobfuscate_source(source), '#!/usr/bin/env node\nconsole.log(1);')

    def test_what_the_hash_bang_line_says_is_not_code(self):
        """
        Node prints `1` and never `boom`: the call written on the first line is inside the comment
        the line is, and the one written below it is the whole program. The line comes back as it
        was written, a comment still.
        """
        source = F"#!console.log('boom'){chr(0x000A)}console.log(1);"
        self._prints(source, '1\n')
        self.assertEqual(deobfuscate_source(source), "#!console.log('boom')\nconsole.log(1);")

    def test_a_file_whose_hash_bang_line_is_all_of_it_prints_nothing(self):
        source = '#!/usr/bin/env node'
        self.assertEqual(behavior(source), ('', None))
        self.assertEqual(deobfuscate_source(source), source)
        self.assertEqual(behavior(deobfuscate_source(source)), ('', None))

    def test_the_statements_below_a_hash_bang_line_end_where_their_lines_end(self):
        """
        Node prints `2 1`: the line ending closes `var y = x`, so `++x` is a statement of its own,
        exactly as it is in a file that opens with no such line. A `#!` line that took the ending
        with it would leave the two statements below it reading as `x ++ x`, which is no program.
        """
        for ending in [chr(0x000A), chr(0x000D) + chr(0x000A)]:
            with self.subTest(ending=' '.join(F'U+{ord(c):04X}' for c in ending)):
                lines = [
                    '#!/usr/bin/env node',
                    'var x = 1',
                    'var y = x',
                    '++x',
                    'console.log(x, y)',
                ]
                self._prints(ending.join(lines), '2 1\n')


_SMILE = chr(0x1F600)
_ACUTE = chr(0xE9)

_SMILE_ESCAPED_SPELLINGS = [
    R'\uD83D\uDE00',
    R'\u{1F600}',
]
"""
The two ways to write `U+1F600` without typing it: an escape for each of the code units that spell
it, and one escape naming the code point.
"""

_SMILE_SPELLINGS = [_SMILE, *_SMILE_ESCAPED_SPELLINGS]
"""
Every way a program may write the one character `U+1F600`, the character itself included. Node
reports the three literals equal to one another and each of them two code units long.
"""

_ACUTE_SPELLINGS = [_ACUTE, R'\u00E9', R'\u{E9}']
"""
The same three ways of writing `U+00E9`, a character the basic multilingual plane holds, where one
code unit is the whole character.
"""

_SMILE_HALVES = R"'\uD83D' + '\uDE00'"
"""
An expression joining the two code units of `U+1F600`, each written as a string of its own. Node
reports the result equal to every spelling of the character.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestHowAStringIsSpelledIsNoPartOfTheStringItDenotes(TestBase):
    """
    A JavaScript string is a sequence of UTF-16 code units, and nothing it answers recalls how the
    source wrote it down: a character typed as itself, written as an escape for each of its two code
    units, and written as one escape naming its code point are three spellings of one string. Every
    output below is the one Node prints, and the deobfuscation of each program has to print it too.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def _compared(self, spellings: list[str], operator: str) -> str:
        answers = ', '.join(
            F"'{left}' {operator} '{right}'"
            for left in spellings
            for right in spellings
        )
        return F'console.log({answers});'

    def _counted_and_indexed(self, spelling: str) -> str:
        subject = F"'a{spelling}b'"
        answers = ', '.join([
            F'{subject}.length',
            F'{subject}.charCodeAt(1)',
            F'{subject}.charCodeAt(2)',
            F"{subject}.indexOf('b')",
            F'{subject}.slice(1, 3)',
            F'{subject}.substring(1, 3)',
            F"{subject}.split('').length",
        ])
        return F'console.log({answers});'

    def _code_points_read(self, spelling: str) -> str:
        subject = F"'a{spelling}b'"
        answers = ', '.join(
            F'{subject}.codePointAt({position})' for position in range(4)
        )
        return F'console.log({answers});'

    def _searched(self, haystack: str, needle: str) -> str:
        subject = F"'a{haystack}b'"
        answers = ', '.join([
            F"{subject}.indexOf('{needle}')",
            F"{subject}.includes('{needle}')",
            F"{subject}.replace('{needle}', 'X')",
        ])
        return F'console.log({answers});'

    def _assembled(self, spelling: str) -> str:
        subject = F"'{spelling}'"
        answers = ', '.join([
            F'String.fromCharCode(0xD83D, 0xDE00) === {subject}',
            F'String.fromCodePoint(0x1F600) === {subject}',
            F'({_SMILE_HALVES}) === {subject}',
        ])
        return F'console.log({answers});'

    def _branched(self, left: str, right: str) -> str:
        return (
            F"if ('{left}' === '{right}') {{ console.log('same'); }}"
            F" else {{ console.log('different'); }}"
        )

    def test_the_spellings_of_an_astral_character_denote_one_string(self):
        """
        Node prints `true` nine times: each spelling of `U+1F600` is equal to each of them, itself
        included.
        """
        self._prints(
            self._compared(_SMILE_SPELLINGS, '==='),
            'true true true true true true true true true\n',
        )

    def test_the_spellings_of_a_basic_plane_character_denote_one_string(self):
        """
        Node prints `true` nine times for `U+00E9` as well, which is the same rule read where one
        code unit is the whole character.
        """
        self._prints(
            self._compared(_ACUTE_SPELLINGS, '==='),
            'true true true true true true true true true\n',
        )

    def test_no_spelling_of_an_astral_character_orders_before_another(self):
        """
        Node prints `false` nine times for each operator: strings holding the same code units in the
        same order stand in no order to one another.
        """
        for operator in ['<', '>']:
            with self.subTest(operator=operator):
                self._prints(
                    self._compared(_SMILE_SPELLINGS, operator),
                    'false false false false false false false false false\n',
                )

    def test_a_comparison_of_two_spellings_selects_the_branch_that_runs(self):
        """
        Node prints `same` for every pairing. The other branch is never reached, so a deobfuscation
        that keeps it has deleted the code the program runs and written in the code it does not.
        """
        for left in _SMILE_SPELLINGS:
            for right in _SMILE_SPELLINGS:
                with self.subTest(left=left, right=right):
                    self._prints(self._branched(left, right), 'same\n')

    def test_a_search_finds_the_character_however_the_needle_is_spelled(self):
        """
        Node prints `1 true aXb` for every pairing: the character stands at code unit 1 of the
        string, whichever of the two was written which way.
        """
        for haystack in _SMILE_SPELLINGS:
            for needle in _SMILE_SPELLINGS:
                with self.subTest(haystack=haystack, needle=needle):
                    self._prints(self._searched(haystack, needle), '1 true aXb\n')

    def test_an_astral_character_assembled_at_run_time_equals_every_spelling_of_it(self):
        """
        Node prints `true` three times for each spelling: a string is the code units it holds, so
        one assembled from those units equals one the source wrote out.
        """
        for spelling in _SMILE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(self._assembled(spelling), 'true true true\n')

    def test_an_astral_character_written_with_escapes_is_counted_and_indexed_in_code_units(self):
        """
        Node prints `4 55357 56832 3`, the character twice, and `4`: it occupies units 1 and 2, so
        the string is four units long, `b` begins at unit 3, and either cut from 1 to 3 is the
        character itself.
        """
        for spelling in _SMILE_ESCAPED_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(
                    self._counted_and_indexed(spelling),
                    F'4 55357 56832 3 {_SMILE} {_SMILE} 4\n',
                )

    def test_a_basic_plane_character_is_counted_and_indexed_the_same_in_every_spelling(self):
        """
        Node prints `3 233 98 2`, the character followed by `b` twice, and `3`: one code unit is the
        whole character here, so every count and every offset falls one short of the astral string.
        """
        for spelling in _ACUTE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(
                    self._counted_and_indexed(spelling),
                    F'3 233 98 2 {_ACUTE}b {_ACUTE}b 3\n',
                )

    def test_the_character_beginning_at_a_position_is_read_from_the_units_standing_there(self):
        """
        Node prints `97 128512 56832 98` for every spelling of the astral string: the position
        holding the high surrogate answers with the whole character, and the one holding the low
        surrogate answers with that surrogate alone. For `U+00E9` it prints `97 233 98 undefined`,
        where the fourth position is past the end of a string one unit shorter.
        """
        for spelling in _SMILE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(self._code_points_read(spelling), '97 128512 56832 98\n')
        for spelling in _ACUTE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(self._code_points_read(spelling), '97 233 98 undefined\n')


A_PROGRAM_THAT_REPORTS_ITS_MODE = (
    'function probe() { return this; } console.log(probe() === undefined);'
)
"""
A program that says which mode it runs in. A plain call passes no receiver, so `this` in the body is
the global object where the code is sloppy and `undefined` where it is strict: Node prints `false`
for the one and `true` for the other.
"""

SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE = [
    "('use strict');",
    "'use ' + 'strict';",
    "'use' + ' ' + 'strict';",
    "['use', 'strict'].join(' ');",
    "'USE STRICT'.toLowerCase();",
    "'a', 'use strict';",
]
"""
Statements that denote the same text and are not directives either: a bracket around the literal, an
operator beside it, or a call that computes it each leaves a statement that merely evaluates to the
text. The last of them denotes it without computing anything at all, a sequence expression being
worth its final operand. Node runs every program opening with one of these as sloppy code too, and
what the tool makes of them is law in `test.lib.scripts.js.test_directive_prologue`.
"""

SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING = [
    "('abc'[0]);",
    "atob('YQ==');",
    "'a' + 'b';",
    "['a', 'b'].join('');",
    "'A'.toLowerCase();",
    "'use strict', 'a';",
]
"""
Statements that are not string literals and that a fold rewrites as one. None of them denotes `use
strict`, so none becomes a directive itself — not even the last, which spells the text and discards
it, a sequence expression being worth its final operand. What each does is continue the Directive
Prologue it should have ended, which hands a `'use strict'` written below it the directive position
it never had. The first of them is a read a fold already declines in this position, written inside a
bracket:
the refusal reads the tree, where the bracket stands between the statement and the read, and the
printer does not write that bracket back. What the tool makes of them is law in
`test.lib.scripts.js.test_directive_prologue`.
"""

_SPELLINGS_THAT_ONLY_DENOTE_THE_TEXT_OF_A_DIRECTIVE = [
    R"'use\u0020strict';",
]
"""
Statements that denote the text `use strict` and are not directives. A directive is a string literal
written plainly, so an escape inside it leaves a statement that merely evaluates to the same text.
Node runs every program opening with one of these as sloppy code.
"""


def a_script_opening_with(head: str) -> str:
    return F'{head} {A_PROGRAM_THAT_REPORTS_ITS_MODE}'


def a_function_body_opening_with(head: str) -> str:
    return (
        F'function probe() {{ {head} return this; }}'
        ' console.log(probe() === undefined);'
    )


def a_file_holding_an_octal_literal_opening_with(head: str) -> str:
    return F'{head} console.log(010);'


def a_script_whose_directive_stands_below(head: str) -> str:
    return F"{head} 'use strict'; {A_PROGRAM_THAT_REPORTS_ITS_MODE}"


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhetherAStatementIsADirectiveIsDecidedByHowItIsWritten(TestBase):
    """
    The first statement of a script, and the first of a function body, is a directive when it is a
    string literal and only then: what the statement denotes decides nothing and how it was written
    decides everything. The tool rewrites a statement as it simplifies it, and a rewrite arriving at
    the plain spelling turns sloppy code strict, silently and for the whole of the file or body the
    statement stands at the top of.
    """

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:{chr(10)}{deobfuscated}',
        )

    def test_a_plainly_written_string_is_the_directive_and_stays_one(self):
        """
        Node prints `true` for both, since the file and the function body each open with the
        directive. A rewrite that dropped it would leave the code sloppy.
        """
        self._prints(a_script_opening_with("'use strict';"), 'true' + chr(10))
        self._prints(a_function_body_opening_with("'use strict';"), 'true' + chr(10))

    def test_a_statement_that_only_denotes_the_text_leaves_the_script_sloppy(self):
        for head in _SPELLINGS_THAT_ONLY_DENOTE_THE_TEXT_OF_A_DIRECTIVE:
            with self.subTest(head=head):
                self._prints(a_script_opening_with(head), 'false' + chr(10))

    def test_a_statement_that_only_denotes_the_text_leaves_the_function_body_sloppy(self):
        for head in _SPELLINGS_THAT_ONLY_DENOTE_THE_TEXT_OF_A_DIRECTIVE:
            with self.subTest(head=head):
                self._prints(a_function_body_opening_with(head), 'false' + chr(10))

    def test_a_file_that_holds_an_octal_literal_still_parses(self):
        """
        Node prints `8` for each of these, an octal literal being a number in sloppy code and one of
        the spellings strict mode forbids outright. A directive that appears where none was written
        costs the file its ability to parse at all, so what comes back is not a program.
        """
        for head in _SPELLINGS_THAT_ONLY_DENOTE_THE_TEXT_OF_A_DIRECTIVE:
            with self.subTest(head=head):
                self._prints(
                    a_file_holding_an_octal_literal_opening_with(head), '8' + chr(10))

    def test_a_use_strict_below_a_statement_that_is_no_directive_is_none_either(self):
        """
        Node prints `false` for each of these files. The head is not a string literal, so the
        Directive Prologue ends at it, and the `'use strict'` on the line below is an expression
        statement that computes a string and discards it. What the tool makes of these files is
        law in `test.lib.scripts.js.test_directive_prologue`.
        """
        for head in SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING:
            with self.subTest(head=head):
                self.assertEqual(
                    behavior(a_script_whose_directive_stands_below(head)),
                    ('false' + chr(10), None),
                )
