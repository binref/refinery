from __future__ import annotations

import inspect
import json
import unicodedata
import unittest

from test import TestBase, opportunity, todo

from refinery.lib.scripts import canonical
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.interpreter import BUILTIN_REGISTRY, InterpreterError
from refinery.lib.scripts.js.lexer import JsLexer
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.options import ExecutionModel
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

    def _check(self, source: str) -> str:
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

    def test_closure_counter(self):
        self._check(
            'function mk(){ var c = 0; return function(){ return ++c; }; }'
            ' var f = mk(); console.log(f(), f(), f());')

    def test_function_and_var_hoisting(self):
        self._check('console.log(g()); function g(){ var r = 41; return r + 1; }')

    def test_dead_variable_and_constant_folding(self):
        deobfuscated = self._check('var a = 1 + 2; var unused = 5; console.log(a * 2);')
        self.assertEqual(deobfuscated, 'console.log(6);')

    def test_dead_global_read_with_installed_getter_preserved(self):
        self._check(
            'var SINK = [];'
            " Object.defineProperty(globalThis, 'TextDecoder',"
            " { configurable: true, get: function () { SINK.push('read'); return 1; } });"
            ' var dead = globalThis.TextDecoder;'
            " console.log(SINK.join('|'));")

    def test_dead_global_alias_read_with_installed_getter_preserved(self):
        self._check(
            'var SINK = [];'
            " Object.defineProperty(globalThis, 'TextDecoder',"
            " { configurable: true, get: function () { SINK.push('read'); return 1; } });"
            ' var g = globalThis || {};'
            ' var dead = g.TextDecoder;'
            " console.log(SINK.join('|'));")

    def test_constant_not_substituted_into_member_property_name(self):
        self._check(
            'function f(o){ var g = 5; return o.g + g; } console.log(f({ g: 9 }));')

    def test_with_scoped_throwing_iife_argument_not_dropped(self):
        self._check(
            'var SINK = [];'
            ' var o = { p0: 1 };'
            " with (o) { delete p0; SINK.push((function(a){ return 'x'; })(p0)); }"
            " console.log(SINK.join('|'));")

    def test_indirect_eval_block_hoisted_var_creates_observable_global(self):
        self._check(
            "function f(){ (0, eval)('{ var g = 1; }'); }"
            ' f();'
            ' console.log(typeof g);')

    def test_indirect_eval_implicit_global_write_not_captured_by_local(self):
        self._check(
            "function f(){ var g; (0, eval)('g = 5;'); return g; }"
            ' console.log(f(), typeof g);')

    def test_objectfold_parenthesized_function_value_folds_soundly(self):
        deobfuscated = self._check(
            'var o = { f: (function(a){ return a + 1; }) };'
            ' console.log(o.f(2), o.f === o.f);')
        self.assertNotIn('o.f(2)', deobfuscated)

    def test_function_constructor_this_resolves_to_global_object(self):
        self._check(
            "globalThis.marker = 'G';"
            " var out = new Function('return this.marker')();"
            ' console.log(out);')

    def test_sequence_callee_preserves_indirect_this_binding(self):
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

    def test_globals_used_only_by_one_function_keep_its_result(self):
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
        deobfuscated = self._check(
            'function f(){ var x = 1; x = 2; return x; }'
            " var t = eval('6 * 7'); console.log(f(), t);")
        self.assertNotIn('x = 1', deobfuscated)

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
        self._check(
            'function probe(){ return c; }'
            ' var call = String.fromCharCode(112, 114, 111, 98, 101, 40, 41);'
            ' eval(call); const c = 5;')

    def test_global_alias_not_collapsed_into_catch_binding(self):
        self._check(
            "globalThis.X = 'global';"
            ' function probe(){ try { throw "caught"; } catch (X) { return globalThis.X; } }'
            ' console.log(probe());')

    def test_free_global_alias_member_read_preserved(self):
        self._check('console.log(globalThis.notDeclaredAnywhere);')

    def test_non_universal_global_alias_member_read_preserved(self):
        self._check('console.log(globalThis.execScript);')

    def test_shadowed_alias_base_member_read_preserved(self):
        self._check('console.log((function (self) { return self.Array; })({ Array: 7 }));')

    def test_implicit_global_alias_read_before_write_preserved(self):
        self._check(
            'function f(v) { return v; } var y = f(globalThis.X); X = 5; console.log(y, X);')

    def test_namespace_flatten_preserves_block_scoped_shadow(self):
        self._check(
            'var NS = {}; NS.x = 1; var r = [];'
            ' { let x = 9; r.push(x); } r.push(NS.x); console.log(r.join(","));')

    def test_namespace_function_not_hoisted_before_early_read(self):
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

    def test_argwrap_spread_argument_call_keeps_its_result(self):
        self._check(
            'function W() { W = function () {}; }'
            ' var arr = [1, 2];'
            ' var y = W(...arr);'
            ' console.log(typeof y);')

    def test_const_not_inlined_past_inherited_param_shadow(self):
        self._check(
            'const k = 5; function A(k) { function B() { return k; } return B(); }'
            ' console.log(A(9));')

    def test_dead_const_removed_only_when_truly_unreferenced(self):
        self._check(
            "const x = 'outer';"
            ' const f = () => x;'
            ' function wrap(){ const g = () => x; if (true) { var x = "inner"; } return g(); }'
            ' console.log(f(), wrap());')

    def test_nested_closures_share_binding(self):
        self._check(
            'function outer(){ var s = ""; function add(x){ s += x; } add("a"); add("b");'
            ' return s; } console.log(outer());')

    def test_function_constructor_return_this_is_global_object(self):
        self._check(
            'var g = new Function("return this")();'
            ' console.log(g === globalThis, typeof g.Array);')

    def test_function_constructor_body_var_does_not_capture_caller_scope(self):
        self._check('var x = 1; new Function("var x = 2;")(); console.log(x);')

    def test_function_constructor_body_lexical_does_not_redeclare_caller_block(self):
        self._check(
            '{ let y = 1; new Function("let y = 2; console.log(y);")(); console.log(y); }')

    def test_function_constructor_body_var_does_not_cross_block_let(self):
        self._check('{ let x = 9; new Function("var x = 2;")(); console.log(x); }')

    def test_function_constructor_body_called_from_strict_code_stays_sloppy(self):
        self._check('function f(){ "use strict"; return new Function("return 010")(); } console.log(f());')

    def test_dead_pure_call_binding_removal_preserves_behavior(self):
        deobfuscated = self._check(
            'function tag(x){ return "<" + x + ">"; }'
            ' var dead = tag("a");'
            ' console.log("result");')
        self.assertEqual(deobfuscated, 'console.log("result");')

    def test_constant_if_preserves_effectful_test(self):
        self._check(
            'function v6(){ console.log(-1); }'
            ' if ([v6(), false]) {} else {}')

    def test_unary_minus_preserves_negative_zero(self):
        self._check(
            'function f(){ var x = -false; return x; } console.log([f()]);')

    def test_multiplication_preserves_negative_zero(self):
        self._check(
            'function f(){ return 0 * -5; } console.log(1 / f());')

    def test_dead_store_effectful_call_keeps_orphan_function(self):
        self._check(
            'var SINK = [];'
            ' function leak() { SINK.push("x"); }'
            ' var dead;'
            ' dead = leak();'
            ' console.log(SINK.join(","));')

    def test_dead_store_effectful_inline_iife_initializer_kept(self):
        self._check(
            'var x = function(){ globalThis.g = 9; }();'
            ' console.log(globalThis.g);')

    def test_effectful_inline_iife_argument_to_inlined_iife_kept(self):
        self._check(
            'console.log((function(unused){ return 7; })(function(){ globalThis.g = 9; }()));'
            ' console.log(globalThis.g);')

    def test_new_array_invalid_length_throw_preserved(self):
        self._check('var x = new Array(-1); console.log("after");')

    def test_new_array_pure_length_drop_preserves_behavior(self):
        deobfuscated = self._check('var x = new Array(128); console.log("after");')
        self.assertEqual(deobfuscated, 'console.log("after");')

    def test_relational_comparison_of_non_numeric_strings(self):
        self._check('console.log([false] <= ("op" + 7), (["ef", true] >= "cd") + 4);')

    def test_nested_implicit_global_write_read_elsewhere_is_kept(self):
        self._check(
            'var SINK = [];'
            ' function v1() { function v2() { v0 = 12; } return v2(); }'
            ' function v5() { for (let i = 0; i < 1; i++) { SINK.push(v1()); } return v0; }'
            ' SINK.push(v5());'
            ' console.log(SINK.join(","));')

    def test_call_mutating_container_before_reassignment_not_inlined(self):
        self._check(
            'var o = { v: 1 };'
            ' function bump(x) { x.v = 9; }'
            ' bump(o);'
            ' bump = function(x) {};'
            ' console.log(o.v);')

    def test_premature_bare_assignment_call_keeps_throw(self):
        self._check(
            'var f;'
            ' f();'
            ' function dead(){}'
            ' f = function(){ return 1; };'
            ' console.log("after");')

    def test_premature_const_call_keeps_throw(self):
        self._check(
            'foo();'
            ' function dead(){}'
            ' const foo = () => 1;'
            ' console.log("after");')

    def test_premature_iife_argument_call_keeps_throw(self):
        self._check(
            'var f;'
            ' console.log((function(p){ return 7; })(f()));'
            ' f = function(){ return 1; };')

    def test_call_before_function_reassignment_keeps_side_effect(self):
        self._check(
            'var SINK = [];'
            ' function v0(v1) { SINK.push(v1); }'
            ' v0(true);'
            ' function v6() {}'
            ' v0 = function(){};'
            ' console.log(SINK.join(","));')

    def test_reassigned_global_not_inlined_as_initial_value(self):
        self._check(
            'var SINK = [];'
            ' var v0 = 7;'
            ' function v3(v4) { return [-5, -v0, ["ij", "gh"]]; }'
            ' function v6() { v0 = ["ij"]; return v3(true ? v0 : v0); }'
            ' SINK.push(v6());'
            ' SINK.push((!v0) === v3(3));'
            ' console.log(SINK.join("|"));')

    def test_escaping_global_temp_write_is_preserved(self):
        self._check(
            'const dec = function(s){ rr = s; return "x"; };'
            ' var y = dec("hi");'
            ' console.log(y, rr);')

    def test_uninitialized_var_promoted_constant_not_inlined_before_assignment(self):
        self._check(
            'var SINK = [];'
            ' var x;'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_var_initializer_declared_after_call_not_inlined(self):
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' var x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_const_declared_after_call_not_inlined_past_tdz(self):
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' try { SINK.push(g()); } catch (e) { SINK.push(e.name); }'
            ' const x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_redeclared_wrapper_is_not_inlined(self):
        self._check(
            'var SINK = [];'
            ' function v(){ return 1; }'
            ' function v(){ SINK.push("x"); return 2; }'
            ' SINK.push(v());'
            " console.log(SINK.join('|'));")

    def test_uninitialized_var_assigned_in_block_not_inlined_before_call(self):
        self._check(
            'var SINK = [];'
            ' var x;'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' { x = 5; }'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_var_initializer_in_block_not_inlined_before_call(self):
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' SINK.push(g());'
            ' try { var x = 5; } catch (e) {}'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_array_index_not_inlined_before_assignment(self):
        self._check(
            'var SINK = [];'
            ' var A;'
            ' function read(){ return A[0]; }'
            ' try { SINK.push(read()); } catch (e) { SINK.push(e.name); }'
            ' A = [1, 2, 3];'
            ' SINK.push(read());'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_escaping_function_before_value(self):
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' try { [g].forEach(function(h){ SINK.push(h()); }); } catch (e) { SINK.push(e.name); }'
            ' const x = 5;'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_aliased_function_before_value(self):
        self._check(
            'var SINK = [];'
            ' function g(){ return x; }'
            ' var p = g;'
            ' try { SINK.push(p()); } catch (e) { SINK.push(e.name); }'
            ' const x = 5;'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_wrapper_referenced_only_inside_surviving_wrapper_is_kept(self):
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
        self._check(
            'var SINK = [];'
            ' function f(){ try { SINK.push(c); } catch (e) { SINK.push(e.name); } const c = 5;'
            ' SINK.push(c); }'
            ' f();'
            " console.log(SINK.join('|'));")

    def test_uninitialized_var_not_inlined_into_own_function_before_assignment(self):
        self._check(
            'var SINK = [];'
            ' function f(){ SINK.push(x); var x; x = 5; SINK.push(x); }'
            ' f();'
            " console.log(SINK.join('|'));")

    def test_const_not_inlined_into_same_named_free_reference(self):
        self._check(
            'var SINK = [];'
            ' { const secret = "X"; SINK.push(secret); }'
            ' function read(){ try { return secret; } catch (e) { return e.name; } }'
            ' SINK.push(read());'
            " console.log(SINK.join('|'));")

    def test_reflection_alias_eval_shadowed_base_not_inlined(self):
        self._check(
            'function f(window){ return window.eval("1"); }'
            ' console.log(f({ eval: function(){ return 99; } }));')

    def test_reflection_alias_timer_shadowed_base_not_lowered(self):
        self._check(
            'function f(window){ window.setTimeout("console.log(0)", 0); }'
            ' f({ setTimeout: function(c){ console.log(typeof c); } });')

    def test_reflection_computed_alias_eval_inlined(self):
        deobfuscated = self._check('console.log(globalThis["eval"]("1"));')
        self.assertEqual(deobfuscated, 'console.log(1);')

    def test_reflection_bare_eval_shadowed_not_inlined(self):
        self._check(
            'function f(eval){ return eval("1"); }'
            ' console.log(f(function(){ return 99; }));')

    def test_reflection_sequence_eval_shadowed_not_inlined(self):
        self._check(
            'function f(eval){ return (0, eval)("1"); }'
            ' console.log(f(function(){ return 99; }));')

    def test_reflection_bare_timer_shadowed_not_lowered(self):
        self._check(
            'function f(setTimeout){ setTimeout("console.log(0)", 0); }'
            ' f(function(c){ console.log(typeof c); });')

    def test_reflection_function_constructor_shadowed_not_inlined(self):
        self._check(
            'function f(Function){ return Function("return 1")(); }'
            ' console.log(f(function(){ return function(){ return 99; }; }));')

    def test_private_class_fields_and_methods(self):
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
        self._check(
            'var log = [];'
            ' class C { static #n = 0; static { log.push("sb"); C.#n = 7; } static n() { return C.#n; } }'
            ' console.log(log.join(","), C.n());')

    def test_static_block_var_does_not_leak_to_enclosing_function(self):
        self._check(
            'function f() { var x = "outer"; class C { static { var x = "inner"; } } return x; }'
            ' console.log(f());')

    def test_dynamic_import_of_data_url(self):
        self._check(
            "import('data:text/javascript,export const v = 5').then(m => console.log(m.v));")

    def test_dynamic_import_side_effect_preserved(self):
        self._check(
            "import('data:text/javascript,globalThis.SIDE = 9')"
            '.then(() => console.log(globalThis.SIDE));')

    def test_global_read_by_dynamic_import_kept_alive(self):
        self._check(
            'globalThis.CFG = 3;'
            " import('data:text/javascript,console.log(globalThis.CFG)').then(() => {});")

    def test_yield_as_identifier_multiplied_in_sloppy_function(self):
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

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_with_scoped_getter_read_in_sequence_not_dropped(self):
        self._check(
            'var SINK = [];'
            ' var x = 1;'
            " var o = { get x() { SINK.push('g'); return 2; } };"
            " with (o) { SINK.push((x, 'y')); }"
            " console.log(SINK.join('|'));")

    def test_with_scoped_getter_read_as_iife_argument_not_dropped(self):
        self._check(
            'var SINK = [];'
            ' var x = 1;'
            " var o = { get x() { SINK.push('g'); return 2; } };"
            " with (o) { SINK.push((function(a){ return 'y'; })(x)); }"
            " console.log(SINK.join('|'));")

    def test_with_scoped_getter_read_in_pruned_if_test_not_dropped(self):
        self._check(
            'var SINK = [];'
            ' var x = 1;'
            " var o = { get x() { SINK.push('g'); return 2; } };"
            " with (o) { if ([x]) SINK.push('t'); }"
            " console.log(SINK.join('|'));")

    def test_with_scoped_indirect_eval_prefix_read_not_dropped(self):
        self._check(
            'var SINK = [];'
            ' var e = 0;'
            " var o = { get e() { SINK.push('g'); return 0; } };"
            ' with (o) { (e, eval)("1"); }'
            " console.log(SINK.join('|'));")

    def test_with_scoped_constructor_chain_base_read_not_dropped(self):
        self._check(
            'var SINK = [];'
            " var s = '';"
            " var o = { get s() { SINK.push('g'); return ''; } };"
            ' with (o) { s.constructor.constructor("return 1")(); }'
            " console.log(SINK.join('|'));")

    def test_with_scoped_throwing_operand_not_dropped(self):
        self._check(
            'var SINK = [];'
            ' var o = { p0: 1 };'
            " with (o) { delete p0; SINK.push((p0, 'x')); }"
            " console.log(SINK.join('|'));")

    def test_function_called_only_in_with_body_not_removed(self):
        self._check(
            'var SINK = [];'
            " function f() { var dead = 1; return 'z'; }"
            ' var o = { p0: f() };'
            ' with (o) { SINK.push(f()); }'
            " console.log(SINK.join('|'));")

    def test_with_scoped_alias_eval_member_not_inlined(self):
        self._check(
            'var o = { window: { eval: function(){ return 99; } } };'
            ' var r;'
            ' with (o) { r = window.eval("1"); }'
            ' console.log(r);')

    def test_with_scoped_bare_eval_not_inlined(self):
        self._check(
            'var o = { eval: function(){ return 99; } };'
            ' var r;'
            ' with (o) { r = eval("1"); }'
            ' console.log(r);')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestGuaranteedGlobalNamesInWithScope(TestBase):

    def _unchanged(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(deobfuscate_source(source), source)

    def _folds_to(self, source: str, folded: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(folded), (output, None))
        self.assertEqual(deobfuscate_source(source), folded)

    def test_typeof_undefined_is_not_folded_where_the_with_object_supplies_the_name(self):
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

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source, execution=ExecutionModel.module)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_indirect_eval_global_declaration_preserved_in_module_scope(self):
        self._check(
            'var SINK = [];'
            ' (0, eval)("var g = 7;");'
            ' SINK.push(globalThis.g);'
            " console.log(SINK.join('|'));"
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationExpressionRegressions(TestBase):

    def _check(self, source: str, environment: HostEnvironment = HostEnvironment.universal) -> str:
        deobfuscated = deobfuscate_source(source, environment=environment)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

    def test_method_value_read_is_not_invoked(self):
        self._check("console.log(typeof 'abc'.charAt, typeof 'abc'.toUpperCase, typeof 'abc'.split);")

    def test_length_is_not_callable(self):
        self._check("console.log((function(){ return [1, 2].length(); })());")

    def test_string_length_is_not_callable(self):
        self._check("console.log((function(){ return 'hello'.length(); })());")

    def test_astral_split_by_code_unit(self):
        self._check(R"console.log('\u{1F600}x'.split('').length);")

    def test_astral_split_yields_lone_surrogates(self):
        self._check(R"console.log('\u{1F600}x'.split('')[0].charCodeAt(0));")

    def test_unimplemented_method_read_is_not_undefined(self):
        self._check("console.log(typeof 'abc'.normalize, typeof [1, 2].sort, typeof [1, 2].map);")

    def test_inherited_object_member_read_is_not_undefined(self):
        self._check(
            "console.log(typeof 'abc'.hasOwnProperty, typeof [1, 2].constructor,"
            ' typeof ({ a: 1 }).toString);')

    def test_absent_member_read_is_still_undefined(self):
        self._check("console.log(typeof 'abc'.nosuch, typeof ({ a: 1 }).nosuch);")

    def test_own_property_shadows_inherited_member(self):
        self._check('console.log(({ toString: 1 }).toString, ({ map: 7 }).map, ({ length: 5 }).length);')

    def test_non_canonical_index_key_is_not_an_index(self):
        self._check("console.log('abc'['1'], typeof 'abc'['+1'], typeof 'abc'['01']);")

    def test_in_operator_sees_whole_prototype_chain(self):
        self._check(
            "console.log('sort' in [1, 2], 'map' in [1, 2], 'nosuch' in [1, 2],"
            " '0' in [1, 2], '2' in [1, 2], '+1' in [1, 2]);")

    def test_arguments_evaluate_before_non_callable_throws(self):
        self._check(
            'var log = [];'
            " try { 'hello'.length(log.push('arg')); } catch (e) { log.push('threw'); }"
            " console.log(log.join('|'));")

    def test_math_sign_of_nan_folds_to_nan_not_zero(self):
        deobfuscated = self._check(
            'var SINK = [];'
            " SINK.push(Math.sign('ab'));"
            " console.log(SINK.join('|'));")
        self.assertNotIn('Math.sign', deobfuscated)

    def test_delete_parameter_not_substituted_when_inlined(self):
        self._check(
            'var SINK = [];'
            ' function f(p) { return ((p instanceof Array) || (delete p)); }'
            " SINK.push(f('ef'));"
            " console.log(SINK.join('|'));")

    def test_typeof_of_unfoldable_builtin_not_folded_to_undefined(self):
        self._check(
            'var SINK = [];'
            " function m0() { return (typeof Math.max('mn', 4)); }"
            ' SINK.push(m0());'
            " console.log(SINK.join('|'));")

    def test_function_local_not_dropped_when_body_is_inlined(self):
        self._check(
            'var SINK = [];'
            ' function g() { var x = [5]; return (x[0] instanceof Object); }'
            ' SINK.push(g());'
            " console.log(SINK.join('|'));")

    def test_assignment_target_parameter_not_substituted_when_inlined(self):
        self._check(
            'var SINK = [];'
            ' function f(p) { return ((p = 5) instanceof Object); }'
            ' SINK.push(f(3));'
            " console.log(SINK.join('|'));")

    def test_math_round_of_negative_zero_preserves_sign(self):
        self._check(
            'var SINK = [];'
            ' SINK.push(1 / Math.round(-0));'
            " console.log(SINK.join('|'));")

    def test_json_parsed_proto_key_survives_the_fold(self):
        """
        `JSON.parse` makes `__proto__` an own property, while a `__proto__:` key in an object
        literal sets the prototype instead.
        """
        self._check(R"console.log(JSON.stringify(JSON.parse('{\"__proto__\":{\"x\":1}}')));")

    def test_json_parsed_proto_key_stays_enumerable(self):
        self._check(R"console.log(Object.keys(JSON.parse('{\"__proto__\":{\"x\":1}}')).length);")

    def test_nested_json_parsed_proto_key_survives_the_fold(self):
        self._check(R"console.log(JSON.stringify(JSON.parse('{\"a\":{\"__proto__\":{\"x\":1}}}')));")

    def test_proto_literal_installs_prototype_rather_than_property(self):
        self._check(
            'function f() { return Object.keys({ __proto__: { x: 1 } }).length; }'
            ' console.log(f());')

    def test_proto_literal_member_is_inherited(self):
        self._check(
            'function f() { var o = { __proto__: { x: 1 } }; return o.x; }'
            ' console.log(f());')

    def test_computed_proto_literal_is_an_own_property(self):
        deobfuscated = self._check(
            "function f() { var o = { ['__proto__']: { x: 1 } };"
            ' return Object.keys(o).length + (o.x === undefined); }'
            ' console.log(f());')
        self.assertNotIn('__proto__', deobfuscated)

    def test_proto_assignment_installs_prototype(self):
        self._check(
            "function f() { var o = {}; o['__proto__'] = { x: 1 };"
            ' return Object.keys(o).length + (o.x === 1); }'
            ' console.log(f());')

    def test_buffer_survives_the_fold(self):
        self._check(
            "function f() { return Buffer.from([65, 66]); }"
            " console.log(Buffer.isBuffer(f()), f().toString('hex'));")

    def test_buffer_decoded_to_string_folds_where_the_host_is_node(self):
        deobfuscated = self._check(
            R"console.log((function(){ return Buffer.from('QUJD', 'base64').toString('utf8'); })());",
            HostEnvironment.node,
        )
        self.assertEqual(deobfuscated, "console.log('ABC');")

    def test_buffer_decoded_to_string_keeps_its_value_where_the_host_may_lack_it(self):
        self._check(
            R"console.log((function(){ return Buffer.from('QUJD', 'base64').toString('utf8'); })());")

    @todo
    def test_buffer_decoded_to_string_keeps_the_buffer_where_the_host_may_lack_it(self):
        deobfuscated = deobfuscate_source(
            R"console.log((function(){ return Buffer.from('QUJD', 'base64').toString('utf8'); })());")
        self.assertIn('Buffer', deobfuscated)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationReflectionScope(TestBase):

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_indirect_eval_lexical_declaration_is_transient(self):
        self._check(
            "(0, eval)('let g = 1;');"
            ' console.log(typeof g);')

    def test_indirect_eval_in_expression_position_writes_the_global_and_not_a_local(self):
        self._check(
            "function f() { var g = 0; var x = (0, eval)('g = 7'); return g + '|' + x; }"
            ' console.log(f());')

    def test_indirect_eval_free_name_is_not_recaptured_by_a_local(self):
        self._check(
            'globalThis.g = 1;'
            " function f() { var g = 100; return (0, eval)('g'); }"
            ' console.log(f());')

    def test_indirect_eval_this_is_the_global_object_inside_a_method(self):
        self._check(
            "globalThis.tag = 'global';"
            " var o = { tag: 'obj', f: function() { return (0, eval)('this.tag'); } };"
            ' console.log(o.f());')

    def test_constructor_iife_without_return_yields_undefined(self):
        self._check(
            'globalThis.x = 5;'
            ' var y = Function("x")();'
            ' console.log(typeof y);')

    def test_indirect_eval_top_level_return_is_a_syntax_error(self):
        self._check(
            'var y = (0, eval)("return 1");'
            ' console.log(y);')

    def test_indirect_eval_free_name_not_inlined_into_with_body(self):
        self._check(
            'var out = [];'
            " globalThis.foo = function(){ out.push('global'); };"
            " var obj = { foo: function(){ out.push('obj'); } };"
            ' function f(){ with (obj) { (0, eval)("foo()"); } }'
            " f(); console.log(out.join('|'));")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationInlinerScope(TestBase):

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_substitution_does_not_recapture_an_outer_binding_shadowed_at_the_call_site(self):
        self._check(
            'var g = 1;'
            ' function f(n) { switch (n) { case 5: return g; } }'
            ' function caller() { var g = 100; return f(5); }'
            ' console.log(caller());')

    def test_substitution_does_not_recapture_a_free_name_shadowed_at_the_call_site(self):
        self._check(
            'function f(n) { switch (n) { case 5: return externalThing; } }'
            ' function caller() { var externalThing = 100; return f(5); }'
            ' console.log(caller());')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationDirectEvalScope(TestBase):

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_direct_eval_lexical_declaration_is_transient(self):
        self._check(
            'function f(){ eval("let x = 1;"); return typeof x; }'
            ' console.log(f());')

    def test_direct_eval_var_in_strict_context_is_eval_local(self):
        self._check(
            'function f(){ "use strict"; eval("var x = 1;"); return typeof x; }'
            ' console.log(f());')

    def test_direct_eval_var_not_inlined_past_earlier_reference(self):
        self._check(
            'globalThis.x = 5;'
            ' function f(){ var out = x; eval("var x = 1;"); return out; }'
            ' console.log(f());')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestModelBlindFoldRegressions(TestBase):

    def _check(self, source: str) -> str:
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

    def test_shadowed_string_from_char_code_is_not_the_builtin(self):
        self._check(
            "var String = { fromCharCode: function(){ return 'X'; } };"
            ' console.log(String.fromCharCode(65));')

    def test_shadowed_string_in_function_scope_is_not_the_builtin(self):
        self._check(
            "(function(){ var String = { fromCharCode: function(){ return 'X'; } };"
            ' console.log(String.fromCharCode(65)); })();')

    def test_shadowed_parse_int_is_not_the_builtin(self):
        self._check(
            'var parseInt = function(){ return 99; };'
            " console.log(parseInt('10'), parseInt('12', 10));")

    def test_callback_writing_outer_binding_is_not_pure(self):
        self._check(
            'var n = 0;'
            " console.log((function(a){ return a.map(function(x){ n += x; return x; }).join(''); })([1, 2]), n);")

    def test_foreach_callback_write_survives(self):
        self._check(
            'var n = 0;'
            ' (function(a){ a.forEach(function(x){ n += x; }); })([1, 2]);'
            ' console.log(n);')

    def test_patched_string_method_is_not_the_builtin(self):
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
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            ' function f() { return [1, 2].join(\'-\'); } console.log(f());')

    def test_patched_array_method_via_define_property_is_not_the_builtin(self):
        self._check(
            "Object.defineProperty(Array.prototype, 'join', { value: function () { return 'X'; } });"
            ' function f() { return [1, 2].join(\'-\'); } console.log(f());')

    def test_unpatched_prototype_methods_still_fold(self):
        deobfuscated = self._check(
            "function f() { return [1, 2].join('-') + 'ab'.toUpperCase() + 'abc'.indexOf('b'); }"
            ' console.log(f());')
        for method in ('.join(', '.toUpperCase(', '.indexOf('):
            with self.subTest(method=method):
                self.assertNotIn(method, deobfuscated)

    def test_patched_static_method_is_not_the_builtin_in_a_function(self):
        self._check(
            'Math.floor = function () { return 99; };'
            ' function f() { return Math.floor(1.7); } console.log(f());')

    def test_patched_array_hof_is_not_the_builtin_in_a_function(self):
        self._check(
            "Array.prototype.map = function () { return ['X']; };"
            ' function f() { return [1, 2].map(function (x) { return x + 1; }).length; }'
            ' console.log(f());')

    def test_patched_join_on_a_string_array_is_not_the_builtin(self):
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            " console.log(['a', 'b'].join('-'));")

    def test_patched_join_after_split_is_not_the_builtin(self):
        self._check(
            "Array.prototype.join = function () { return 'X'; };"
            " console.log('a-b'.split('-').join('+'));")


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestBuiltinNameBoundByAnEnclosingParameter(TestBase):

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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMemberCalleeChainFolds(TestBase):

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def _folds_to(self, source: str, expected: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(expected, deobfuscated.strip())
        self.assertEqual(behavior(source), behavior(deobfuscated))

    def test_map_join_xor_decoder_folds(self):
        self._folds_to(
            'console.log([66, 79, 70, 70, 69].map('
            "function (c) { return String.fromCharCode(c ^ 42); }).join(''));",
            "console.log('hello');")

    def test_map_join_on_empty_array_folds(self):
        self._folds_to(
            "console.log([].map(function (c) { return String.fromCharCode(c ^ 42); }).join(''));",
            "console.log('');")

    def test_filter_join_folds(self):
        self._folds_to(
            "console.log(['a', '', 'b'].filter(function (s) { return s; }).join('|'));",
            "console.log('a|b');")

    def test_slice_join_folds(self):
        self._folds_to("console.log([1, 2, 3, 4].slice(1, 3).join('+'));", "console.log('2+3');")

    def test_concat_join_folds(self):
        self._folds_to("console.log([1, 2].concat([3]).join('-'));", "console.log('1-2-3');")

    def test_reduce_decoder_folds(self):
        self._folds_to(
            "console.log([72, 73].reduce(function (a, c) { return a + String.fromCharCode(c); }, ''));",
            "console.log('HI');")

    def test_callback_writing_outer_binding_blocks_the_chain(self):
        self._check(
            'var n = 0;'
            " console.log([1, 2].map(function (x) { n += x; return x; }).join(''), n);")

    def test_effectful_receiver_blocks_the_chain(self):
        self._check(
            'var n = 0;'
            ' function mk() { n += 1; return [1, 2]; }'
            " console.log(mk().join('-'), n);")

    def test_effectful_argument_to_an_inner_chain_link_blocks_the_chain(self):
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

    def test_identifier_receiver_chain_keeps_its_value(self):
        self._check(
            'var a = [66, 79];'
            " console.log(a.map(function (x) { return x; }).join(''));")

    @opportunity
    def test_identifier_receiver_chain_folds_where_nothing_writes_the_array(self):
        self._folds_to(
            'var a = [66, 79];'
            " console.log(a.map(function (x) { return x; }).join(''));",
            "console.log('6679');")

    def test_throwing_callback_blocks_the_chain(self):
        self._check(
            "try { console.log([1, 2].map(function (x) { throw new Error('boom'); }).join('')); }"
            " catch (e) { console.log('caught'); }")

    def test_data_property_call_on_a_chain_still_throws(self):
        self._check(
            'try { console.log([1, 2].concat([3]).length()); }'
            ' catch (e) { console.log(e.constructor.name); }')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMemberBaseSafety(TestBase):

    def _check(self, source: str) -> str:
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

    def test_getter_on_object_literal_base_still_runs(self):
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
        self._check(
            "function f() { var t = { a: { get k() { console.log('getter'); return 1; } } }.a.k; }"
            ' f();'
            " console.log('done');")

    def test_setter_on_object_literal_base_is_not_run_by_a_read(self):
        self._check(
            "function f() { var t = { set k(v) { console.log('setter'); } }.k; }"
            ' f();'
            " console.log('done');")

    @todo
    def test_setter_only_literal_base_read_leaves_a_global_of_the_same_name_alone(self):
        source = (
            "function f() { var t = { set k(v) { console.log('setter'); } }.k; }"
            ' f();'
            " console.log('done');")
        host = "globalThis.t = 'host'; globalThis.readT = function () { return t; };"
        self.assertEqual(
            host_behavior(source, prelude=host, calls=('readT',)),
            host_behavior(deobfuscate_source(source), prelude=host, calls=('readT',)),
        )

    @opportunity
    def test_setter_only_literal_base_read_is_removed(self):
        deobfuscated = deobfuscate_source(
            "function f() { var t = { set k(v) { console.log('setter'); } }.k; }"
            ' f();'
            " console.log('done');")
        self.assertEqual(deobfuscated, "console.log('done');")

    def test_plain_literal_base_read_keeps_its_value(self):
        self._check("function f() { console.log({ k: 7 }.k); } f(); console.log('done');")

    @opportunity
    def test_plain_literal_base_read_still_folds(self):
        deobfuscated = deobfuscate_source(
            "function f() { console.log({ k: 7 }.k); } f(); console.log('done');")
        self.assertIn('console.log(7);', deobfuscated)

    def test_valid_two_link_chain_keeps_its_value(self):
        self._check("function f() { console.log({ a: { k: 5 } }.a.k); } f(); console.log('done');")

    @opportunity
    def test_valid_two_link_chain_still_folds(self):
        deobfuscated = deobfuscate_source(
            "function f() { console.log({ a: { k: 5 } }.a.k); } f(); console.log('done');")
        self.assertIn('console.log(5);', deobfuscated)

    def test_primitive_base_property_read_still_folds(self):
        deobfuscated = self._check("function f() { console.log('abc'.length); } f(); console.log('done');")
        self.assertIn('console.log(3);', deobfuscated)

    def test_function_literal_base_property_read_keeps_its_value(self):
        self._check("function f() { console.log((function (a, b) {}).length); } f();")

    @opportunity
    def test_function_literal_base_property_read_still_folds(self):
        deobfuscated = deobfuscate_source(
            "function f() { console.log((function (a, b) {}).length); } f();")
        self.assertIn('console.log(2);', deobfuscated)

    def test_arrow_literal_base_property_read_keeps_its_value(self):
        self._check('function f() { console.log((() => 1).length); } f();')

    @opportunity
    def test_arrow_literal_base_property_read_still_folds(self):
        deobfuscated = deobfuscate_source('function f() { console.log((() => 1).length); } f();')
        self.assertIn('console.log(0);', deobfuscated)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestPrototypeChainTrust(TestBase):

    def _check(self, source: str) -> str:
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

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
        self._check(
            self._getter('Object')
            + ' function f() { var t = Math.zz; }'
            " f(); console.log('done');")

    def test_throwing_getter_on_a_patched_prototype_still_throws(self):
        self._check(
            "Object.defineProperty(Array.prototype, 'zz',"
            " { get: function () { throw new Error('boom'); } });"
            ' function f() { var t = [1].zz; }'
            " f(); console.log('unreachable');")

    def test_value_read_through_a_patched_prototype_is_not_folded_to_undefined(self):
        self._check(
            "Array.prototype.zz = 7;"
            ' function f() { return [1, 2].zz; }'
            ' console.log(String(f()));')

    def test_patched_prototype_method_is_not_folded_to_the_builtin(self):
        self._check(
            "Array.prototype.join = function () { return 'PATCHED'; };"
            " console.log([1, 2].join('-'));")

    def test_pristine_array_literal_read_still_folds(self):
        deobfuscated = self._check("function f() { console.log([1, 2].length); } f(); console.log('done');")
        self.assertIn('console.log(2);', deobfuscated)

    def test_pristine_intrinsic_root_read_keeps_its_value(self):
        self._check("function f() { console.log(Math.zz); } f(); console.log('done');")

    @opportunity
    def test_pristine_intrinsic_root_read_still_folds(self):
        deobfuscated = deobfuscate_source("function f() { console.log(Math.zz); } f(); console.log('done');")
        self.assertIn('console.log(void 0);', deobfuscated)

    def test_object_prototype_patch_does_not_block_an_owned_method_call(self):
        deobfuscated = self._check(
            "Object.prototype.join = function () { return 'PATCHED'; };"
            " console.log([1, 2].join('-'));")
        self.assertIn("console.log('1-2');", deobfuscated)

    def test_object_prototype_patch_does_not_block_an_owned_string_method_call(self):
        deobfuscated = self._check(
            "Object.prototype.toUpperCase = function () { return 'PATCHED'; };"
            " console.log('ab'.toUpperCase());")
        self.assertIn("console.log('AB');", deobfuscated)

    def test_patched_function_apply_is_not_dispatched_as_the_builtin(self):
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
        deobfuscated = self._check(
            ' function f() { var g = function (a) { return a * 3; }; return g.apply(null, [3]); }'
            ' console.log(String(f()));')
        self.assertNotIn('.apply(', deobfuscated)

    def test_pristine_function_call_still_folds(self):
        deobfuscated = self._check(
            ' function f() { var g = function (a) { return a + 1; }; return g.call(null, 2); }'
            ' console.log(String(f()));')
        self.assertNotIn('.call(', deobfuscated)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAliasedIntrinsicPatches(TestBase):

    def _check(self, source: str) -> str:
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

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
        deobfuscated = self._check('var m = Math; console.log(String(m.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_write_on_an_unrelated_local_still_folds(self):
        deobfuscated = self._check('var m = {}; m.floor = 1; console.log(String(Math.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_write_on_the_result_of_an_intrinsic_call_still_folds(self):
        deobfuscated = self._check(
            "var s = String.fromCharCode(65); s.x = 1;"
            ' console.log(String(String.fromCharCode(66)));')
        self.assertIn("console.log('B');", deobfuscated)

    def test_write_on_the_result_of_a_method_call_still_folds(self):
        deobfuscated = self._check(
            "var s = 'ab'.toUpperCase(); s.x = 1;"
            ' console.log(String(String.fromCharCode(66)));')
        self.assertIn("console.log('B');", deobfuscated)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEscapedIntrinsicPatches(TestBase):

    def _check(self, source: str) -> str:
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )
        return deobfuscated

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
            "function p(...r) { r[0].floor = function () { return 'PATCHED'; }; } p(Math);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_the_arguments_object_is_honored(self):
        self._check(
            "function p() { arguments[0].floor = function () { return 'PATCHED'; }; } p(Math);"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_callback_is_honored(self):
        self._check(
            'function each(f) { f(Math); }'
            " each(function (o) { o.floor = function () { return 'PATCHED'; }; });"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_a_returned_intrinsic_is_honored(self):
        self._check(
            "function get() { return Math; } get().floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_intrinsic_a_callee_returns_is_honored(self):
        self._check(
            'function get(o) { return o; } var m = get(Math);'
            " m.floor = function () { return 'PATCHED'; };"
            ' console.log(String(Math.floor(1.7)));')

    def test_patch_through_an_unknown_computed_key_is_honored(self):
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
        deobfuscated = self._check(
            'function log(o) { return o.PI; } log(Math); console.log(String(Math.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_argument_to_a_callee_that_ignores_it_still_folds(self):
        deobfuscated = self._check(
            'function ignore(o) { return 1; } ignore(Math); console.log(String(Math.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_argument_to_a_reading_callee_two_hops_deep_still_folds(self):
        deobfuscated = self._check(
            'function inner(o) { return o.PI; } function outer(o) { return inner(o); } outer(Math);'
            ' console.log(String(Math.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_method_called_on_a_parameter_keeps_its_value(self):
        self._check('function use(o) { return o.floor(1.7); } console.log(String(use(Math)));')

    @opportunity
    def test_method_called_on_a_parameter_still_folds(self):
        deobfuscated = deobfuscate_source(
            'function use(o) { return o.floor(1.7); } console.log(String(use(Math)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_write_on_a_constant_read_off_an_intrinsic_still_folds(self):
        deobfuscated = self._check(
            'function p(v) { v.x = 1; } p(Math.PI); console.log(String(Math.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)

    def test_write_on_a_method_read_off_an_intrinsic_still_folds(self):
        deobfuscated = self._check(
            'function p(v) { v.x = 1; } p(Math.floor); console.log(String(Math.floor(1.7)));')
        self.assertIn("console.log('1');", deobfuscated)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestHostEntrypointPreservation(TestBase):

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
        self._check_host(
            "var log = [];"
            " function record(x) { log.push(x); return x; }"
            " function run() { return record('called'); }"
            " console.log(record('loaded'));",
            calls=('run',),
            entrypoints=('run',))

    def test_a_dead_function_beside_a_named_entrypoint_is_removed(self):
        source = (
            "function junk() { return 'unused'; }"
            " function run() { return 'kept'; }"
            " console.log('loaded');"
        )
        deobfuscated = deobfuscate_source(source, entrypoints=('run',))
        self.assertEqual(
            deobfuscated,
            inspect.cleandoc("""
                function run() {
                  return 'kept';
                }
                console.log('loaded');
            """),
        )
        self.assertEqual(
            host_behavior(source, calls=('run',)),
            host_behavior(deobfuscated, calls=('run',)),
        )

    def test_a_host_still_calls_the_function_no_entrypoint_names_in_a_file_of_only_functions(self):
        self._check_host(
            "function junk() { return 'unused'; }"
            " function run() { return 'kept'; }",
            calls=('run', 'junk'),
            entrypoints=('run',),
        )

    def test_entrypoint_held_by_a_var_is_still_callable_by_the_host(self):
        self._check_host(
            "var run = function() { return 'from-var'; };",
            calls=('run',),
            entrypoints=('run',))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNumericLiteralsAreDoubles(TestBase):

    def _folds_to(self, source: str, expected: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(deobfuscated, expected)
        self.assertEqual(behavior(deobfuscated), behavior(source))

    def _folds_to_one_of(self, source: str, *expected: str):
        deobfuscated = deobfuscate_source(source)
        self.assertIn(deobfuscated, expected)
        self.assertEqual(behavior(deobfuscated), behavior(source))

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_large_integer_a_double_represents_exactly_folds_to_that_integer(self):
        self._folds_to(
            'console.log(4503599627370496 * 2);',
            'console.log(9007199254740992);')

    def test_integer_literal_too_precise_for_a_double_folds_to_the_double_it_denotes(self):
        self._folds_to(
            'console.log(String(9007199254740993));',
            "console.log('9007199254740992');")

    def test_two_spellings_of_one_double_are_equal_and_differ_by_zero(self):
        self._folds_to(
            'console.log(9007199254740993 === 9007199254740992, 9007199254740993 - 9007199254740992);',
            'console.log(true, 0);')

    def test_product_of_two_over_precise_literals_folds_to_the_double_product(self):
        """
        Each operand rounds to `2**53`, so the product is `2**106`; the exact product of the written
        digits rounds to a different double.
        """
        self._folds_to(
            'console.log(String(9007199254740993 * 9007199254740993));',
            "console.log('8.112963841460668e+31');")

    def test_sum_of_exact_operands_whose_result_is_inexact_folds_to_the_double_sum(self):
        self._folds_to(
            'console.log(String(9007199254740992 + 1));',
            "console.log('9007199254740992');")

    def test_arithmetic_that_overflows_the_double_range_still_means_infinity(self):
        self._prints('console.log(String(1.7976931348623157e308 * 2));', 'Infinity\n')

    def test_literal_outside_the_double_range_and_its_negation_fold_to_the_infinities(self):
        self._folds_to(
            'console.log(String(1e400), String(-1e400));',
            "console.log('Infinity', '-Infinity');")

    def test_decimal_integer_outside_the_double_range_and_its_negation_fold_to_the_infinities(self):
        self._folds_to(
            F'console.log(String({10 ** 400}), String(-{10 ** 400}));',
            "console.log('Infinity', '-Infinity');")

    def test_negative_zero_survives_a_fold(self):
        self._folds_to('console.log(1 / (0 * -1));', 'console.log(-1e999);')

    def test_bitwise_operators_coerce_an_over_precise_literal_through_its_double(self):
        """
        The literal `9007199254740993` denotes the double `2**53`, whose ToInt32 is `0`; the exact
        integer it spells would give `1`.
        """
        self._folds_to(
            'console.log(9007199254740993 | 0, 9007199254740993 >>> 0);',
            'console.log(0, 0);')

    def test_every_radix_spells_the_same_over_precise_integer(self):
        """
        Each left operand is `2**53 + 1`, which has no double of its own and rounds to the right
        operand `2**53`.
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
        self._folds_to_one_of(
            'console.log(String(9007199254740993n + 1n), String(9007199254740993 + 1));',
            "console.log(String(9007199254740993n + 1n), '9007199254740992');",
            "console.log('9007199254740994', '9007199254740992');")

    def test_bigint_beyond_the_double_range_keeps_every_digit(self):
        self._folds_to_one_of(
            'console.log(String(2n ** 70n), 1 + 1);',
            'console.log(String(2n ** 70n), 2);',
            "console.log('1180591620717411303424', 2);")

    @opportunity
    def test_bigint_arithmetic_folds_to_its_exact_value(self):
        self._folds_to(
            'console.log(String(9007199254740993n + 1n), String(2n ** 70n));',
            "console.log('9007199254740994', '1180591620717411303424');")

    def test_a_bigint_added_to_a_number_is_not_folded(self):
        """
        `1n + 1` throws a `TypeError`: arithmetic does not mix a BigInt with a Number.
        """
        self._folds_to('console.log(1n + 1);', 'console.log(1n + 1);')

    def test_parse_int_yields_the_double_its_digits_denote(self):
        self._folds_to(
            "console.log(String(parseInt('9007199254740993')), String(parseInt('123456789012345678901234567890')));",
            "console.log('9007199254740992', '1.2345678901234568e+29');")

    def test_a_folded_number_is_spelled_the_way_javascript_prints_it(self):
        self._folds_to(
            'console.log(1e21 + 0, 1e-7 + 0, 0.1 + 0.2);',
            'console.log(1e+21, 1e-7, 0.30000000000000004);')

    def test_a_byte_array_keeps_its_grid_and_its_values(self):
        self._folds_to(
            inspect.cleandoc("""
                var key = [
                    15, 216, 150, 85, 200, 21, 150, 34, 117, 192, 188, 159, 55, 161, 212,
                    83, 194, 215, 4, 31, 78, 146, 105, 234, 185, 106, 130, 223, 47, 187
                ];
                console.log(key[3 + 4], key[process.argv.length]);
            """),
            inspect.cleandoc("""
                var key = [
                  0x0F, 0xD8, 0x96, 0x55, 0xC8, 0x15, 0x96, 0x22, 0x75, 0xC0, 0xBC, 0x9F, 0x37, 0xA1, 0xD4,
                  0x53, 0xC2, 0xD7, 0x04, 0x1F, 0x4E, 0x92, 0x69, 0xEA, 0xB9, 0x6A, 0x82, 0xDF, 0x2F, 0xBB
                ];
                console.log(34, key[process.argv.length]);
            """),
        )

    def test_an_array_index_folds_to_its_element_and_a_fraction_to_undefined(self):
        self._folds_to(
            'console.log([10, 20, 30][1 + 1], [10, 20, 30][0.5 + 1]);',
            'console.log(30, void 0);')

    def test_exponentiation_with_a_large_integer_exponent_terminates(self):
        source = 'console.log(3 ** 1000000000);'
        deobfuscated = deobfuscate_within(source, seconds=20)
        if deobfuscated is None:
            self.fail('the fold did not terminate')
        self.assertEqual(behavior(deobfuscated), ('Infinity\n', None))

    def test_an_integral_double_is_spelled_with_the_digits_an_engine_prints(self):
        """
        Above `2**53` JavaScript does not print a double's exact value: `2**64` is exactly
        `18446744073709551616` but prints as `18446744073709552000`.
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
        A leading zero is not a base prefix: `parseInt('077')` is seventy-seven, not the octal
        sixty-three.
        """
        self._folds_to(
            "console.log(parseInt('0x1F'), parseInt('0x1F', 16), parseInt('0x1F', 10),"
            " parseInt('077'), parseInt('077', 8));",
            'console.log(31, 31, 0, 77, 63);')

    def test_parse_int_of_a_digit_string_beyond_double_precision_keeps_the_printed_digits(self):
        """
        The double nearest `11111111111111111111` is exactly `11111111111111110656`, but JavaScript
        prints it as `11111111111111110000`.
        """
        self._folds_to(
            "console.log(String(parseInt('11111111111111111111')),"
            " String(parseInt('111111111111111111111111111111')));",
            "console.log('11111111111111110000', '1.111111111111111e+29');")

    def test_numeric_coercion_declines_a_string_only_python_reads_as_a_number(self):
        """
        `Number` reads an infinity only when it is spelled exactly `Infinity`, and a numeric
        separator such as `1_0` is valid in a literal but not in a string.
        """
        self._folds_to(
            "console.log(Number('inf'), Number('infinity'), Number('-inf'), Number('1_0'),"
            " Math.abs('inf'), Math.round('infinity'), Number('Infinity'), Number('0x1F'));",
            'console.log(0 / 0, 0 / 0, 0 / 0, 0 / 0, 0 / 0, 0 / 0, 1e999, 31);')

    def test_an_integer_literal_beyond_the_double_range_is_neither_an_index_nor_a_radix(self):
        """
        The literal denotes `Infinity`, which indexes no element, and ToInt32 maps it to a radix of
        zero, which `parseInt` reads as ten.
        """
        self._prints(
            F"console.log(String([10, 20, 30][{10 ** 400}]), String(parseInt('10', {10 ** 400})));",
            'undefined 10\n')

    def test_an_integer_literal_beyond_the_double_range_is_not_a_rotation_count(self):
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
        Without the parentheses, `-2 ** e` does not parse, `-2[k]` negates the element rather than
        indexing `-2`, and `-2(k)` calls `2`.
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
        A base of `-1` raised to either infinity is `NaN` in JavaScript, where Python answers `1.0`.
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
        `Number('-0')` and `parseInt('-0')` are both negative zero, not zero.
        """
        self._folds_to_one_of(
            "console.log(1 / Number('-0'), Object.is(Number('-0'), -0),"
            " 1 / parseInt('-0'), Object.is(parseInt('-0'), -0));",
            'console.log(-1e999, Object.is(-0, -0), -1e999, Object.is(-0, -0));',
            'console.log(-1e999, true, -1e999, true);')

    def test_unary_plus_on_a_string_that_names_negative_zero_folds_to_negative_zero(self):
        self._folds_to_one_of(
            "var f = function () { return +'-0'; };"
            ' console.log(1 / f(), Object.is(f(), -0));',
            'console.log(-1e999, Object.is(-0, -0));',
            'console.log(-1e999, true);')

    @opportunity
    def test_object_is_of_a_string_that_names_negative_zero_folds_to_its_answer(self):
        self._folds_to(
            "console.log(Object.is(Number('-0'), -0), Object.is(Number('-0'), 0));",
            'console.log(true, false);')

    def test_numeric_coercion_refuses_the_decimal_digits_only_python_reads(self):
        self._folds_to(
            R"console.log(Number('\u0661\u0662\u0663'), Number('\uFF11\uFF12\uFF13'),"
            R" Number('\u0967\u0968\u0969'));",
            'console.log(0 / 0, 0 / 0, 0 / 0);')

    def test_numeric_coercion_refuses_the_padding_only_python_strips(self):
        self._folds_to(
            R"console.log(Number('\u001C5'), Number('\u001D5'), Number('\u001E5'),"
            R" Number('\u001F5'));",
            'console.log(0 / 0, 0 / 0, 0 / 0, 0 / 0);')

    def test_parse_int_refuses_the_padding_only_python_strips(self):
        self._prints(
            R"console.log(String(parseInt('\u001C5')), String(parseInt('\u001D5')),"
            R" String(parseInt('\u001E5')), String(parseInt('\u001F5')));",
            'NaN NaN NaN NaN\n')

    def test_numeric_coercion_accepts_the_byte_order_mark_as_whitespace(self):
        self._folds_to(
            R"console.log(Number('\uFEFF5'), Number('5\uFEFF'), parseInt('\uFEFF5'),"
            R" Number('\uFEFF\uFEFF12\uFEFF'));",
            'console.log(5, 5, 5, 12);')

    def test_unary_plus_reads_the_padding_and_digits_the_engine_reads(self):
        self._prints(
            R"var f = function () { return +'\u0661\u0662\u0663'; };"
            R" var g = function () { return +'\u001C5'; };"
            R" var h = function () { return +'\uFEFF5'; };"
            ' console.log(String(f()), String(g()), String(h()));',
            'NaN NaN 5\n')

    def test_arithmetic_on_a_string_reads_the_number_the_language_reads(self):
        self._prints(
            "console.log(+'1e3', +' 42 ', String(+'1e'), String(+'1_0'), 1 / +'-0',"
            " String(+'0x10' * 2), String('3' * '4'));",
            '1000 42 NaN NaN -Infinity 32 12\n')

    def test_a_string_coerced_behind_a_function_reads_the_same_grammar(self):
        self._prints(
            'var f = function (s) { return s * 1; };'
            " console.log(f('1e3'), String(f('1e')), String(f('Infinity')), f('0x10'));",
            '1000 NaN Infinity 16\n')

    def test_parse_int_reads_its_radix_through_the_signed_32_bit_wrap(self):
        self._folds_to(
            "var f = function () { return parseInt('10', 4294967312); };"
            " var g = function () { return parseInt('10', 4294967296); };"
            " var h = function () { return parseInt('ff', -4294967280); };"
            ' console.log(f(), g(), h());',
            'console.log(16, 10, 255);')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestParseFloatGrammar(TestBase):

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_the_grammar_without_an_exponent_or_an_infinity_folds_to_its_numbers(self):
        source = (
            "console.log(parseFloat('3.14'), parseFloat(' 42 '), parseFloat('2.5abc'),"
            " parseFloat('0x10'), parseFloat('1e'), parseFloat('1.2.3'), parseFloat('Infinit'),"
            " parseFloat('nope'));")
        self._prints(source, '3.14 42 2.5 0 1 1.2 NaN NaN\n')
        self.assertEqual(
            deobfuscate_source(source),
            'console.log(3.14, 42, 2.5, 0, 1, 1.2, 0 / 0, 0 / 0);')

    def test_an_exponent_belongs_to_the_literal_parse_float_reads(self):
        self._prints(
            "console.log(parseFloat('1e3'), parseFloat('1E3'), parseFloat('1e+3'),"
            " parseFloat('1e-3'), parseFloat('.5e2'), parseFloat('-1.5e2'));",
            '1000 1000 1000 0.001 50 -150\n')

    def test_the_word_infinity_is_a_literal_parse_float_reads(self):
        self._prints(
            "console.log(parseFloat('Infinity'), parseFloat('-Infinity'),"
            " parseFloat('+Infinity'), parseFloat('Infinityabc'));",
            'Infinity -Infinity Infinity Infinity\n')

    def test_an_exponent_that_is_begun_and_never_finished_shortens_the_literal(self):
        self._prints(
            "console.log(parseFloat('1e'), parseFloat('1E'), parseFloat('1e+'), parseFloat('1e-'),"
            " parseFloat('1.2e'), parseFloat('1e2.5'), parseFloat('1ee3'), parseFloat('1e+3e4'));",
            '1 1 1 1 1.2 100 1 1000\n')

    def test_an_exponent_with_no_digits_ahead_of_it_names_no_number(self):
        self._prints(
            "console.log(String(parseFloat('e3')), String(parseFloat('.e3')),"
            " parseFloat('.5e2'));",
            'NaN NaN 50\n')

    def test_a_sign_is_read_where_the_literal_begins_and_nowhere_else(self):
        self._prints(
            "console.log(parseFloat('+1'), parseFloat('-.5'), String(parseFloat('- 1')),"
            " String(parseFloat('+-1')), parseFloat('1-'), String(parseFloat('-')));",
            '1 -0.5 NaN NaN 1 NaN\n')

    def test_an_infinity_by_overflow_and_a_zero_by_underflow_keep_their_signs(self):
        self._prints(
            "console.log(String(parseFloat('1e999')), String(parseFloat('-1e999')),"
            " Object.is(parseFloat('-1e-999'), -0), Object.is(parseFloat('1e-999'), -0),"
            " String(parseFloat('5e-324')));",
            'Infinity -Infinity true false 5e-324\n')

    def test_a_parse_that_stops_at_a_base_prefix_keeps_the_sign_of_its_zero(self):
        self._prints(
            "console.log(Object.is(parseFloat('-0'), -0), Object.is(parseFloat('-0x10'), -0),"
            " Object.is(parseFloat('-0b101'), -0), Object.is(parseFloat('+0x10'), -0));",
            'true true true false\n')

    def test_padding_is_what_the_language_calls_whitespace_and_nothing_else(self):
        """
        `U+FEFF`, `U+00A0` and `U+3000` are whitespace to `parseFloat`; `U+0085`, `U+001C` and
        `U+200B` are not.
        """
        self._prints(
            R"console.log(parseFloat('\uFEFF 2.5'), parseFloat('\u00A0-1.5e2\u3000'),"
            R" String(parseFloat('\u00855')), String(parseFloat('\u001C5')),"
            R" parseFloat('5\u0085'), String(parseFloat('\u200B5')));",
            '2.5 -150 NaN NaN 5 NaN\n')

    def test_digits_of_another_script_and_characters_that_look_like_digits_are_not_digits(self):
        self._prints(
            R"console.log(String(parseFloat('\u0661\u0662\u0663')), parseFloat('1\u0661'),"
            R" String(parseFloat('\u00B2')), parseFloat('2\u00B2'),"
            R" String(parseFloat('\u216B')));",
            'NaN 1 NaN 2 NaN\n')

    def test_a_base_other_than_ten_is_read_no_further_than_its_prefix(self):
        """
        A leading zero is not a base prefix, so `parseFloat('0777')` is seven hundred and
        seventy-seven.
        """
        self._prints(
            "console.log(parseFloat('0x10'), parseFloat('0b101'), parseFloat('0o17'),"
            " parseFloat('1_0'), parseFloat('0777'), parseFloat('10n'));",
            '0 0 0 1 777 10\n')

    def test_an_empty_string_names_no_number_here_and_zero_to_the_whole_string_reader(self):
        self._prints(
            R"console.log(String(parseFloat('')), String(parseFloat('   ')),"
            R" String(parseFloat('\uFEFF')), Number(''), Number('   '), Number('\uFEFF'));",
            'NaN NaN NaN 0 0 0\n')

    def test_a_very_long_run_of_digits_names_the_infinity_it_denotes(self):
        digits = '1' * 400
        self._prints(
            F"console.log(String(parseFloat('{digits}')), String(parseFloat('1e{'9' * 400}')),"
            F" String(parseFloat('{digits}x')), String(Number('{digits}x')));",
            'Infinity Infinity Infinity NaN\n')

    def test_parse_float_reached_through_a_name_reads_the_same_grammar(self):
        self._prints(
            "var read = parseFloat;"
            " console.log(read('2.5abc'), read('1e'), String(read('nope')));",
            '2.5 1 NaN\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestStringTrimReadsTheWhitespaceOfTheLanguage(TestBase):

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_the_padding_only_python_strips_survives_a_trim(self):
        self._prints(
            R"console.log('\u001CX\u001C'.trim() === '\u001CX\u001C',"
            R" '\u001DX\u001D'.trim() === '\u001DX\u001D',"
            R" '\u001EX\u001E'.trim() === '\u001EX\u001E',"
            R" '\u001FX\u001F'.trim() === '\u001FX\u001F',"
            R" '\u0085X\u0085'.trim() === '\u0085X\u0085');",
            'true true true true true\n')

    def test_the_byte_order_mark_python_leaves_in_place_is_taken_off_by_all_three(self):
        source = (
            R"console.log('\uFEFFX\uFEFF'.trim() === 'X', '\uFEFFX'.trimStart() === 'X',"
            R" 'X\uFEFF'.trimEnd() === 'X');")
        self._prints(source, 'true true true\n')
        self.assertEqual(deobfuscate_source(source), 'console.log(true, true, true);')

    def test_one_end_is_trimmed_with_the_set_that_trims_both(self):
        self._prints(
            R"console.log('\u001CX'.trimStart() === '\u001CX', 'X\u0085'.trimEnd() === 'X\u0085');",
            'true true\n')

    def test_every_whitespace_character_is_taken_off_and_a_look_alike_is_not(self):
        self._prints(
            R"console.log('\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}"
            R"\u0009\u000A\u000B\u000C\u000D\u0020\u00A0\u1680\u2000"
            R"\u200A\u2028\u2029\u202F\u205F\u3000\uFEFFX'.trimStart() === 'X',"
            R" '\u200BX\u200B'.trim() === '\u200BX\u200B');",
            'true true\n')

    def test_a_trim_stops_at_the_first_character_the_language_keeps(self):
        self._prints(
            R"console.log('\uFEFF \u001CX\u0085 \uFEFF'.trim() === '\u001CX\u0085');",
            'true\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestParseIntEvaluatesEveryArgumentItIsWrittenWith(TestBase):

    def _preserves(self, source: str, expected: tuple[str, str | None]):
        self.assertEqual(expected, behavior(source))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            expected,
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_third_argument_that_names_nothing_throws_before_parse_int_is_reached(self):
        self._preserves("console.log(parseInt('10', 2, nowhere));", ('', 'ReferenceError'))

    def test_a_third_argument_that_increments_is_evaluated(self):
        self._preserves("var x = 0; console.log(parseInt('10', 2, x++), x);", ('2 1\n', None))

    def test_a_third_argument_that_calls_is_evaluated(self):
        self._preserves(
            "var sink = []; var n = parseInt('10', 2, sink.push('third'));"
            " console.log(n, sink.join('|'));",
            ('2 third\n', None))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestUnaryOperatorFoldCoverage(TestBase):

    def _folds(self, source: str, token: str):
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

    def test_bitwise_not_of_infinity_folds(self):
        self._folds('console.log(String(~Infinity));', '~')

    def test_bitwise_not_of_negative_infinity_folds(self):
        self._folds('console.log(String(~(-Infinity)));', '~')

    def test_typeof_null_folds(self):
        self._folds('console.log(typeof null);', 'typeof')

    def test_typeof_an_object_literal_folds(self):
        self._folds('console.log(typeof {});', 'typeof')

    def test_typeof_an_array_literal_folds(self):
        self._folds('console.log(typeof []);', 'typeof')

    def test_typeof_a_function_expression_folds(self):
        self._folds('console.log(typeof function () {});', 'typeof')

    def test_unary_plus_on_a_string_literal_folds(self):
        self._folds("console.log(String(+'12'));", '+')

    def test_unary_plus_on_null_folds(self):
        self._folds('console.log(String(+null));', '+')

    def test_logical_not_of_an_object_literal_folds(self):
        self._folds('console.log(String(!{}));', '!')

    def test_delete_of_a_property_of_a_local_object_literal_folds(self):
        self._folds("var o = { a: 1 }; console.log(String(delete o.a));", 'delete')

    def test_typeof_a_numeric_literal_already_folds(self):
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
            'console.log(typeof 1);',
            "console.log(typeof 'a');",
            'console.log(typeof true);',
            'console.log(String(void 7));',
            'console.log(String(!null));',
            'console.log(String(~1e21));',
        ):
            with self.subTest(source=source):
                self._preserves(source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNegatedInfinityTermination(TestBase):

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

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_computed_class_member_name_is_a_variable_read(self):
        source = (
            "var k = 'a'; class C { [k] = 1; }"
            " console.log(new C().a, Object.keys(new C()).join('|'));")
        self._prints(source, '1 a\n')
        self.assertIn(
            deobfuscate_source(source),
            (
                inspect.cleandoc(
                    """
                    class C {
                      ['a'] = 1;
                    }
                    console.log(new C().a, Object.keys(new C()).join('|'));
                    """
                ),
                inspect.cleandoc(
                    """
                    class C {
                      a = 1;
                    }
                    console.log(new C().a, Object.keys(new C()).join('|'));
                    """
                ),
            ),
        )

    @opportunity
    def test_a_computed_class_member_name_that_folds_to_a_plain_name_is_written_as_one(self):
        source = (
            "var k = 'a'; class C { [k] = 1; }"
            " console.log(new C().a, Object.keys(new C()).join('|'));")
        self.assertEqual(
            deobfuscate_source(source),
            inspect.cleandoc(
                """
                class C {
                  a = 1;
                }
                console.log(new C().a, Object.keys(new C()).join('|'));
                """
            ),
        )

    def test_an_instance_field_name_is_not_a_variable_read(self):
        self._prints(
            "var label = 'X'; class C { label = 1; }"
            " console.log(new C().label, Object.keys(new C()).join('|'), label);",
            '1 label X\n')

    def test_an_instance_method_name_is_not_a_variable_read(self):
        self._prints(
            "var greet = 'hi'; class C { greet() { return 5; } }"
            ' console.log(new C().greet(), greet);',
            '5 hi\n')

    def test_a_static_field_name_is_not_a_variable_read(self):
        self._prints(
            "var tag = 'T'; class C { static tag = 7; } console.log(C.tag, tag);",
            '7 T\n')

    def test_a_static_method_name_is_not_a_variable_read(self):
        self._prints(
            "var run = 'R'; class C { static run() { return 9; } } console.log(C.run(), run);",
            '9 R\n')


class TestANamedEntrypointIsKeptInTheEmittedText(TestBase):

    def test_a_declared_function_named_as_an_entrypoint_is_kept(self):
        source = 'function handler() { return 5; } run();'
        self.assertEqual(deobfuscate_source(source), 'run();')
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('handler',)),
            'function handler() {\n  return 5;\n}\nrun();',
        )

    def test_a_file_of_only_functions_keeps_the_function_no_entrypoint_names(self):
        source = "function junk() { return 'unused'; } function run() { return 'kept'; }"
        self.assertEqual(
            deobfuscate_source(source, entrypoints=('run',)),
            inspect.cleandoc("""
                function junk() {
                  return 'unused';
                }
                function run() {
                  return 'kept';
                }
            """),
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

    def test_module_scoped_var_is_removed_even_when_exported(self):
        """
        Under the module model a top-level `var` never becomes a property of the global object, so
        no host can reach it by name, and removing it is sound although an entrypoint names it.
        """
        source = 'var handler = function () { return 5; };'
        output = deobfuscate_source(source, execution=ExecutionModel.module, entrypoints=('handler',))
        self.assertEqual(output, '')

    def test_module_scoped_global_still_folds_when_exported(self):
        source = 'var VERSION = 3; console.log(VERSION);'
        self.assertEqual(
            deobfuscate_source(source, execution=ExecutionModel.module, entrypoints=('VERSION',)),
            'console.log(3);',
        )

    def test_module_scoped_dead_function_is_removed_even_when_exported(self):
        source = 'function handler() { return 5; }'
        output = deobfuscate_source(source, execution=ExecutionModel.module, entrypoints=('handler',))
        self.assertEqual(output, '')


class TestDeobfuscateWithin(TestBase):

    def test_a_deobfuscation_whose_program_is_not_ascii_is_reported_as_finished(self):
        source = "console.log('日本語');"
        self.assertEqual(deobfuscate_within(source, seconds=20), source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDecidedTestsKeepTheirEffects(TestBase):

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

    def _check(self, source: str):
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(source),
            behavior(deobfuscated),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_undefined_keeps_its_value_in_a_function_whose_parameter_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            var u;
            function f(undefined) {
              return String(u) + '/' + String(undefined);
            }
            console.log(f('shadow'));
        """))

    def test_nan_keeps_its_value_in_a_function_whose_parameter_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            var n = 0 / 0;
            function f(NaN) {
              return String(n) + '/' + String(NaN);
            }
            console.log(f(3));
        """))

    def test_infinity_keeps_its_value_in_a_function_whose_parameter_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            var big = 1 / 0;
            function f(Infinity) {
              return String(big) + '/' + String(Infinity);
            }
            console.log(f('shadow'));
        """))

    def test_negative_infinity_keeps_its_value_in_a_function_whose_parameter_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            var small = -1 / 0;
            function f(Infinity) {
              return String(small) + '/' + String(Infinity);
            }
            console.log(f('shadow'));
        """))

    def test_nan_keeps_its_value_in_a_function_whose_var_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            function f() {
              var NaN = 'shadow';
              return String(0 / 0) + '/' + String(NaN);
            }
            console.log(f());
        """))

    def test_infinity_keeps_its_value_above_the_var_that_rebinds_the_name_later_in_the_body(self):
        self._check(inspect.cleandoc("""
            function f() {
              var head = String(1 / 0);
              var Infinity = 'shadow';
              return head + '/' + String(Infinity);
            }
            console.log(f());
        """))

    def test_nan_keeps_its_value_in_a_function_whose_function_declaration_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            function f() {
              var head = String(0 / 0);
              function NaN() {}
              return head + '/' + typeof NaN;
            }
            console.log(f());
        """))

    def test_infinity_keeps_its_value_in_a_function_whose_let_rebinds_the_name(self):
        self._check(inspect.cleandoc("""
            function f() {
              let Infinity = 'shadow';
              return String(1 / 0) + '/' + String(Infinity);
            }
            console.log(f());
        """))

    def test_undefined_keeps_its_value_in_a_block_whose_let_rebinds_the_name(self):
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

    def test_undefined_keeps_its_value_in_a_catch_block_whose_binding_rebinds_the_name(self):
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

    def test_nan_keeps_its_value_in_a_with_body_whose_object_supplies_the_name(self):
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

    def test_undefined_keeps_its_value_in_a_with_body_whose_object_supplies_the_name(self):
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

    def test_nan_keeps_its_value_in_a_nested_function_that_inherits_the_parameter_rebinding(self):
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
        self._check(inspect.cleandoc("""
            globalThis.marker = 'G';
            function f(globalThis) {
              return new Function('return this.marker')() + '/' + globalThis.marker;
            }
            console.log(f({ marker: 'X' }));
        """))

    def test_constructed_this_compared_where_a_parameter_rebinds_the_global_object_name(self):
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
        The oracle runs the program as a CommonJS module, whose top level is a function scope, so
        the `var` binds the name. At the top level of a classic script it would change nothing,
        because the global `undefined` is neither writable nor configurable.
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

    def test_typeof_undefined_is_not_folded_where_a_direct_eval_declares_the_name(self):
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
    In JScript, the engine these scripts are written for, `NaN`, `Infinity` and `undefined` are
    writable, so each assignment here changes what the name denotes. Node makes them read-only and
    ignores the assignments, so the cases assert the emitted text instead of what Node prints.
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
        self._preserves(
            self._receiver_program('(1 ? o.m : null)'),
            self._receiver_program('o.m'),
        )

    def test_conditional_taking_its_alternate_calls_without_a_receiver(self):
        self._preserves(
            self._receiver_program('(0 ? null : o.m)'),
            self._receiver_program('o.m'),
        )

    def test_logical_and_with_a_truthy_test_calls_its_right_hand_side_without_a_receiver(self):
        self._preserves(
            self._receiver_program('(1 && o.m)'),
            self._receiver_program('o.m'),
        )

    def test_logical_or_with_a_falsy_test_calls_its_right_hand_side_without_a_receiver(self):
        self._preserves(
            self._receiver_program('(0 || o.m)'),
            self._receiver_program('o.m'),
        )

    def test_nullish_with_a_nullish_test_calls_its_right_hand_side_without_a_receiver(self):
        self._preserves(
            self._receiver_program('(null ?? o.m)'),
            self._receiver_program('o.m'),
        )

    def test_conditional_taking_its_consequent_leaves_its_eval_indirect(self):
        self._preserves(
            self._direct_eval_program('(1 ? eval : null)'),
            self._direct_eval_program('eval'),
        )

    def test_logical_and_with_a_truthy_test_leaves_its_eval_indirect(self):
        self._preserves(
            self._direct_eval_program('(1 && eval)'),
            self._direct_eval_program('eval'),
        )

    def test_logical_or_with_a_falsy_test_leaves_its_eval_indirect(self):
        self._preserves(
            self._direct_eval_program('(0 || eval)'),
            self._direct_eval_program('eval'),
        )

    def test_nullish_with_a_nullish_test_leaves_its_eval_indirect(self):
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
whitespace of the language as the engine reads it.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTokensAreSeparatedByTheWhitespaceOfTheLanguage(TestBase):

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
        _, ends = self._node_reading()
        self.assertEqual(ends, self._read_as_a_line_ending())

    def test_a_program_woven_with_every_whitespace_character_is_the_spaced_program(self):
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
        program = 'var greeting = 1 + 2;\nconsole.log(greeting);'
        marked = chr(0xFEFF) + program
        self.assertEqual(behavior(marked), ('3\n', None))
        self.assertEqual(canonical(JsParser(marked).parse()), canonical(JsParser(program).parse()))
        self.assertEqual(deobfuscate_source(marked), 'console.log(3);')

    def test_a_character_python_calls_a_space_and_the_language_does_not_separates_nothing(self):
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
        self._prints('var x = 1\nvar y = x\n++x\nconsole.log(x, y)', '2 1\n')
        self._prints('var x = 1\r\nvar y = x\r\n++x\r\nconsole.log(x, y)', '2 1\n')

    def test_whitespace_that_ends_no_line_does_not_end_a_return_statement(self):
        for cp in [0x0009, 0x000B, 0x000C, 0x00A0, 0x3000, 0xFEFF]:
            with self.subTest(character=F'U+{cp:04X}'):
                self._prints(F'function f() {{ return{chr(cp)}42; }} console.log(f());', '42\n')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheLineSeparatorsEndALineRatherThanSeparateLikeASpace(TestBase):

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_line_separator_ends_a_single_line_comment(self):
        self._prints(F'console.log(1); // done{chr(0x2028)}console.log(2);', '1\n2\n')
        self._prints(F'console.log(1); // done{chr(0x2029)}console.log(2);', '1\n2\n')

    def test_a_line_separator_between_two_operands_is_no_token_of_its_own(self):
        self._prints(F'console.log(1{chr(0x2028)}+ 2);', '3\n')
        self._prints(F'console.log(1{chr(0x2029)}+ 2);', '3\n')

    def test_a_line_separator_inside_an_expression_leaves_the_expression_whole(self):
        self._prints(F'var x = 1 +{chr(0x2028)}2; console.log(x);', '3\n')
        self._prints(F'var x = 1 +{chr(0x2029)}2; console.log(x);', '3\n')

    def test_a_line_separator_after_return_ends_the_return_statement(self):
        self._prints(F'function f() {{ return{chr(0x2028)}42; }} console.log(f());', 'undefined\n')
        self._prints(F'function f() {{ return{chr(0x2029)}42; }} console.log(f());', 'undefined\n')

    def test_a_line_separator_inside_a_string_literal_is_a_character_of_the_string(self):
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

    def _folded(self, code_point: int) -> str:
        return deobfuscate_source(RF"SINK(atob('QUJ\u{{{code_point:X}}}D'));")

    def _catching_program(self, escape: str) -> str:
        return (
            F"try {{ console.log(atob('QUJ{escape}D')); }}"
            F' catch (error) {{ console.log(error.name); }}')

    def test_the_characters_a_decode_removes_are_the_ones_node_removes_and_no_others(self):
        source = F'const CANDIDATES = {json.dumps(SPACE_LIKE_CODE_POINTS)};'
        output, error = behavior(source + _ASK_WHICH_CHARACTERS_A_FORGIVING_DECODE_REMOVES)
        self.assertIsNone(error)
        self.assertEqual(
            json.loads(output),
            [cp for cp in SPACE_LIKE_CODE_POINTS if self._folded(cp) == "SINK('ABC');"],
        )

    def test_an_argument_padded_with_them_decodes_to_the_text_it_names(self):
        padded = R"console.log(atob('\t\n\f\r QUJD \r\f\n\t'));"
        self.assertEqual(behavior(padded), ('ABC\n', None))
        self.assertEqual(deobfuscate_source(padded), "console.log('ABC');")
        interior = R"console.log(atob('SGVs\nbG8s\tIHdv\rcmxk'));"
        self.assertEqual(behavior(interior), ('Hello, world\n', None))
        self.assertEqual(deobfuscate_source(interior), "console.log('Hello, world');")

    def test_an_argument_holding_a_character_it_does_not_remove_is_refused(self):
        """
        A forgiving base64 decode removes only the tab, line feed, form feed, carriage return and
        space, so the vertical tab and every non-ASCII space make the call throw.
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
        Node reports an uncaught `DOMException` without an `XxxError:` line, so the oracle returns
        its type as the bare `ERROR`.
        """
        source = R"console.log(atob('QUJ\u000BD'));"
        self.assertEqual(behavior(source), ('', 'ERROR'))
        self.assertEqual(behavior(deobfuscate_source(source)), ('', 'ERROR'))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNumberParseIntAndParseFloatAreTheGlobalFunctions(TestBase):

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
        through_number = self._parse_int_calls('Number.parseInt')
        through_global = self._parse_int_calls('parseInt')
        self._prints(through_number, '5 255 31 1 42 NaN\n')
        self._prints(through_global, '5 255 31 1 42 NaN\n')
        self.assertEqual(
            deobfuscate_source(through_number), "console.log(5, 255, 31, 1, 42, 'NaN');")
        self.assertEqual(deobfuscate_source(through_number), deobfuscate_source(through_global))

    def test_parse_float_reached_through_number_folds_as_the_global_one_does(self):
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

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        self.assertEqual(behavior(deobfuscate_source(source)), (output, None))

    def test_a_run_of_digits_a_double_holds_names_the_integer_it_spells(self):
        """
        `0x20000000000001` is `2**53 + 1`, which has no double of its own and names `2**53`.
        """
        source = (
            "console.log(Number('0xff'), Number('0x1fffffffffffff'),"
            " Number('0x20000000000001'));")
        self._prints(source, '255 9007199254740991 9007199254740992\n')
        self.assertEqual(
            deobfuscate_source(source),
            'console.log(255, 9007199254740991, 9007199254740992);')

    def test_a_run_of_digits_past_the_double_range_names_an_infinity(self):
        for prefix, digit, count in [('0x', 'f', 300), ('0b', '1', 1100), ('0o', '7', 400)]:
            with self.subTest(prefix=prefix):
                source = F"console.log(String(Number('{prefix}{digit * count}')));"
                self._prints(source, 'Infinity\n')
                self.assertEqual(deobfuscate_source(source), "console.log('Infinity');")

    def test_leading_zeros_are_not_digits_of_the_number_they_precede(self):
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
    A forgiving base64 decode removes a trailing `=` or `==` only when the argument, with its
    whitespace removed, has a length divisible by four; otherwise `=` is a character outside the
    alphabet and the call throws. So `atob('QQ==')` and `atob('QQ')` are both `'A'`, while
    `atob('QQ=')` throws.
    """

    def _node_answers(self) -> list[str | None]:
        source = F'const ARGUMENTS = {json.dumps(_ATOB_ARGUMENTS)};'
        output, error = behavior(source + _ASK_WHAT_A_FORGIVING_DECODE_ANSWERS)
        self.assertIsNone(error)
        return json.loads(output)

    def _builtin_answers(self) -> list[str | None]:
        decode = BUILTIN_REGISTRY[None, 'atob'].function
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
        Node reports an uncaught `DOMException` without an `XxxError:` line, so the oracle returns
        its type as the bare `ERROR`.
        """
        source = "console.log(atob('QQ='));"
        self.assertEqual(behavior(source), ('', 'ERROR'))
        self.assertEqual(deobfuscate_source(source), source)
        self.assertEqual(behavior(deobfuscate_source(source)), ('', 'ERROR'))

    def test_the_refusal_a_program_catches_is_the_one_node_raises(self):
        for argument in ['QQ=', 'QUJDRA=', 'QUJD=', 'QQ===']:
            with self.subTest(argument=argument):
                source = (
                    F"try {{ console.log(atob('{argument}')); }}"
                    F' catch (error) {{ console.log(error.name); }}')
                self.assertEqual(behavior(source), ('InvalidCharacterError\n', None))
                self.assertEqual(
                    behavior(deobfuscate_source(source)), ('InvalidCharacterError\n', None))

    def test_a_dead_binding_whose_decode_is_refused_keeps_the_refusal(self):
        refused = "var value = atob('QQ='); console.log('after');"
        self.assertEqual(behavior(refused), ('', 'ERROR'))
        self.assertEqual(behavior(deobfuscate_source(refused)), ('', 'ERROR'))
        decoded = "var value = atob('QQ=='); console.log('after');"
        self.assertEqual(behavior(decoded), ('after\n', None))
        self.assertEqual(deobfuscate_source(decoded), "console.log('after');")

    def test_the_same_text_decodes_where_its_group_is_whole_or_its_padding_is_absent(self):
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
                    row.append([ord(unit) for unit in BUILTIN_REGISTRY[None, name].function([argument])])
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

    def _calls_that_catch(self, arguments: list[str]) -> str:
        return ''.join(
            F'try {{ console.log(decodeURIComponent({json.dumps(argument)})); }}'
            F' catch (error) {{ console.log(error.name); }}\n'
            for argument in arguments
        )

    def test_every_argument_no_decode_reads_raises_the_error_node_raises(self):
        source = self._calls_that_catch(_ARGUMENTS_NO_DECODE_READS)
        refused = ('URIError\n' * len(_ARGUMENTS_NO_DECODE_READS), None)
        self.assertEqual(behavior(source), refused)
        self.assertEqual(behavior(deobfuscate_source(source)), refused)

    def test_a_refused_call_is_left_standing_and_the_program_still_aborts(self):
        for argument in ('100%', '%ED%A0%80'):
            with self.subTest(argument=argument):
                source = F'console.log(decodeURIComponent({json.dumps(argument)}));'
                self.assertEqual(behavior(source), ('', 'URIError'))
                self.assertEqual(deobfuscate_source(source), source)
                self.assertEqual(behavior(deobfuscate_source(source)), ('', 'URIError'))

    def test_a_dead_binding_whose_decode_is_refused_keeps_the_refusal(self):
        refused = 'var value = decodeURIComponent("100%"); console.log("after");'
        self.assertEqual(behavior(refused), ('', 'URIError'))
        self.assertEqual(behavior(deobfuscate_source(refused)), ('', 'URIError'))
        decoded = 'var value = decodeURIComponent("%41"); console.log("after");'
        self.assertEqual(behavior(decoded), ('after\n', None))
        self.assertEqual(deobfuscate_source(decoded), 'console.log("after");')

    def test_an_argument_whose_escapes_are_whole_folds_to_the_text_it_names(self):
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

    def test_every_argument_a_decode_refuses_is_one_unescape_reads(self):
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
        Each escape names one code unit rather than a UTF-8 byte, so `unescape('%C3%A9')` is two
        characters.
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

    def test_a_surrogate_no_partner_completes_is_refused(self):
        for spelling in (R'\uD800', R'\uDFFF', R'a\uD83Db', R'\uDC00\uD800'):
            with self.subTest(spelling=spelling):
                source = F'console.log(encodeURIComponent("{spelling}"));'
                self.assertEqual(behavior(source), ('', 'URIError'))
                self.assertEqual(behavior(deobfuscate_source(source)), ('', 'URIError'))

    def test_a_pair_that_is_whole_is_encoded_as_the_utf8_of_the_character_it_names(self):
        source = R'console.log(encodeURIComponent("a😀b"));'
        self.assertEqual(behavior(source), ('a%F0%9F%98%80b\n', None))
        self.assertEqual(deobfuscate_source(source), "console.log('a%F0%9F%98%80b');")

    def test_the_characters_an_encode_writes_as_themselves_are_the_unreserved_ones(self):
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

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_discarded_call_prints_what_the_program_around_it_prints(self):
        self._prints("Number.parseInt('42'); console.log('after');", 'after\n')
        self._prints("Number.parseFloat('2.5'); console.log('after');", 'after\n')
        self._prints("Number.parseInt('nope'); console.log('after');", 'after\n')
        self._prints("Number.parseFloat('Infinity'); console.log('after');", 'after\n')
        self._prints("Number.parseInt('42', 10); console.log('after');", 'after\n')

    def test_a_call_whose_value_is_read_is_the_number_it_names(self):
        integer = "console.log(Number.parseInt('42'));"
        self._prints(integer, '42\n')
        self.assertEqual(deobfuscate_source(integer), 'console.log(42);')
        decimal = "console.log(Number.parseFloat('2.5'));"
        self._prints(decimal, '2.5\n')
        self.assertEqual(deobfuscate_source(decimal), 'console.log(2.5);')

    def test_a_discarded_call_whose_argument_names_nothing_still_throws(self):
        source = "Number.parseInt(nowhere); console.log('after');"
        self.assertEqual(behavior(source), ('', 'ReferenceError'))
        self.assertEqual(behavior(deobfuscate_source(source)), ('', 'ReferenceError'))

    def test_a_discarded_call_whose_argument_writes_still_writes(self):
        self._prints("var x = 0; Number.parseInt('10', 2, x++); console.log(x);", '1\n')

    def test_a_discarded_call_whose_argument_calls_still_calls(self):
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

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_binding_whose_name_holds_a_joiner_is_read_by_that_name(self):
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                source = F'var a{joiner}b = 7; console.log(a{joiner}b);'
                self._prints(source, '7\n')
                self.assertEqual(deobfuscate_source(source), 'console.log(7);')

    def test_two_names_that_differ_only_by_a_joiner_are_two_names(self):
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                self._prints(
                    F'var ab = 1; var a{joiner}b = 2; console.log(ab, a{joiner}b);', '1 2\n')

    def test_the_two_joiners_name_two_different_bindings(self):
        non_joiner, joiner = _JOINERS
        self._prints(
            F'var a{non_joiner}b = 1; var a{joiner}b = 2;'
            F' console.log(a{non_joiner}b, a{joiner}b);',
            '1 2\n')

    def test_a_name_spelled_without_the_joiner_reaches_no_binding(self):
        for joiner in _JOINERS:
            with self.subTest(joiner=F'U+{ord(joiner):04X}'):
                self._prints(
                    F'var a{joiner}b = 7;'
                    ' try { console.log(ab); } catch (error) { console.log(error.name); }',
                    'ReferenceError\n')

    def test_a_parameter_whose_name_holds_a_joiner_is_read_in_the_body(self):
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

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
        )

    def test_a_file_is_read_the_same_whichever_terminator_ends_its_hash_bang_line(self):
        for ending in _LINE_ENDINGS:
            with self.subTest(ending=' '.join(F'U+{ord(c):04X}' for c in ending)):
                source = F'#!/usr/bin/env node{ending}console.log(1);'
                self._prints(source, '1\n')
                self.assertEqual(deobfuscate_source(source), '#!/usr/bin/env node\nconsole.log(1);')

    def test_what_the_hash_bang_line_says_is_not_code(self):
        source = F"#!console.log('boom'){chr(0x000A)}console.log(1);"
        self._prints(source, '1\n')
        self.assertEqual(deobfuscate_source(source), "#!console.log('boom')\nconsole.log(1);")

    def test_a_file_whose_hash_bang_line_is_all_of_it_prints_nothing(self):
        source = '#!/usr/bin/env node'
        self.assertEqual(behavior(source), ('', None))
        self.assertEqual(deobfuscate_source(source), source)
        self.assertEqual(behavior(deobfuscate_source(source)), ('', None))

    def test_the_statements_below_a_hash_bang_line_end_where_their_lines_end(self):
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
        self._prints(
            self._compared(_SMILE_SPELLINGS, '==='),
            'true true true true true true true true true\n',
        )

    def test_the_spellings_of_a_basic_plane_character_denote_one_string(self):
        self._prints(
            self._compared(_ACUTE_SPELLINGS, '==='),
            'true true true true true true true true true\n',
        )

    def test_no_spelling_of_an_astral_character_orders_before_another(self):
        for operator in ['<', '>']:
            with self.subTest(operator=operator):
                self._prints(
                    self._compared(_SMILE_SPELLINGS, operator),
                    'false false false false false false false false false\n',
                )

    def test_a_comparison_of_two_spellings_selects_the_branch_that_runs(self):
        for left in _SMILE_SPELLINGS:
            for right in _SMILE_SPELLINGS:
                with self.subTest(left=left, right=right):
                    self._prints(self._branched(left, right), 'same\n')

    def test_a_search_finds_the_character_however_the_needle_is_spelled(self):
        for haystack in _SMILE_SPELLINGS:
            for needle in _SMILE_SPELLINGS:
                with self.subTest(haystack=haystack, needle=needle):
                    self._prints(self._searched(haystack, needle), '1 true aXb\n')

    def test_an_astral_character_assembled_at_run_time_equals_every_spelling_of_it(self):
        for spelling in _SMILE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(self._assembled(spelling), 'true true true\n')

    def test_an_astral_character_written_with_escapes_is_counted_and_indexed_in_code_units(self):
        for spelling in _SMILE_ESCAPED_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(
                    self._counted_and_indexed(spelling),
                    F'4 55357 56832 3 {_SMILE} {_SMILE} 4\n',
                )

    def test_a_basic_plane_character_is_counted_and_indexed_the_same_in_every_spelling(self):
        for spelling in _ACUTE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self._prints(
                    self._counted_and_indexed(spelling),
                    F'3 233 98 2 {_ACUTE}b {_ACUTE}b 3\n',
                )

    def test_the_character_beginning_at_a_position_is_read_from_the_units_standing_there(self):
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
Statements that denote the text `use strict` and ask for no strict mode. Such a string literal is
a directive, but the Use Strict Directive is the literal written plainly, so an escape inside it
leaves a directive that asks for nothing. Node runs every program opening with one of these as
sloppy code.
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

    def _prints(self, source: str, output: str):
        self.assertEqual(behavior(source), (output, None))
        deobfuscated = deobfuscate_source(source)
        self.assertEqual(
            behavior(deobfuscated),
            (output, None),
            F'deobfuscation changed observable behavior; result was:{chr(10)}{deobfuscated}',
        )

    def test_a_plainly_written_string_is_the_directive_and_stays_one(self):
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
        for head in _SPELLINGS_THAT_ONLY_DENOTE_THE_TEXT_OF_A_DIRECTIVE:
            with self.subTest(head=head):
                self._prints(
                    a_file_holding_an_octal_literal_opening_with(head), '8' + chr(10))

    def test_a_use_strict_below_a_statement_that_is_no_directive_is_none_either(self):
        for head in SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING:
            with self.subTest(head=head):
                self.assertEqual(
                    behavior(a_script_whose_directive_stands_below(head)),
                    ('false' + chr(10), None),
                )
