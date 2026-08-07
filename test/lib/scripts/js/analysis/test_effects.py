from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.effects import (
    GLOBAL_OBJECT,
    EffectSummary,
    build_effects,
    object_member_access_runs_accessor,
)
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBinaryExpression,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestEffectModel(TestBase):

    @staticmethod
    def _effects(source: str):
        ast = JsParser(source).parse()
        return ast, build_effects(build_semantic_model(ast))

    @staticmethod
    def _func(ast, name: str) -> JsFunctionDeclaration:
        for node in ast.walk():
            if isinstance(node, JsFunctionDeclaration) and node.id is not None and node.id.name == name:
                return node
        raise AssertionError(F'no function named {name}')

    @staticmethod
    def _only_call(ast) -> JsCallExpression:
        return next(n for n in ast.walk_in_order() if isinstance(n, JsCallExpression))

    def _summary(self, source: str, name: str):
        ast, effects = self._effects(source)
        return effects.summary_of(self._func(ast, name))

    def _binding(self, ast, model, name: str):
        for node in ast.walk():
            if isinstance(node, JsIdentifier) and node.name == name:
                binding = model.resolve(node)
                if binding is not None:
                    return binding
        raise AssertionError(F'no resolvable binding named {name}')

    def test_return_literal_is_pure(self):
        self.assertTrue(self._summary('function f(){ return 42; }', 'f').is_pure)

    def test_arithmetic_on_parameters_is_pure(self):
        self.assertTrue(self._summary('function f(a, b){ return a * b + 1; }', 'f').is_pure)

    def test_fresh_object_is_pure(self):
        self.assertTrue(self._summary('function f(){ return { a: 1, b: [2, 3] }; }', 'f').is_pure)

    def test_local_variable_mutation_is_pure(self):
        self.assertTrue(self._summary('function f(){ var s = 0; s = s + 1; return s; }', 'f').is_pure)

    def test_pure_intrinsic_call_is_pure(self):
        summary = self._summary('function f(n){ return String.fromCharCode(n); }', 'f')
        self.assertTrue(summary.is_pure)

    def test_async_function_is_pure_but_not_value_replaceable(self):
        summary = self._summary('async function f(){ return 1; }', 'f')
        self.assertTrue(summary.is_pure)
        self.assertFalse(summary.is_value_replaceable)

    def test_generator_function_is_not_value_replaceable(self):
        summary = self._summary('function* f(){ return 1; }', 'f')
        self.assertFalse(summary.is_value_replaceable)

    def test_global_assignment_is_a_global_write(self):
        source = 'function f(){ leaked = 1; } function r(){ return leaked; }'
        summary = self._summary(source, 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.writes_captured)
        self.assertFalse(summary.is_pure)

    def test_assignment_to_declared_global_is_a_global_write(self):
        source = 'var g; function f(){ g = 2; } function r(){ return g; }'
        summary = self._summary(source, 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_mutated_bindings_records_captured_write(self):
        ast, effects = self._effects('function f(){ var x = 0; function g(){ x = 2; } g(); return x; }')
        x = self._binding(ast, effects.model, 'x')
        self.assertEqual(effects.mutated_bindings(self._func(ast, 'g')), frozenset({x}))

    def test_mutated_bindings_is_transitive_through_calls(self):
        ast, effects = self._effects(
            'var x = 1; function w(){ x = 2; } function f(){ w(); } function r(){ return x; }')
        x = self._binding(ast, effects.model, 'x')
        self.assertTrue(effects.function_can_mutate(self._func(ast, 'f'), x))

    def test_mutated_bindings_excludes_own_local(self):
        ast, effects = self._effects('function f(){ var s = 0; s = s + 1; return s; }')
        self.assertEqual(effects.mutated_bindings(self._func(ast, 'f')), frozenset())

    def test_mutated_bindings_distinguishes_same_named_bindings(self):
        source = (
            'function a(){ var x = 1; function w(){ x = 2; } w(); return x; }'
            ' function b(){ var x = 9; return x; }'
        )
        ast, effects = self._effects(source)
        model = effects.model
        x_a = model.lookup('x', model.function_scope(self._func(ast, 'a')))
        x_b = model.lookup('x', model.function_scope(self._func(ast, 'b')))
        assert x_a is not None and x_b is not None
        w = self._func(ast, 'w')
        self.assertTrue(effects.function_can_mutate(w, x_a))
        self.assertFalse(effects.function_can_mutate(w, x_b))

    def test_mutated_bindings_handles_mutual_recursion(self):
        source = 'var x = 0; function f(){ x = 1; g(); } function g(){ x = 2; f(); } function r(){ return x; }'
        ast, effects = self._effects(source)
        x = self._binding(ast, effects.model, 'x')
        self.assertTrue(effects.function_can_mutate(self._func(ast, 'f'), x))
        self.assertTrue(effects.function_can_mutate(self._func(ast, 'g'), x))

    def test_write_only_unobservable_global_is_pure_with_no_mutated_bindings(self):
        """
        A write-only global in a reflection-free program is an unobservable scratch write, so it neither
        makes the function impure nor names a mutated binding.
        """
        ast, effects = self._effects('function f(){ scratch = 1; }')
        f = self._func(ast, 'f')
        self.assertTrue(effects.summary_of(f).is_pure)
        self.assertEqual(effects.mutated_bindings(f), frozenset())

    def test_summary_equality_accounts_for_written_bindings(self):
        ast, effects = self._effects('var x = 0; function f(){ x = 1; } function r(){ return x; }')
        populated = effects.summary_of(self._func(ast, 'f'))
        self.assertTrue(populated.written_bindings)
        self.assertNotEqual(populated, EffectSummary(writes_global=True))

    def test_mutated_bindings_records_confined_but_read_write(self):
        """
        Every reference to `x` is confined to `f`, so the write is unobservable outside it and `f` stays
        pure; the write still changes `x` between the two reads inside `f`, so `x` is a mutated binding.
        """
        ast, effects = self._effects('var x = 1; function f(){ var a = x; x = 2; var b = x; }')
        f = self._func(ast, 'f')
        x = self._binding(ast, effects.model, 'x')
        self.assertTrue(effects.summary_of(f).is_pure)
        self.assertEqual(effects.mutated_bindings(f), frozenset({x}))

    def test_call_to_redeclared_function_is_unknown(self):
        """
        A name bound by two function declarations resolves to no single body — the later declaration
        wins at runtime — so a call through it is an unknown callee, not silently the first definition.
        """
        ast, effects = self._effects('function g(){} function g(){} function h(){ g(); }')
        self.assertTrue(effects.summary_of(self._func(ast, 'h')).calls_unknown)

    def test_write_to_never_read_global_under_reflection_is_impure(self):
        source = "function f(){ scratch = 1; } eval('1');"
        ast, effects = self._effects(source)
        self.assertFalse(effects.global_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_write_to_never_read_global_under_accessor_install_is_impure(self):
        source = (
            "Object.defineProperty(globalThis, 'scratch', { set: function(v){} });"
            ' function f(){ scratch = 1; }'
        )
        ast, effects = self._effects(source)
        self.assertFalse(effects.global_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_write_to_function_confined_global_is_pure(self):
        self.assertTrue(self._summary('function f(n){ acc = 0; acc = acc + n; return acc; }', 'f').is_pure)

    def test_confined_global_read_in_another_function_is_impure(self):
        source = 'function f(n){ acc = 0; acc = acc + n; return acc; } function g(){ return acc; }'
        summary = self._summary(source, 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_global_object_property_write_is_a_global_write(self):
        summary = self._summary('function f(){ globalThis.cache = 1; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.throws)
        self.assertFalse(summary.is_pure)

    def test_delete_of_global_object_property_is_a_global_write(self):
        summary = self._summary('function f(){ delete globalThis.cache; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_write_to_fresh_rest_param_is_not_a_global_write(self):
        summary = self._summary('function f(...xs){ xs[0] = 9; return xs[1]; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)

    def test_write_to_fresh_local_array_is_not_a_global_write(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; return o[0]; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)

    def test_write_to_fresh_local_object_is_not_a_global_write(self):
        summary = self._summary('function f(){ var o = {}; o.k = 9; return o.k; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)

    def test_write_to_plain_param_is_a_global_write(self):
        summary = self._summary('function f(a){ a[0] = 99; return a; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_write_to_local_aliasing_a_param_is_a_global_write(self):
        summary = self._summary('function f(a){ var o = a; o[0] = 9; return o[0]; }', 'f')
        self.assertTrue(summary.writes_global)

    def test_fresh_local_returned_after_write_mutates_returned_local(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; return o; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)
        self.assertTrue(summary.mutates_returned_local)
        self.assertFalse(summary.is_pure)
        self.assertFalse(summary.is_value_replaceable)

    def test_fresh_local_passed_to_call_after_write_mutates_returned_local(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; sink(o); return 1; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertTrue(summary.mutates_returned_local)
        self.assertFalse(summary.is_pure)

    def test_fresh_local_aliased_after_write_mutates_returned_local(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; var b = o; return b[0]; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertTrue(summary.mutates_returned_local)
        self.assertFalse(summary.is_pure)

    def test_rest_param_returned_after_write_is_discardable(self):
        summary = self._summary('function f(...xs){ xs[0] = 9; return xs; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)
        self.assertFalse(summary.throws)
        self.assertTrue(summary.mutates_returned_local)
        self.assertFalse(summary.is_pure)
        self.assertFalse(summary.is_value_replaceable)
        self.assertTrue(summary.is_effect_free_when_discarded)

    def test_decoder_factory_iife_is_discardable(self):
        source = (
            'function F(...A3LWTls){'
            ' A3LWTls.length = 0;'
            ' A3LWTls.b = new Array(128);'
            ' A3LWTls[-42] = String.fromCodePoint || String.fromCharCode;'
            ' A3LWTls.d = [];'
            ' return function(w){ return A3LWTls.d; }; }'
        )
        summary = self._summary(source, 'F')
        self.assertFalse(summary.throws)
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)
        self.assertFalse(summary.calls_unknown)
        self.assertTrue(summary.mutates_returned_local)
        self.assertFalse(summary.is_pure)
        self.assertTrue(summary.is_effect_free_when_discarded)

    def test_member_write_on_hoisted_var_before_init_may_throw(self):
        summary = self._summary('function g(){ A3.length = 0; var A3 = []; return A3; }', 'g')
        self.assertTrue(summary.throws)
        self.assertFalse(summary.is_effect_free_when_discarded)

    def test_member_write_on_lexical_before_init_may_throw(self):
        summary = self._summary('function g(){ A3.length = 0; let A3 = []; return A3; }', 'g')
        self.assertTrue(summary.throws)
        self.assertFalse(summary.is_effect_free_when_discarded)

    def test_inner_mutating_captured_enclosing_local_stays_observable(self):
        source = (
            'function outer(){ var a = [];'
            ' function inner(){ a[0] = 1; }'
            ' inner();'
            ' return function(){ return a; }; }'
        )
        summary = self._summary(source, 'inner')
        self.assertFalse(summary.mutates_returned_local)
        self.assertTrue(summary.writes_global or summary.writes_captured)
        self.assertFalse(summary.is_pure)
        self.assertFalse(summary.is_effect_free_when_discarded)

    def test_write_to_fresh_array_literal_base_is_pure(self):
        summary = self._summary('function f(){ [1, 2][0] = 9; return 1; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertTrue(summary.is_pure)

    def test_write_to_fresh_object_with_setter_is_a_global_write(self):
        summary = self._summary(
            'function f(){ var o = { set k(v){ g = v; } }; o.k = 9; } var g;', 'f')
        self.assertTrue(summary.writes_global)

    def test_write_through_object_literal_setting_proto_is_a_global_write(self):
        summary = self._summary('function f(){ return { __proto__: proto }.k = 9; }', 'f')
        self.assertTrue(summary.writes_global)

    def test_read_through_object_literal_setting_proto_is_not_pure(self):
        summary = self._summary('function f(){ return { __proto__: proto }.k; }', 'f')
        self.assertFalse(summary.is_pure)

    def test_write_to_plain_object_literal_base_is_pure(self):
        summary = self._summary('function f(){ return { a: 1 }.k = 9; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertTrue(summary.is_pure)

    @staticmethod
    def _object(source: str) -> JsObjectExpression:
        ast = JsParser(source).parse()
        return next(n for n in ast.walk_in_order() if isinstance(n, JsObjectExpression))

    def test_object_with_getter_runs_accessor(self):
        self.assertTrue(object_member_access_runs_accessor(self._object('x = { get k(){} };')))

    def test_object_with_setter_runs_accessor(self):
        self.assertTrue(object_member_access_runs_accessor(self._object('x = { set k(v){} };')))

    def test_object_setting_prototype_runs_accessor(self):
        self.assertTrue(object_member_access_runs_accessor(self._object('x = { __proto__: p };')))

    def test_object_with_proto_method_does_not_run_accessor(self):
        self.assertFalse(object_member_access_runs_accessor(self._object('x = { __proto__(){} };')))

    def test_object_with_proto_shorthand_does_not_run_accessor(self):
        self.assertFalse(object_member_access_runs_accessor(self._object('x = { __proto__ };')))

    def test_plain_data_object_does_not_run_accessor(self):
        self.assertFalse(object_member_access_runs_accessor(self._object('x = { a: 1 };')))

    def test_parenthesized_member_write_to_global_is_not_value_replaceable(self):
        summary = self._summary('function f(){ (g.x) = 9; return 7; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_value_replaceable)

    def test_destructuring_member_write_to_global_is_not_value_replaceable(self):
        summary = self._summary('function f(){ [g.x] = arr; return 7; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_value_replaceable)

    def test_for_in_member_target_to_global_is_a_global_write(self):
        summary = self._summary('function f(){ for (g.x in obj) {} return 7; }', 'f')
        self.assertTrue(summary.writes_global)

    def test_parenthesized_member_write_to_fresh_local_is_not_a_global_write(self):
        summary = self._summary('function f(){ var o = {}; (o.x) = 9; return o.x; }', 'f')
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.writes_captured)

    def test_closure_mutation_is_a_captured_write(self):
        source = (
            'function outer(){ var c = 0;'
            ' function inc(){ c += 1; }'
            ' function read(){ return c; }'
            ' return [inc, read]; }'
        )
        summary = self._summary(source, 'inc')
        self.assertTrue(summary.writes_captured)
        self.assertFalse(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_write_to_never_read_capture_is_unobservable(self):
        source = 'function outer(){ var c; function inner(){ c = 1; } return inner; }'
        self.assertTrue(self._summary(source, 'inner').is_pure)

    def test_defining_a_mutating_closure_is_itself_pure(self):
        source = 'function outer(){ var c = 0; function inc(){ c += 1; } return inc; }'
        self.assertTrue(self._summary(source, 'outer').is_pure)

    def test_throw_is_impure(self):
        summary = self._summary('function f(){ throw 1; }', 'f')
        self.assertTrue(summary.throws)
        self.assertFalse(summary.is_pure)

    def test_property_access_on_parameter_may_throw(self):
        summary = self._summary('function f(o){ return o.x; }', 'f')
        self.assertTrue(summary.throws)
        self.assertFalse(summary.is_pure)

    def test_property_read_through_global_object_may_run_getter(self):
        summary = self._summary('function f(){ return globalThis.foo; }', 'f')
        self.assertFalse(summary.throws)
        self.assertTrue(summary.calls_unknown)
        self.assertFalse(summary.is_pure)

    def test_unknown_call_is_impure(self):
        summary = self._summary('function f(){ return ext(); }', 'f')
        self.assertTrue(summary.calls_unknown)
        self.assertFalse(summary.is_pure)

    def test_call_to_pure_local_function_is_pure(self):
        source = 'function p(){ return 1; } function f(){ return p(); }'
        self.assertTrue(self._summary(source, 'f').is_pure)

    def test_call_to_impure_local_function_propagates_its_effect(self):
        source = 'function w(){ leaked = 1; } function f(){ w(); } function r(){ return leaked; }'
        summary = self._summary(source, 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_self_recursive_pure_function_is_pure(self):
        source = 'function f(n){ return n <= 1 ? 1 : f(n - 1); }'
        self.assertTrue(self._summary(source, 'f').is_pure)

    def test_mutual_recursion_propagates_effect_to_fixpoint(self):
        source = 'function a(){ b(); } function b(){ leaked = 1; a(); } function r(){ return leaked; }'
        self.assertTrue(self._summary(source, 'a').writes_global)
        self.assertFalse(self._summary(source, 'a').is_pure)

    def test_is_pure_call_recognizes_intrinsic(self):
        ast, effects = self._effects('String.fromCharCode(65);')
        self.assertTrue(effects.is_pure_call(self._only_call(ast)))

    def test_is_pure_call_rejects_unknown(self):
        ast, effects = self._effects('ext(1);')
        self.assertFalse(effects.is_pure_call(self._only_call(ast)))

    def test_is_pure_call_recognizes_pure_local(self):
        ast, effects = self._effects('function p(){ return 1; } p();')
        self.assertTrue(effects.is_pure_call(self._only_call(ast)))

    def test_is_pure_call_rejects_callee_reassigned_through_with(self):
        ast, effects = self._effects('function p(){ return 1; } with (o) { p = q; } p();')
        self.assertFalse(effects.is_pure_call(self._only_call(ast)))

    def test_is_pure_call_rejects_reassigned_declaration(self):
        ast, effects = self._effects('function p(){ return 1; } p = function(){ return 1; }; p();')
        self.assertFalse(effects.is_pure_call(self._only_call(ast)))

    def test_is_pure_call_recognizes_const_initialized_function(self):
        ast, effects = self._effects('const p = () => 1; p();')
        self.assertTrue(effects.is_pure_call(self._only_call(ast)))

    def test_is_pure_call_recognizes_bare_assignment_function(self):
        ast, effects = self._effects('var p; p = function(){ return 1; }; p();')
        self.assertTrue(effects.is_pure_call(self._only_call(ast)))

    def test_is_side_effect_free_rejects_call_to_reassigned_impure_declaration(self):
        ast, effects = self._effects('var S = []; function v0(x){ S.push(x); } v0(1); v0 = function(){};')
        call = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsCallExpression)
            and isinstance(n.callee, JsIdentifier)
            and n.callee.name == 'v0'
        )
        self.assertFalse(effects.is_side_effect_free(call))

    def test_is_side_effect_free_clears_hoisted_declaration_call(self):
        ast, effects = self._effects('function p(){ return 1; } p();')
        self.assertTrue(effects.is_side_effect_free(self._only_call(ast)))

    def test_is_side_effect_free_refuses_non_hoisted_callee_call(self):
        ast, effects = self._effects('const p = () => 1; p();')
        self.assertFalse(effects.is_side_effect_free(self._only_call(ast)))

    def test_static_callee_none_for_callee_reassigned_through_with(self):
        ast, effects = self._effects('function g(){ return 1; } with (o) { g = h; } g();')
        self.assertIsNone(effects.static_callee(self._only_call(ast)))

    def test_static_callee_resolves_function_not_named_by_with(self):
        ast, effects = self._effects('function g(){ return 1; } with (o) { z = 1; } g();')
        self.assertIs(effects.static_callee(self._only_call(ast)), self._func(ast, 'g'))

    def test_clean_program_is_pristine(self):
        _, effects = self._effects('function f(n){ return String.fromCharCode(n); }')
        self.assertTrue(effects.intrinsics_pristine)

    def test_reassigned_intrinsic_method_voids_pristine(self):
        source = 'Math.floor = function(){ return 0; }; function f(){ return Math.floor(1.5); }'
        ast, effects = self._effects(source)
        self.assertFalse(effects.intrinsics_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_reflection_surface_voids_pristine(self):
        source = "function f(){ return String.fromCharCode(65); } eval('1');"
        ast, effects = self._effects(source)
        self.assertFalse(effects.intrinsics_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_indirect_eval_voids_pristine(self):
        source = "function f(){ return String.fromCharCode(65); } (0, eval)('1');"
        ast, effects = self._effects(source)
        self.assertFalse(effects.intrinsics_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_locally_shadowed_intrinsic_is_not_trusted(self):
        source = 'function f(){ var Math = { floor: 0 }; return Math.floor; }'
        self.assertFalse(self._summary(source, 'f').is_pure)

    def test_global_intrinsic_read_is_pure(self):
        self.assertTrue(self._summary('function f(){ return globalThis.Uint8Array; }', 'f').is_pure)

    def test_global_intrinsic_read_through_window_alias_is_pure(self):
        self.assertTrue(self._summary('function f(){ return window.String; }', 'f').is_pure)

    def test_host_global_intrinsic_read_is_pure(self):
        self.assertTrue(self._summary('function f(){ return globalThis.TextDecoder; }', 'f').is_pure)

    def test_non_intrinsic_global_read_stays_impure(self):
        summary = self._summary('function f(){ return globalThis.location; }', 'f')
        self.assertTrue(summary.calls_unknown)
        self.assertFalse(summary.is_pure)

    def test_computed_global_intrinsic_read_stays_impure(self):
        summary = self._summary("function f(){ return globalThis['String']; }", 'f')
        self.assertTrue(summary.calls_unknown)
        self.assertFalse(summary.is_pure)

    def test_global_read_voided_by_accessor_install(self):
        source = (
            "Object.defineProperty(globalThis, 'String', { get: function(){ return 0; } });"
            ' function f(){ return globalThis.Uint8Array; }'
        )
        ast, effects = self._effects(source)
        self.assertFalse(effects.global_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_global_read_voided_by_computed_accessor_install(self):
        """
        `Object['defineProperty']` installs the accessor just as the dotted form does, so a global read is
        no longer getter-free. Reading only dotted property names answered `True` here, and a later fold of
        the key would then withdraw the trust after a consumer had relied on it.
        """
        source = (
            "Object['defineProperty'](globalThis, 'String', { get: function(){ return 0; } });"
            ' function f(){ return globalThis.Uint8Array; }'
        )
        ast, effects = self._effects(source)
        self.assertFalse(effects.global_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_global_read_voided_by_concatenated_accessor_install(self):
        source = (
            "Object['define' + 'Property'](globalThis, 'String', { get: function(){ return 0; } });"
            ' function f(){ return globalThis.Uint8Array; }'
        )
        _, effects = self._effects(source)
        self.assertFalse(effects.global_pristine)

    def test_global_read_survives_a_dynamic_key_call(self):
        """
        The precision control: a key whose value is unknown is not an install. Treating it as one would
        make almost every obfuscated program lose this trust, and it guards nothing — such a key is only
        resolved in a later pass, which rebuilds this model.
        """
        source = (
            "var o = { f: function(){} }; var k = 'f'; o[k]();"
            ' function f(){ return globalThis.Uint8Array; }'
        )
        _, effects = self._effects(source)
        self.assertTrue(effects.global_pristine)

    def test_global_read_voided_by_reflection_surface(self):
        source = "function f(){ return globalThis.Uint8Array; } eval('1');"
        ast, effects = self._effects(source)
        self.assertFalse(effects.global_pristine)
        self.assertFalse(effects.summary_of(self._func(ast, 'f')).is_pure)

    def test_shadowed_global_alias_read_is_not_trusted(self):
        source = 'function f(){ var globalThis = { String: 0 }; return globalThis.String; }'
        self.assertFalse(self._summary(source, 'f').is_pure)

    def test_clean_program_is_global_pristine(self):
        _, effects = self._effects('function f(){ return globalThis.Uint8Array; }')
        self.assertTrue(effects.global_pristine)

    def _intrinsic_of(self, expr: str, prefix: str = ''):
        ast, effects = self._effects(F'{prefix}var _t = {expr};')
        decl = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsVariableDeclarator) and isinstance(n.id, JsIdentifier) and n.id.name == '_t'
        )
        return effects.intrinsic_of(decl.init)

    def test_intrinsic_of_canonical_global_object(self):
        self.assertIs(self._intrinsic_of('globalThis'), GLOBAL_OBJECT)

    def test_intrinsic_of_global_object_existence_guard(self):
        self.assertIs(self._intrinsic_of('globalThis || {}'), GLOBAL_OBJECT)

    def test_intrinsic_of_bare_pristine_root(self):
        self.assertEqual(self._intrinsic_of('Array'), 'Array')

    def test_intrinsic_of_existence_guard_of_roots(self):
        self.assertEqual(self._intrinsic_of('String || String'), 'String')

    def test_intrinsic_of_falsy_guard_is_not_an_intrinsic(self):
        self.assertIsNone(self._intrinsic_of('NaN || 5'))

    def test_intrinsic_of_host_alias_is_none(self):
        self.assertIsNone(self._intrinsic_of('window'))

    def test_intrinsic_of_shadowed_root_is_none(self):
        self.assertIsNone(self._intrinsic_of('Array', prefix='var Array = 0; '))

    def test_intrinsic_of_reflective_program_is_none(self):
        self.assertIsNone(self._intrinsic_of('Array', prefix="eval('1'); "))

    def test_intrinsic_of_does_not_follow_local_alias(self):
        self.assertIsNone(self._intrinsic_of('a', prefix='var a = Array; '))

    def test_intrinsic_poison_pill_read_is_impure(self):
        self.assertFalse(self._summary('function f(){ return String.caller; }', 'f').is_pure)

    def test_intrinsic_static_read_stays_pure(self):
        self.assertTrue(self._summary('function f(){ return String.fromCodePoint; }', 'f').is_pure)

    def test_new_array_literal_length_is_pure(self):
        self.assertTrue(self._summary('function f(){ return new Array(128); }', 'f').is_pure)

    def test_new_array_no_args_is_pure(self):
        self.assertTrue(self._summary('function f(){ return new Array(); }', 'f').is_pure)

    def test_new_array_multiple_args_is_pure(self):
        self.assertTrue(self._summary('function f(){ return new Array(1, 2, 3); }', 'f').is_pure)

    def test_new_array_non_number_literal_is_pure(self):
        self.assertTrue(self._summary("function f(){ return new Array('x'); }", 'f').is_pure)

    def test_new_array_negative_length_is_impure(self):
        self.assertFalse(self._summary('function f(){ return new Array(-1); }', 'f').is_pure)

    def test_new_array_fractional_length_is_impure(self):
        self.assertFalse(self._summary('function f(){ return new Array(+3.5); }', 'f').is_pure)

    def test_new_array_overflow_length_is_impure(self):
        self.assertFalse(self._summary('function f(){ return new Array(4294967296); }', 'f').is_pure)

    def test_new_array_spread_arg_is_impure(self):
        self.assertFalse(self._summary('function f(){ return new Array(...xs); }', 'f').is_pure)

    def test_new_array_dynamic_length_is_impure(self):
        self.assertFalse(self._summary('function f(){ return new Array(n); }', 'f').is_pure)

    def test_new_array_getter_arg_is_impure(self):
        self.assertFalse(self._summary('function f(){ return new Array(obj.x); }', 'f').is_pure)

    def test_new_array_shadowed_is_impure(self):
        self.assertFalse(self._summary('function f(){ var Array = 0; return new Array(1); }', 'f').is_pure)

    def test_new_object_is_not_a_pure_construct(self):
        self.assertFalse(self._summary('function f(){ return new Object(); }', 'f').is_pure)

    def _member(self, source: str) -> JsMemberExpression:
        ast, effects = self._effects(source)
        member = next(n for n in ast.walk_in_order() if isinstance(n, JsMemberExpression))
        self._member_effects = effects
        return member

    def test_side_effect_free_clears_intrinsic_static_read(self):
        member = self._member('String.fromCodePoint;')
        self.assertTrue(self._member_effects.is_side_effect_free(member))

    def test_side_effect_free_rejects_intrinsic_poison_pill_read(self):
        member = self._member('String.caller;')
        self.assertFalse(self._member_effects.is_side_effect_free(member))

    def test_side_effect_free_rejects_shadowed_intrinsic_read(self):
        member = self._member('var String = {}; String.fromCodePoint;')
        self.assertFalse(self._member_effects.is_side_effect_free(member))

    def test_side_effect_free_rejects_intrinsic_read_under_reflection(self):
        member = self._member("String.fromCodePoint; eval('1');")
        self.assertFalse(self._member_effects.is_side_effect_free(member))

    def test_call_to_parameter_is_not_pure(self):
        summary = self._summary('function f(g){ return g(); }', 'f')
        self.assertTrue(summary.calls_unknown)
        self.assertFalse(summary.is_pure)

    def test_side_effect_free_clears_pure_intrinsic_call(self):
        ast, effects = self._effects('String.fromCharCode(65);')
        self.assertTrue(effects.is_side_effect_free(self._only_call(ast)))

    def test_side_effect_free_rejects_unknown_call(self):
        ast, effects = self._effects('ext();')
        self.assertFalse(effects.is_side_effect_free(self._only_call(ast)))

    def test_side_effect_free_composes_pure_call_inside_expression(self):
        ast, effects = self._effects('1 + String.fromCharCode(65);')
        expr = next(n for n in ast.walk_in_order() if isinstance(n, JsBinaryExpression))
        self.assertTrue(effects.is_side_effect_free(expr))

    def test_side_effect_free_rejects_array_holding_parameter_call(self):
        ast, effects = self._effects('function f(g){ return [g()]; }')
        array = next(n for n in ast.walk_in_order() if isinstance(n, JsArrayExpression))
        self.assertFalse(effects.is_side_effect_free(array))

    def test_side_effect_free_rejects_with_scoped_read_backed_by_binding(self):
        ast, effects = self._effects('var x = 1; with (o) { x; }')
        x_use = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsIdentifier) and n.name == 'x' and effects.model.binding_of(n) is None
        )
        self.assertFalse(effects.is_side_effect_free(x_use))

    def test_side_effect_free_clears_function_value_reading_through_with(self):
        ast, effects = self._effects('(function () { with (o) { x; } });')
        fn = next(n for n in ast.walk_in_order() if isinstance(n, JsFunctionExpression))
        self.assertTrue(effects.is_side_effect_free(fn))

    def test_side_effect_free_sees_through_parentheses_to_pure_inner(self):
        ast, effects = self._effects('(function () {});')
        paren = next(n for n in ast.walk_in_order() if isinstance(n, JsParenthesizedExpression))
        self.assertTrue(effects.is_side_effect_free(paren))

    def test_side_effect_free_sees_through_parentheses_to_effectful_inner(self):
        ast, effects = self._effects('(ext());')
        paren = next(n for n in ast.walk_in_order() if isinstance(n, JsParenthesizedExpression))
        self.assertFalse(effects.is_side_effect_free(paren))

    def test_side_effect_free_rejects_effectful_inline_iife(self):
        ast, effects = self._effects('var _ = function () { ext(); }();')
        iife = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsCallExpression) and isinstance(n.callee, JsFunctionExpression)
        )
        self.assertFalse(effects.is_side_effect_free(iife))

    def test_side_effect_free_clears_pure_inline_iife(self):
        ast, effects = self._effects('var _ = function () { return 1; }();')
        iife = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsCallExpression) and isinstance(n.callee, JsFunctionExpression)
        )
        self.assertTrue(effects.is_side_effect_free(iife))

    @staticmethod
    def _container(source: str, name: str = 'a', *, member_calls_mutate: bool = True) -> bool:
        ast = JsParser(F'function W(){{ {source} }}').parse()
        model = build_semantic_model(ast)
        effects = build_effects(model)
        binding = None
        for node in ast.walk_in_order():
            if isinstance(node, JsIdentifier) and node.name == name:
                binding = model.resolve(node) or model.binding_of(node)
                if binding is not None:
                    break
        assert binding is not None
        return effects.binding_is_immutable_container(binding, member_calls_mutate=member_calls_mutate)

    def test_read_only_array_is_immutable(self):
        self.assertTrue(self._container('var a = [1, 2, 3]; SINK(a[0]);'))

    def test_read_only_object_is_immutable(self):
        self.assertTrue(self._container('var o = {p: 1}; SINK(o.p);', 'o'))

    def test_element_write_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; a[0] = 9;'))

    def test_delete_element_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; delete a[0];'))

    def test_element_update_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; a[0]++;'))

    def test_object_property_write_is_mutable(self):
        self.assertFalse(self._container('var o = {p: 1}; SINK(o.p); o.p = 2;', 'o'))

    def test_escape_via_call_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_escape_via_return_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; return a;'))

    def test_escape_into_non_mutating_callee_is_immutable(self):
        self.assertTrue(self._container(
            'function read(x){ return x[0]; } var a = [1, 2]; read(a); SINK(a[0]);'))

    def test_escape_into_mutating_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function mut(x){ x[0] = 9; } var a = [1, 2]; mut(a); SINK(a[0]);'))

    def test_escape_into_returning_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function ret(x){ return x; } var a = [1, 2]; ret(a); SINK(a[0]);'))

    def test_escape_into_transitive_mutator_is_mutable(self):
        self.assertFalse(self._container(
            'function mut(y){ y[0] = 9; } function pass(x){ mut(x); }'
            ' var a = [1, 2]; pass(a); SINK(a[0]);'))

    def test_escape_into_transitive_reader_is_immutable(self):
        self.assertTrue(self._container(
            'function rd(y){ return y[0]; } function pass(x){ return rd(x); }'
            ' var a = [1, 2]; pass(a); SINK(a[0]);'))

    def test_argument_beyond_declared_parameters_is_immutable(self):
        self.assertTrue(self._container(
            'function nop(){} var a = [1, 2]; nop(a); SINK(a[0]);'))

    def test_escape_into_rest_parameter_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function r(...xs){} var a = [1, 2]; r(a); SINK(a[0]);'))

    def test_escape_into_method_callee_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; obj.m(a); SINK(a[0]);'))

    def test_escape_into_reassigned_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function f(x){ return x[0]; } f = g; var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_escape_into_reassigned_to_literal_mutating_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function keep(x){ x[0] = 9; } var a = [1, 2]; keep(a);'
            ' keep = function(x){ return x[0]; }; SINK(a[0]);'))

    def test_escape_into_reassigned_to_literal_mutating_object_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function keep(x){ x.v = 9; } var o = {v: 1}; keep(o);'
            ' keep = function(x){ return x.v; }; SINK(o.v);', 'o'))

    def test_escape_into_callee_reaching_arg_via_arguments_is_mutable(self):
        self.assertFalse(self._container(
            'function f(x){ arguments[0][0] = 9; } var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_escape_as_extra_argument_into_arguments_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function f(p){ arguments[1][0] = 9; } var a = [1, 2]; f(0, a); SINK(a[0]);'))

    def test_over_passed_argument_into_callee_with_eval_is_mutable(self):
        self.assertFalse(self._container(
            'function f(){ eval("arguments[0][0]=9"); } var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_over_passed_argument_reached_via_nested_arrow_eval_is_mutable(self):
        self.assertFalse(self._container(
            'function f(){ const g = () => { eval("arguments[0][0]=9"); }; g(); }'
            ' var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_argument_into_arrow_callee_naming_it_via_direct_eval_is_mutable(self):
        self.assertFalse(self._container(
            'var f = () => { eval("a[0]=9"); }; var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_escape_into_callee_invoking_nested_method_is_mutable_with_trusted_methods(self):
        self.assertFalse(self._container(
            'function f(x){ x.a.unshift(9); } var o = { a: [1, 2] }; f(o); SINK(o.a[0]);',
            'o', member_calls_mutate=False))

    def test_escape_as_argument_after_spread_is_mutable(self):
        self.assertFalse(self._container(
            'function keep(p, q){ p[0] = 9; } var pre = [1]; var a = [1, 2]; keep(...pre, a); SINK(a[0]);'))

    def test_escape_into_eval_containing_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function f(x){ eval("x[0]=9"); } var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_escape_into_with_containing_callee_is_mutable(self):
        self.assertFalse(self._container(
            'function f(x){ with (o) { x[0] = 9; } } var a = [1, 2]; f(a); SINK(a[0]);'))

    def test_container_member_mutated_through_with_is_mutable(self):
        self.assertFalse(self._container('var a = [1]; with (q) { a.push(2); } SINK(a[0]);'))

    def test_container_indexed_write_through_with_is_mutable(self):
        self.assertFalse(self._container('var a = [1]; with (q) { a[0] = 9; } SINK(a[0]);'))

    def test_container_reassigned_through_with_is_mutable(self):
        self.assertFalse(self._container('var a = [1]; with (q) { a = [9]; } SINK(a[0]);'))

    def test_container_only_read_through_with_is_immutable(self):
        self.assertTrue(self._container('var a = [1]; with (q) { y = a[0]; } SINK(a[0]);'))

    def test_container_not_named_by_with_is_immutable(self):
        self.assertTrue(self._container('var a = [1]; var b = [2]; with (q) { b.push(3); } SINK(a[0]);'))

    def test_local_container_in_function_with_direct_eval_is_mutable(self):
        self.assertFalse(self._container('var a = [1]; eval("x"); SINK(a[0]);'))

    def test_local_container_with_parenthesized_direct_eval_is_mutable(self):
        self.assertFalse(self._container('var a = [1]; (eval)("a[0]=9"); SINK(a[0]);'))

    def test_local_container_with_indirect_comma_eval_is_immutable(self):
        self.assertTrue(self._container('var a = [1]; (0, eval)("a[0]=9"); SINK(a[0]);'))

    def test_local_container_with_only_with_not_naming_it_is_immutable(self):
        self.assertTrue(self._container('var a = [1]; with (q) { z = 1; } SINK(a[0]);'))

    def test_benign_alias_is_immutable(self):
        self.assertTrue(self._container('var a = [1, 2]; var b = a; SINK(b[0]);'))

    def test_alias_then_mutated_alias_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; var b = a; b[0] = 9;'))

    def test_transitive_alias_mutation_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; var b = a; var c = b; c[0] = 9;'))

    def test_reassigned_then_read_is_immutable(self):
        self.assertTrue(self._container('var a; a = [1, 2]; SINK(a[0]);'))

    def test_reassigned_and_benignly_aliased_is_immutable(self):
        self.assertTrue(self._container('var a; a = [1, 2]; var b = a; SINK(a[0]); SINK(b[1]);'))

    def test_mutating_method_call_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; a.push(3); SINK(a[0]);'))

    def test_sort_method_call_is_mutable(self):
        self.assertFalse(self._container('var a = [3, 1, 2]; a.sort(); SINK(a[0]);'))

    def test_captured_method_call_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; function g(){ a.push(3); } g(); SINK(a[0]);'))

    def test_aliased_method_call_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; var b = a; b.push(3); SINK(a[0]);'))

    def test_method_call_permitted_when_calls_do_not_mutate(self):
        self.assertTrue(self._container(
            'var o = {f: 1}; o.toString(); SINK(o.f);', 'o', member_calls_mutate=False))

    def test_for_of_member_target_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; for (a[0] of xs) {} SINK(a[1]);'))

    def test_destructuring_member_target_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; [a[0]] = ys; SINK(a[1]);'))

    def test_destructuring_default_member_target_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; [a[0] = 9] = ys; SINK(a[1]);'))

    def test_parenthesized_element_write_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; (a[0]) = 9; SINK(a[1]);'))

    def test_parenthesized_method_call_is_mutable(self):
        self.assertFalse(self._container('var a = [1, 2]; (a.sort)(); SINK(a[0]);'))


class TestTrustedIntrinsic(TestBase):
    """
    `trusted_intrinsic` asks whether one named global is still the built-in at a use site. It answers per
    name rather than program-wide, which is what lets a program that patches `Object.prototype` keep
    folding `Math.floor`: `intrinsics_pristine` collapses every root into a single flag, so one disturbed
    name withdraws trust from all of them, including names the disturbance cannot reach.

    A refusal must cover every way a name can stop being the built-in — all six declaration forms, a write
    anywhere along a member chain rooted at it, a `delete`, and a descriptor install that never writes the
    name syntactically. The paired trust cases are equally load-bearing: over-refusal silently disables
    correct folds, so each refusal has a control that must still be trusted.
    """

    @staticmethod
    def _trust(source: str, name: str):
        """
        `trusted_intrinsic` for the callee root named *name* in the single call it appears in.
        """
        ast = JsParser(source).parse()
        effects = build_effects(build_semantic_model(ast))
        target = None
        for node in ast.walk():
            if not isinstance(node, JsCallExpression):
                continue
            callee = node.callee
            if isinstance(callee, JsMemberExpression) and isinstance(callee.object, JsIdentifier):
                if callee.object.name == name:
                    target = callee.object
            elif isinstance(callee, JsIdentifier) and callee.name == name:
                target = callee
        if target is None:
            raise AssertionError(F'no call with a callee rooted at {name}')
        return effects.trusted_intrinsic(target)

    def _refuses(self, source: str, name: str = 'Math'):
        self.assertIsNone(self._trust(source, name))

    def _trusts(self, source: str, name: str = 'Math'):
        self.assertEqual(name, self._trust(source, name))

    def test_unshadowed_name_is_trusted(self):
        self._trusts('console.log(Math.floor(1.7));')

    def test_unshadowed_free_function_is_trusted(self):
        self._trusts("console.log(parseInt('10'));", 'parseInt')

    def test_name_absent_from_any_blessed_list_is_trusted(self):
        """
        Trust is not restricted to a list of known intrinsics: whether a fold knows how to evaluate the
        call is the caller's question. `atob` is absent from the effect model's pure-intrinsic vocabulary,
        yet an unshadowed `atob` is still the built-in.
        """
        self._trusts("console.log(atob('QUJD'));", 'atob')

    def test_var_shadow_is_refused(self):
        self._refuses('var Math = { floor: function(){ return 1; } }; console.log(Math.floor(1.7));')

    def test_let_shadow_is_refused(self):
        self._refuses('let Math = { floor: function(){ return 1; } }; console.log(Math.floor(1.7));')

    def test_const_shadow_is_refused(self):
        self._refuses('const Math = { floor: function(){ return 1; } }; console.log(Math.floor(1.7));')

    def test_function_declaration_shadow_is_refused(self):
        self._refuses("function parseInt(){ return 1; } console.log(parseInt('10'));", 'parseInt')

    def test_parameter_shadow_is_refused(self):
        self._refuses('(function (Math) { console.log(Math.floor(1.7)); })({ floor: null });')

    def test_assignment_shadow_is_refused(self):
        """
        A bare assignment introduces an implicit-global binding for the name, which is why no separate scan
        of write-role identifiers is needed to catch it.
        """
        self._refuses('Math = { floor: function(){ return 1; } }; console.log(Math.floor(1.7));')

    def test_assignment_inside_a_function_is_refused(self):
        self._refuses('(function(){ Math = 1; })(); console.log(Math.floor(1.7));')

    def test_for_of_target_assignment_is_refused(self):
        self._refuses('for (Math of xs) {} console.log(Math.floor(1.7));')

    def test_destructuring_assignment_target_is_refused(self):
        self._refuses('[Math] = xs; console.log(Math.floor(1.7));')

    def test_destructuring_shadow_is_refused(self):
        self._refuses('var { Math } = {}; console.log(Math.floor(1.7));')

    def test_catch_parameter_shadow_is_refused(self):
        self._refuses('try {} catch (Math) {} console.log(Math.floor(1.7));')

    def test_shadow_in_an_unrelated_scope_is_refused(self):
        """
        The shadow is in a sibling function the use site never enters, so JavaScript resolves the use site
        to the global and a per-site scope lookup would permit the fold. Refusing is deliberate and is why
        no such lookup is performed: a name the program binds anywhere is one an obfuscator may be routing
        values through, and the price of refusing is an unfolded call rather than a wrong value.
        """
        self._refuses('(function(){ var Math = 1; })(); console.log(Math.floor(1.7));')

    def test_property_write_on_the_name_is_refused(self):
        self._refuses('Math.floor = function(){ return 1; }; console.log(Math.floor(1.7));')

    def test_nested_property_write_is_refused(self):
        """
        The write is two levels deep, so the assignment target's own `.object` is another member
        expression rather than the name. Attribution has to follow the chain to its root.
        """
        self._refuses('Math.prototype.zz = 1; console.log(Math.floor(1.7));')

    def test_computed_property_write_is_refused(self):
        self._refuses("Math['floor'] = function(){ return 1; }; console.log(Math.floor(1.7));")

    def test_property_update_is_refused(self):
        self._refuses('Math.PI++; console.log(Math.floor(1.7));')

    def test_property_delete_is_refused(self):
        self._refuses('delete Math.floor; console.log(Math.floor(1.7));')

    def test_define_property_on_the_name_is_refused(self):
        """
        `Object.defineProperty` replaces a method without writing the name syntactically, so a scan for
        assignments alone would leave it looking untouched.
        """
        self._refuses("Object.defineProperty(Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_define_getter_on_the_name_is_refused(self):
        self._refuses("Math.__defineGetter__('floor', function(){}); console.log(Math.floor(1.7));")

    def test_define_property_through_a_computed_key_is_refused(self):
        """
        `Object['defineProperty']` reaches the same method as the dotted form. Matching only a dotted
        property name left the install invisible, so the patched name stayed foldable.
        """
        self._refuses(
            "Object['defineProperty'](Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_define_property_through_a_concatenated_key_is_refused(self):
        self._refuses(
            "Object['define' + 'Property'](Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_define_property_through_a_template_key_is_refused(self):
        self._refuses(
            'Object[`defineProperty`](Math, \'floor\', { value: 1 }); console.log(Math.floor(1.7));')

    def test_define_getter_through_a_concatenated_key_is_refused(self):
        self._refuses(
            "Math['__define' + 'Getter__']('floor', function(){}); console.log(Math.floor(1.7));")

    def test_install_on_a_guarded_target_is_refused(self):
        """
        The install target is the value the argument denotes, not its syntax: `Math || 0` evaluates to
        `Math`, so the descriptor lands on the intrinsic.
        """
        self._refuses(
            "Object.defineProperty(Math || 0, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_a_target_guarded_from_the_right_is_refused(self):
        """
        Which operand survives depends on the values, so both must be attributed. Following only the left
        of `||` — correct for `intrinsic_of`, which certifies what a node *does* denote — misses this one,
        because collecting writes needs the opposite approximation.
        """
        self._refuses(
            "Object.defineProperty(0 || Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_a_conditional_target_is_refused(self):
        self._refuses(
            "Object.defineProperty(x ? 0 : Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_a_sequenced_target_is_refused(self):
        self._refuses(
            "Object.defineProperty((0, Math), 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_an_assigned_target_is_refused(self):
        self._refuses(
            "var q; Object.defineProperty(q = Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_a_guarded_prototype_chain_is_refused(self):
        self._refuses(
            "Object.defineProperty(0 || Math.prototype, 'floor', { value: 1 });"
            ' console.log(Math.floor(1.7));')

    def test_install_on_an_unrelated_object_is_trusted(self):
        """
        The precision control for the whole install family: attributing every argument to every name would
        refuse folds the program never endangered.
        """
        self._trusts(
            "var o = {}; Object['defineProperty'](o, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_an_unrelated_guarded_object_is_trusted(self):
        self._trusts(
            'var o = {}; Object.defineProperty(0 || o, \'floor\', { value: 1 });'
            ' console.log(Math.floor(1.7));')

    def test_install_on_another_intrinsic_is_trusted(self):
        self._trusts(
            "Object['defineProperty'](String.prototype, 'zz', { value: 1 }); console.log(Math.floor(1.7));")

    def test_dynamic_key_call_on_an_unrelated_object_is_trusted(self):
        """
        A key whose value is unknown is not treated as an install. Doing so would refuse a fold for every
        dynamic call in the program, and it protects nothing: a variable key is resolved by substitution in
        a later pass, which rebuilds this model.
        """
        self._trusts(
            "var o = { f: function(){} }; var k = 'f'; o[k](); console.log(Math.floor(1.7));")

    def test_reflection_surface_refuses_every_name(self):
        """
        A direct `eval` can rebind anything at runtime, so no name is provably intact.
        """
        self._refuses("eval('Math = 1'); console.log(Math.floor(1.7));")

    def test_property_read_alone_is_trusted(self):
        self._trusts('console.log(Math.PI, Math.floor(1.7));')

    def test_passing_the_method_as_a_value_is_trusted(self):
        self._trusts('[1].map(Math.floor); console.log(Math.floor(1.7));')

    def test_aliasing_the_name_is_trusted(self):
        """
        Binding the intrinsic to a local reads it; it does not disturb it.
        """
        self._trusts('var m = Math; console.log(Math.floor(1.7));')

    def test_another_name_being_shadowed_is_trusted(self):
        self._trusts('var Object = 1; console.log(Math.floor(1.7));')

    def test_another_name_being_patched_is_trusted(self):
        """
        The precision this query exists for: patching `Object.prototype` cannot affect `Math`, so `Math`
        stays foldable. The program-wide `intrinsics_pristine` flag cannot express this.
        """
        self._trusts('Object.prototype.zz = 1; console.log(Math.floor(1.7));')

    def test_the_patched_name_itself_is_refused(self):
        self._refuses('Object.prototype.zz = 1; console.log(Object.keys({ a: 1 }));', 'Object')


class TestTrustedPrototype(TestBase):
    """
    `trusted_prototype` answers the question a literal receiver raises: `'ab'.toUpperCase()` mentions no
    identifier, so no name-based query can see that `String.prototype.toUpperCase` was replaced. It maps
    the receiver's type to the intrinsic that owns its methods and asks that name the same question.
    """

    @staticmethod
    def _trusted(source: str, value_type: type) -> bool:
        ast = JsParser(source).parse()
        effects = build_effects(build_semantic_model(ast))
        return effects.trusted_prototype(value_type)

    def test_untouched_prototypes_are_trusted(self):
        self.assertTrue(self._trusted("var r = 'ab'.toUpperCase();", str))
        self.assertTrue(self._trusted("var r = [1, 2].join('-');", list))

    def test_patched_string_prototype_is_refused(self):
        self.assertFalse(self._trusted(
            "String.prototype.toUpperCase = function () { return 'X'; };", str))

    def test_patched_array_prototype_is_refused(self):
        self.assertFalse(self._trusted(
            "Array.prototype.join = function () { return 'X'; };", list))

    def test_patch_of_one_prototype_leaves_the_other_trusted(self):
        """
        The same precision as the per-name query: patching `Array.prototype` cannot change what a string
        method means.
        """
        source = "Array.prototype.join = function () { return 'X'; };"
        self.assertFalse(self._trusted(source, list))
        self.assertTrue(self._trusted(source, str))

    def test_define_property_on_a_prototype_is_refused(self):
        self.assertFalse(self._trusted(
            "Object.defineProperty(Array.prototype, 'join', { value: 1 });", list))

    def test_shadowing_the_owner_name_is_refused(self):
        self.assertFalse(self._trusted('var String = {};', str))

    def test_reflection_surface_refuses_every_prototype(self):
        self.assertFalse(self._trusted("eval('x');", str))

    def test_type_with_no_known_owner_is_refused(self):
        self.assertFalse(self._trusted('var r = 1;', object))

    def test_number_and_boolean_owners_are_recognized(self):
        self.assertTrue(self._trusted('var r = 1;', int))
        self.assertTrue(self._trusted('var r = 1;', bool))
        self.assertFalse(self._trusted('Number.prototype.toFixed = function () {};', int))
        self.assertFalse(self._trusted('Boolean.prototype.toString = function () {};', bool))


class TestCallIsFoldable(TestBase):
    """
    `call_is_foldable` is the single gate every constant fold shares. It must admit exactly the calls whose
    value can replace them: the callee is still the built-in it is spelled as, and no argument carries an
    effect the fold would discard. The admit cases matter as much as the refusals — a gate that refuses too
    much silently disables correct folding, which is the failure mode that looks like success.
    """

    @staticmethod
    def _foldable(source: str, receiver_type: type | None = None) -> bool:
        ast = JsParser(source).parse()
        effects = build_effects(build_semantic_model(ast))
        outermost = None
        for node in ast.walk():
            if not isinstance(node, JsCallExpression):
                continue
            if outermost is None or not node.is_descendant_of(outermost):
                outermost = node
        if outermost is None:
            raise AssertionError('no call expression in source')
        return effects.call_is_foldable(outermost, receiver_type=receiver_type)

    def test_free_function_is_admitted(self):
        self.assertTrue(self._foldable("var r = parseInt('10');"))

    def test_static_method_is_admitted(self):
        self.assertTrue(self._foldable('var r = String.fromCharCode(65);'))

    def test_instance_method_is_admitted(self):
        self.assertTrue(self._foldable("var r = 'ab'.toUpperCase();", str))

    def test_pure_callback_is_admitted(self):
        self.assertTrue(self._foldable(
            'var r = [1, 2].map(function (x) { return x + 1; });', list))

    def test_shadowed_callee_is_refused(self):
        self.assertFalse(self._foldable("var parseInt = function () {}; var r = parseInt('10');"))

    def test_shadowed_static_root_is_refused(self):
        self.assertFalse(self._foldable('var String = {}; var r = String.fromCharCode(65);'))

    def test_patched_receiver_prototype_is_refused(self):
        self.assertFalse(self._foldable(
            "String.prototype.toUpperCase = function () {}; var r = 'ab'.toUpperCase();", str))

    def test_literal_receiver_needs_no_receiver_type(self):
        """
        A literal receiver's type is fixed by its own syntax, so the gate resolves the prototype question
        itself rather than requiring the caller to answer it. This is what lets a fold ask about a whole
        chain without first walking down to its innermost receiver.
        """
        self.assertTrue(self._foldable("var r = 'ab'.toUpperCase();"))
        self.assertTrue(self._foldable("var r = [1, 2].join('-');"))
        self.assertTrue(self._foldable('var r = (5).toString(2);'))

    def test_patched_prototype_refused_for_a_literal_receiver_without_a_type(self):
        self.assertFalse(self._foldable(
            "String.prototype.toUpperCase = function () {}; var r = 'ab'.toUpperCase();"))

    def test_computed_receiver_without_a_receiver_type_is_refused(self):
        """
        Where the syntax settles nothing — an identifier, a member read, a conditional, a concatenation —
        the receiver's type is genuinely unknown, and an unanswered question is not a yes. The caller must
        supply the type it knows, or be refused.
        """
        self.assertFalse(self._foldable("var s = 'ab'; var r = s.toUpperCase();"))
        self.assertFalse(self._foldable("var o = { s: 'ab' }; var r = o.s.toUpperCase();"))
        self.assertFalse(self._foldable("var r = ('a' + 'b').toUpperCase();"))
        self.assertFalse(self._foldable("var x = 1; var r = (x ? 'a' : 'b').toUpperCase();"))

    def test_chain_link_receiver_is_judged_by_the_inner_call(self):
        """
        At a link whose receiver is another call no prototype can be named, so the inner call is put through
        this same gate in full. Its arguments are judged too: an effectful argument to the inner link is as
        observable as one to the outer, and checking only the inner callee's trust would fold it away.
        """
        self.assertTrue(self._foldable(
            "var r = [1, 2].map(function (x) { return x + 1; }).join('-');"))
        self.assertFalse(self._foldable(
            'var n = 0;'
            " var r = [1, 2].map(function (x) { n += x; return x; }).join('-');"))
        self.assertFalse(self._foldable(
            'var n = 0; function h() { n += 1; return 1; }'
            " var r = [1, 2].slice(h()).join('-');"))

    def test_callback_writing_a_script_scope_var_is_refused(self):
        """
        The write reports `writes_captured=False`, because the binding is not captured from the callback's
        perspective, so purity alone admits it and the write would be lost. `written_bindings` catches it.
        """
        self.assertFalse(self._foldable(
            'var n = 0; var r = [1, 2].map(function (x) { n += x; return x; });', list))

    def test_callback_writing_a_global_is_refused(self):
        self.assertFalse(self._foldable(
            'var r = [1, 2].map(function (x) { globalThis.q = x; return x; });', list))

    def test_callback_calling_an_unknown_function_is_refused(self):
        self.assertFalse(self._foldable(
            'var r = [1, 2].map(function (x) { return WScript.f(x); });', list))

    def test_throwing_callback_is_refused(self):
        self.assertFalse(self._foldable(
            "var r = [1, 2].map(function (x) { throw 'boom'; });", list))

    def test_callback_mutating_an_outer_container_is_refused(self):
        self.assertFalse(self._foldable(
            'var s = [9]; var r = [1, 2].map(function (x) { s.push(x); return x; });', list))

    def test_trusted_call_valued_argument_is_admitted(self):
        """
        A nested call is admissible precisely because the same questions are asked of it. Refusing all
        nested calls would disable a large class of correct folds.
        """
        self.assertTrue(self._foldable('var r = Math.floor(Math.abs(-1.7));'))
        self.assertTrue(self._foldable('var r = parseInt(String.fromCharCode(65));'))

    def test_shadowed_nested_callee_is_refused(self):
        """
        The nested call is what makes this refusable: `String` is shadowed, so the inner call is not the
        built-in, and the outer fold must not proceed on a value it cannot trust.
        """
        self.assertFalse(self._foldable(
            'var String = {}; var r = parseInt(String.fromCharCode(65));'))

    def test_nested_callee_with_a_patched_prototype_is_refused(self):
        self.assertFalse(self._foldable(
            "Array.prototype.join = function () {};"
            " var r = parseInt([1, 2].join(''));", None))

    def test_reflection_surface_is_refused(self):
        self.assertFalse(self._foldable("eval('x'); var r = Math.floor(1.7);"))

    def test_unrelated_prototype_patch_still_admits(self):
        """
        The precision control: patching `Object.prototype` cannot reach `Math`, so the fold survives.
        """
        self.assertTrue(self._foldable('Object.prototype.zz = 1; var r = Math.floor(1.7);'))

    def test_callee_that_is_not_a_name_is_refused(self):
        self.assertFalse(self._foldable('var r = (function () { return 1; })();'))


class TestFoldsRevealNoTrust(TestBase):
    """
    The program-wide facts a fold gate rests on must not become *less* restrictive as folds fire. A
    simplification pass reads these facts many times, and a consumer may legitimately hold one answer for
    the length of a pass; if a rewrite could reveal an intrinsic write that the held answer predates, that
    consumer would admit a fold against an already-patched built-in.

    Each case therefore hides an install behind a form a fold collapses, and asserts the facts read the same
    before and after. The direction matters: `_globals_written` growing is the hazard, because the held set
    is the smaller earlier one, and `global_pristine` going `True` to `False` is the hazard for the same
    reason. Testing the shapes alone is not enough — an earlier version of this check diffed only the
    written-name set and reported every channel closed while `global_pristine` was still moving.
    """

    @staticmethod
    def _facts(source: str):
        ast = JsParser(source).parse()
        model = build_semantic_model(ast)
        effects = build_effects(model)
        return (
            frozenset(effects._globals_written),
            effects.intrinsics_pristine,
            effects.global_pristine,
            model.has_reflection_surface(),
        )

    def _stable(self, source: str):
        """
        Assert one simplification pass leaves every fact a fold gate consumes unchanged.
        """
        ast = JsParser(source).parse()
        JsSimplifications().visit(ast)
        self.assertEqual(self._facts(source), self._facts(JsSynthesizer().convert(ast)))

    def test_computed_install_key_reveals_nothing(self):
        self._stable(
            "Object['defineProperty'](Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_concatenated_install_key_reveals_nothing(self):
        self._stable(
            "Object['define' + 'Property'](Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_concatenated_getter_key_reveals_nothing(self):
        self._stable(
            "Math['__define' + 'Getter__']('floor', function(){}); console.log(Math.floor(1.7));")

    def test_guarded_install_target_reveals_nothing(self):
        self._stable(
            "Object.defineProperty(0 || Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_conditional_install_target_reveals_nothing(self):
        self._stable(
            "Object.defineProperty(x ? 0 : Math, 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_sequenced_install_target_reveals_nothing(self):
        self._stable(
            "Object.defineProperty((0, Math), 'floor', { value: 1 }); console.log(Math.floor(1.7));")

    def test_install_on_the_global_object_reveals_nothing(self):
        self._stable(
            "Object['define' + 'Property'](globalThis, 'zz', { get: function(){ return 7; } });"
            ' console.log(globalThis.zz);')

    def test_computed_property_write_reveals_nothing(self):
        self._stable("Math['fl' + 'oor'] = function(){}; console.log(Math.floor(1.7));")

    def test_a_program_that_only_folds_reveals_nothing(self):
        """
        The control: a pass that folds but installs nothing must also leave the facts alone, or the
        assertion above would hold for reasons unrelated to install attribution.
        """
        self._stable("console.log('a' + 'b'); console.log(Math.floor(1.7));")


