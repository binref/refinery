from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.effects import EffectSummary, build_effects, object_member_access_runs_accessor
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBinaryExpression,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsObjectExpression,
    JsParenthesizedExpression,
)
from refinery.lib.scripts.js.parser import JsParser


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

    def test_fresh_local_returned_after_write_is_a_global_write(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; return o; }', 'f')
        self.assertTrue(summary.writes_global)

    def test_fresh_local_passed_to_call_after_write_is_a_global_write(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; sink(o); return 1; }', 'f')
        self.assertTrue(summary.writes_global)

    def test_fresh_local_aliased_after_write_is_a_global_write(self):
        summary = self._summary('function f(){ var o = []; o[0] = 9; var b = o; return b[0]; }', 'f')
        self.assertTrue(summary.writes_global)

    def test_rest_param_returned_after_write_is_a_global_write(self):
        summary = self._summary('function f(...xs){ xs[0] = 9; return xs; }', 'f')
        self.assertTrue(summary.writes_global)

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
