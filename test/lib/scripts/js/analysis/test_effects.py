from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.effects import build_effects
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsCallExpression, JsFunctionDeclaration
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

    def test_write_to_never_read_global_is_unobservable(self):
        self.assertTrue(self._summary('function f(){ scratch = 1; }', 'f').is_pure)

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

    def test_global_object_property_write_is_a_global_write(self):
        summary = self._summary('function f(){ globalThis.cache = 1; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.throws)
        self.assertFalse(summary.is_pure)

    def test_delete_of_global_object_property_is_a_global_write(self):
        summary = self._summary('function f(){ delete globalThis.cache; }', 'f')
        self.assertTrue(summary.writes_global)
        self.assertFalse(summary.is_pure)

    def test_closure_mutation_is_a_captured_write(self):
        source = 'function outer(){ var c = 0; function inc(){ c += 1; } return inc; }'
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
