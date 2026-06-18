from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.model import (
    BindingKind,
    ScopeKind,
    build_semantic_model,
)
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


class TestSemanticModel(TestBase):

    @staticmethod
    def _model(source: str):
        ast = JsParser(source).parse()
        return ast, build_semantic_model(ast)

    @staticmethod
    def _idents(ast, name: str) -> list[JsIdentifier]:
        seen: set[int] = set()
        out: list[JsIdentifier] = []
        for node in ast.walk_in_order():
            if isinstance(node, JsIdentifier) and node.name == name and id(node) not in seen:
                seen.add(id(node))
                out.append(node)
        return out

    def _decl(self, ast, model, name: str) -> JsIdentifier:
        return next(n for n in self._idents(ast, name) if model.binding_of(n) is not None)

    def _use(self, ast, model, name: str) -> JsIdentifier:
        return next(n for n in self._idents(ast, name) if model.binding_of(n) is None)

    def test_var_use_before_declaration_resolves_to_function_var(self):
        ast, model = self._model('function f(){ x; var x; }')
        x_use, x_decl = self._idents(ast, 'x')
        binding = model.binding_of(x_decl)
        self.assertIs(model.resolve(x_use), binding)
        self.assertEqual(binding.kind, BindingKind.VAR)
        self.assertEqual(binding.scope.kind, ScopeKind.FUNCTION)

    def test_var_in_block_is_function_scoped(self):
        ast, model = self._model('function f(c){ if (c) { var a; } return a; }')
        binding = model.binding_of(self._decl(ast, model, 'a'))
        self.assertIs(model.resolve(self._use(ast, model, 'a')), binding)
        self.assertEqual(binding.scope.kind, ScopeKind.FUNCTION)

    def test_let_is_block_scoped_and_outer_use_is_free(self):
        ast, model = self._model('{ let a; a; } a;')
        a_decl, a_inner, a_outer = self._idents(ast, 'a')
        binding = model.binding_of(a_decl)
        self.assertEqual(binding.kind, BindingKind.LET)
        self.assertEqual(binding.scope.kind, ScopeKind.BLOCK)
        self.assertIs(model.resolve(a_inner), binding)
        self.assertIsNone(model.resolve(a_outer))

    def test_param_shadows_outer_var(self):
        ast, model = self._model('var x; function f(x){ return x; }')
        x_outer_decl, x_param, x_use = self._idents(ast, 'x')
        self.assertEqual(model.binding_of(x_outer_decl).kind, BindingKind.VAR)
        param_binding = model.binding_of(x_param)
        self.assertEqual(param_binding.kind, BindingKind.PARAM)
        self.assertIs(model.resolve(x_use), param_binding)

    def test_closure_capture_resolves_to_outer_binding(self):
        ast, model = self._model('function o(){ var x; return function(){ return x; }; }')
        x_decl, x_use = self._idents(ast, 'x')
        binding = model.binding_of(x_decl)
        self.assertIs(model.resolve(x_use), binding)
        self.assertEqual(binding.scope.kind, ScopeKind.FUNCTION)
        self.assertIs(binding.scope.node, ast.body[0])

    def test_catch_param_scoped_to_catch(self):
        ast, model = self._model('try {} catch (e) { e; } e;')
        e_decl, e_inner, e_outer = self._idents(ast, 'e')
        binding = model.binding_of(e_decl)
        self.assertEqual(binding.kind, BindingKind.CATCH)
        self.assertEqual(binding.scope.kind, ScopeKind.CATCH)
        self.assertIs(model.resolve(e_inner), binding)
        self.assertIsNone(model.resolve(e_outer))

    def test_named_function_expression_name_visible_only_inside(self):
        ast, model = self._model('var f = function g(){ return g; }; g;')
        g_decl, g_inner, g_outer = self._idents(ast, 'g')
        binding = model.binding_of(g_decl)
        self.assertEqual(binding.kind, BindingKind.FUNC_NAME)
        self.assertIs(model.resolve(g_inner), binding)
        self.assertIsNone(model.resolve(g_outer))

    def test_destructuring_params_bind_all_targets(self):
        ast, model = self._model('function f({a, b: c}, [d]){ return a + c + d; }')
        for name in ('a', 'c', 'd'):
            decl = self._decl(ast, model, name)
            use = self._use(ast, model, name)
            binding = model.binding_of(decl)
            self.assertEqual(binding.kind, BindingKind.PARAM, name)
            self.assertIs(model.resolve(use), binding, name)

    def test_arguments_is_bound_in_non_arrow_function(self):
        ast, model = self._model('function f(){ return arguments; }')
        binding = model.resolve(self._idents(ast, 'arguments')[0])
        self.assertEqual(binding.kind, BindingKind.ARGUMENTS)
        self.assertEqual(binding.scope.kind, ScopeKind.FUNCTION)

    def test_arrow_inherits_enclosing_arguments(self):
        ast, model = self._model('function f(){ return () => arguments; }')
        binding = model.resolve(self._idents(ast, 'arguments')[0])
        self.assertEqual(binding.kind, BindingKind.ARGUMENTS)
        self.assertIs(binding.scope.node, ast.body[0])

    def test_top_level_arguments_is_free(self):
        ast, model = self._model('var f = () => arguments;')
        self.assertIsNone(model.resolve(self._idents(ast, 'arguments')[0]))

    def test_with_body_use_is_unresolved(self):
        ast, model = self._model('var z; with (o) { z; }')
        z_decl, z_use = self._idents(ast, 'z')
        self.assertEqual(model.binding_of(z_decl).kind, BindingKind.VAR)
        self.assertIsNone(model.resolve(z_use))

    def test_for_let_head_scopes_iteration_variable(self):
        ast, model = self._model('for (let i = 0; i < 1; i++) { i; } i;')
        i_decl = self._decl(ast, model, 'i')
        binding = model.binding_of(i_decl)
        self.assertEqual(binding.kind, BindingKind.LET)
        self.assertEqual(binding.scope.kind, ScopeKind.BLOCK)
        i_idents = self._idents(ast, 'i')
        self.assertIs(model.resolve(i_idents[-2]), binding)
        self.assertIsNone(model.resolve(i_idents[-1]))

    def test_function_declaration_hoisted_and_visible_before_definition(self):
        ast, model = self._model('f(); function f(){}')
        f_use, f_decl = self._idents(ast, 'f')
        binding = model.binding_of(f_decl)
        self.assertEqual(binding.kind, BindingKind.FUNCTION)
        self.assertEqual(binding.scope.kind, ScopeKind.SCRIPT)
        self.assertIs(model.resolve(f_use), binding)

    def test_free_identifier_resolves_to_none(self):
        ast, model = self._model('foo(bar);')
        self.assertIsNone(model.resolve(self._idents(ast, 'foo')[0]))
        self.assertIsNone(model.resolve(self._idents(ast, 'bar')[0]))

    def test_member_property_name_is_not_resolved(self):
        ast, model = self._model('var x; o.x;')
        x_decl, x_property = self._idents(ast, 'x')
        self.assertIsNotNone(model.binding_of(x_decl))
        self.assertIsNone(model.resolve(x_property))

    def test_object_literal_shorthand_value_is_a_use(self):
        ast, model = self._model('var a = 1; var o = {a};')
        a_decl, a_shorthand = self._idents(ast, 'a')
        binding = model.binding_of(a_decl)
        self.assertEqual(binding.kind, BindingKind.VAR)
        self.assertIs(model.resolve(a_shorthand), binding)
