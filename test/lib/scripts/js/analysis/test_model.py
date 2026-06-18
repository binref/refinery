from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.model import (
    BindingKind,
    ScopeKind,
    build_semantic_model,
)
from refinery.lib.scripts.js.model import JsIdentifier, JsReturnStatement
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

    def test_const_at_script_scope_is_bound(self):
        ast, model = self._model('const c = 1; c;')
        c_decl, c_use = self._idents(ast, 'c')
        binding = model.binding_of(c_decl)
        self.assertEqual(binding.kind, BindingKind.CONST)
        self.assertEqual(binding.scope.kind, ScopeKind.SCRIPT)
        self.assertIs(model.resolve(c_use), binding)

    def test_lexical_declaration_in_function_body_is_bound(self):
        ast, model = self._model('function f(){ const c = 1; let d = 2; return c + d; }')
        for name, kind in (('c', BindingKind.CONST), ('d', BindingKind.LET)):
            binding = model.binding_of(self._decl(ast, model, name))
            self.assertEqual(binding.kind, kind, name)
            self.assertEqual(binding.scope.kind, ScopeKind.FUNCTION, name)
            self.assertIs(model.resolve(self._use(ast, model, name)), binding, name)

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

    def _binding(self, ast, model, name: str):
        return model.binding_of(self._decl(ast, model, name))

    def test_reads_and_writes_are_counted(self):
        ast, model = self._model('function f(){ var x = 1; x; x = 2; x += 1; }')
        binding = self._binding(ast, model, 'x')
        self.assertEqual(len(binding.reads), 2)
        self.assertEqual(len(binding.writes), 2)

    def test_dead_local_has_no_reads(self):
        ast, model = self._model('function f(){ var x = 1; return 2; }')
        self.assertTrue(self._binding(ast, model, 'x').is_dead)

    def test_read_local_is_live(self):
        ast, model = self._model('function f(){ var x = 1; return x; }')
        self.assertFalse(self._binding(ast, model, 'x').is_dead)

    def test_simple_assignment_is_write_only(self):
        ast, model = self._model('function f(){ var x; x = 1; }')
        binding = self._binding(ast, model, 'x')
        self.assertEqual(len(binding.writes), 1)
        self.assertTrue(binding.is_dead)

    def test_compound_assignment_reads_and_writes(self):
        ast, model = self._model('function f(){ var x = 0; x += 1; }')
        binding = self._binding(ast, model, 'x')
        self.assertEqual(len(binding.reads), 1)
        self.assertEqual(len(binding.writes), 1)

    def test_update_expression_reads_and_writes(self):
        ast, model = self._model('function f(){ var x = 0; x++; }')
        binding = self._binding(ast, model, 'x')
        self.assertEqual(len(binding.reads), 1)
        self.assertEqual(len(binding.writes), 1)

    def test_destructuring_assignment_target_is_write_only(self):
        ast, model = self._model('function f(){ var a; [a] = arr; }')
        binding = self._binding(ast, model, 'a')
        self.assertEqual(len(binding.writes), 1)
        self.assertTrue(binding.is_dead)

    def test_closure_read_marks_captured_and_keeps_binding_live(self):
        ast, model = self._model('function o(){ var x; x = 7; return function(){ return x; }; }')
        binding = self._binding(ast, model, 'x')
        self.assertTrue(binding.captured)
        self.assertFalse(binding.is_dead)
        self.assertEqual(len(binding.writes), 1)

    def test_local_use_is_not_captured(self):
        ast, model = self._model('function o(){ var x = 1; return x; }')
        self.assertFalse(self._binding(ast, model, 'x').captured)

    def test_references_can_exclude_a_subtree(self):
        ast, model = self._model('function f(){ var x = 1; x; return x; }')
        binding = self._binding(ast, model, 'x')
        self.assertEqual(len(model.references(binding)), 2)
        ret = next(n for n in ast.walk_in_order() if isinstance(n, JsReturnStatement))
        self.assertEqual(len(model.references(binding, exclude=ret)), 1)

    def test_is_shadowed_by_inner_binding(self):
        ast, model = self._model(
            'function outer(){ var x; function inner(){ var x; return x; } return x; }')
        outer_scope = model.root_scope.children[0]
        _, _, inner_use, outer_use = self._idents(ast, 'x')
        self.assertTrue(model.is_shadowed('x', inner_use, outer_scope))
        self.assertFalse(model.is_shadowed('x', outer_use, outer_scope))

    def test_implicit_global_assignment_creates_script_binding(self):
        ast, model = self._model('g = 1; g;')
        g_write, g_read = self._idents(ast, 'g')
        binding = model.resolve(g_write)
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertEqual(binding.scope.kind, ScopeKind.SCRIPT)
        self.assertIs(model.resolve(g_read), binding)

    def test_implicit_global_links_write_and_read_across_functions(self):
        ast, model = self._model('function f(){ s = 4; } function h(){ return s; }')
        s_write, s_read = self._idents(ast, 's')
        binding = model.resolve(s_write)
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertIs(model.resolve(s_read), binding)
        self.assertFalse(binding.is_dead)
        self.assertEqual(len(binding.writes), 1)
        self.assertEqual(len(binding.reads), 1)

    def test_read_only_free_name_stays_unresolved(self):
        ast, model = self._model('console.log(foo);')
        self.assertIsNone(model.resolve(self._idents(ast, 'foo')[0]))
        self.assertNotIn('foo', model.root_scope.bindings)

    def test_write_only_implicit_global_is_dead(self):
        ast, model = self._model('leak = 5;')
        binding = model.resolve(self._idents(ast, 'leak')[0])
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertTrue(binding.is_dead)

    def test_local_var_is_distinct_from_script_implicit_global(self):
        ast, model = self._model('function f(){ var x; x = 2; } x = 9; x;')
        x_decl, x_local_write, x_global_write, x_global_read = self._idents(ast, 'x')
        local = model.binding_of(x_decl)
        self.assertEqual(local.kind, BindingKind.VAR)
        self.assertIs(model.resolve(x_local_write), local)
        glob = model.resolve(x_global_write)
        self.assertEqual(glob.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertIsNot(glob, local)
        self.assertIs(model.resolve(x_global_read), glob)

    def test_write_inside_with_does_not_create_implicit_global(self):
        ast, model = self._model('with (o) { g = 1; }')
        self.assertNotIn('g', model.root_scope.bindings)
        self.assertIsNone(model.resolve(self._idents(ast, 'g')[0]))

    def test_for_in_undeclared_target_is_a_live_implicit_global(self):
        ast, model = self._model('for (k in o) { k; }')
        k_target, k_read = self._idents(ast, 'k')
        binding = model.resolve(k_target)
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertFalse(binding.is_dead)
        self.assertIs(model.resolve(k_read), binding)

    def test_compound_assignment_to_undeclared_name_is_implicit_global(self):
        ast, model = self._model('g += 1;')
        binding = model.resolve(self._idents(ast, 'g')[0])
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertEqual(len(binding.reads), 1)
        self.assertEqual(len(binding.writes), 1)

    def test_eval_is_a_reflection_surface(self):
        _, model = self._model('eval(payload);')
        self.assertTrue(model.has_reflection_surface())

    def test_function_constructor_is_a_reflection_surface(self):
        _, model = self._model("var f = Function('return 1'); new Function('a');")
        self.assertTrue(model.has_reflection_surface())

    def test_string_timer_is_a_reflection_surface(self):
        _, model = self._model("setTimeout('x()', 10);")
        self.assertTrue(model.has_reflection_surface())

    def test_function_timer_is_not_a_reflection_surface(self):
        _, model = self._model('setTimeout(function(){ x(); }, 10);')
        self.assertFalse(model.has_reflection_surface())

    def test_dynamic_global_access_is_a_reflection_surface(self):
        _, model = self._model('window[key]();')
        self.assertTrue(model.has_reflection_surface())

    def test_static_global_access_is_not_a_reflection_surface(self):
        _, model = self._model("window['x']; self.y;")
        self.assertFalse(model.has_reflection_surface())

    def test_with_is_a_reflection_surface(self):
        _, model = self._model('with (o) { z; }')
        self.assertTrue(model.has_reflection_surface())

    def test_plain_program_has_no_reflection_surface(self):
        _, model = self._model('var a = 1; console.log(a);')
        self.assertFalse(model.has_reflection_surface())
