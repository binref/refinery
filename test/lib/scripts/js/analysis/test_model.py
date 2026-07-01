from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    ContainerRole,
    Role,
    ScopeKind,
    build_semantic_model,
    container_reference_role,
    is_simple_assignment_target,
    reference_role,
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

    def _binding(self, ast, model, name: str) -> Binding:
        binding = model.binding_of(self._decl(ast, model, name))
        assert binding is not None
        return binding

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

    def test_destructuring_default_target_is_write_only(self):
        ast, model = self._model('function f(){ var a; [a = 9] = arr; }')
        binding = self._binding(ast, model, 'a')
        self.assertEqual(len(binding.writes), 1)
        self.assertEqual(len(binding.reads), 0)
        self.assertTrue(binding.is_dead)

    def test_for_of_rest_target_is_write_only(self):
        ast, model = self._model('function f(){ var a; for ([...a] of xs) {} }')
        binding = self._binding(ast, model, 'a')
        self.assertEqual(len(binding.writes), 1)
        self.assertEqual(len(binding.reads), 0)
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

    def test_would_capture_is_false_when_all_occurrences_are_shadowed(self):
        _, model = self._model(
            'function outer(){ function inner(){ var x; return x; } }')
        outer_scope = model.root_scope.children[0]
        self.assertFalse(model.would_capture({'x'}, outer_scope))

    def test_would_capture_is_true_for_a_free_reference(self):
        _, model = self._model('function outer(){ return x; }')
        outer_scope = model.root_scope.children[0]
        self.assertTrue(model.would_capture({'x'}, outer_scope))

    def test_would_capture_is_true_for_a_reference_bound_in_the_scope(self):
        _, model = self._model('function outer(){ var x; return x; }')
        outer_scope = model.root_scope.children[0]
        self.assertTrue(model.would_capture({'x'}, outer_scope))

    def test_would_capture_is_true_for_a_nested_closure_reference(self):
        _, model = self._model(
            'function outer(){ function inner(){ return x; } }')
        outer_scope = model.root_scope.children[0]
        self.assertTrue(model.would_capture({'x'}, outer_scope))

    def test_would_capture_is_false_when_the_name_is_absent(self):
        _, model = self._model('function outer(){ return y; }')
        outer_scope = model.root_scope.children[0]
        self.assertFalse(model.would_capture({'x'}, outer_scope))

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

    def test_global_alias_member_write_creates_implicit_global(self):
        ast, model = self._model('globalThis.g = 99; g;')
        prop_g, read_g = self._idents(ast, 'g')
        binding = model.root_scope.bindings['g']
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertEqual(len(binding.writes), 1)
        self.assertIs(model.resolve(read_g), binding)

    def test_global_alias_computed_string_member_write_creates_implicit_global(self):
        ast, model = self._model("globalThis['g'] = 99; g;")
        binding = model.root_scope.bindings['g']
        self.assertEqual(binding.kind, BindingKind.IMPLICIT_GLOBAL)
        self.assertEqual(len(binding.writes), 1)
        self.assertIs(model.resolve(self._idents(ast, 'g')[0]), binding)

    def test_global_alias_member_write_records_on_declared_global_var(self):
        ast, model = self._model('var g; globalThis.g = 99;')
        binding = self._binding(ast, model, 'g')
        self.assertEqual(binding.kind, BindingKind.VAR)
        self.assertEqual(len(binding.writes), 1)

    def test_non_alias_member_write_does_not_create_global(self):
        ast, model = self._model('obj.g = 99; g;')
        self.assertNotIn('g', model.root_scope.bindings)
        self.assertIsNone(model.resolve(self._idents(ast, 'g')[-1]))

    def test_shadowed_alias_member_write_does_not_create_global(self):
        ast, model = self._model('function f(){ var window = {}; window.g = 99; }')
        self.assertNotIn('g', model.root_scope.bindings)

    def test_alias_member_read_does_not_create_global(self):
        ast, model = self._model('var x = globalThis.g;')
        self.assertNotIn('g', model.root_scope.bindings)

    def test_alias_member_write_inside_with_does_not_create_global(self):
        ast, model = self._model('with (o) { globalThis.g = 99; }')
        self.assertNotIn('g', model.root_scope.bindings)

    def test_dynamic_alias_member_write_does_not_create_named_global(self):
        ast, model = self._model('globalThis[k] = 99;')
        self.assertNotIn('k', model.root_scope.bindings)

    def _role(self, source: str, name: str = 'a') -> ContainerRole:
        ast, model = self._model(source)
        ref = next(n for n in self._idents(ast, name) if model.binding_of(n) is None)
        return container_reference_role(ref)

    def test_container_indexed_read_is_member_read(self):
        self.assertEqual(self._role('var a = [1]; a[0];'), ContainerRole.MEMBER_READ)

    def test_container_dotted_read_is_member_read(self):
        self.assertEqual(self._role('var a = {k: 1}; a.k;'), ContainerRole.MEMBER_READ)

    def test_container_indexed_write_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; a[0] = 9;'), ContainerRole.MEMBER_WRITE)

    def test_container_property_write_is_member_write(self):
        self.assertEqual(self._role('var a = {}; a.k = 9;'), ContainerRole.MEMBER_WRITE)

    def test_container_deep_chain_write_is_member_write(self):
        self.assertEqual(self._role('var a = {}; a.b.c = 9;'), ContainerRole.MEMBER_WRITE)

    def test_container_delete_element_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; delete a[0];'), ContainerRole.MEMBER_WRITE)

    def test_container_element_update_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; a[0]++;'), ContainerRole.MEMBER_WRITE)

    def test_container_reassignment_is_rebind(self):
        self.assertEqual(self._role('var a; a = [1];'), ContainerRole.REBIND)

    def test_container_call_argument_is_escape(self):
        self.assertEqual(self._role('var a = [1]; f(a);'), ContainerRole.ESCAPE)

    def test_container_alias_initializer_is_escape(self):
        self.assertEqual(self._role('var a = [1]; var b = a;'), ContainerRole.ESCAPE)

    def test_container_deep_chain_read_is_member_read(self):
        self.assertEqual(self._role('var a = {}; a.b.c;'), ContainerRole.MEMBER_READ)

    def test_container_method_call_is_member_call(self):
        self.assertEqual(self._role('var a = [1]; a.push(2);'), ContainerRole.MEMBER_CALL)

    def test_container_chained_method_call_is_member_call(self):
        self.assertEqual(self._role('var a = []; a.b.c();'), ContainerRole.MEMBER_CALL)

    def test_container_for_of_target_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; for (a[0] of xs) {}'), ContainerRole.MEMBER_WRITE)

    def test_container_for_in_target_is_member_write(self):
        self.assertEqual(self._role('var a = {}; for (a.k in xs) {}'), ContainerRole.MEMBER_WRITE)

    def test_container_for_of_rest_member_target_is_member_write(self):
        self.assertEqual(self._role('var a = {}; for ([...a.b] of xs) {}'), ContainerRole.MEMBER_WRITE)

    def test_container_spread_member_in_array_literal_is_member_read(self):
        self.assertEqual(self._role('var a = {}; y = [...a.b];'), ContainerRole.MEMBER_READ)

    def test_container_array_destructuring_target_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; [a[0]] = xs;'), ContainerRole.MEMBER_WRITE)

    def test_container_destructuring_default_target_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; [a[0] = 9] = xs;'), ContainerRole.MEMBER_WRITE)

    def test_container_destructuring_default_value_is_member_read(self):
        self.assertEqual(self._role('var a = [1]; [x = a[0]] = xs;'), ContainerRole.MEMBER_READ)

    def test_container_iterable_in_for_of_is_escape(self):
        self.assertEqual(self._role('var a = [1]; for (k of a) {}'), ContainerRole.ESCAPE)

    def test_container_parenthesized_member_write_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; (a[0]) = 9;'), ContainerRole.MEMBER_WRITE)

    def test_container_parenthesized_element_update_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; (a[0])++;'), ContainerRole.MEMBER_WRITE)

    def test_container_parenthesized_delete_is_member_write(self):
        self.assertEqual(self._role('var a = [1]; delete (a[0]);'), ContainerRole.MEMBER_WRITE)

    def test_container_parenthesized_method_call_is_member_call(self):
        self.assertEqual(self._role('var a = [1]; (a.sort)();'), ContainerRole.MEMBER_CALL)

    def test_container_tagged_template_call_is_member_call(self):
        self.assertEqual(self._role('var a = [1]; a.tag`x`;'), ContainerRole.MEMBER_CALL)

    def _ref_role(self, source: str, name: str = 'a') -> Role:
        ast, model = self._model(source)
        ref = next(n for n in self._idents(ast, name) if model.binding_of(n) is None)
        return reference_role(ref)

    def test_reference_role_parenthesized_assignment_is_write(self):
        self.assertEqual(self._ref_role('var a; (a) = 1;'), Role.WRITE)

    def test_reference_role_parenthesized_update_is_readwrite(self):
        self.assertEqual(self._ref_role('var a = 0; (a)++;'), Role.READWRITE)

    def test_reference_role_array_destructuring_default_is_write(self):
        self.assertEqual(self._ref_role('var a = 1; [a = 9] = xs;'), Role.WRITE)

    def test_reference_role_object_destructuring_default_is_write(self):
        self.assertEqual(self._ref_role('var a = 1; ({k: a = 9} = obj);'), Role.WRITE)

    def test_reference_role_for_of_rest_target_is_write(self):
        self.assertEqual(self._ref_role('var a = 1; for ([b, ...a] of xs) {}'), Role.WRITE)

    def test_reference_role_for_of_object_rest_target_is_write(self):
        self.assertEqual(self._ref_role('var a = 1; for ({...a} of xs) {}'), Role.WRITE)

    def test_reference_role_array_spread_argument_is_read(self):
        self.assertEqual(self._ref_role('var a = 1; f(...a);'), Role.READ)

    def test_reference_role_delete_target_is_readwrite(self):
        self.assertEqual(self._ref_role('var a = 1; delete a;'), Role.READWRITE)

    def test_reference_role_delete_member_base_is_read(self):
        self.assertEqual(self._ref_role('var a = []; delete a[0];'), Role.READ)

    def _is_simple_target(self, source: str, name: str = 'a') -> bool:
        ast, model = self._model(source)
        ref = next(n for n in self._idents(ast, name) if model.binding_of(n) is None)
        return is_simple_assignment_target(ref)

    def test_simple_assignment_target_is_simple(self):
        self.assertTrue(self._is_simple_target('var a; a = 1;'))

    def test_parenthesized_assignment_target_is_simple(self):
        self.assertTrue(self._is_simple_target('var a; (a) = 1;'))

    def test_array_destructuring_target_is_simple(self):
        self.assertTrue(self._is_simple_target('var a; [a] = xs;'))

    def test_array_destructuring_default_target_is_simple(self):
        self.assertTrue(self._is_simple_target('var a; [a = 9] = xs;'))

    def test_object_destructuring_default_target_is_simple(self):
        self.assertTrue(self._is_simple_target('var a; ({k: a = 9} = obj);'))

    def test_for_of_head_target_is_not_simple(self):
        self.assertFalse(self._is_simple_target('var a; for (a of xs) {}'))

    def test_for_in_head_target_is_not_simple(self):
        self.assertFalse(self._is_simple_target('var a; for (a in o) {}'))

    def test_compound_assignment_target_is_not_simple(self):
        self.assertFalse(self._is_simple_target('var a = 0; a += 1;'))

    def test_update_target_is_not_simple(self):
        self.assertFalse(self._is_simple_target('var a = 0; a++;'))

    def test_plain_read_is_not_simple(self):
        self.assertFalse(self._is_simple_target('var a = 1; f(a);'))

    def test_destructuring_default_value_is_not_simple(self):
        self.assertFalse(self._is_simple_target('var a = 1; [x = a] = xs;'))

    def test_object_assignment_shorthand_default_value_is_not_simple(self):
        self.assertFalse(self._is_simple_target('({a = d} = o);', 'd'))

    def test_object_assignment_shorthand_default_target_is_a_write(self):
        ast, _ = self._model('({a = d} = o);')
        target = self._idents(ast, 'a')[0]
        self.assertEqual(reference_role(target), Role.WRITE)
        self.assertTrue(is_simple_assignment_target(target))

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

    def test_local_reachable_by_eval_inside_its_function(self):
        ast, model = self._model("function f(){ var x; eval('x'); }")
        self.assertTrue(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_local_not_reachable_by_eval_outside_its_function(self):
        ast, model = self._model('function f(){ var x; } eval(payload);')
        self.assertFalse(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_local_reachable_by_with_inside_its_function(self):
        ast, model = self._model('function f(o){ var x; with (o) { x; } }')
        self.assertTrue(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_local_reachable_by_eval_in_nested_function(self):
        ast, model = self._model("function f(){ var x; function g(){ eval('x'); } }")
        self.assertTrue(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_local_not_reachable_by_global_scope_surfaces(self):
        ast, model = self._model(
            'function f(){ var x; }'
            " var g = Function('return 1'); setTimeout('y()', 1); window[k]();")
        self.assertFalse(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_local_not_reachable_by_indirect_eval_inside_its_function(self):
        ast, model = self._model("function f(o){ var x; o.eval('x'); }")
        self.assertFalse(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_global_reachable_by_any_surface(self):
        ast, model = self._model('var x; eval(payload);')
        self.assertTrue(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_global_not_reachable_without_surface(self):
        ast, model = self._model('var x = 1; console.log(x);')
        self.assertFalse(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def _dynamic_role(self, source: str, name: str = 'o') -> ContainerRole:
        ast, model = self._model(source)
        refs = model.dynamic_references(self._binding(ast, model, name))
        self.assertEqual(len(refs), 1)
        return container_reference_role(refs[0])

    def test_with_member_call_is_a_dynamic_reference(self):
        self.assertEqual(self._dynamic_role('var o = [1]; with (q) { o.push(2); }'), ContainerRole.MEMBER_CALL)

    def test_with_indexed_write_is_a_dynamic_reference(self):
        self.assertEqual(self._dynamic_role('var o = [1]; with (q) { o[0] = 2; }'), ContainerRole.MEMBER_WRITE)

    def test_with_reassignment_is_a_dynamic_reference(self):
        self.assertEqual(self._dynamic_role('var o = [1]; with (q) { o = 2; }'), ContainerRole.REBIND)

    def test_with_argument_escape_is_a_dynamic_reference(self):
        self.assertEqual(self._dynamic_role('var o = [1]; with (q) { f(o); }'), ContainerRole.ESCAPE)

    def test_with_member_read_is_a_dynamic_reference(self):
        self.assertEqual(
            self._dynamic_role('var o = [1]; var y; with (q) { y = o[0]; }'), ContainerRole.MEMBER_READ)

    def test_with_not_naming_container_attributes_nothing(self):
        ast, model = self._model('var o = [1]; with (q) { z = 2; }')
        self.assertEqual(model.dynamic_references(self._binding(ast, model, 'o')), [])

    def test_dynamic_reference_is_not_a_static_reference(self):
        ast, model = self._model('var o = [1]; with (q) { o[0] = 2; }')
        binding = self._binding(ast, model, 'o')
        self.assertEqual(model.references(binding), [])
        self.assertEqual(len(model.dynamic_references(binding)), 1)

    def test_dynamic_reference_respects_shadowing(self):
        ast, model = self._model('var o = [1]; function f(q){ var o = [2]; with (q) { o.push(3); } }')
        outer_decl, inner_decl = (n for n in self._idents(ast, 'o') if model.binding_of(n) is not None)
        outer, inner = model.binding_of(outer_decl), model.binding_of(inner_decl)
        assert outer is not None and inner is not None
        self.assertEqual(model.dynamic_references(outer), [])
        inner_refs = model.dynamic_references(inner)
        self.assertEqual(len(inner_refs), 1)
        self.assertEqual(container_reference_role(inner_refs[0]), ContainerRole.MEMBER_CALL)

    def test_nested_with_attributes_across_both_boundaries(self):
        self.assertEqual(
            self._dynamic_role('var o = [1]; with (a) { with (b) { o.push(2); } }'), ContainerRole.MEMBER_CALL)

    def test_free_name_in_with_is_not_attributed(self):
        model = self._model('with (q) { missing.push(1); }')[1]
        self.assertNotIn('missing', model.root_scope.bindings)

    def test_local_reachable_by_direct_eval_in_its_function(self):
        ast, model = self._model("function f(){ var x; eval('x'); }")
        self.assertTrue(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))

    def test_local_not_reachable_by_direct_eval_when_only_with(self):
        ast, model = self._model('function f(o){ var x; with (o) { x; } }')
        self.assertFalse(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))

    def test_local_reachable_by_direct_eval_in_nested_function(self):
        ast, model = self._model("function f(){ var x; function g(){ eval('x'); } }")
        self.assertTrue(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))

    def test_local_not_reachable_by_indirect_eval(self):
        ast, model = self._model("function f(o){ var x; o.eval('x'); }")
        self.assertFalse(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))

    def test_global_not_reachable_by_direct_eval(self):
        ast, model = self._model('var x; eval(payload);')
        self.assertFalse(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))
