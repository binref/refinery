from __future__ import annotations

import inspect

from test import TestBase
from test.lib.scripts.js.analysis.write_positions import WRITE_POSITIONS

from refinery.lib.scripts import Node
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
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsReturnStatement,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


_GLOBAL_WRITE_ROLES = {
    'assignment': (False, True),
    'compound assignment': (True, True),
    'postfix increment': (True, True),
    'prefix decrement': (True, True),
    'delete': (True, True),
    'array pattern': (False, True),
    'array pattern with default': (False, True),
    'object pattern': (False, True),
    'nested pattern': (False, True),
    'for-in head': (True, True),
    'for-of head': (True, True),
}
"""
Each write position of a `globalThis[key]` access, mapped to whether the program holds a
read-naming surface and whether it stores an opaque global property. Every position stores one —
the write fact is about the store, not the spelling. The positions that read the old value on the
way (compound, update, `delete`, loop heads) remain read-naming surfaces; the ones that overwrite
outright (assignment, destructuring) name nothing and are exempt.
"""


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

    @staticmethod
    def _member(ast) -> JsMemberExpression:
        return next(n for n in ast.walk() if isinstance(n, JsMemberExpression))

    def _decl(self, ast, model, name: str) -> JsIdentifier:
        return next(n for n in self._idents(ast, name) if model.binding_of(n) is not None)

    def _use(self, ast, model, name: str) -> JsIdentifier:
        return next(n for n in self._idents(ast, name) if model.binding_of(n) is None)

    @staticmethod
    def _call(ast, name: str) -> JsCallExpression:
        return next(
            n for n in ast.walk()
            if isinstance(n, JsCallExpression)
            and isinstance(n.callee, JsIdentifier)
            and n.callee.name == name
        )

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

    def test_singular_value_resolves_declaration_and_assignment_forms(self):
        ast, model = self._model(
            'function f() {}\n'
            'var g = function () {};\n'
            'var h;\n'
            'h = function () {};'
        )
        self.assertIsInstance(
            model.singular_value(model.binding_of(self._decl(ast, model, 'f'))),
            JsFunctionDeclaration,
        )
        self.assertIsInstance(
            model.singular_value(model.binding_of(self._decl(ast, model, 'g'))),
            JsFunctionExpression,
        )
        self.assertIsInstance(
            model.singular_value(model.binding_of(self._decl(ast, model, 'h'))),
            JsFunctionExpression,
        )

    def test_singular_value_is_none_for_reassigned_binding(self):
        ast, model = self._model('var x;\nx = 1;\nx = 2;')
        self.assertIsNone(model.singular_value(model.binding_of(self._decl(ast, model, 'x'))))

    def test_singular_value_is_none_when_a_write_overwrites_the_declaration_value(self):
        for label, source in {
            'initializer': 'var x = 1; x = 5; console.log(x);',
            'function declaration': 'function x() {} x = 5; console.log(x);',
            'class declaration': 'class x {} x = 5; console.log(x);',
        }.items():
            with self.subTest(label):
                ast, model = self._model(source)
                binding = model.binding_of(self._decl(ast, model, 'x'))
                self.assertIsNone(model.singular_value(binding))
                self.assertIsNone(model.binding_establishment_sites(binding))

    def test_binding_values_lists_every_spelled_value_of_a_multiply_written_name(self):
        ast, model = self._model('var x = 1;\nx = 2;\nx = 3;\nconsole.log(x);')
        values, complete = model.binding_values(model.binding_of(self._decl(ast, model, 'x')))
        self.assertTrue(complete)
        self.assertEqual(sorted(JsSynthesizer().convert(value) for value in values), ['1', '2', '3'])

    def test_binding_values_of_a_parameter_are_incomplete(self):
        for label, expected in {
            'function f(p) { return p; }': [],
            'function f(p) { p = 1; return p; }': ['1'],
        }.items():
            with self.subTest(label):
                ast, model = self._model(label)
                values, complete = model.binding_values(model.binding_of(self._decl(ast, model, 'p')))
                self.assertFalse(complete)
                self.assertEqual([JsSynthesizer().convert(value) for value in values], expected)

    def test_binding_values_are_incomplete_where_a_channel_spells_no_value(self):
        for label, source in {
            'compound assignment': 'var x = 1; x += 2; console.log(x);',
            'update': 'var x = 1; x++; console.log(x);',
            'destructured initializer': 'var { x } = console; console.log(x);',
            'destructured assignment': 'var x; [x] = [1]; console.log(x);',
            'for-of head': 'for (var x of [1]) { console.log(x); }',
            'for-in head': 'for (var x in console) { console.log(x); }',
            'catch parameter': 'try {} catch (x) { console.log(x); }',
        }.items():
            with self.subTest(label):
                ast, model = self._model(source)
                _, complete = model.binding_values(model.binding_of(self._decl(ast, model, 'x')))
                self.assertFalse(complete)
                self.assertIsNone(model.singular_value(model.binding_of(self._decl(ast, model, 'x'))))

    def test_values_at_call_admits_the_mapped_argument_as_the_entry_channel(self):
        ast, model = self._model('function f(p) { return p; }\nf(1);')
        binding = model.binding_of(self._decl(ast, model, 'p'))
        call = self._call(ast, 'f')
        values, complete = model.values_at_call(binding, {binding: call.arguments[0]})
        self.assertTrue(complete)
        self.assertEqual([JsSynthesizer().convert(value) for value in values], ['1'])

    def test_values_at_call_lists_the_argument_and_every_later_write(self):
        ast, model = self._model('function f(p) { p = 2; return p; }\nf(1);')
        binding = model.binding_of(self._decl(ast, model, 'p'))
        call = self._call(ast, 'f')
        values, complete = model.values_at_call(binding, {binding: call.arguments[0]})
        self.assertTrue(complete)
        self.assertEqual(sorted(JsSynthesizer().convert(value) for value in values), ['1', '2'])

    def test_values_at_call_with_a_missing_argument_is_incomplete(self):
        ast, model = self._model('function f(p) { return p; }\nf();')
        binding = model.binding_of(self._decl(ast, model, 'p'))
        values, complete = model.values_at_call(binding, {binding: None})
        self.assertFalse(complete)
        self.assertEqual(values, [])

    def test_values_at_call_is_incomplete_where_a_dynamic_channel_can_rebind(self):
        for label, source in {
            'direct eval': 'function f(p) { eval("p = 2"); return p; }\nf(1);',
            'escaping arguments object': 'function f(p) { console.log(arguments); return p; }\nf(1);',
            'arguments element write': 'function f(p) { arguments[0] = 2; return p; }\nf(1);',
        }.items():
            with self.subTest(label):
                ast, model = self._model(source)
                binding = model.binding_of(self._decl(ast, model, 'p'))
                call = self._call(ast, 'f')
                _, complete = model.values_at_call(binding, {binding: call.arguments[0]})
                self.assertFalse(complete)

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

    def test_read_has_dynamic_effect_for_with_body_read_backed_by_binding(self):
        ast, model = self._model('var x = 1; with (o) { x; }')
        self.assertTrue(model.read_has_dynamic_effect(self._use(ast, model, 'x')))

    def test_read_has_dynamic_effect_for_unresolved_with_body_read(self):
        ast, model = self._model('with (o) { y; }')
        y_use = next(n for n in self._idents(ast, 'y') if model.binding_of(n) is None)
        self.assertTrue(model.read_has_dynamic_effect(y_use))

    def test_read_has_no_dynamic_effect_for_static_read(self):
        ast, model = self._model('var x = 1; x;')
        self.assertFalse(model.read_has_dynamic_effect(self._use(ast, model, 'x')))

    def test_read_has_no_dynamic_effect_for_declaration(self):
        ast, model = self._model('var x = 1;')
        self.assertFalse(model.read_has_dynamic_effect(self._decl(ast, model, 'x')))

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

    def test_local_read_only_through_with_is_not_dead(self):
        ast, model = self._model('function f(o){ var x = 1; with (o) { x; } }')
        binding = self._binding(ast, model, 'x')
        self.assertEqual(binding.reads, [])
        self.assertFalse(binding.is_dead)

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

    def test_has_member_reference_true_for_alias_member_write(self):
        _, model = self._model('var g; globalThis.g = 99;')
        self.assertTrue(model.root_scope.bindings['g'].has_member_reference)

    def test_has_member_reference_true_for_alias_member_read(self):
        _, model = self._model('var g = 1; globalThis.g;')
        self.assertTrue(model.root_scope.bindings['g'].has_member_reference)

    def test_has_member_reference_false_for_plain_local(self):
        _, model = self._model('function f(){ var x = 1; return x; }')
        function_scope = model.root_scope.children[0]
        self.assertFalse(function_scope.bindings['x'].has_member_reference)

    def test_reaches_global_object_implicit_global(self):
        _, model = self._model('globalThis.g = 1;')
        g = model.root_scope.bindings['g']
        self.assertTrue(model.reaches_global_object(g, module_scope=False))
        self.assertTrue(model.reaches_global_object(g, module_scope=True))

    def test_reaches_global_object_top_level_var_depends_on_execution_model(self):
        _, model = self._model('var v = 1;')
        v = model.root_scope.bindings['v']
        self.assertTrue(model.reaches_global_object(v, module_scope=False))
        self.assertFalse(model.reaches_global_object(v, module_scope=True))

    def test_reaches_global_object_false_for_top_level_let(self):
        _, model = self._model('let x = 1;')
        x = model.root_scope.bindings['x']
        self.assertFalse(model.reaches_global_object(x, module_scope=False))

    def test_reaches_global_object_false_for_nested_var(self):
        _, model = self._model('function f(){ var n = 1; return n; }')
        n = model.root_scope.children[0].bindings['n']
        self.assertFalse(model.reaches_global_object(n, module_scope=False))

    def test_reference_role_reads_global_alias_member_value(self):
        ast, _ = self._model('sink(globalThis.g);')
        self.assertIs(reference_role(self._member(ast)), Role.READ)

    def test_reference_role_writes_global_alias_member_target(self):
        ast, _ = self._model('globalThis.g = 1;')
        self.assertIs(reference_role(self._member(ast)), Role.WRITE)

    def test_reference_role_readwrites_global_alias_member_compound(self):
        ast, _ = self._model('globalThis.g += 1;')
        self.assertIs(reference_role(self._member(ast)), Role.READWRITE)

    def test_reference_role_writes_global_alias_member_for_in_head(self):
        ast, _ = self._model('for (globalThis.g in o) {}')
        self.assertIs(reference_role(self._member(ast)), Role.WRITE)

    def test_global_alias_member_read_records_on_declared_global_var(self):
        ast, model = self._model('var g = 7; sink(globalThis.g);')
        binding = self._binding(ast, model, 'g')
        self.assertEqual(binding.kind, BindingKind.VAR)
        self.assertEqual(len(binding.reads), 1)
        self.assertTrue(binding.is_read)
        self.assertFalse(binding.is_dead)

    def test_global_alias_computed_member_read_records_on_declared_global_var(self):
        ast, model = self._model("var g = 7; sink(globalThis['g']);")
        self.assertEqual(len(self._binding(ast, model, 'g').reads), 1)

    def test_global_alias_member_compound_records_read_and_write(self):
        ast, model = self._model('var g = 0; globalThis.g += 1;')
        binding = self._binding(ast, model, 'g')
        self.assertEqual(len(binding.reads), 1)
        self.assertEqual(len(binding.writes), 1)

    def test_shadowed_alias_member_read_attributes_nothing(self):
        ast, model = self._model('var g = 1; function f(){ var globalThis = {}; return globalThis.g; }')
        self.assertEqual(self._binding(ast, model, 'g').reads, [])

    def test_alias_member_read_inside_with_attributes_nothing(self):
        ast, model = self._model('var g = 1; with (o) { sink(globalThis.g); }')
        self.assertEqual(self._binding(ast, model, 'g').reads, [])

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

    def test_is_reference_true_for_bound_read(self):
        ast, model = self._model('function f(x){ return x; }')
        self.assertTrue(model.is_reference(self._use(ast, model, 'x')))

    def test_is_reference_false_for_binding_sites(self):
        ast, model = self._model('function f(x){ return x; }')
        self.assertFalse(model.is_reference(self._decl(ast, model, 'x')))
        self.assertFalse(model.is_reference(self._decl(ast, model, 'f')))

    def test_is_reference_false_for_property_name_true_for_base(self):
        ast, model = self._model('o.p;')
        self.assertTrue(model.is_reference(self._idents(ast, 'o')[0]))
        self.assertFalse(model.is_reference(self._idents(ast, 'p')[0]))

    def test_is_reference_true_for_free_name_that_resolves_to_nothing(self):
        ast, model = self._model('g();')
        g = self._idents(ast, 'g')[0]
        self.assertTrue(model.is_reference(g))
        self.assertIsNone(model.resolve(g))

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

    def test_member_form_string_timer_is_a_reflection_surface(self):
        _, model = self._model("window.setTimeout('x()', 10);")
        self.assertTrue(model.has_reflection_surface())

    def test_member_form_computed_string_timer_is_a_reflection_surface(self):
        _, model = self._model("globalThis['setInterval']('x()', 10);")
        self.assertTrue(model.has_reflection_surface())

    def test_member_form_function_timer_is_not_a_reflection_surface(self):
        _, model = self._model('window.setTimeout(function(){ x(); }, 10);')
        self.assertFalse(model.has_reflection_surface())

    def test_string_timer_on_non_global_object_is_not_a_reflection_surface(self):
        _, model = self._model("obj.setTimeout('x()', 10);")
        self.assertFalse(model.has_reflection_surface())

    def test_dynamic_global_access_is_a_reflection_surface(self):
        _, model = self._model('window[key]();')
        self.assertTrue(model.has_reflection_surface())

    def test_a_computed_global_write_names_nothing_but_stores_one(self):
        """
        Each position a member expression can be written in, asked both questions the surface split
        separates: whether the access could *read* a global by a runtime-computed name
        (`has_reflection_surface`), and whether it *stores* a property on the global object under such
        a key (`has_opaque_global_write`). Pinning both per row keeps a detection change honest: a
        walk that loses the site from one fact cannot pass by losing it from both.
        """
        for position, template in WRITE_POSITIONS:
            source = template.replace('TARGET', 'globalThis[key]')
            with self.subTest(position=position):
                _, model = self._model(source)
                self.assertEqual(
                    (model.has_reflection_surface(), model.has_opaque_global_write()),
                    _GLOBAL_WRITE_ROLES[position],
                )

    def test_a_computed_global_read_stores_nothing(self):
        _, model = self._model('console.log(globalThis[key]); globalThis[key]();')
        self.assertTrue(model.has_reflection_surface())
        self.assertFalse(model.has_opaque_global_write())

    def test_a_computed_global_write_through_a_name_holding_the_object_stores_one(self):
        """
        The write fact resolves the base through the model — the row that distinguishes it from the
        spelling-level exemption the read-naming surface grants: `g` is not spelled as the object,
        but it holds it, and `g[key] = 1` stores a global under a key no spelling sees.
        """
        _, model = self._model('var g = globalThis; g[key] = 1;')
        self.assertFalse(model.has_reflection_surface())
        self.assertTrue(model.has_opaque_global_write())

    def test_a_statically_keyed_global_write_is_neither_fact(self):
        """
        A string-literal key names the global it writes, so the effect model attributes the store to
        that name; neither fact is needed to distrust it.
        """
        _, model = self._model("var g = globalThis; g['q'] = 1; globalThis.q = 2;")
        self.assertFalse(model.has_reflection_surface())
        self.assertFalse(model.has_opaque_global_write())

    def test_a_computed_write_on_another_object_stores_no_global(self):
        _, model = self._model('var o = {}; o[key] = 1;')
        self.assertFalse(model.has_reflection_surface())
        self.assertFalse(model.has_opaque_global_write())

    def test_static_global_access_is_not_a_reflection_surface(self):
        _, model = self._model("window['x']; self.y;")
        self.assertFalse(model.has_reflection_surface())

    def test_with_is_a_reflection_surface(self):
        _, model = self._model('with (o) { z; }')
        self.assertTrue(model.has_reflection_surface())

    def test_plain_program_has_no_reflection_surface(self):
        _, model = self._model('var a = 1; console.log(a);')
        self.assertFalse(model.has_reflection_surface())

    def test_an_escaping_constructor_read_is_a_reflection_surface(self):
        _, model = self._model("var F = (function () {}).constructor; F('x')();")
        self.assertTrue(model.has_reflection_surface())

    def test_an_invoked_constructor_read_is_not_a_reflection_surface(self):
        _, model = self._model("g.toString().constructor(g).search('a');")
        self.assertFalse(model.has_reflection_surface())

    def test_a_constructor_read_ending_in_a_plain_key_is_not_a_reflection_surface(self):
        _, model = self._model("t(''.__proto__.constructor.name);")
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

    def test_local_not_reachable_by_with_that_does_not_name_it(self):
        ast, model = self._model('function f(o){ var x; with (o) { z; } }')
        self.assertFalse(model.reflection_can_reach(self._binding(ast, model, 'x')))

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

    def test_global_reachable_by_an_opaque_global_write(self):
        """
        Storing a property on the global object under a runtime key reads nothing, but the stored
        key may be the name a script-scope binding answers to, so the write can rebind it without a
        reference the model records — the write-direction half of the reachability question.
        """
        ast, model = self._model('var x = 1; globalThis[k] = 2; console.log(x);')
        self.assertFalse(model.has_reflection_surface())
        self.assertTrue(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_local_not_reachable_by_an_opaque_global_write(self):
        ast, model = self._model('function f(){ var x; } globalThis[k] = 2;')
        self.assertFalse(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'x'))))

    def test_a_destructuring_write_to_an_installed_property_is_not_a_read_of_it(self):
        """
        The reference points of a function installed as `BASE.key = function` are the reads of that
        property. A destructuring target writes `BASE.key` without reading it, so it is not one —
        the case the shared `is_simple_assignment_target` climb added when it replaced the
        parent-only write-target check.
        """
        source = (
            'var o = {};'
            ' o.f = function () {};'
            ' [o.f] = [1];'
            ' console.log(o.f);'
        )
        ast, model = self._model(source)
        function = next(n for n in ast.walk() if isinstance(n, JsFunctionExpression))
        read = next(
            node for node in ast.walk()
            if isinstance(node, JsMemberExpression)
            and node.object.name == 'o'
            and isinstance(node.parent, JsCallExpression)
        )
        points = model.object_property_reference_points(function)
        self.assertEqual(points, [read])

    def test_opaque_reflection_reaches_global_through_eval(self):
        ast, model = self._model('var x; eval(payload);')
        self.assertTrue(model.reachable_by_opaque_reflection(self._binding(ast, model, 'x')))

    def test_opaque_reflection_ignores_a_with_that_does_not_name_the_global(self):
        """
        A `with` names its targets precisely as dynamic references, so the opaque-surface query — used
        where a caller already consults `dynamic_refs` — must not report a global reachable merely
        because a `with` exists, unlike the conservative `reflection_can_reach`.
        """
        ast, model = self._model('var x; with (o) { z; }')
        binding = self._binding(ast, model, 'x')
        self.assertTrue(model.reflection_can_reach(binding))
        self.assertFalse(model.reachable_by_opaque_reflection(binding))

    def test_opaque_reflection_reaches_global_through_function_and_timer(self):
        ast, model = self._model("var x; var g = Function('return 1'); setTimeout('y()', 1);")
        self.assertTrue(model.reachable_by_opaque_reflection(self._binding(ast, model, 'x')))

    def test_opaque_reflection_absent_without_surface(self):
        ast, model = self._model('var x = 1; console.log(x);')
        self.assertFalse(model.reachable_by_opaque_reflection(self._binding(ast, model, 'x')))

    def test_opaque_reflection_reaches_local_through_direct_eval(self):
        ast, model = self._model("function f(){ var x; eval('x'); }")
        self.assertTrue(model.reachable_by_opaque_reflection(self._binding(ast, model, 'x')))

    def test_opaque_reflection_does_not_reach_local_through_global_surfaces(self):
        ast, model = self._model('function f(){ var x; } eval(payload);')
        self.assertFalse(model.reachable_by_opaque_reflection(self._binding(ast, model, 'x')))

    def test_binding_never_reassigned_holds_for_a_write_free_binding(self):
        ast, model = self._model('var x = 1; console.log(x);')
        self.assertTrue(model.binding_never_reassigned(self._binding(ast, model, 'x')))

    def test_binding_never_reassigned_false_when_statically_written(self):
        ast, model = self._model('var x = 1; x = 2; console.log(x);')
        self.assertFalse(model.binding_never_reassigned(self._binding(ast, model, 'x')))

    def test_binding_never_reassigned_false_when_a_with_may_rebind_it(self):
        ast, model = self._model('var x = 1; function f(o){ with (o) { x = 2; } }')
        self.assertFalse(model.binding_never_reassigned(self._binding(ast, model, 'x')))

    def test_binding_never_reassigned_holds_when_a_with_only_reads_it(self):
        """
        A `with`-body read does not rebind the name, so the value stays stable — the distinction between
        value stability, which this reports, and orderability, which the read still breaks.
        """
        ast, model = self._model('var x = 1; function f(o){ with (o) { g(x); } }')
        self.assertTrue(model.binding_never_reassigned(self._binding(ast, model, 'x')))

    def test_binding_never_reassigned_false_when_a_local_direct_eval_may_rebind_it(self):
        ast, model = self._model('function f(){ var x = 1; eval("x = 2"); return x; }')
        self.assertFalse(model.binding_never_reassigned(self._binding(ast, model, 'x')))

    def test_indirect_comma_eval_is_a_reflection_surface(self):
        _, model = self._model("var G = 1; (0, eval)('G');")
        self.assertTrue(model.has_reflection_surface())

    def test_computed_literal_eval_access_is_a_reflection_surface(self):
        _, model = self._model("window['eval']('G');")
        self.assertTrue(model.has_reflection_surface())

    def test_computed_literal_eval_on_unknown_base_is_a_reflection_surface(self):
        _, model = self._model("o['eval']('G');")
        self.assertTrue(model.has_reflection_surface())

    def test_eval_alias_is_a_reflection_surface(self):
        _, model = self._model('var e = eval;')
        self.assertTrue(model.has_reflection_surface())

    def test_function_value_read_is_a_reflection_surface(self):
        _, model = self._model('var p = Function.prototype;')
        self.assertTrue(model.has_reflection_surface())

    def test_shadowed_eval_is_not_a_reflection_surface(self):
        _, model = self._model('function eval(){ return 0; } eval();')
        self.assertFalse(model.has_reflection_surface())

    def test_global_reachable_by_indirect_comma_eval(self):
        ast, model = self._model("var G = 1; (0, eval)('G');")
        self.assertTrue(model.reflection_can_reach(model.binding_of(self._decl(ast, model, 'G'))))

    def test_local_not_reachable_by_indirect_comma_eval_outside_its_function(self):
        ast, model = self._model("function f(){ var x; } (0, eval)('x');")
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

    def test_local_reachable_by_parenthesized_direct_eval(self):
        ast, model = self._model("function f(){ var x; (eval)('x'); }")
        self.assertTrue(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))

    def test_local_not_reachable_by_indirect_comma_eval(self):
        ast, model = self._model("function f(){ var x; (0, eval)('x'); }")
        self.assertFalse(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))

    def test_global_not_reachable_by_direct_eval(self):
        ast, model = self._model('var x; eval(payload);')
        self.assertFalse(model.local_reachable_by_direct_eval(self._binding(ast, model, 'x')))


class TestWhereADynamicScopeCouldRebindABinding(TestBase):
    """
    The located form of the volatility question `binding_maybe_reassigned_dynamically` answers
    with a boolean: the nodes a dynamic scope could rebind a binding at, so a consumer can order
    a read against each one, or `None` for the one rebind with no node — the write the call itself
    makes on entry. Every row asserts the boolean beside the located answer, so the two queries
    cannot drift apart.
    """

    @staticmethod
    def _model(source: str):
        ast = JsParser(source).parse()
        return ast, build_semantic_model(ast)

    def _located(self, source: str) -> tuple[Node, Binding, list[Node] | None, bool]:
        ast, model = self._model(source)
        decl = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsIdentifier) and n.name == 'x' and model.binding_of(n) is not None
        )
        binding = model.binding_of(decl)
        assert binding is not None
        return (
            ast, binding,
            model.binding_dynamic_rebind_sites(binding),
            model.binding_maybe_reassigned_dynamically(binding),
        )

    def test_a_direct_eval_in_the_owning_function_is_located(self):
        source = "function f(){ var x = 1; eval('x'); }"
        ast, binding, sites, volatile = self._located(source)
        call = next(
            n for n in ast.walk()
            if isinstance(n, JsCallExpression) and n.callee.name == 'eval'
        )
        self.assertTrue(volatile)
        self.assertEqual(sites, [call])

    def test_a_with_body_write_is_located(self):
        source = 'function f(o){ var x = 1; with (o) { x = 2; } }'
        ast, binding, sites, volatile = self._located(source)
        write = next(
            n for n in ast.walk()
            if isinstance(n, JsIdentifier) and n.name == 'x'
            and isinstance(n.parent, JsAssignmentExpression)
        )
        self.assertTrue(volatile)
        self.assertEqual(sites, [write])

    def test_a_with_body_read_is_no_rebind(self):
        ast, binding, sites, volatile = self._located('function f(o){ var x = 1; with (o) { x; } }')
        self.assertFalse(volatile)
        self.assertEqual(sites, [])

    def test_a_write_through_the_mapped_arguments_object_is_located(self):
        source = 'function f(x){ var q; arguments[0] = 1; }'
        ast, binding, sites, volatile = self._located(source)
        member = next(
            n for n in ast.walk()
            if isinstance(n, JsMemberExpression) and n.object.name == 'arguments'
        )
        self.assertTrue(volatile)
        self.assertEqual(sites, [member])

    def test_a_span_of_source_the_model_never_read_is_located(self):
        ast, binding, sites, volatile = self._located('function f(){ var x; h("abc\n; }')
        self.assertTrue(volatile)
        self.assertEqual(len(sites), 1)

    def test_the_entry_write_is_the_nodeless_kill(self):
        ast, model = self._model('function f(x = 1) { var x; }')
        declarator = next(
            n for n in ast.walk()
            if isinstance(n, JsVariableDeclarator) and n.id.name == 'x'
        )
        binding = model.binding_of(declarator.id)
        assert binding is not None
        self.assertTrue(model.binding_maybe_reassigned_dynamically(binding))
        self.assertIsNone(model.binding_dynamic_rebind_sites(binding))

    def test_a_clean_binding_has_no_sites(self):
        ast, binding, sites, volatile = self._located('var x = 1; console.log(x);')
        self.assertFalse(volatile)
        self.assertEqual(sites, [])

    def test_a_global_is_not_frozen_on_a_global_scope_surface(self):
        ast, binding, sites, volatile = self._located('var x; eval(payload);')
        self.assertFalse(volatile)
        self.assertEqual(sites, [])

    def test_a_local_is_not_frozen_on_a_global_scope_surface(self):
        ast, binding, sites, volatile = self._located('function f(){ var x; } eval(payload);')
        self.assertFalse(volatile)
        self.assertEqual(sites, [])


class TestFreeNameReachableByDirectEval(TestBase):
    """
    A direct `eval` can declare a binding that no reference in the source records, so a name the
    model resolves to nothing is not necessarily the global one. Which positions can see such a
    binding follows from what escapes an `eval`: a `var` or a function declaration is created in
    the var scope the call stands in and outlives the call, while a `let` or a `const` lives in a
    scope discarded with it. So the reachable positions are exactly those whose scope that var
    scope contains — every position in the function the `eval` stands in, including nested ones,
    and no position outside it.

    That containment is about position and not about order: a function written above the `eval`
    reads the binding just as one written below it does, because the declaration is made when the
    `eval` runs and the reading function's scope chain is the one it was created in.
    """

    @staticmethod
    def _model(source: str):
        ast = JsParser(source).parse()
        return ast, build_semantic_model(ast)

    def _reachable(self, source: str, name: str) -> bool:
        ast, model = self._model(source)
        node = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsIdentifier) and n.name == name and model.is_reference(n)
        )
        return model.free_name_reachable_by_direct_eval(node)

    def test_no_direct_eval_in_the_program(self):
        self.assertFalse(self._reachable('function g(){ return q; }', 'q'))

    def test_direct_eval_and_read_in_the_same_scope(self):
        self.assertTrue(self._reachable('eval(payload); q;', 'q'))

    def test_read_written_before_the_direct_eval_of_its_scope(self):
        self.assertTrue(self._reachable('q; eval(payload);', 'q'))

    def test_read_in_a_function_written_before_the_direct_eval_of_its_scope(self):
        self.assertTrue(self._reachable('function g(){ return q; } eval(payload);', 'q'))

    def test_read_in_a_function_below_the_scope_of_the_direct_eval(self):
        self.assertTrue(self._reachable('eval(payload); function g(){ return q; }', 'q'))

    def test_read_in_the_function_holding_the_direct_eval(self):
        self.assertTrue(self._reachable('function g(){ eval(payload); return q; }', 'q'))

    def test_read_in_a_function_nested_in_the_one_holding_the_direct_eval(self):
        self.assertTrue(
            self._reachable('function g(){ eval(payload); function h(){ return q; } }', 'q'))

    def test_direct_eval_in_a_block_declares_into_the_enclosing_function(self):
        self.assertTrue(self._reachable('function g(){ { eval(payload); } return q; }', 'q'))

    def test_read_outside_the_function_holding_the_direct_eval(self):
        self.assertFalse(self._reachable('function g(){ eval(payload); } q;', 'q'))

    def test_read_in_a_sibling_of_the_function_holding_the_direct_eval(self):
        self.assertFalse(
            self._reachable('function g(){ eval(payload); } function h(){ return q; }', 'q'))

    def test_read_outside_the_arrow_function_holding_the_direct_eval(self):
        self.assertFalse(self._reachable('var g = () => { eval(payload); }; q;', 'q'))

    def test_indirect_eval_declares_onto_the_global_object(self):
        """
        An indirect `eval` runs in the global scope, so its `var` becomes a property of the global
        object rather than a binding that shadows one — and for a name whose global property is
        neither writable nor configurable it cannot even do that.
        """
        self.assertFalse(self._reachable('function g(){ (0, eval)(payload); return q; }', 'q'))


def _alias_sites(source: str, name: str) -> tuple[list[str], list[str], list[str]]:
    """
    The source text of every site recorded against the parameter *name*, as the three channels the
    model keeps them in: the definitions, the kills that name no value, and the reads.
    """
    ast = JsParser(source).parse()
    model = build_semantic_model(ast)
    node = next(
        n for n in ast.walk_in_order()
        if isinstance(n, JsIdentifier) and n.name == name and model.binding_of(n) is not None
    )
    binding = model.binding_of(node)
    assert binding is not None
    return (
        [JsSynthesizer().convert(site) for site in binding.writes],
        [JsSynthesizer().convert(site) for site in binding.indefinite_writes],
        [JsSynthesizer().convert(site) for site in binding.reads],
    )


class TestWhatAnAccessOnAMappedArgumentsObjectReaches(TestBase):
    """
    An element of a mapped `arguments` object and the parameter at that position are one location:
    a reference through the object is attributed to the parameter its key names. Which parameter a
    key names is decided from the key: one that is the canonical spelling of an index in range names
    that parameter, and one that is statically known and is no such index names none.

    The read half of such a reference is a definite read of the parameter. The write half is never a
    definition of it: §10.2.11 maps an element onto a parameter only at a position the call supplied
    an argument for, so `arguments[0] = 9` writes the first parameter where the call passed one and
    creates an ordinary property where it passed none, and the text of the function says which
    neither way. Such a write is therefore recorded as a kill that names no value.

    A key the text does not decide is where naming and reaching come apart. Every parameter is in
    reach of such an access, so every one of them is read by it — reading is what makes a write to a
    parameter observable — and every one of them is killed by it, since it may write any single one
    and a definition of each would be a claim about a value only one of them can hold.
    """

    def test_an_index_in_range_kills_the_one_parameter_it_names_and_defines_none(self):
        source = 'function f(a, b) { arguments[1] = 9; }'
        self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
        self.assertEqual(_alias_sites(source, 'b'), ([], ['arguments[1]'], []))

    def test_an_index_in_range_reads_the_one_parameter_it_names(self):
        source = 'function f(a, b) { g(arguments[1]); }'
        self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
        self.assertEqual(_alias_sites(source, 'b'), ([], [], ['arguments[1]']))

    def test_a_key_the_text_does_not_decide_kills_every_parameter_and_reads_every_one(self):
        source = 'function f(a, b) { arguments[c] = 9; }'
        self.assertEqual(_alias_sites(source, 'a'), ([], ['arguments[c]'], ['arguments']))
        self.assertEqual(_alias_sites(source, 'b'), ([], ['arguments[c]'], ['arguments']))

    def test_a_key_that_is_no_index_reaches_no_parameter_at_all(self):
        for key in ['1e400', '1e21', '1.5', "'01'", "'+1'", "' 1'", "'1e0'", "'²'", "'١'"]:
            with self.subTest(key=key):
                source = F'function f(a, b) {{ arguments[{key}] = 9; }}'
                self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
                self.assertEqual(_alias_sites(source, 'b'), ([], [], []))

    def test_a_negated_number_is_a_key_the_text_does_not_decide(self):
        """
        `-1` is a unary expression rather than a literal, so no key is read out of it and every
        parameter is answered as in reach. Node reaches no element through it, as the corpus in
        `test.lib.scripts.js.deobfuscation.test_arguments_aliasing` records, so the answer here is
        weaker than the one the text supports and never stronger.
        """
        source = 'function f(a, b) { arguments[-1] = 9; }'
        self.assertEqual(_alias_sites(source, 'a'), ([], ['arguments[-1]'], ['arguments']))
        self.assertEqual(_alias_sites(source, 'b'), ([], ['arguments[-1]'], ['arguments']))

    def test_an_index_past_the_end_of_the_list_reaches_no_parameter(self):
        source = 'function f(a, b) { arguments[2] = 9; }'
        self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
        self.assertEqual(_alias_sites(source, 'b'), ([], [], []))

    def test_a_parenthesized_receiver_reaches_what_the_bare_one_reaches(self):
        self.assertEqual(
            _alias_sites('function f(a, b) { (arguments)[1] = 9; }', 'b'),
            ([], ['(arguments)[1]'], []),
        )
        self.assertEqual(
            _alias_sites('function f(a, b) { ((arguments))[1] = 9; }', 'b'),
            ([], ['((arguments))[1]'], []),
        )

    def test_a_parenthesized_receiver_leaves_the_parameters_it_does_not_name_alone(self):
        self.assertEqual(
            _alias_sites('function f(a, b) { (arguments)[1] = 9; }', 'a'),
            ([], [], []),
        )

    def test_a_name_bound_to_something_else_attributes_nothing_to_a_parameter(self):
        for source in [
            'function f(arguments, b) { arguments[1] = 9; }',
            'function f(a, b) { var arguments = [7]; arguments[1] = 9; }',
            'function f(a, b) { try { q(); } catch (arguments) { arguments[1] = 9; } }',
            'function f(a, b) { arguments = [7]; arguments[1] = 9; }',
        ]:
            with self.subTest(source=source):
                self.assertEqual(_alias_sites(source, 'b'), ([], [], []))

    def test_a_strict_body_has_an_object_that_aliases_nothing(self):
        source = "function f(a, b) { 'use strict'; arguments[1] = 9; }"
        self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
        self.assertEqual(_alias_sites(source, 'b'), ([], [], []))


class TestWhatABareUseOfAMappedArgumentsObjectReaches(TestBase):
    """
    A use of the object that names no element is attributed by what its governing position can do
    with the object rather than by the object being mentioned. A position that observes what the
    object is — a `typeof`, a `void`, a negation, the test of a branch or a loop, a `for-in`
    head — reaches no parameter. One that reads every element and hands the object nowhere — a
    spread, a synchronous `for-of` head — reads every parameter and kills none. Every other
    position may hand the object to code that writes an element, so it reads every parameter and
    kills every one of them.

    Which of the three a position falls in is the whole answer, so each of these varies the position
    and nothing else. `for await` and `for of` differ by one keyword and fall in different ones: the
    asynchronous walk looks `@@asyncIterator` up, which §10.2.11 gives the object none of, so the
    lookup leaves the object for `Object.prototype` and calls what stands there with the object as
    `this` — a hand-off the synchronous walk never makes, its `@@iterator` being its own.
    `test.lib.scripts.js.deobfuscation.test_arguments_aliasing` records what Node makes of a body
    that puts a parameter write behind that lookup.
    """

    def test_a_position_that_observes_what_the_object_is_reaches_no_parameter(self):
        for use in [
            'typeof arguments;',
            'void arguments;',
            '!arguments;',
            'if (arguments) {}',
            'while (arguments) { break; }',
            'do { break; } while (arguments);',
            'for (; arguments; ) {}',
            'arguments ? 1 : 2;',
            'for (var k in arguments) {}',
        ]:
            with self.subTest(use=use):
                source = F'function f(a, b) {{ {use} }}'
                self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
                self.assertEqual(_alias_sites(source, 'b'), ([], [], []))

    def test_a_mention_whose_value_a_statement_discards_reaches_no_parameter(self):
        """
        An expression statement evaluates its expression, takes the value, and throws it away, so a
        statement that is nothing but the name performs no access on the object and hands it to
        nobody. The parenthesized spelling is the same statement.
        `test.lib.scripts.js.deobfuscation.test_arguments_aliasing` records what Node makes of such
        a statement in a body that has poisoned the one route out of an object it could enter.
        """
        for use in ['arguments;', '(arguments);']:
            with self.subTest(use=use):
                source = F'function f(a, b) {{ {use} }}'
                self.assertEqual(_alias_sites(source, 'a'), ([], [], []))
                self.assertEqual(_alias_sites(source, 'b'), ([], [], []))

    def test_a_walk_that_reads_every_element_reads_every_parameter_and_kills_none(self):
        for use in [
            'for (var v of arguments) {}',
            'var s = [...arguments];',
            'g(...arguments);',
        ]:
            with self.subTest(use=use):
                source = F'function f(a, b) {{ {use} }}'
                self.assertEqual(_alias_sites(source, 'a'), ([], [], ['arguments']))
                self.assertEqual(_alias_sites(source, 'b'), ([], [], ['arguments']))

    def test_an_asynchronous_walk_kills_every_parameter_as_any_other_hand_off_does(self):
        source = 'async function f(a, b) { for await (var v of arguments) {} }'
        self.assertEqual(_alias_sites(source, 'a'), ([], ['arguments'], ['arguments']))
        self.assertEqual(_alias_sites(source, 'b'), ([], ['arguments'], ['arguments']))

    def test_a_position_that_hands_the_object_on_kills_every_parameter(self):
        for use in [
            'g(arguments);',
            'var h = arguments;',
            'return arguments;',
            'yield* arguments;',
        ]:
            with self.subTest(use=use):
                keyword = 'function*' if use.startswith('yield') else 'function'
                source = F'{keyword} f(a, b) {{ {use} }}'
                self.assertEqual(_alias_sites(source, 'a'), ([], ['arguments'], ['arguments']))
                self.assertEqual(_alias_sites(source, 'b'), ([], ['arguments'], ['arguments']))


class TestWhichBindingsAreReachedThroughTheGlobalObject(TestBase):
    """
    Two kinds of object reach a binding the access spells no lexical name of: the global object,
    where `globalThis.x` reaches the global `x`, and a mapped `arguments` object, where
    `arguments[0]` reaches the first parameter. Both are recorded as a member access standing in for
    a referencing identifier, so a predicate that reads only the recorded node's type cannot tell
    them apart — and they mean opposite things to a caller. A global reached that way is reachable
    from anywhere and must not be treated as a local; a parameter reached that way is reachable from
    nothing outside the one function that holds it.
    """

    @staticmethod
    def _binding(source: str, name: str) -> Binding:
        ast = JsParser(source).parse()
        model = build_semantic_model(ast)
        node = next(
            n for n in ast.walk_in_order()
            if isinstance(n, JsIdentifier) and n.name == name
            and (model.binding_of(n) or model.resolve(n)) is not None
        )
        binding = model.binding_of(node) or model.resolve(node)
        assert binding is not None
        return binding

    def _reached_through_the_global_object(self, source: str, name: str) -> tuple[bool, bool]:
        binding = self._binding(source, name)
        return binding.has_global_member_write, binding.has_member_reference

    def test_a_parameter_written_through_its_own_arguments_object_is_not(self):
        self.assertEqual(
            self._reached_through_the_global_object(
                'function f(a) { arguments[0] = 9; return a; }', 'a'),
            (False, False),
        )

    def test_that_parameter_still_carries_the_write(self):
        binding = self._binding('function f(a) { arguments[0] = 9; return a; }', 'a')
        self.assertEqual(
            [JsSynthesizer().convert(site) for site in binding.indefinite_writes],
            ['arguments[0]'],
        )

    def test_a_parameter_read_through_its_own_arguments_object_is_not(self):
        self.assertEqual(
            self._reached_through_the_global_object(
                'function f(a) { a = 2; return arguments[0]; }', 'a'),
            (False, False),
        )

    def test_a_global_written_through_the_global_object_is(self):
        self.assertEqual(
            self._reached_through_the_global_object('var x; globalThis.x = 1;', 'x'),
            (True, True),
        )

    def test_an_implicit_global_written_through_the_global_object_is(self):
        self.assertEqual(
            self._reached_through_the_global_object('globalThis.x = 1; log(x);', 'x'),
            (True, True),
        )

    def test_a_global_only_read_through_the_global_object_carries_no_write(self):
        self.assertEqual(
            self._reached_through_the_global_object('var y = 1; globalThis.y;', 'y'),
            (False, True),
        )


class TestWhenAHandedApplyReceiverIsObserved(TestBase):
    """
    The gate that lets the global object handed as an `apply`/`call` receiver stay foldable, asked
    on each text as written. The behavior rows over these same shapes run the whole pipeline,
    where another pass can rewrite the shape before the gate answers — collapsing an alias into
    the name it copies, or freezing every global on a reflection surface — so only the direct
    question proves the gate itself refuses each displacement.
    """

    @staticmethod
    def _observed(source: str) -> bool:
        ast = JsParser(inspect.cleandoc(source)).parse()
        model = build_semantic_model(ast)
        call = next(
            n for n in ast.walk()
            if isinstance(n, JsCallExpression)
            and isinstance(n.callee, JsIdentifier)
            and n.callee.name == 'wrap'
        )
        return model.global_object_argument_is_observed(call.arguments[0])

    def test_each_displaced_apply_target_marks_the_hand_over_observed(self):
        for label, source in {
            'an own apply property write': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload) {
                  payload.apply = function (r) { return inner(r); };
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a defineProperty install': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload) {
                  Object.defineProperty(payload, 'apply', {
                    value: function (r) { return inner(r); }
                  });
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a two-valued alias write': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload, flag) {
                  var other = flag ? payload : payload;
                  other.apply = function (r) { return inner(r); };
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}, 1));
                """,
            'a helper handed the target': """
                function inner(host) { return host.secret; }
                function install(x) { x.apply = function (r) { return inner(r); }; }
                function wrap(recv, payload) {
                  install(payload);
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'an assign copies the forwarder': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload) {
                  Object.assign(payload, { apply: function (r) { return inner(r); } });
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a prototype swap': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload) {
                  Object.setPrototypeOf(payload, { apply: function (r) { return inner(r); } });
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a chain write through __proto__': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload) {
                  payload.__proto__.apply = function (r) { return inner(r); };
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a constructor-reached prototype': """
                function inner(host) { return host.secret; }
                (function () {}).constructor.prototype.apply = function (r) { return inner(r); };
                function wrap(recv, payload) {
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a poisoned Function prototype': """
                function inner(host) { return host.secret; }
                Function.prototype.apply = function (r) { return inner(r); };
                function wrap(recv, payload) {
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a reassignment to a this-reader': """
                function inner(host) { return host.secret; }
                function wrap(recv, payload) {
                  payload = function () { return inner(this); };
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
        }.items():
            with self.subTest(label):
                self.assertTrue(self._observed(source))

    def test_an_undisplaced_this_free_apply_leaves_the_hand_over_unobserved(self):
        for label, source in {
            'a plain this-free payload': """
                function wrap(recv, payload) {
                  return payload.apply(recv, []);
                }
                console.log(wrap(this, function () {}));
                """,
            'a truth-guarded apply': """
                function wrap(recv, payload) {
                  if (payload) {
                    return payload.apply(recv, []);
                  }
                }
                console.log(wrap(this, function () {}));
                """,
            'a typeof-guarded apply': """
                function wrap(recv, payload) {
                  return typeof payload === 'function' ? payload.apply(recv, []) : 0;
                }
                console.log(wrap(this, function () {}));
                """,
            'a null reassignment after the apply': """
                function wrap(recv, payload) {
                  var kept = payload.apply(recv, []);
                  payload = null;
                  return kept;
                }
                console.log(wrap(this, function () {}));
                """,
        }.items():
            with self.subTest(label):
                self.assertFalse(self._observed(source))


def _how_each_occurrence_is_read(source: str, name: str) -> list[tuple[bool, bool]]:
    """
    For every identifier spelled *name* in *source*, in source order, whether the model calls it a
    reference and whether it answers that reading it may throw.
    """
    ast = JsParser(source).parse()
    model = build_semantic_model(ast)
    return [
        (model.is_reference(node), model.read_may_throw(node))
        for node in ast.walk_in_order()
        if isinstance(node, JsIdentifier) and node.name == name
    ]


class TestANameSpelledInAKeyPositionReadsNoBinding(TestBase):
    """
    A name a class body spells out is the key its member is stored under; so is the key of an import
    attribute, and so is the name an `export * as` exports a module under. None of the three reads a
    binding, and none of them can throw for want of one.

    Every program below spells the same name twice: once in such a position, and once as a bare
    expression statement, which is a read of a name nothing binds. The pair is the assertion — the
    second occurrence is what the first would answer if it were being read as a name. A key written
    in brackets is the case where the two occurrences agree, because there the name really is an
    expression the definition evaluates.
    """

    def test_a_class_member_name_spelled_out_reads_no_binding(self):
        for member in [
            'gk() {}',
            'get gk() { return 0; }',
            'set gk(v) {}',
            'static gk() {}',
            'static get gk() { return 0; }',
            'async gk() {}',
            '*gk() {}',
            'gk = 1;',
            'static gk = 1;',
        ]:
            with self.subTest(member=member):
                self.assertEqual(
                    _how_each_occurrence_is_read(F'class C {{ {member} }}\ngk;', 'gk'),
                    [(False, False), (True, True)],
                )

    def test_a_class_member_name_in_brackets_reads_the_binding_it_spells(self):
        for member in [
            '[gk]() {}',
            'get [gk]() { return 0; }',
            'set [gk](v) {}',
            'static [gk]() {}',
            '[gk] = 1;',
            'static [gk] = 1;',
        ]:
            with self.subTest(member=member):
                self.assertEqual(
                    _how_each_occurrence_is_read(F'class C {{ {member} }}\ngk;', 'gk'),
                    [(True, True), (True, True)],
                )

    def test_an_object_literal_key_reads_no_binding(self):
        self.assertEqual(
            _how_each_occurrence_is_read('var o = { gk: 1 };\ngk;', 'gk'),
            [(False, False), (True, True)],
        )

    def test_an_import_attribute_key_reads_no_binding(self):
        self.assertEqual(
            _how_each_occurrence_is_read("import x from 'm' with { type: 'json' };\ntype;", 'type'),
            [(False, False), (True, True)],
        )

    def test_the_name_an_export_all_exports_a_module_under_reads_no_binding(self):
        self.assertEqual(
            _how_each_occurrence_is_read("export * as ns from 'm';\nns;", 'ns'),
            [(False, False), (True, True)],
        )
