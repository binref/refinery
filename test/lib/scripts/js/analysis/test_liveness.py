from __future__ import annotations

from test import TestBase, opportunity

from refinery.lib.scripts.js.analysis.liveness import build_liveness
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsFunctionDeclaration,
    JsIdentifier,
    JsReturnStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.parser import JsParser


class TestLiveness(TestBase):

    @staticmethod
    def _build(source: str):
        ast = JsParser(source).parse()
        model = build_semantic_model(ast)
        return ast, build_liveness(model)

    @staticmethod
    def _decl(ast, name: str, index: int = 0) -> JsIdentifier:
        ids = [
            d.id for d in ast.walk_in_order()
            if isinstance(d, JsVariableDeclarator)
            and isinstance(d.id, JsIdentifier)
            and d.id.name == name
        ]
        return ids[index]

    @staticmethod
    def _store(ast, name: str, index: int = 0) -> JsIdentifier:
        targets = [
            a.left for a in ast.walk_in_order()
            if isinstance(a, JsAssignmentExpression)
            and isinstance(a.left, JsIdentifier)
            and a.left.name == name
        ]
        return targets[index]

    @staticmethod
    def _stmt(ast, kind, index: int = 0):
        return [n for n in ast.walk_in_order() if isinstance(n, kind)][index]

    @staticmethod
    def _names(bindings) -> set[str]:
        return {binding.name for binding in bindings}

    @staticmethod
    def _func(ast, name: str) -> JsFunctionDeclaration:
        for node in ast.walk_in_order():
            if (
                isinstance(node, JsFunctionDeclaration)
                and node.id is not None
                and node.id.name == name
            ):
                return node
        raise AssertionError(name)

    @staticmethod
    def _binding(lv, name: str):
        return lv.model.root_scope.bindings[name]

    @classmethod
    def _local(cls, lv, ast, name: str):
        return lv.model.binding_of(cls._decl(ast, name))

    @staticmethod
    def _call(ast, callee: str) -> JsCallExpression:
        for node in ast.walk_in_order():
            if (
                isinstance(node, JsCallExpression)
                and isinstance(node.callee, JsIdentifier)
                and node.callee.name == callee
            ):
                return node
        raise AssertionError(callee)

    @classmethod
    def _live_around_the_call(cls, lv, ast, callee: str):
        live = lv.live_around(cls._call(ast, callee))
        assert live is not None
        return live

    def test_store_overwritten_before_read_is_dead(self):
        ast, lv = self._build('function f() { var x = 1; x = 2; return x; }')
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    def test_store_read_before_overwrite_is_live(self):
        ast, lv = self._build('function f() { var x = 1; g(x); x = 2; return x; }')
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))

    def test_parenthesized_store_kills_prior_store(self):
        ast, lv = self._build('function f() { var x = 1; (x) = 2; return x; }')
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))

    def test_value_never_read_is_dead(self):
        ast, lv = self._build('function f() { var t = compute(); return 0; }')
        self.assertTrue(lv.is_dead_store(self._decl(ast, 't')))

    def test_reassignment_chain_first_store_is_dead(self):
        ast, lv = self._build('function f() { var x = a(); x = b(); return x; }')
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    def test_store_live_on_fallthrough_branch_is_kept(self):
        ast, lv = self._build('function f(c) { var x = 1; if (c) { x = 2; } return x; }')
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))

    def test_short_circuit_write_does_not_kill_prior_store(self):
        ast, lv = self._build('function f(c) { var x = 1; c && (x = 2); return x; }')
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))

    def test_ternary_branch_write_does_not_kill_prior_store(self):
        ast, lv = self._build('function f(c) { var x = 1; c ? (x = 2) : 0; return x; }')
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))

    def test_a_write_a_statement_may_skip_does_not_kill_prior_store(self):
        for write in (
            'y ||= (x = 2);',
            'y &&= (x = 2);',
            'y ??= (x = 2);',
            'o?.g(x = 2);',
            'o?.[x = 2];',
            'o?.a.b(x = 2);',
            'switch (y) { case 0: break; case (x = 2): break; }',
            'class A { v = (x = 2); }',
        ):
            with self.subTest(write=write):
                ast, lv = self._build(F'function f(y, o) {{ var x = 1; {write} return x; }}')
                self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))

    def test_a_write_every_run_of_its_statement_makes_kills_prior_store(self):
        for write in (
            'y += (x = 2);',
            'o.g(x = 2);',
            '(x = 2) && y;',
        ):
            with self.subTest(write=write):
                ast, lv = self._build(F'function f(y, o) {{ var x = 1; {write} return x; }}')
                self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))

    def test_catch_reading_binding_keeps_store_before_throwing_write(self):
        source = 'function f() { var x = 1; try { x = risky(); } catch (e) { return x; } return x; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    def test_stores_an_inner_function_reads_are_live(self):
        source = 'function f() { var x = 1; function g() { return x; } g(); x = 2; return g(); }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    @opportunity
    def test_a_store_overwritten_before_any_call_of_the_inner_function_reading_it_is_dead(self):
        source = 'function f() { var x = 1; function g() { return x; } x = 2; return g(); }'
        ast, lv = self._build(source)
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    def test_same_name_block_bindings_are_independent(self):
        source = 'function f(c) { if (c) { let x = 1; use(x); } else { let x = 2; } return 0; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x', 0)))
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x', 1)))

    def test_loop_counter_and_accumulator_are_live(self):
        source = 'function f(n) { var s = 0; for (var i = 0; i < n; i++) { s = s + i; } return s; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'i')))
        self.assertFalse(lv.is_dead_store(self._decl(ast, 's')))

    def test_a_store_a_for_loop_tests_by_name_is_live(self):
        source = 'function f(m) { var n = 0; for (var go = true; go; ) { if (++n > m) go = false; } return n; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'go')))

    def test_a_store_before_a_for_loop_testing_it_by_name_is_live(self):
        source = 'function f(k) { var n = 0, i; for (i = k; i; ) { n++; i = 0; } return n; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._store(ast, 'i', 0)))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'i', 1)))

    def test_a_store_a_for_loop_updates_by_name_is_live(self):
        source = 'function f(k) { var n = 0, i = k; for (; n < 3; i) { n++; } return n; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'i')))

    def test_a_parameter_store_the_arguments_object_reads_is_live(self):
        ast, lv = self._build('function f(p) { p = 1; return arguments[0]; }')
        self.assertFalse(lv.is_dead_store(self._store(ast, 'p')))

    @opportunity
    def test_a_parameter_store_nothing_reads_is_dead(self):
        ast, lv = self._build('function f(p) { p = 1; return 2; }')
        self.assertTrue(lv.is_dead_store(self._store(ast, 'p')))

    def test_top_level_global_store_is_not_reported(self):
        ast, lv = self._build('g = 1; g = 2;')
        self.assertFalse(lv.is_dead_store(self._store(ast, 'g', 0)))

    def test_live_sets_follow_reads_and_kills(self):
        ast, lv = self._build('function f() { var x = 1; var y = 2; return x; }')
        decl_x = lv.node_of(self._stmt(ast, JsVariableDeclaration, 0))
        decl_y = lv.node_of(self._stmt(ast, JsVariableDeclaration, 1))
        ret = lv.node_of(self._stmt(ast, JsReturnStatement, 0))
        assert decl_x is not None and decl_y is not None and ret is not None
        self.assertEqual(self._names(lv.live_in(decl_x)), set())
        self.assertEqual(self._names(lv.live_out(decl_x)), {'x'})
        self.assertEqual(self._names(lv.live_in(decl_y)), {'x'})
        self.assertEqual(self._names(lv.live_out(decl_y)), {'x'})
        self.assertEqual(self._names(lv.live_in(ret)), {'x'})
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'y')))

    def test_dead_stores_lists_only_the_dead_write(self):
        source = 'function f() { var a = 1; a = 2; var b = keep(); return a + b; }'
        ast, lv = self._build(source)
        self.assertEqual(lv.dead_stores(), [self._decl(ast, 'a', 0)])

    def test_eval_disables_dead_store_reporting(self):
        ast, lv = self._build('function f() { var x = 1; eval("x"); x = 2; return x; }')
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertEqual(lv.dead_stores(), [])

    def test_with_disables_dead_store_reporting(self):
        ast, lv = self._build('function f(o) { var x = 1; with (o) { x; } x = 2; return x; }')
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertEqual(lv.dead_stores(), [])

    def test_eval_outside_function_does_not_block_inner_dead_store(self):
        ast, lv = self._build('function f() { var x = 1; x = 2; return x; } eval(payload);')
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    def test_global_scope_surface_does_not_block_inner_dead_store(self):
        ast, lv = self._build(
            'function f() { var x = 1; x = 2; return x; }'
            " setTimeout('y()', 1); var g = Function('return 1');")
        self.assertTrue(lv.is_dead_store(self._decl(ast, 'x')))

    def test_script_scope_dead_store_is_still_not_reported(self):
        ast, lv = self._build('var x; function f() { x = 1; x = 2; return x; } f();')
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x', 0)))
        self.assertEqual(lv.dead_stores(), [])

    def test_a_var_read_and_stored_only_in_one_function_body_is_owned_by_that_function(self):
        ast, lv = self._build('var x; function f() { x = 1; return x; } f();')
        self.assertIs(lv.pseudo_local_owner(self._binding(lv, 'x')), self._func(ast, 'f'))

    def test_a_var_with_a_site_outside_one_function_body_has_no_owner(self):
        for source in (
            'var x; function f() { x = 1; return x; } x;',
            'var x; function f() { x = 1; } function g() { return x; }',
            'var x; function f(v = x) { x = v; return v; }',
            'for (var x of [0]); function f() { x = 1; return x; }',
        ):
            with self.subTest(source=source):
                _, lv = self._build(source)
                self.assertIsNone(lv.pseudo_local_owner(self._binding(lv, 'x')))

    def test_a_var_a_function_reads_before_any_write_is_not_dead_on_its_entry(self):
        ast, lv = self._build('var x; function f() { return x; } function g() { x = 1; }')
        self.assertFalse(lv.is_dead_on_entry(self._binding(lv, 'x'), self._func(ast, 'f')))

    def test_a_binding_read_after_a_call_is_live_around_it(self):
        ast, lv = self._build('function f() { var x = 1; g(); return x; }')
        self.assertIn(self._local(lv, ast, 'x'), self._live_around_the_call(lv, ast, 'g'))

    def test_a_binding_stored_after_a_call_before_any_read_is_not_live_around_it(self):
        ast, lv = self._build('function f() { var x = 1; g(); x = 2; return x; }')
        self.assertNotIn(self._local(lv, ast, 'x'), self._live_around_the_call(lv, ast, 'g'))

    def test_a_binding_read_in_the_statement_of_a_call_is_live_around_it(self):
        ast, lv = self._build('function f() { var x = 1; h(x, g()); x = 2; return x; }')
        self.assertIn(self._local(lv, ast, 'x'), self._live_around_the_call(lv, ast, 'g'))

    def test_nothing_is_live_around_an_element_no_graph_places(self):
        ast, lv = self._build('var f = function (a = g()) { return a; };')
        self.assertIsNone(lv.live_around(self._call(ast, 'g')))
