from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.liveness import build_liveness
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
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

    def test_catch_reading_binding_keeps_store_before_throwing_write(self):
        source = 'function f() { var x = 1; try { x = risky(); } catch (e) { return x; } return x; }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x')))

    def test_captured_binding_is_never_a_dead_store(self):
        source = 'function f() { var x = 1; function g() { return x; } x = 2; return g(); }'
        ast, lv = self._build(source)
        self.assertFalse(lv.is_dead_store(self._decl(ast, 'x')))
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

    def test_parameter_store_is_not_reported(self):
        ast, lv = self._build('function f(p) { p = 1; return 2; }')
        self.assertFalse(lv.is_dead_store(self._store(ast, 'p')))

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

    def test_pseudo_global_used_in_one_function_localizes_there(self):
        source = (
            'var x;'
            ' function f(n) { x = []; for (var i = 0; i < n; i++) { x.push(i); } return x; }'
            ' console.log(f(3));')
        ast, lv = self._build(source)
        self.assertIs(lv.localization_target(self._binding(lv, 'x')), self._func(ast, 'f'))

    def test_pseudo_global_read_before_write_is_not_localizable(self):
        ast, lv = self._build('var x; function f() { x = (x || 0) + 1; return x; } f(); f();')
        self.assertIsNone(lv.localization_target(self._binding(lv, 'x')))

    def test_pseudo_global_referenced_in_two_functions_is_not_localizable(self):
        ast, lv = self._build('var x; function f() { x = 1; } function g() { return x; } f(); g();')
        self.assertIsNone(lv.localization_target(self._binding(lv, 'x')))

    def test_pseudo_global_also_written_at_script_scope_is_not_localizable(self):
        ast, lv = self._build('var x; x = 1; function f() { x = 2; return x; } f();')
        self.assertIsNone(lv.localization_target(self._binding(lv, 'x')))

    def test_initialized_pseudo_global_is_not_localizable(self):
        ast, lv = self._build('var x = compute(); function f() { x = 1; return x; } f();')
        self.assertIsNone(lv.localization_target(self._binding(lv, 'x')))

    def test_pseudo_global_captured_by_nested_closure_is_not_localizable(self):
        ast, lv = self._build('var x; function f() { x = 1; return function () { return x; }; } f()();')
        self.assertIsNone(lv.localization_target(self._binding(lv, 'x')))

    def test_reflection_surface_disables_localization(self):
        ast, lv = self._build('var x; function f() { x = 1; return x; } eval(payload);')
        self.assertIsNone(lv.localization_target(self._binding(lv, 'x')))

    def test_script_scope_dead_store_is_still_not_reported(self):
        ast, lv = self._build('var x; function f() { x = 1; x = 2; return x; } f();')
        self.assertFalse(lv.is_dead_store(self._store(ast, 'x', 0)))
        self.assertEqual(lv.dead_stores(), [])

    def test_localizable_bindings_lists_each_pseudo_global_with_its_function(self):
        source = (
            'var a, b;'
            ' function f() { a = []; b = 0; while (b < 3) { a.push(b); b = b + 1; } return a; }'
            ' f();')
        ast, lv = self._build(source)
        f = self._func(ast, 'f')
        self.assertEqual(lv.localizable_bindings(), [
            (self._binding(lv, 'a'), f),
            (self._binding(lv, 'b'), f),
        ])
