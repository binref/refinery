from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.localization import localizable_bindings, localization_target
from refinery.lib.scripts.js.model import JsFunctionDeclaration
from refinery.lib.scripts.js.parser import JsParser


class TestLocalization(TestBase):

    @staticmethod
    def _build(source: str) -> tuple[Node, ModelCache]:
        ast = JsParser(source).parse()
        return ast, ModelCache(ast)

    @staticmethod
    def _func(ast: Node, name: str) -> JsFunctionDeclaration:
        for node in ast.walk_in_order():
            if (
                isinstance(node, JsFunctionDeclaration)
                and node.id is not None
                and node.id.name == name
            ):
                return node
        raise AssertionError(name)

    @staticmethod
    def _target(cache: ModelCache) -> Node | None:
        binding = cache.model.root_scope.bindings['x']
        return localization_target(cache.liveness, cache.reaching, binding)

    def assertMovesIntoF(self, source: str):
        ast, cache = self._build(source)
        self.assertIs(self._target(cache), self._func(ast, 'f'))

    def assertStays(self, source: str):
        _, cache = self._build(source)
        self.assertIsNone(self._target(cache))

    def test_pseudo_global_used_in_one_function_localizes_there(self):
        self.assertMovesIntoF(
            'var x;'
            ' function f(n) { x = []; for (var i = 0; i < n; i++) { x.push(i); } return x; }'
            ' console.log(f(3));')

    def test_pseudo_global_read_before_write_is_not_localizable(self):
        self.assertStays('var x; function f() { x = (x || 0) + 1; return x; } f(); f();')

    def test_pseudo_global_referenced_in_two_functions_is_not_localizable(self):
        self.assertStays('var x; function f() { x = 1; } function g() { return x; } f(); g();')

    def test_pseudo_global_also_written_at_script_scope_is_not_localizable(self):
        self.assertStays('var x; x = 1; function f() { x = 2; return x; } f();')

    def test_initialized_pseudo_global_is_not_localizable(self):
        self.assertStays('var x = compute(); function f() { x = 1; return x; } f();')

    def test_pseudo_global_captured_by_nested_closure_is_not_localizable(self):
        self.assertStays('var x; function f() { x = 1; return function () { return x; }; } f()();')

    def test_reflection_surface_disables_localization(self):
        self.assertStays('var x; function f() { x = 1; return x; } eval(payload);')

    def test_localizable_bindings_lists_each_pseudo_global_with_its_function(self):
        ast, cache = self._build(
            'var a, b;'
            ' function f() { a = []; b = 0; while (b < 3) { a.push(b); b = b + 1; } return a; }'
            ' f();')
        f = self._func(ast, 'f')
        bindings = cache.model.root_scope.bindings
        self.assertEqual(localizable_bindings(cache.liveness, cache.reaching), [
            (bindings['a'], f),
            (bindings['b'], f),
        ])

    def test_a_var_read_after_the_body_waits_while_another_run_may_store_it_stays(self):
        for source in (
            'var x; async function f(v) { x = v; await null; return x; }',
            'var x; function* f(v) { x = v; yield; return x; }',
            'var x; async function f(v) { x = v; for await (var e of [0]); return x; }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_read_after_a_call_that_may_run_the_function_again_stays(self):
        for source in (
            'var x; function f(n) { x = n; if (n) f(n - 1); return x; }',
            'var x; function g(n) { f(n); } function f(n) { x = n; if (n) g(n - 1); return x; }',
            'var x; function f(n, g) { x = n; g(); return x; }',
            'var x; function f(n) { x = n; if (n) [0].forEach(function () { f(0); }); return x; }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_the_parameter_list_reads_or_writes_stays(self):
        for source in (
            'var x; function f(v = x) { x = v; return v; }',
            'var x; function f(n, d = (x = 7)) { x = n; return x; }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_the_script_stores_into_where_it_declares_it_stays(self):
        for source in (
            'var x = 0; function f(v) { x = v; return x; }',
            'for (var x of [0]); function f(v) { x = v; return x; }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_dead_wherever_another_run_may_store_it_moves(self):
        for source in (
            'var x; function f(n) { x = n; console.log(x); if (n) f(n - 1); }',
            'var x; function f(n) { if (n) f(n - 1); x = n; console.log(x); }',
            'var x; async function f(v) { await null; x = v; console.log(x); }',
            'var x; function g(v) { return v + 1; } function f(n) { x = g(n); console.log(x); }',
            'var x; function f(n) { x = [n]; x.push(n); return x; }',
        ):
            with self.subTest(source=source):
                self.assertMovesIntoF(source)
