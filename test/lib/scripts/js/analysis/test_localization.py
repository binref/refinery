from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.analysis.localization import localizable_bindings, localization_target
from refinery.lib.scripts.js.model import JsFunctionDeclaration
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
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
            ' console.log(f(3));'
        )

    def test_pseudo_global_read_before_write_is_not_localizable(self):
        self.assertStays('var x; function f() { x = (x || 0) + 1; return x; } f(); f();')

    def test_pseudo_global_referenced_in_two_functions_is_not_localizable(self):
        self.assertStays('var x; function f() { x = 1; } function g() { return x; } f(); g();')

    def test_pseudo_global_a_field_of_a_returned_class_reads_is_not_localizable(self):
        self.assertStays(
            'var x;'
            ' function f(n) { x = n; return class { y = x; }; }'
            ' var C = f(1); f(2); console.log(new C().y);'
        )

    def test_pseudo_global_also_written_at_script_scope_is_not_localizable(self):
        self.assertStays('var x; x = 1; function f() { x = 2; return x; } f();')

    def test_initialized_pseudo_global_is_not_localizable(self):
        self.assertStays('var x = compute(); function f() { x = 1; return x; } f();')

    def test_pseudo_global_captured_by_nested_closure_is_not_localizable(self):
        self.assertStays('var x; function f() { x = 1; return function () { return x; }; } f()();')

    def test_reflection_surface_disables_localization(self):
        self.assertStays('var x; function f() { x = 1; return x; } eval(payload);')

    def test_a_var_the_function_reaches_through_a_name_holding_the_global_object_stays(self):
        for source in (
            'var G = this; var x; function f(v) { x = v; console.log(G.x); } f(1);',
            'var G = this; var x; function f(v) { x = v; G.x = 5; console.log(x); } f(1);',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_localizable_bindings_lists_each_pseudo_global_with_its_function(self):
        ast, cache = self._build(
            'var a, b;'
            ' function f() { a = []; b = 0; while (b < 3) { a.push(b); b = b + 1; } return a; }'
            ' f();'
        )
        f = self._func(ast, 'f')
        bindings = cache.model.root_scope.bindings
        self.assertEqual(
            localizable_bindings(cache.liveness, cache.reaching),
            [
                (bindings['a'], f),
                (bindings['b'], f),
            ],
        )

    def test_a_var_read_after_the_body_waits_while_another_run_may_store_it_stays(self):
        for source in (
            'var x; async function f(v) { x = v; await null; return x; }',
            'var x; function* f(v) { x = v; yield; return x; }',
            'var x; async function f(v) { x = v; for await (var e of [0]); return x; }',
            'var x; async function* f(v) { x = v; try { return 0; } finally { console.log(x); } }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_read_after_the_body_of_a_for_await_loop_is_left_stays(self):
        for source in (
            'var x; async function f(v) { for await (var e of [0]) { x = v; break; } return x; }',
            'var x; async function f(v) { a: for (var i = 0; i < 1; i++) { for await (var e of [0]) { x = v; continue a; } } log(x); }',
            'var x; async function f(v) { try { for await (var e of [0]) { x = v; return; } } finally { log(x); } }',
            'var x; async function f(v) { try { for await (var e of [0]) { x = v; throw 0; } } catch (r) { log(x); } }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_read_after_a_continue_to_the_head_of_a_for_await_loop_moves(self):
        self.assertMovesIntoF(
            'var x; async function f(v) { for await (var e of [0]) { x = v; console.log(x); continue; } }'
        )

    def test_a_var_of_a_function_the_host_may_run_again_while_it_runs_stays_at_the_top(self):
        source = 'var x; function onClick(n) { x = n; if (n) dispatch(); log(x); }'
        cache = ModelCache(JsParser(source).parse(), DeobfuscationOptions(entrypoints=('onClick',)))
        self.assertIsNone(self._target(cache))

    def test_a_var_of_a_function_a_host_names_moves_where_the_name_is_no_global(self):
        source = 'var x; function onClick(n) { x = n; if (n) dispatch(); log(x); }'
        options = DeobfuscationOptions(entrypoints=('onClick',), execution=ExecutionModel.commonjs)
        ast = JsParser(source).parse()
        cache = ModelCache(ast, options)
        self.assertIs(self._target(cache), self._func(ast, 'onClick'))

    def test_a_var_read_after_a_call_that_may_run_the_function_again_stays(self):
        for source in (
            'var x; function f(n) { x = n; if (n) f(n - 1); return x; }',
            'var x; function g(n) { f(n); } function f(n) { x = n; if (n) g(n - 1); return x; }',
            'var x; function f(n, g) { x = n; g(); return x; }',
            'var x; function f(n) { x = n; if (n) [0].forEach(function () { f(0); }); return x; }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_read_after_a_call_an_importer_of_the_function_may_make_stays(self):
        self.assertStays('var x; export function f(n, o) { x = n; if (n) o.m(n - 1); return x; }')

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

    def test_a_name_no_declaration_binds_used_in_one_function_moves_there(self):
        for source in (
            'function f(n) { x = []; x.push(n); return x; } console.log(f(3));',
            'function f(a) { x = 0; for (var i = 0; i < a.length; i++) x += a[i]; return x; } console.log(f([1, 2]));',
        ):
            with self.subTest(source=source):
                self.assertMovesIntoF(source)

    def test_a_name_no_declaration_binds_stored_in_strict_code_stays(self):
        for source in (
            "'use strict'; function f(v) { x = v; return x; }",
            "function f(v) { 'use strict'; x = v; return x; }",
            'class C { m(v) { x = v; return x; } }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_name_no_declaration_binds_stays_in_a_file_that_may_be_an_es_module(self):
        source = 'function f(v) { x = v; return x; }'
        cache = ModelCache(JsParser(source).parse(), DeobfuscationOptions(execution=ExecutionModel.module))
        self.assertIsNone(self._target(cache))

    def test_a_name_no_declaration_binds_the_function_deletes_stays(self):
        self.assertStays('function f(v) { x = v; delete x; return typeof x; }')

    def test_a_name_no_declaration_binds_the_program_installs_under_stays(self):
        for source in (
            "Object.defineProperty(Object.prototype, 'x', { set: function (v) {} }); function f(v) { x = v; return x; }",
            "globalThis.__defineSetter__('x', function (v) {}); function f(v) { x = v; return x; }",
            '__proto__ = { set x(v) {} }; function f(v) { x = v; return x; }',
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_name_an_install_under_another_key_leaves_moves(self):
        self.assertMovesIntoF(
            "Object.defineProperty(Object.prototype, 'y', { set: function (v) {} }); function f(v) { x = v; return x; }"
        )

    def test_a_name_a_host_inherits_keeping_its_own_value_stays(self):
        source = 'function f(v) { self = v; return self; }'
        ast = JsParser(source).parse()
        cache = ModelCache(ast, DeobfuscationOptions(environment=HostEnvironment.worker))
        self.assertIsNone(localization_target(cache.liveness, cache.reaching, cache.model.root_scope.bindings['self']))

    def test_a_global_stays_where_the_file_may_run_code_it_does_not_hold(self):
        for source in (
            'function f(v) { x = v; run(); return x; }',
            'var x; function f(v) { x = v; run(); return x; }',
            "function f(v) { x = v; document.write('<p>'); return x; }",
        ):
            with self.subTest(source=source):
                self.assertStays(source)

    def test_a_var_of_a_commonjs_file_moves_where_the_file_may_run_code_it_does_not_hold(self):
        source = 'var x; function f(v) { x = v; run(); return x; }'
        ast = JsParser(source).parse()
        cache = ModelCache(ast, DeobfuscationOptions(execution=ExecutionModel.commonjs))
        self.assertIs(self._target(cache), self._func(ast, 'f'))

    def test_a_var_dead_wherever_another_run_may_store_it_moves(self):
        for source in (
            'var x; function f(n) { x = n; console.log(x); if (n) f(n - 1); }',
            'var x; function f(n) { if (n) f(n - 1); x = n; console.log(x); }',
            'var x; async function f(v) { await null; x = v; console.log(x); }',
            'var x; async function f(v) { x = v; try { return 0; } finally { console.log(x); } }',
            'var x; function g(v) { return v + 1; } function f(n) { x = g(n); console.log(x); }',
            'var x; function f(n) { x = [n]; x.push(n); return x; }',
        ):
            with self.subTest(source=source):
                self.assertMovesIntoF(source)
