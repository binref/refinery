from __future__ import annotations

from test import TestBase, opportunity

from refinery.lib.scripts.analysis.cfg import Projection
from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.keys import key_text
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.parser import JsParser


class TestDominance(TestBase):

    @staticmethod
    def _dominance(source: str):
        ast = JsParser(source).parse()
        return ast, build_dominance(build_semantic_model(ast))

    @staticmethod
    def _idents(ast, name: str) -> list[JsIdentifier]:
        return [n for n in ast.walk_in_order() if isinstance(n, JsIdentifier) and n.name == name]

    def test_sequential_statements_dominate_in_order(self):
        ast, dom = self._dominance('var a = 1; var b = 2;')
        a = self._idents(ast, 'a')[0]
        b = self._idents(ast, 'b')[0]
        self.assertTrue(dom.dominates(a, b))
        self.assertFalse(dom.dominates(b, a))

    def test_node_dominates_itself_within_a_statement(self):
        ast, dom = self._dominance('var a = 1, b = a;')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.dominates(decl, use))

    def test_conditional_definition_does_not_dominate_use_after(self):
        ast, dom = self._dominance('if (c) { var a = 1; } a;')
        decl, use = self._idents(ast, 'a')
        self.assertFalse(dom.dominates(decl, use))

    def test_definition_before_branch_dominates_use_inside(self):
        ast, dom = self._dominance('var a = 1; if (c) { a; }')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.dominates(decl, use))

    def test_loop_body_definition_does_not_dominate_use_after(self):
        ast, dom = self._dominance('while (c) { var a = 1; } a;')
        decl, use = self._idents(ast, 'a')
        self.assertFalse(dom.dominates(decl, use))

    def test_definition_after_throwing_statement_does_not_dominate_catch(self):
        ast, dom = self._dominance('try { f(); var a = 1; } catch (e) { a; }')
        decl = self._idents(ast, 'a')[0]
        use = self._idents(ast, 'a')[1]
        self.assertFalse(dom.dominates(decl, use))

    def test_dominance_does_not_cross_function_boundary(self):
        ast, dom = self._dominance('var a = 1; function g(){ return a; }')
        decl, use = self._idents(ast, 'a')
        self.assertFalse(dom.dominates(decl, use))

    def test_use_before_definition_is_not_dominated(self):
        ast, dom = self._dominance('a; var a = 1;')
        use, decl = self._idents(ast, 'a')
        self.assertFalse(dom.dominates(decl, use))

    @staticmethod
    def _func(ast, name: str) -> JsFunctionDeclaration:
        for node in ast.walk_in_order():
            if isinstance(node, JsFunctionDeclaration) and node.id is not None and node.id.name == name:
                return node
        raise AssertionError(F'no function named {name}')

    @staticmethod
    def _def(ast, name: str) -> JsIdentifier:
        for node in ast.walk_in_order():
            if isinstance(node, JsVariableDeclarator) and isinstance(node.id, JsIdentifier):
                if node.id.name == name:
                    return node.id
        raise AssertionError(F'no declarator named {name}')

    def test_runs_before_direct_call_after_definition(self):
        ast, dom = self._dominance('const c = 5; function f(){ return c; } f();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_direct_call_before_definition(self):
        ast, dom = self._dominance('function f(){ return c; } f(); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_nested_call_when_caller_runs_after_definition(self):
        ast, dom = self._dominance(
            'const c = 5; function f(){ return c; } function main(){ return f(); } main();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_nested_call_when_caller_runs_before_definition(self):
        ast, dom = self._dominance(
            'function f(){ return c; } function main(){ return f(); } main(); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_function_passed_as_argument_after_definition(self):
        ast, dom = self._dominance('const c = 5; function f(){ return c; } g(f);')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_function_passed_before_definition(self):
        ast, dom = self._dominance('function f(){ return c; } g(f); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_function_invoked_through_with(self):
        ast, dom = self._dominance('function f(){ return c; } with (o) { f(); } const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_uncalled_function_is_vacuously_safe(self):
        ast, dom = self._dominance('const c = 5; function f(){ return c; }')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_mutual_recursion_entered_after_the_definition_is_ordered(self):
        ast, dom = self._dominance(
            'const c = 5; function f(){ return g(); } function g(){ return f(); } f();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_mutual_recursion_entered_before_the_definition_is_refused(self):
        ast, dom = self._dominance(
            'function f(){ return g(); } function g(){ return f(); } f(); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_a_function_called_only_from_a_recursive_one_is_ordered_by_its_entry(self):
        ast, dom = self._dominance(
            'const c = 5; function g(){ return c; } function f(n){ return n ? f(n - 1) : g(); } f(2);')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'g')))

    def test_a_reader_only_its_own_recursion_calls_is_not_entered(self):
        ast, dom = self._dominance('var c = 5; function f(n){ return n ? f(n - 1) : c; }')
        definition, function = self._def(ast, 'c'), self._func(ast, 'f')
        self.assertTrue(dom.runs_before_function(definition, function))
        self.assertFalse(dom.runs_before_every_invocation(definition, function))

    def test_a_reader_only_an_uncalled_function_calls_is_not_entered(self):
        ast, dom = self._dominance('var c = 5; function f(){ return c; } function g(){ return f(); }')
        self.assertFalse(dom.runs_before_every_invocation(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_a_recursive_reader_called_after_the_definition_is_entered(self):
        ast, dom = self._dominance('var c = 5; function f(n){ return n ? f(n - 1) : c; } f(1);')
        self.assertTrue(dom.runs_before_every_invocation(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_a_long_chain_of_callers_is_ordered(self):
        """
        The chain holds three times as many callers as Python's default recursion limit lets a
        recursive walk nest.
        """
        count = 3000
        functions = ' '.join(F'function f{k}(){{ return f{k + 1}(); }}' for k in range(count))
        ast, dom = self._dominance(F'const c = 5; function f{count}(){{ return c; }} {functions} f0();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, F'f{count}')))

    @staticmethod
    def _func_expr(ast) -> JsFunctionExpression:
        for node in ast.walk_in_order():
            if isinstance(node, JsFunctionExpression):
                return node
        raise AssertionError('no function expression')

    @staticmethod
    def _method(ast, base: str, key: str) -> JsFunctionExpression:
        for node in ast.walk_in_order():
            left = node.left if isinstance(node, JsAssignmentExpression) else None
            if (
                isinstance(left, JsMemberExpression)
                and isinstance(left.object, JsIdentifier) and left.object.name == base
                and isinstance(left.property, JsIdentifier) and left.property.name == key
                and isinstance(node.right, JsFunctionExpression)
            ):
                return node.right
        raise AssertionError(F'no method {base}.{key}')

    def test_runs_before_directly_invoked_iife_after_definition(self):
        ast, dom = self._dominance('const c = 5; (function(){ return c; })();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_does_not_run_before_iife_before_definition(self):
        ast, dom = self._dominance('(function(){ return c; })(); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_runs_before_callback_created_after_definition(self):
        ast, dom = self._dominance('const c = 5; [0].forEach(function(){ return c; });')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_does_not_run_before_callback_created_before_definition(self):
        ast, dom = self._dominance('[0].forEach(function(){ return c; }); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_does_not_run_before_call_sharing_the_definition_statement(self):
        ast, dom = self._dominance('var x = f(), c = 5; function f(){ return c; }')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_caller_default_parameter_evaluated_before_definition(self):
        ast, dom = self._dominance(
            'inner(); const c = 5; function f(){ return c; } function inner(a = f()){ return a; }')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_caller_default_parameter_evaluated_after_definition(self):
        ast, dom = self._dominance(
            'const c = 5; function f(){ return c; } function inner(a = f()){ return a; } inner();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_namespace_method_called_after_definition(self):
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; var c = 5; NS.f();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_does_not_run_before_namespace_method_called_before_definition(self):
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; NS.f(); var c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_does_not_run_before_method_when_object_escapes(self):
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; sink(NS); var c = 5; NS.f();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_a_destructuring_write_to_a_namespace_method_does_not_obtain_it(self):
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; [NS.f] = [1]; var c = 5; console.log(NS.f);')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_a_method_call_on_the_object_hands_it_to_the_callee(self):
        forms = [
            'NS.f()',
            '(NS.f)()',
            'NS.f``',
            'NS.f?.()',
            'NS?.f()',
            'NS["f"]()',
            'NS[k]()',
        ]
        for form in forms:
            for call_first, expected in ((True, False), (False, True)):
                statements = [
                    'var NS = {}',
                    'NS.g = function(){ return c; }',
                    'NS.f = function(){ return this.g(); }',
                    'var c = 5',
                ]
                statements.insert(3 if call_first else 4, form)
                source = '; '.join(statements) + ';'
                with self.subTest(source=source):
                    ast, dom = self._dominance(source)
                    method = self._method(ast, 'NS', 'g')
                    self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), method), expected)

    def test_a_call_detaching_the_receiver_hands_the_object_to_nothing(self):
        ast, dom = self._dominance(
            'var NS = {}; NS.g = function(){ return c; }; NS.f = function(){ return 1; };'
            ' (0, NS.f)(); var c = 5; NS.g();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_every_access_hands_the_object_over_where_the_literal_has_an_accessor(self):
        ast, dom = self._dominance(
            'var NS = { get k() { return this.g(); } }; NS.g = function(){ return c; };'
            ' NS.k; var c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_every_access_hands_the_object_over_where_the_literal_sets_a_prototype(self):
        ast, dom = self._dominance(
            'var NS = { __proto__: P }; NS.g = function(){ return c; }; NS.k; var c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_a_plain_read_of_another_key_hands_a_plain_object_to_nothing(self):
        ast, dom = self._dominance(
            'var NS = {}; NS.g = function(){ return c; }; NS.k; var c = 5; NS.g();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_every_access_hands_the_object_over_where_the_program_writes_the_object_prototype(self):
        ast, dom = self._dominance(
            'Object.defineProperty(Object.prototype, "k", { get: function(){ return this.g(); } });'
            ' var NS = {}; NS.g = function(){ return c; }; NS.k; var c = 5; NS.g();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_the_establishing_write_is_a_point_where_a_setter_may_run(self):
        ast, dom = self._dominance(
            'Object.defineProperty(Object.prototype, "g", { set: function(v){ v(); } });'
            ' var NS = {}; NS.g = function(){ return c; }; var c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_a_prototype_written_through_the_object_hands_it_over(self):
        for write in ('NS.__proto__ = P', 'NS["__proto__"] = P', 'NS[key] = P'):
            with self.subTest(write=write):
                ast, dom = self._dominance(
                    F'var NS = {{}}; NS.g = function(){{ return c; }}; {write}; var c = 5; NS.k;')
                method = self._method(ast, 'NS', 'g')
                self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), method))

    def test_a_declared_host_entrypoint_has_no_orderable_invocations(self):
        """
        A host may call an entry point by name whenever the script hands it control, as `fire()`
        may. In a CommonJS file a top-level declaration is no property of the global object, so no
        host can call `OnEvent` by name there.
        """
        source = 'function OnEvent(){ return c; } fire(); var c = 5;'
        for kind, expected in ((FileKind.script, False), (FileKind.commonjs, True)):
            with self.subTest(kind.name):
                ast = JsParser(source).parse()
                dom = build_dominance(build_semantic_model(
                    ast,
                    file_kind=kind,
                    host_entrypoint=lambda name: name == 'OnEvent',
                ))
                ordered = dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'OnEvent'))
                self.assertEqual(ordered, expected)

    def test_an_export_of_a_module_in_an_import_cycle_has_no_orderable_invocations(self):
        """
        Only a module in an import cycle with this one can call an export before the body defining
        `c` has run, and a module that imports nothing is in no cycle. A module that awaits at the
        top level also finishes before any importer runs.
        """
        cases = {
            'import "./b.mjs"; export function f(){ return c; } const c = 5;': False,
            'export * from "./b.mjs"; export function f(){ return c; } const c = 5;': False,
            'export { g } from "./b.mjs"; export function f(){ return c; } const c = 5;': False,
            'import "./b.mjs"; function f(){ return c; } export { f }; const c = 5;': False,
            'export function f(){ return c; } const c = 5;': True,
            'export function f(){ return c; } for await (const x of []) {} const c = 5;': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                ordered = dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f'))
                self.assertEqual(ordered, expected)

    def test_an_anonymous_default_export_of_a_module_in_an_import_cycle_is_unordered(self):
        cases = {
            'import "./b.mjs"; export default function (){ return c; } const c = 5;': False,
            'const c = 5; export default function (){ return c; }': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                function = next(n for n in ast.walk() if isinstance(n, JsFunctionDeclaration))
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), function), expected)

    def test_a_method_the_value_of_its_install_hands_on_is_ordered_by_its_creation(self):
        cases = {
            'var NS = {}; var f = NS.g = function(){ return c; }; f(); var c = 5; NS.g();': False,
            'var NS = {}; (NS.g = function(){ return c; })(); var c = 5; NS.g();': False,
            'var NS = {}; run(NS.g = function(){ return c; }); var c = 5; NS.g();': False,
            'var c = 5; var NS = {}; var f = NS.g = function(){ return c; }; f();': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                method = self._method(ast, 'NS', 'g')
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), method), expected)

    def test_a_recursive_method_called_through_the_value_of_its_install_is_refused(self):
        ast, dom = self._dominance(
            'var o = {}; var f = o.key = function(n){ return n > 0 ? o.key(n - 1) : c; };'
            ' f(1); var c = 1;'
        )
        method = self._method(ast, 'o', 'key')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), method))

    def test_a_function_the_value_of_its_install_hands_on_is_ordered_by_its_creation(self):
        ast, dom = self._dominance(
            'var f; var h = f = function(){ return c; }; h(); var c = 5; f();'
        )
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_code_this_file_cannot_read_gives_every_access_an_accessor(self):
        cases = {
            'function main(code){ var NS = {}; NS.g = function(){ return c; };'
            ' (0, eval)(code); NS.k; const c = 5; }': False,
            'function main(code){ const c = 5; var NS = {}; NS.g = function(){ return c; };'
            ' (0, eval)(code); NS.k; }': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                method = self._method(ast, 'NS', 'g')
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), method), expected)

    def test_an_access_reaching_the_prototype_gives_every_access_an_accessor(self):
        reaches = [
            'NS.constructor.prototype',
            'NS["constructor"].prototype',
            'NS.__proto__',
            'NS[key]',
        ]
        for reach in reaches:
            source = (
                'var NS = {}; NS.g = function(){ return c; };'
                F' {reach}.__defineGetter__("k", function(){{ return this.g(); }});'
                ' NS.k; var c = 5;'
            )
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                method = self._method(ast, 'NS', 'g')
                self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), method))

    def test_an_accessor_an_earlier_call_installed_is_ordered_against_the_next_call(self):
        ast, dom = self._dominance(
            'function main(){ var NS = {}; NS.g = function(){ return c; }; NS.k; const c = 5;'
            ' NS.__proto__.__defineGetter__("k", function(){ return this.g(); }); }'
            ' main(); main();'
        )
        method = self._method(ast, 'NS', 'g')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), method))

    def test_a_method_of_an_object_a_host_reaches_is_ordered_by_its_creation(self):
        """
        A host may call a method of `handlers` whenever the script hands it control, as `fire()`
        may. In a CommonJS file a top-level declaration is no property of the global object, so no
        host reaches `handlers` there.
        """
        source = 'var handlers = {}; handlers.onload = function(){ return c; }; fire(); var c = 5;'
        for kind, expected in ((FileKind.script, False), (FileKind.commonjs, True)):
            with self.subTest(kind.name):
                ast = JsParser(source).parse()
                dom = build_dominance(build_semantic_model(
                    ast,
                    file_kind=kind,
                    host_entrypoint=lambda name: name == 'handlers',
                ))
                method = self._method(ast, 'handlers', 'onload')
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), method), expected)

    def test_a_method_of_an_object_an_importer_in_an_import_cycle_reaches_is_ordered_by_its_creation(self):
        """
        A module in an import cycle can call a method of an object this module exports before its
        body has finished, as it may during `fire()`. A module that imports nothing is in no cycle,
        and an object it does not export is reached by no importer.
        """
        cases = {
            'import "./b.mjs"; export var handlers = {}; handlers.onload = function(){ return c; }; fire(); const c = 5;': False,
            'export var handlers = {}; handlers.onload = function(){ return c; }; fire(); const c = 5;': True,
            'import "./b.mjs"; var handlers = {}; handlers.onload = function(){ return c; }; fire(); const c = 5;': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast = JsParser(source).parse()
                dom = build_dominance(build_semantic_model(ast, file_kind=FileKind.es_module))
                method = self._method(ast, 'handlers', 'onload')
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), method), expected)

    def test_a_store_before_the_one_call_of_a_library_function_does_not_precede_the_calls_of_its_loader(self):
        """
        A file of nothing but function declarations is a library: code that loads it may call `use`
        by name without calling `main` first. A file that calls `main` itself is no library.
        """
        cases = {
            'function main() { G = 5; use(); } function use() { return G; }': False,
            'function main() { G = 5; use(); } function use() { return G; } main();': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast = JsParser(source).parse()
                dom = build_dominance(build_semantic_model(ast))
                store = next(node for node in ast.walk() if isinstance(node, JsAssignmentExpression))
                self.assertEqual(dom.runs_before_function(store, self._func(ast, 'use')), expected)

    def test_a_function_installed_as_the_prototype_is_ordered_by_its_creation(self):
        """
        A function stored at `o.__proto__` becomes the prototype of `o`, so
        `o.prototype.constructor` is that function, reached without reading `o.__proto__`.
        """
        ast, dom = self._dominance(
            'var o = {}; o.__proto__ = function(){ return c; };'
            ' o.prototype.constructor(); var c = 5;'
        )
        function = self._method(ast, 'o', '__proto__')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), function))

    def test_an_export_of_a_module_that_imports_nothing_is_ordered_against_its_end(self):
        """
        An importer calls the export once the module has finished, also on a run where `c` is falsy
        and `y` is never assigned.
        """
        cases = {
            'export function f(){ return y; } if (c) { var y = 5; f(); }': False,
            'export function f(){ return y; } var y = 5; if (c) { f(); }': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                ordered = dom.runs_before_function(self._def(ast, 'y'), self._func(ast, 'f'))
                self.assertEqual(ordered, expected)

    def test_a_method_stored_after_the_definition_is_ordered_whatever_hands_its_object_over(self):
        cases = {
            'var NS = {}; NS.f = function(){}; NS.f();'
            ' const c = 5; NS.g = function(){ return c; };': True,
            'var NS = {}; NS.f = function(){}; NS.f();'
            ' NS.g = function(){ return c; }; const c = 5;': False,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                method = self._method(ast, 'NS', 'g')
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), method), expected)
        ast, dom = self._dominance('g(); const c = 5; function g(){ return c; }')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'g')))

    def test_a_method_no_code_obtains_is_not_entered_through_its_object(self):
        sources = [
            'var c = 5; var NS = { get k(){ return 1; } }; NS.g = function(){ return c; }; NS.k;',
            'var c = 5; var NS = {}; NS.f = function(){}; NS.g = function(){ return c; }; NS.f();',
        ]
        for source in sources:
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                method = self._method(ast, 'NS', 'g')
                self.assertFalse(dom.runs_before_every_invocation(self._def(ast, 'c'), method))
        ast, dom = self._dominance(
            'var c = 5; var NS = {}; NS.g = function(){ return c; }; NS.g();'
        )
        method = self._method(ast, 'NS', 'g')
        self.assertTrue(dom.runs_before_every_invocation(self._def(ast, 'c'), method))

    def test_the_methods_of_a_namespace_calling_each_other_are_ordered_by_their_installs(self):
        count = 300
        methods = [
            F'NS.f{k} = function(a){{ return NS.f{(k + 1) % count}(a) + {k}; }};'
            for k in range(count)
        ]
        calls = [F'NS.f{k}(1);' for k in range(count)]
        ast, dom = self._dominance(' '.join(['var NS = {};', *methods, *calls]))
        accesses = [node for node in ast.walk() if isinstance(node, JsMemberExpression)]
        ordered = [
            dom.runs_before_all(install, [
                access for access in accesses
                if key_text(access) == F'f{k}' and not access.is_descendant_of(install)
            ])
            for k, install in enumerate(ast.body[1:count + 1])
        ]
        self.assertEqual(ordered, [True] * count)

    def test_dominates_node_reflexive_and_ordered(self):
        ast, dom = self._dominance('var a = 1; var b = 2;')
        a = self._idents(ast, 'a')[0]
        b = self._idents(ast, 'b')[0]
        located_a = dom.locate(a)
        located_b = dom.locate(b)
        assert located_a is not None and located_b is not None
        graph, na = located_a
        nb = located_b[1]
        self.assertTrue(dom.dominates_node(graph, na, na, Projection.MAY))
        self.assertTrue(dom.dominates_node(graph, na, nb, Projection.MAY))
        self.assertFalse(dom.dominates_node(graph, nb, na, Projection.MAY))

    def test_strictly_dominates_orders_sequential_statements(self):
        ast, dom = self._dominance('var a = 1; var b = 2;')
        a = self._idents(ast, 'a')[0]
        b = self._idents(ast, 'b')[0]
        self.assertTrue(dom.strictly_dominates(a, b))
        self.assertFalse(dom.strictly_dominates(b, a))

    def test_strictly_dominates_refuses_same_statement(self):
        ast, dom = self._dominance('var a, b; a = 1, b = a;')
        _, store, use = self._idents(ast, 'a')
        self.assertTrue(dom.dominates(store, use))
        self.assertFalse(dom.strictly_dominates(store, use))

    def test_a_declarator_strictly_dominates_the_declarators_after_it(self):
        ast, dom = self._dominance('var a = 1, b = a;')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.strictly_dominates(decl, use))
        self.assertFalse(dom.dominates(use, decl))

    def test_strictly_dominates_refuses_a_node_against_itself(self):
        ast, dom = self._dominance('var a = 1;')
        a = self._idents(ast, 'a')[0]
        self.assertTrue(dom.dominates(a, a))
        self.assertFalse(dom.strictly_dominates(a, a))

    def test_runs_before_reference_later_in_scope(self):
        ast, dom = self._dominance('var a = 1; a;')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.runs_before(decl, use))

    def test_does_not_run_before_reference_earlier_in_scope(self):
        ast, dom = self._dominance('a; var a = 1;')
        use, decl = self._idents(ast, 'a')
        self.assertFalse(dom.runs_before(decl, use))

    def test_runs_before_is_strict_within_a_statement(self):
        ast, dom = self._dominance('var a, b; a = 1, b = a;')
        _, store, use = self._idents(ast, 'a')
        self.assertTrue(dom.dominates(store, use))
        self.assertFalse(dom.runs_before(store, use))

    def test_a_declarator_runs_before_the_declarators_after_it(self):
        ast, dom = self._dominance('var a = 1, b = a;')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.runs_before(decl, use))

    def test_a_declarator_runs_before_the_declarators_after_it_wherever_the_declaration_stands(self):
        for source, kind in (
            ('L: var a = 1, b = a;', FileKind.script),
            ('for (var a = 1, b = a; ; ) break;', FileKind.script),
            ('export var a = 1, b = a;', FileKind.es_module),
            ('let a = 1, b = a;', FileKind.script),
        ):
            with self.subTest(source=source):
                ast = JsParser(source).parse()
                dom = build_dominance(build_semantic_model(ast, file_kind=kind))
                decl, use = self._idents(ast, 'a')
                self.assertTrue(dom.runs_before(decl, use))

    def test_runs_before_reference_in_function_called_after_definition(self):
        ast, dom = self._dominance('var c = 5; function f(){ return c; } f();')
        reference = self._idents(ast, 'c')[1]
        self.assertTrue(dom.runs_before(self._def(ast, 'c'), reference))

    def test_does_not_run_before_reference_in_function_called_before_definition(self):
        ast, dom = self._dominance('function f(){ return c; } f(); var c = 5;')
        reference = self._idents(ast, 'c')[0]
        self.assertFalse(dom.runs_before(self._def(ast, 'c'), reference))

    def test_runs_before_all_true_when_every_reference_after(self):
        ast, dom = self._dominance('var c = 5; c; c;')
        references = self._idents(ast, 'c')[1:]
        self.assertTrue(dom.runs_before_all(self._def(ast, 'c'), references))

    def test_runs_before_all_false_when_any_reference_before(self):
        ast, dom = self._dominance('c; var c = 5; c;')
        idents = self._idents(ast, 'c')
        self.assertFalse(dom.runs_before_all(self._def(ast, 'c'), [idents[0], idents[2]]))

    def test_runs_before_all_vacuously_true_for_no_references(self):
        ast, dom = self._dominance('var c = 5;')
        self.assertTrue(dom.runs_before_all(self._def(ast, 'c'), []))

    def test_a_store_that_may_throw_is_entered_but_not_completed_before_its_handler(self):
        ast, dom = self._dominance('var r; try { r = window; } catch (e) { r; }')
        _, store, read = self._idents(ast, 'r')
        self.assertTrue(dom.strictly_dominates(store, read))
        self.assertFalse(dom.completes_before(store, read))
        self.assertFalse(dom.runs_before(store, read))

    def test_a_store_that_cannot_throw_completes_before_its_handler(self):
        ast, dom = self._dominance('var r; try { r = 1; g(); } catch (e) { r; }')
        _, store, read = self._idents(ast, 'r')
        self.assertTrue(dom.completes_before(store, read))
        self.assertTrue(dom.runs_before(store, read))

    def test_a_declarator_behind_one_that_may_throw_does_not_run_before_a_later_call(self):
        ast, dom = self._dominance(
            'try { var a = window, w = 5; } catch (e) {} function g() { return w; } g();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'w'), self._func(ast, 'g')))

    def test_a_declaration_that_cannot_throw_runs_before_a_call_after_its_handler(self):
        ast, dom = self._dominance(
            'try { var w = 5; h(); } catch (e) {} function g() { return w; } g();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'w'), self._func(ast, 'g')))

    def test_a_function_declared_in_a_try_block_in_a_loop_is_in_place_for_a_call_after_it(self):
        ast, dom = self._dominance(
            'function g() { for (var i = 0; i < 2; i++) { try { function f() { return i; } f(); } catch (e) {} } }')
        declaration, call = self._idents(ast, 'f')
        self.assertTrue(dom.binding_established_before(dom.model.binding_of(declaration), call))

    def test_a_function_declared_after_a_throw_in_its_try_block_is_not_in_place_for_the_handler(self):
        ast, dom = self._dominance(
            'function g() { for (var i = 0; i < 2; i++) { try { if (i === 0) { throw 1; } '
            'function f() {} f(); } catch (e) { f; } } }')
        _, call, handler = self._idents(ast, 'f')
        self.assertTrue(dom.binding_established_before(dom.model.resolve(call), call))
        self.assertFalse(dom.binding_established_before(dom.model.resolve(handler), handler))

    def test_a_block_function_is_not_in_place_after_its_block_where_a_throw_skips_the_block(self):
        ast, dom = self._dominance(
            'function g() { for (var i = 0; i < 3; i++) { try { if (i === 0) { throw 1; } '
            '{ function f() { return i; } } } catch (e) {} f; } }')
        _, read = self._idents(ast, 'f')
        self.assertFalse(dom.binding_established_before(dom.model.resolve(read), read))

    def test_a_function_declared_in_a_try_block_in_a_loop_is_not_in_place_after_the_loop(self):
        ast, dom = self._dominance(
            'function g(n) { for (var i = 0; i < n; i++) { try { function f() { return i; } f(); } catch (e) {} } f(); }')
        _, call, after = self._idents(ast, 'f')
        self.assertTrue(dom.binding_established_before(dom.model.resolve(call), call))
        self.assertFalse(dom.binding_established_before(dom.model.resolve(after), after))

    @opportunity
    def test_a_function_declared_in_a_try_block_of_a_loop_that_runs_is_in_place_after_the_loop(self):
        ast, dom = self._dominance(
            'function g() { for (var i = 0; i < 2; i++) { try { function f() { return i; } f(); } catch (e) {} } f(); }')
        _, _, after = self._idents(ast, 'f')
        self.assertTrue(dom.binding_established_before(dom.model.resolve(after), after))

    def test_a_call_through_the_block_name_is_in_place_before_the_declaration_runs(self):
        ast, dom = self._dominance('function g() { { f(); function f() {} } }')
        call = next(node for node in ast.walk() if isinstance(node, JsCallExpression))
        self.assertTrue(dom.callee_established_before(call))

    def test_a_call_through_the_copy_is_in_place_only_once_the_declaration_has_run(self):
        ast, dom = self._dominance('function g() { f(); { function f() {} } f(); }')
        before, after = (node for node in ast.walk_in_order() if isinstance(node, JsCallExpression))
        self.assertFalse(dom.callee_established_before(before))
        self.assertTrue(dom.callee_established_before(after))

    def test_a_for_in_const_is_past_its_dead_zone_in_the_body(self):
        ast, dom = self._dominance('function g(o) { for (const k in o) { k; } }')
        declaration, read = self._idents(ast, 'k')
        self.assertTrue(dom.past_dead_zone(dom.model.binding_of(declaration), read))

    def test_a_var_loop_target_runs_before_a_read_in_the_body_and_not_after_the_loop(self):
        ast, dom = self._dominance('function g(xs) { var x = 0; for (x of xs) { x; } x; }')
        _, target, body, after = self._idents(ast, 'x')
        self.assertTrue(dom.runs_before(target, body))
        self.assertFalse(dom.runs_before(target, after))

    def test_a_for_of_subject_runs_before_the_body_once(self):
        ast, dom = self._dominance('function g(xs) { var x; for (var k of (x = xs)) { x; } x; }')
        _, store, body, after = self._idents(ast, 'x')
        self.assertTrue(dom.runs_before(store, body))
        self.assertTrue(dom.runs_before(store, after))


class TestAStoreItsStatementMaySkip(TestBase):

    SKIPPED = (
        'x && (c = 5);',
        'x ? (c = 5) : 0;',
        'x ? 0 : (c = 5);',
        'x ||= (c = 5);',
        'x &&= (c = 5);',
        'x ??= (c = 5);',
        'o?.f(c = 5);',
        'o?.p[c = 5];',
        'o?.p.f(c = 5);',
        'switch (x) { case 0: break; case (c = 5): break; }',
        '({ a: b = (c = 5) } = o);',
        '[b = (c = 5)] = o;',
    )

    PERFORMED = (
        '(c = 5) && x;',
        '(c = 5) ? x : 0;',
        'x += (c = 5);',
        'o.f(c = 5);',
        'switch (c = 5) { case 0: break; }',
    )

    @staticmethod
    def _store_and_reads(statement: str):
        source = F'var c, b, x, o; {statement} c; function f() {{ return c; }} f();'
        ast = JsParser(source).parse()
        dom = build_dominance(build_semantic_model(ast))
        store, read, inner = [
            node for node in ast.walk_in_order()
            if isinstance(node, JsIdentifier) and node.name == 'c'
        ][1:]
        function = next(node for node in ast.walk() if isinstance(node, JsFunctionDeclaration))
        return dom, store, read, inner, function

    def test_a_skipped_store_runs_before_nothing(self):
        for statement in self.SKIPPED:
            with self.subTest(statement):
                dom, store, read, inner, function = self._store_and_reads(statement)
                self.assertFalse(dom.completes_before(store, read))
                self.assertFalse(dom.runs_before(store, read))
                self.assertFalse(dom.runs_before_all(store, [read]))
                self.assertFalse(dom.runs_before(store, inner))
                self.assertFalse(dom.runs_before_function(store, function))
                self.assertFalse(dom.runs_before_every_invocation(store, function))

    def test_a_performed_store_runs_before_what_follows_its_statement(self):
        for statement in self.PERFORMED:
            with self.subTest(statement):
                dom, store, read, inner, function = self._store_and_reads(statement)
                self.assertTrue(dom.completes_before(store, read))
                self.assertTrue(dom.runs_before(store, read))
                self.assertTrue(dom.runs_before(store, inner))
                self.assertTrue(dom.runs_before_function(store, function))

    def test_nothing_after_the_statement_precedes_a_store_it_may_skip(self):
        for statement in self.SKIPPED + self.PERFORMED:
            with self.subTest(statement):
                dom, store, read, inner, _ = self._store_and_reads(statement)
                self.assertTrue(dom.cannot_precede(read, store))
                self.assertTrue(dom.cannot_precede(inner, store))

    def test_a_read_before_the_statement_may_precede_the_store(self):
        source = 'var c, x; c; x && (c = 5);'
        ast = JsParser(source).parse()
        dom = build_dominance(build_semantic_model(ast))
        _, read, store = [
            node for node in ast.walk_in_order()
            if isinstance(node, JsIdentifier) and node.name == 'c'
        ]
        self.assertFalse(dom.cannot_precede(read, store))

    def test_a_binding_stored_on_some_runs_is_not_established(self):
        dom, store, read, _, _ = self._store_and_reads('x && (c = 5);')
        self.assertFalse(dom.binding_established_before(dom.model.resolve(store), read))

    def test_nothing_is_ordered_against_an_anchor_in_a_field_initializer(self):
        source = 'function f() { class A { v = c(); } g(); return new A().v; }'
        ast = JsParser(source).parse()
        dom = build_dominance(build_semantic_model(ast))
        anchor, after = [
            node for node in ast.walk_in_order()
            if isinstance(node, JsIdentifier) and node.name in ('c', 'g')
        ]
        self.assertFalse(dom.cannot_precede(after, anchor))


class TestADefinitionInsideAFunctionCalledWhereItIsWritten(TestBase):

    @staticmethod
    def _answers(source: str) -> tuple[bool, bool, bool, bool]:
        ast = JsParser(source).parse()
        model = build_semantic_model(ast)
        dominance = build_dominance(model)
        definition = next(node for node in ast.walk() if isinstance(node, JsAssignmentExpression))
        reader = next(
            node for node in ast.walk()
            if isinstance(node, JsFunctionDeclaration) and node.id is not None and node.id.name == 'f'
        )
        read = next(node for node in reader.walk() if isinstance(node, JsIdentifier) and node.name == 'T')
        binding = model.resolve(read)
        assert binding is not None
        return (
            dominance.runs_before(definition, read),
            dominance.runs_before_function(definition, reader),
            dominance.runs_before_every_invocation(definition, reader),
            dominance.binding_established_before(binding, read),
        )

    def test_the_call_orders_the_definition_for_a_function_called_after_it(self):
        source = 'var T; (function () { T = ["a", "b"]; })(); function f(i) { return T[i]; } console.log(f(0), f(1));'
        self.assertEqual(self._answers(source), (True, True, True, True))

    def test_nested_calls_order_the_definition(self):
        source = 'var T; (function () { (function () { T = ["a"]; })(); })(); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (True, True, True, True))

    def test_a_return_before_the_definition_orders_nothing(self):
        source = 'var T; (function (c) { if (c) { return; } T = ["a"]; })(c); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (False, False, False, False))

    def test_an_async_function_orders_nothing(self):
        source = 'var T; (async function () { await 0; T = ["a"]; })(); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (False, False, False, False))

    def test_a_generator_function_orders_nothing(self):
        source = 'var T; (function* () { T = ["a"]; })(); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (False, False, False, False))

    def test_a_call_on_one_branch_orders_nothing(self):
        source = 'var T; c && (function () { T = ["a"]; })(); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (False, False, False, False))

    def test_a_definition_on_one_branch_inside_a_try_with_an_empty_finally_orders_nothing(self):
        source = 'var T; (function (c) { try { if (c) { } else { T = ["a"]; } } finally { } })(c); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (False, False, False, False))

    def test_a_read_the_call_makes_before_the_definition_is_not_ordered(self):
        source = 'var T; function f() { return T[0]; } (function () { f(); T = ["a"]; })(); f();'
        self.assertEqual(self._answers(source), (False, False, False, False))

    def test_a_function_called_later_but_not_where_it_is_written_orders_all_or_nothing(self):
        source = 'var T; var g = function () { T = ["a"]; }; g(); function f() { return T[0]; } f();'
        self.assertIn(self._answers(source), ((False, False, False, False), (True, True, True, True)))

    @opportunity
    def test_a_function_called_later_through_the_name_holding_it_orders_the_definition(self):
        source = 'var T; var g = function () { T = ["a"]; }; g(); function f() { return T[0]; } f();'
        self.assertEqual(self._answers(source), (True, True, True, True))
