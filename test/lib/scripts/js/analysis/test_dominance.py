from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.analysis.cfg import Projection
from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
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
        """
        `f()` may throw before `var a = 1` runs, so a path reaches the handler without the definition;
        the definition therefore does not dominate the catch-bound use.
        """
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
        """
        `f` is called only inside `main`, and `main` is called after the definition, so every
        invocation of `f` runs after it — the lookup-table-read-in-a-callee shape the b91 sample uses.
        """
        ast, dom = self._dominance(
            'const c = 5; function f(){ return c; } function main(){ return f(); } main();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_nested_call_when_caller_runs_before_definition(self):
        ast, dom = self._dominance(
            'function f(){ return c; } function main(){ return f(); } main(); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_function_passed_as_argument_after_definition(self):
        """
        `f` escapes into `g`, which may call it at any later point, but the value it captures is
        established before `f` is even passed — so every invocation still runs after the definition.
        """
        ast, dom = self._dominance('const c = 5; function f(){ return c; } g(f);')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_function_passed_before_definition(self):
        """
        `f` is handed to `g` before the definition runs, so `g` could invoke it while the value is
        still unset; the reference that lets it escape is not dominated by the definition.
        """
        ast, dom = self._dominance('function f(){ return c; } g(f); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_function_invoked_through_with(self):
        """
        `f` is invoked inside a `with` body — a call site no static reference records, since the name
        may denote a property of the `with` object — and that call runs before the definition. The
        with-body reference makes the points unorderable (mirroring `function_escapes`), so the
        definition is not judged to run before every invocation; ordering it against the static
        references alone would miss the earlier dynamic call.
        """
        ast, dom = self._dominance('function f(){ return c; } with (o) { f(); } const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_uncalled_function_is_vacuously_safe(self):
        ast, dom = self._dominance('const c = 5; function f(){ return c; }')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_mutually_recursive_calls_are_refused(self):
        ast, dom = self._dominance(
            'const c = 5; function f(){ return g(); } function g(){ return f(); } f();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

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
        """
        A callback escapes into `forEach`, which invokes it synchronously or not at all, but the value
        it reads is established before the callback is even created — so no invocation precedes it.
        """
        ast, dom = self._dominance('const c = 5; [0].forEach(function(){ return c; });')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_does_not_run_before_callback_created_before_definition(self):
        """
        The callback is created — and could be invoked — before the definition runs, so the value it
        reads is not yet established; its creation point is not dominated by the definition.
        """
        ast, dom = self._dominance('[0].forEach(function(){ return c; }); const c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func_expr(ast)))

    def test_does_not_run_before_call_sharing_the_definition_statement(self):
        """
        The earlier declarator `x = f()` calls `f` before the later `c = 5` runs, so `f` reads `c` while
        it is unset; the call and the definition share one statement, which statement-granularity
        dominance cannot order, so the definition must not be treated as running before the call.
        """
        ast, dom = self._dominance('var x = f(), c = 5; function f(){ return c; }')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_does_not_run_before_caller_default_parameter_evaluated_before_definition(self):
        """
        `f` is referenced only in `inner`'s default parameter, which runs when `inner` is invoked; the
        hoisted `inner()` runs before the definition, so that invocation reads `c` early.
        """
        ast, dom = self._dominance(
            'inner(); const c = 5; function f(){ return c; } function inner(a = f()){ return a; }')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_caller_default_parameter_evaluated_after_definition(self):
        """
        `f` is referenced only in `inner`'s default parameter, and `inner` is called after the
        definition, so every evaluation of that parameter — and hence every call of `f` — runs after it.
        """
        ast, dom = self._dominance(
            'const c = 5; function f(){ return c; } function inner(a = f()){ return a; } inner();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_runs_before_namespace_method_called_after_definition(self):
        """
        `NS.f` is stored as a method of a non-escaping local object and invoked only after `c` is
        assigned; the method's invocation is ordered by that call site, not by its earlier creation, so
        the definition runs before every call even though it is written after the method is created.
        """
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; var c = 5; NS.f();')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_does_not_run_before_namespace_method_called_before_definition(self):
        """
        The `NS.f()` call precedes `var c = 5`, so the method reads `c` while it is still unset; the
        property read that pins the call runs before the definition, so it is not judged to run before.
        """
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; NS.f(); var c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_does_not_run_before_method_when_object_escapes(self):
        """
        `NS` is passed to `sink`, which could invoke `NS.f()` before `c` is assigned; because the object
        escapes, the method's call sites are no longer enumerable through property reads alone, so the
        definition is not judged to run before every invocation despite the later in-scope call.
        """
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; sink(NS); var c = 5; NS.f();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_a_destructuring_write_to_a_namespace_method_does_not_obtain_it(self):
        """
        A destructuring target writes `NS.f` without reading it, so the write before the definition
        hands the method to nothing, and the one read that does obtain it runs after.
        """
        ast, dom = self._dominance(
            'var NS = {}; NS.f = function(){ return c; }; [NS.f] = [1]; var c = 5; console.log(NS.f);')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'f')))

    def test_a_method_call_on_the_object_hands_it_to_the_callee(self):
        """
        A method call on `NS` runs its callee with `NS` as `this`, and the callee can call `NS.g`
        through it without spelling `NS.g` anywhere. Every call form that passes the receiver is such
        a point, so a call before the definition refuses and the same call after it does not.
        """
        forms = [
            'NS.f()',
            '(NS.f)()',
            'NS.f``',
            'NS.f?.()',
            'NS?.f()',
            "NS['f']()",
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
        """
        `(0, NS.f)()` calls `f` with no receiver, so `f` cannot reach `NS.g` through `this` and the
        call before the definition orders nothing about `NS.g`.
        """
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
            "Object.defineProperty(Object.prototype, 'k', { get: function(){ return this.g(); } });"
            ' var NS = {}; NS.g = function(){ return c; }; NS.k; var c = 5; NS.g();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_the_establishing_write_is_a_point_where_a_setter_may_run(self):
        """
        A setter installed on `Object.prototype` receives the function the write stores, and may call
        it right there; the write itself precedes the definition, so nothing orders the call.
        """
        ast, dom = self._dominance(
            "Object.defineProperty(Object.prototype, 'g', { set: function(v){ v(); } });"
            ' var NS = {}; NS.g = function(){ return c; }; var c = 5;')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._method(ast, 'NS', 'g')))

    def test_a_prototype_written_through_the_object_hands_it_over(self):
        for write in ('NS.__proto__ = P', "NS['__proto__'] = P", 'NS[key] = P'):
            with self.subTest(write=write):
                ast, dom = self._dominance(
                    F'var NS = {{}}; NS.g = function(){{ return c; }}; {write}; var c = 5; NS.k;')
                method = self._method(ast, 'NS', 'g')
                self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), method))

    def test_a_declared_host_entrypoint_has_no_orderable_invocations(self):
        """
        A host calls an entry point by name whenever the script hands it control, which the call to
        `fire` may do before the definition runs. Under the module model the declaration never
        becomes a property of the global object, so the host cannot reach it by name.
        """
        source = 'function OnEvent(){ return c; } fire(); var c = 5;'
        for module_scope, expected in ((False, False), (True, True)):
            with self.subTest(module_scope=module_scope):
                ast = JsParser(source).parse()
                dom = build_dominance(
                    build_semantic_model(ast),
                    module_scope=module_scope,
                    host_entrypoint=lambda name: name == 'OnEvent',
                )
                ordered = dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'OnEvent'))
                self.assertEqual(ordered, expected)

    def test_an_export_of_a_module_in_an_import_cycle_has_no_orderable_invocations(self):
        """
        A module that imports another can be in a cycle with it, and the other module can then call
        an exported declaration before the body that defines `c` has run. A module that imports
        nothing runs its whole body before any importer calls into it, and so does one that awaits:
        an importer waits for it to finish.
        """
        cases = {
            "import './b.mjs'; export function f(){ return c; } const c = 5;": False,
            "export * from './b.mjs'; export function f(){ return c; } const c = 5;": False,
            "export { g } from './b.mjs'; export function f(){ return c; } const c = 5;": False,
            "import './b.mjs'; function f(){ return c; } export { f }; const c = 5;": False,
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
            "import './b.mjs'; export default function (){ return c; } const c = 5;": False,
            'const c = 5; export default function (){ return c; }': True,
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ast, dom = self._dominance(source)
                function = next(n for n in ast.walk() if isinstance(n, JsFunctionDeclaration))
                self.assertEqual(dom.runs_before_function(self._def(ast, 'c'), function), expected)

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
        """
        A pair sharing one statement shares one control-flow node, so strict dominance refuses it —
        where the reflexive `dominates` accepts the same pair.
        """
        ast, dom = self._dominance('var a = 1, b = a;')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.dominates(decl, use))
        self.assertFalse(dom.strictly_dominates(decl, use))

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
        """
        A reference sharing the definition's statement cannot be ordered by statement-granularity
        dominance, so strict `runs_before` refuses it — where reflexive `dominates` accepts the same
        pair.
        """
        ast, dom = self._dominance('var a = 1, b = a;')
        decl, use = self._idents(ast, 'a')
        self.assertTrue(dom.dominates(decl, use))
        self.assertFalse(dom.runs_before(decl, use))

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
        """
        Reading `window` may throw, and the handler runs exactly on that run, so the statement of
        the store dominates the read in the handler without having completed before it.
        """
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
