from __future__ import annotations

from test import TestBase, opportunity

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.model import Binding
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsAwaitExpression,
    JsBreakStatement,
    JsCallExpression,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsIdentifier,
    JsReturnStatement,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.parser import JsParser


class TestReaching(TestBase):

    def _query(self, source: str, name: str = 'x') -> bool:
        """
        Whether the value the first declarator named *name* stores still holds at the first read of
        that binding.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        declarator = next(
            node for node in ast.walk_in_order()
            if isinstance(node, JsVariableDeclarator)
            and isinstance(node.id, JsIdentifier)
            and node.id.name == name
        )
        assert isinstance(declarator.id, JsIdentifier) and declarator.init is not None
        binding = cache.model.binding_of(declarator.id)
        assert binding is not None
        return cache.reaching.value_preserved(binding, declarator.init, binding.reads[0])

    def _free_variable_reaches(self, source: str) -> bool:
        """
        Whether the value `x` holds where it is read in the initializer of `r` still holds where `r`
        is read.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        x = self._reference(cache, ast, 'x')
        r = self._reference(cache, ast, 'r')
        return cache.reaching.value_preserved(x, x.reads[0], r.reads[0])

    @staticmethod
    def _reference(cache: ModelCache, ast: Node, name: str) -> Binding:
        for node in ast.walk_in_order():
            if isinstance(node, JsIdentifier) and node.name == name:
                binding = cache.model.resolve(node)
                if binding is not None:
                    return binding
        raise AssertionError(F'no bound reference named {name!r}')

    def test_reaches_with_no_barrier(self):
        self.assertTrue(self._query('var x = 1; x;'))

    def test_does_not_reach_when_use_not_dominated(self):
        self.assertFalse(self._query('if (c) { var x = 1; } x;'))

    def test_does_not_reach_across_same_statement(self):
        self.assertFalse(self._query('var y = x, x = 1;'))

    def test_does_not_reach_past_mutating_call(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } m(); x;'))

    def test_reaches_read_before_mutating_call(self):
        self.assertTrue(self._query('var x = 1; function m() { x = 2; } x; m();'))

    def test_does_not_reach_past_transitive_mutating_call(self):
        self.assertFalse(self._query(
            'var x = 1;'
            ' function inner() { x = 2; }'
            ' function outer() { inner(); }'
            ' outer(); x;'
        ))

    def test_does_not_reach_across_loop_back_edge_to_a_mutating_call(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } while (c) { x; m(); }'))

    def test_reaches_across_sibling_branch_mutating_call(self):
        self.assertTrue(self._query('var x = 1; function m() { x = 2; } if (c) { m(); } else { x; }'))

    def test_does_not_reach_past_mutating_call_sharing_definition_statement(self):
        self.assertFalse(self._query('function m() { x = 2; } var x = 1, y = m(); x;'))

    def test_does_not_reach_past_mutating_call_sharing_use_statement(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } foo(m(), x);'))

    def test_does_not_reach_past_mutating_call_on_exceptional_edge(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; g(); } try { m(); } catch (e) { x; }'))

    def test_reaches_past_call_that_does_not_mutate(self):
        self.assertTrue(self._query('var x = 1; function m() { y = 2; } m(); x;'))

    def test_does_not_reach_past_a_call_a_mutator_escapes_into(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; function m() { x = 2; } g(m); x; })();'
        ))

    @opportunity
    def test_reaches_a_read_before_anything_can_call_an_escaped_mutator(self):
        self.assertTrue(self._query(
            'var x = 1; function m() { x = 2; } var alias = m; x;'
        ))

    def test_does_not_reach_past_a_call_an_aliased_mutator_escapes_into(self):
        self.assertFalse(self._query(
            'var x = 1; function m() { x = 2; } var alias = m; g(alias); x;'
        ))

    def test_does_not_reach_across_bare_lexical_declaration(self):
        self.assertFalse(self._free_variable_reaches('var r = x; let x; r;'))

    def test_reaches_when_lexical_declared_before_the_definition(self):
        self.assertTrue(self._free_variable_reaches('let x; var r = x; r;'))

    def test_reaches_across_bare_var_declaration(self):
        self.assertTrue(self._free_variable_reaches('var r = x; var x; r;'))

    def test_does_not_reach_past_a_var_declaration_that_stores_a_value_it_does_not_spell(self):
        for source in (
            'function f(a, o) { var x = a; var r = x; var {k: x} = o; return r; }',
            'function f(a, o) { var x = a; var r = x; var [x] = o; return r; }',
            'function f(a, o) { var x = a; var r = x; for (var x of o) {} return r; }',
            'function f(a, o) { var x = a; var r = x; for (var x in o) {} return r; }',
            'function f(a, o) { var x = a; var r = x; for (var [x] of o) {} return r; }',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._free_variable_reaches(source))

    def test_does_not_reach_past_a_mutating_call_the_graphs_do_not_place(self):
        self.assertFalse(self._query(
            'var x = 1; function m() { x = 2; } var f = function (a = m()) { return a; }; f(); x;'
        ))

    def test_reaches_past_an_unplaced_call_that_does_not_mutate(self):
        self.assertTrue(self._query(
            'var x = 1; function m() { y = 2; } var f = function (a = m()) { return a; }; f(); x;'
        ))

    def test_reaches_before_a_located_opaque_global_write(self):
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; console.log(x.length); globalThis[k] = 0;"
        ))

    def test_does_not_reach_after_a_located_opaque_global_write(self):
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; globalThis[k] = 0; console.log(x.length);"
        ))

    def test_does_not_reach_after_a_reflection_surface_beside_a_later_write(self):
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; eval(input); console.log(x.length); globalThis[k] = 0;"
        ))

    @opportunity
    def test_reaches_a_read_before_a_reflection_surface_beside_the_write(self):
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; console.log(x.length); eval('1'); globalThis[k] = 0;"
        ))

    def test_does_not_reach_across_a_sibling_store_in_one_statement(self):
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; var t = (globalThis[k] = 0, x.length);"
        ))

    def test_reaches_inside_the_computed_key_of_the_write(self):
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; globalThis[x.length] = 0;"
        ))

    def test_reaches_inside_the_value_of_the_write(self):
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; globalThis[k] = x.length;"
        ))

    def test_does_not_reach_inside_the_key_of_a_store_on_a_cycle(self):
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; for (var i = 0; i < 2; i++) { globalThis[x.length && k] = 0; }"
        ))

    @opportunity
    def test_reaches_inside_a_numeric_key_of_a_store_on_a_cycle(self):
        self.assertTrue(self._query(
            "var x = 'ab'; for (var i = 0; i < 2; i++) { globalThis[x.length] = 0; }"
        ))

    def test_does_not_reach_after_a_call_of_the_function_holding_the_write(self):
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; function w() { globalThis[k] = 0; } w(); console.log(x.length);"
        ))

    @opportunity
    def test_reaches_when_nothing_calls_the_function_holding_the_write(self):
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; function w() { globalThis[k] = 0; } console.log(x.length);"
        ))

    def test_does_not_reach_after_the_object_is_handed_to_a_call(self):
        self.assertFalse(self._query(
            "var x = 'ab'; q(globalThis); console.log(x.length);"
        ))

    @opportunity
    def test_reaches_a_read_before_the_object_is_handed_to_a_call(self):
        self.assertTrue(self._query(
            "var x = 'ab'; console.log(x.length); q(globalThis);"
        ))

    def test_reaches_a_read_before_a_direct_eval_in_the_owning_function(self):
        self.assertTrue(self._query(
            '(function () { var x = 1; f(x); eval(input); })();'
        ))

    def test_does_not_reach_a_read_after_a_direct_eval_in_the_owning_function(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; eval(input); f(x); })();'
        ))

    def test_does_not_reach_a_read_sharing_the_evals_statement(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; f(eval(input), x); })();'
        ))

    def test_does_not_reach_a_read_after_a_nested_closure_running_a_direct_eval(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; (function () { eval(input); })(); f(x); })();'
        ))

    @opportunity
    def test_reaches_a_read_before_a_nested_closure_running_a_direct_eval(self):
        self.assertTrue(self._query(
            '(function () { var x = 1; f(x); (function () { eval(input); })(); })();'
        ))

    def test_reaches_a_read_before_a_with_body_reference(self):
        self.assertTrue(self._query(
            '(function () { var x = 1; f(x); with (o) { x; } })();'
        ))

    def test_does_not_reach_a_read_after_a_with_body_store(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; with (o) { x = 2; } f(x); })();'
        ))

    @opportunity
    def test_reaches_a_read_after_a_with_body_that_only_reads_the_name(self):
        self.assertTrue(self._query(
            '(function () { var x = 1; with (o) { x; } f(x); })();'
        ))

    def test_does_not_reach_past_a_point_where_the_body_suspends_and_other_code_writes_the_binding(self):
        for source in (
            'var x = 1; async function f() { var r = x; await 0; return r; } x = 2;',
            'var x = 1; function* f() { var r = x; yield 0; return r; } x = 2;',
            'var x = 1; async function f(list) { var r = x; for await (var v of list) {} return r; } x = 2;',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._free_variable_reaches(source))

    def test_reaches_past_a_point_where_the_body_suspends_when_only_the_body_writes_the_binding(self):
        self.assertTrue(self._free_variable_reaches(
            'async function f() { var x = 1; var r = x; await 0; return r; }'
        ))

    def test_does_not_reach_past_a_point_where_the_body_suspends_and_another_run_of_it_writes_the_binding(self):
        for source in (
            'var x; async function f(v) { x = v; var r = x; await 0; return r; }',
            'var x; function* f(v) { x = v; var r = x; yield 0; return r; }',
            'var x; async function f(c) { if (c) { var r = x; await 0; return r; } x = 2; }',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._free_variable_reaches(source))

    def test_reaches_past_a_suspension_inside_a_nested_function(self):
        self.assertTrue(self._free_variable_reaches(
            'var x = 1; function f() { var r = x; async function g() { await 0; } return r; } x = 2;'
        ))

    def test_reaches_past_a_default_calling_a_writer_in_a_function_nothing_calls(self):
        for source in (
            'var x = 1; function m() { x = 2; } function g(a = m()) { return a; } x;',
            'var x = 1; function m() { x = 2; } var g = function (a = m()) { return a; }; x;',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._query(source))

    def test_does_not_reach_past_a_call_whose_default_calls_a_writer(self):
        for source in (
            'var x = 1; function m() { x = 2; } function g(a = m()) { return a; } g(); x;',
            'var x = 1; function m() { x = 2; } var g = function (a = m()) { return a; }; g(); x;',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._query(source))

    def _foreign_kills(self, source: str) -> tuple[Node, list[Node] | None]:
        """
        The tree of *source* and the foreign kills of the binding `x` in the body of the function
        declared as `f`.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        function = next(
            node for node in ast.walk_in_order()
            if isinstance(node, JsFunctionDeclaration)
            and node.id is not None
            and node.id.name == 'f'
        )
        return ast, cache.reaching.foreign_kills(self._reference(cache, ast, 'x'), function)

    def test_foreign_kills_are_the_suspensions_and_the_calls_of_a_function_that_writes_the_binding(self):
        ast, sites = self._foreign_kills(
            'var x;'
            ' function m() { x = 0; }'
            ' function n() { return 1; }'
            ' async function f(v) { x = v; await 0; m(); n(); return x; }'
        )
        suspension = next(
            node for node in ast.walk_in_order()
            if isinstance(node, JsAwaitExpression)
        )
        call = next(
            node for node in ast.walk_in_order()
            if isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsIdentifier)
            and node.callee.name == 'm'
        )
        assert sites is not None
        self.assertCountEqual(sites, [suspension, call])

    def test_a_suspension_is_no_foreign_kill_of_a_local_of_each_run(self):
        _, sites = self._foreign_kills('async function f() { var x = 1; await 0; return x; }')
        self.assertEqual(sites, [])

    def test_the_return_of_a_value_in_an_async_generator_is_a_foreign_kill(self):
        ast, sites = self._foreign_kills('var x; async function* f(v) { x = v; return 0; }')
        returned = next(node for node in ast.walk_in_order() if isinstance(node, JsReturnStatement))
        self.assertEqual(sites, [returned])

    def test_the_return_of_a_value_in_an_async_function_is_no_foreign_kill(self):
        _, sites = self._foreign_kills('var x; async function f(v) { x = v; return 0; }')
        self.assertEqual(sites, [])

    def test_a_call_an_escaped_writer_may_run_through_is_a_foreign_kill_or_none_are_listed(self):
        ast, sites = self._foreign_kills(
            'function outer() { var x; function m() { x = 0; } g(m);'
            ' function f() { x = 1; h(); return x; } f(); } outer();'
        )
        call = next(
            node for node in ast.walk_in_order()
            if isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsIdentifier)
            and node.callee.name == 'h'
        )
        self.assertIn(sites, (None, [call]))

    @opportunity
    def test_a_body_that_hands_no_control_away_has_no_foreign_kills_though_a_writer_escapes(self):
        _, sites = self._foreign_kills(
            'var x; function m() { x = 0; } g(m); function f() { x = 1; return x; }'
        )
        self.assertEqual(sites, [])

    def test_every_exit_of_a_for_await_body_is_a_foreign_kill(self):
        ast, sites = self._foreign_kills(
            'var x; async function f(v) {'
            ' x = v; for await (var e of [0]) { if (v) break; if (e) return 1; } return x; }'
        )
        loop = next(node for node in ast.walk_in_order() if isinstance(node, JsForOfStatement))
        exit_by_break = next(node for node in ast.walk_in_order() if isinstance(node, JsBreakStatement))
        exit_by_return = next(node for node in ast.walk_in_order() if isinstance(node, JsReturnStatement))
        assert sites is not None
        self.assertCountEqual(sites, [loop, exit_by_break, exit_by_return])

    def test_a_continue_to_the_head_of_a_for_await_loop_is_no_foreign_kill(self):
        ast, sites = self._foreign_kills(
            'var x; async function f(v) { x = v; for await (var e of [0]) { continue; } return x; }'
        )
        loop = next(node for node in ast.walk_in_order() if isinstance(node, JsForOfStatement))
        self.assertEqual(sites, [loop])

    def test_a_for_await_loop_that_is_the_clause_of_an_if_has_its_exits_listed_or_none_are(self):
        ast, sites = self._foreign_kills(
            'var x; async function f(v) {'
            ' x = v; if (v) for await (var e of [0]) { break; } return x; }'
        )
        loop = next(node for node in ast.walk_in_order() if isinstance(node, JsForOfStatement))
        exit_by_break = next(node for node in ast.walk_in_order() if isinstance(node, JsBreakStatement))
        listed = None if sites is None else sorted(id(site) for site in sites)
        self.assertIn(listed, (None, sorted([id(loop), id(exit_by_break)])))

    @opportunity
    def test_every_exit_of_a_for_await_loop_that_is_the_clause_of_an_if_is_a_foreign_kill(self):
        ast, sites = self._foreign_kills(
            'var x; async function f(v) {'
            ' x = v; if (v) for await (var e of [0]) { break; } return x; }'
        )
        loop = next(node for node in ast.walk_in_order() if isinstance(node, JsForOfStatement))
        exit_by_break = next(node for node in ast.walk_in_order() if isinstance(node, JsBreakStatement))
        assert sites is not None
        self.assertCountEqual(sites, [loop, exit_by_break])

    def test_the_value_does_not_reach_past_a_call_of_the_function_through_its_arguments(self):
        source = 'var x; function f(n) { x = n; if (n) arguments.callee(n - 1); return x; } f(2);'
        cache = ModelCache(JsParser(source).parse())
        store = next(node for node in cache.root.walk() if isinstance(node, JsAssignmentExpression))
        returned = next(node for node in cache.root.walk() if isinstance(node, JsReturnStatement))
        read = returned.argument
        assert isinstance(store.left, JsIdentifier) and store.right is not None and read is not None
        binding = cache.model.resolve(store.left)
        assert binding is not None
        self.assertFalse(cache.reaching.value_preserved(binding, store.right, read))
