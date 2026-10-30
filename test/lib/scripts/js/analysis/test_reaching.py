from __future__ import annotations

from test import TestBase

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
        Whether the value of the first declarator named *name* reaches its first read unchanged, as
        `ReachingModel.value_preserved` reports it. Every case below is single-read, so the first read is
        the use under test.
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
        Whether the value of `x`, read inside the initializer of `r`, still holds where `r` is later
        used, as `ReachingModel.value_preserved` reports it — the free-variable check the inliner makes
        before relocating `r`'s value, with a declaration of `x` the potential kill between the two.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        x = self._reference(cache, ast, 'x')
        r = self._reference(cache, ast, 'r')
        return cache.reaching.value_preserved(x, x.reads[0], r.reads[0])

    @staticmethod
    def _reference(cache: ModelCache, ast: Node, name: str) -> Binding:
        """
        The binding of the first bound reference named *name* in *ast*.
        """
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
        """
        The use in `y = x` is evaluated by the declarator before the definition `x = 1`, so the value
        is not reported as reaching it — the verdict that keeps `var y = x, x = 1` from folding `y`
        to `1` when `x` is undefined at the read.
        """
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
        """
        `m()` runs at the end of each iteration and the loop edge carries control back to the read, so a
        later iteration sees the mutated value — the kill is on a path back to the use.
        """
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } while (c) { x; m(); }'))

    def test_reaches_across_sibling_branch_mutating_call(self):
        """
        `m()` is on the branch the read is not on and cannot reach it, so the value still holds at the
        read — a precision statement position could not express.
        """
        self.assertTrue(self._query('var x = 1; function m() { x = 2; } if (c) { m(); } else { x; }'))

    def test_does_not_reach_past_mutating_call_sharing_definition_statement(self):
        self.assertFalse(self._query('function m() { x = 2; } var x = 1, y = m(); x;'))

    def test_does_not_reach_past_mutating_call_sharing_use_statement(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } foo(m(), x);'))

    def test_does_not_reach_past_mutating_call_on_exceptional_edge(self):
        """
        `m()` may throw after changing the value, and the only path from it to the catch-bound read is
        the exceptional edge, which the reachability follows — so the kill lies between.
        """
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } try { m(); } catch (e) { x; }'))

    def test_reaches_past_call_that_does_not_mutate(self):
        self.assertTrue(self._query('var x = 1; function m() { y = 2; } m(); x;'))

    def test_does_not_reach_when_a_mutator_escapes(self):
        """
        `m` is aliased, so it can be invoked at a point no call site enumerates; the value of `x` it
        writes could change anywhere, so no read is reported as reached.
        """
        self.assertFalse(self._query(
            'var x = 1; function m() { x = 2; } var alias = m; x;'
        ))

    def test_does_not_reach_across_bare_lexical_declaration(self):
        """
        `let x;` ends the binding's temporal dead zone: a read taken before it observes a throw, a read
        after it observes the declared value, so the two are not the same value and the earlier read
        must not be relocated past the declaration.
        """
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
        """
        A parameter default of a function *expression* is evaluated when that function is invoked,
        which is a point no node of the enclosing graph stands for, so `locate` answers `None` for
        the call inside it. That is not the same answer as the call belonging to another graph: it
        says the call cannot be ordered here, and a call that may write the binding then has to
        refuse rather than be dropped from the kills.
        """
        self.assertFalse(self._query(
            'var x = 1; function m() { x = 2; } var f = function (a = m()) { return a; }; f(); x;'
        ))

    def test_reaches_past_an_unplaced_call_that_does_not_mutate(self):
        """
        The floor under the test above: refusing on every unplaced call refuses every script that
        gives a function expression a parameter default.
        """
        self.assertTrue(self._query(
            'var x = 1; function m() { y = 2; } var f = function (a = m()) { return a; }; f(); x;'
        ))

    def test_reaches_before_a_located_opaque_global_write(self):
        """
        The write stores a property on the global object under a key only the runtime resolves, so it
        may replace this script-scope binding's name — but only at the statement spelling the store,
        which runs after the read, so the value still holds there.
        """
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; console.log(x.length); globalThis[k] = 0;"
        ))

    def test_does_not_reach_after_a_located_opaque_global_write(self):
        """
        The same write ahead of the read may have replaced the name by then, so the read is not
        reported as reached — the located kill does the work volatility used to do.
        """
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; globalThis[k] = 0; console.log(x.length);"
        ))

    def test_does_not_reach_under_a_reflection_surface_beside_the_write(self):
        """
        The read stands before both the surface and the write, but the `eval` names globals at
        runtime from anywhere, so the binding stays volatile: a located site answers only the write's
        share of the hazard.
        """
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; console.log(x.length); eval('1'); globalThis[k] = 0;"
        ))

    def test_does_not_reach_across_a_sibling_store_in_one_statement(self):
        """
        The comma evaluates the store before the read that follows it in the same statement, and
        the two share one control-flow node, which orders them no further, so the read is not
        reported as reached — it may observe the written value. Node prints `0` for the twin with
        the read spelled `x`.
        """
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; var t = (globalThis[k] = 0, x.length);"
        ))

    def test_reaches_inside_the_computed_key_of_the_write(self):
        """
        The store is the last step of the assignment spelling it (§13.15.5): the key is evaluated
        first, so a use inside it observes the value the definition established, and the write's own
        node is not a kill for that use. Node prints `0 undefined` for the script-model twin
        `globalThis[x.length > 0 ? 'x' : 'zz'] = 0` — the key was computed while `x` still held its
        value, and the store replaced it afterwards.
        """
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; globalThis[x.length] = 0;"
        ))

    def test_reaches_inside_the_value_of_the_write(self):
        """
        The same ordering for the assigned value: it is evaluated before the store runs, so a use
        inside it observes the definition's value. Node prints `true` for the script-model twin
        `globalThis['x'] = (x === 'ab')`.
        """
        self.assertTrue(self._query(
            "var x = 'ab'; var k = e; globalThis[k] = x.length;"
        ))

    def test_does_not_reach_inside_the_key_of_a_store_on_a_cycle(self):
        """
        The same use inside the same key, but the statement stands in a loop: a later iteration
        evaluates the key after an earlier iteration's store, so a store on a cycle kills the read
        and the value is not reported as reached. Node prints `0 number` for the script-model twin
        run twice — the second iteration's key was computed from the written value.
        """
        self.assertFalse(self._query(
            "var x = 'ab'; for (var i = 0; i < 2; i++) { globalThis[x.length] = 0; }"
        ))

    def test_does_not_reach_when_the_write_sits_in_another_functions_graph(self):
        """
        The write stands inside a function, which runs at its invocation — a point no node of this
        graph stands for — so the site cannot be ordered here and the binding stays volatile.
        """
        self.assertFalse(self._query(
            "var x = 'ab'; var k = e; function w() { globalThis[k] = 0; } console.log(x.length);"
        ))

    def test_does_not_reach_when_the_object_is_handed_to_a_call(self):
        """
        A call handed the global object may write a property of it under a key no text spells, and
        the hand-over is a fact that holds without a site: no located kill answers it, so the
        binding stays volatile even though the read stands before the call.
        """
        self.assertFalse(self._query(
            "var x = 'ab'; console.log(x.length); q(globalThis);"
        ))

    def test_reaches_a_read_before_a_direct_eval_in_the_owning_function(self):
        """
        The `eval` in the same function can rebind the local, but only at the statement spelling the
        call, which runs after the read, so the value still holds there — the located kill doing
        the work volatility used to do for every read alike.
        """
        self.assertTrue(self._query(
            '(function () { var x = 1; f(x); eval(input); })();'
        ))

    def test_does_not_reach_a_read_after_a_direct_eval_in_the_owning_function(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; eval(input); f(x); })();'
        ))

    def test_does_not_reach_a_read_sharing_the_evals_statement(self):
        """
        The read is an argument of the call that also runs the `eval`, and the two share one
        control-flow node, which orders them no further, so the value is not reported as reaching it.
        """
        self.assertFalse(self._query(
            '(function () { var x = 1; f(eval(input), x); })();'
        ))

    def test_does_not_reach_when_the_direct_eval_sits_in_a_nested_closure(self):
        """
        The `eval` stands inside a nested function, which runs at its invocation — a point no node
        of this graph stands for — so the site cannot be ordered here and the binding stays
        volatile.
        """
        self.assertFalse(self._query(
            '(function () { var x = 1; f(x); (function () { eval(input); })(); })();'
        ))

    def test_reaches_a_read_before_a_with_body_reference(self):
        """
        The reference inside the `with` body consults the `with` object first, and a getter there
        could rebind the local, but only at the statement spelling the reference, which runs after
        the read — so the value still holds at the earlier read.
        """
        self.assertTrue(self._query(
            '(function () { var x = 1; f(x); with (o) { x; } })();'
        ))

    def test_does_not_reach_a_read_after_a_with_body_reference(self):
        self.assertFalse(self._query(
            '(function () { var x = 1; with (o) { x; } f(x); })();'
        ))

    def test_does_not_reach_past_a_point_where_the_body_suspends_and_other_code_writes_the_binding(self):
        """
        Other code runs while the body waits at an `await`, a `yield` or the head of a `for await`
        loop, and the store `x = 2` outside the body may be that code.
        """
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
        """
        Every call of `f` shares `x`, and another call may write it while this one waits: after
        `f(1); f(2);` the first call resumes with `x` holding `2`.
        """
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

    def _foreign_kills(self, source: str) -> tuple[Node, list[Node] | None]:
        """
        The tree of *source* and the points
        `refinery.lib.scripts.js.analysis.reaching.ReachingModel.foreign_kills` lists for `x` in the
        body of the function `f`.
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

    def test_foreign_kills_cannot_be_listed_when_a_writer_escapes(self):
        _, sites = self._foreign_kills(
            'var x; function m() { x = 0; } g(m); function f() { x = 1; return x; }'
        )
        self.assertIsNone(sites)

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

    def test_foreign_kills_cannot_be_listed_for_a_for_await_loop_the_graph_cannot_place(self):
        _, sites = self._foreign_kills(
            'var x; async function f(v) {'
            ' x = v; if (v) for await (var e of [0]) { break; } return x; }'
        )
        self.assertIsNone(sites)

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
