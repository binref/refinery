from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
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

    def test_dominates_node_reflexive_and_ordered(self):
        ast, dom = self._dominance('var a = 1; var b = 2;')
        a = self._idents(ast, 'a')[0]
        b = self._idents(ast, 'b')[0]
        na = dom.cfg_node_of(a)
        nb = dom.cfg_node_of(b)
        assert na is not None and nb is not None
        self.assertTrue(dom.dominates_node(na, na))
        self.assertTrue(dom.dominates_node(na, nb))
        self.assertFalse(dom.dominates_node(nb, na))
