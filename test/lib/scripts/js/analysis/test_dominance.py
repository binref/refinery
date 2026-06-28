from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import (
    JsFunctionDeclaration,
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

    def test_does_not_run_before_escaping_function(self):
        ast, dom = self._dominance('const c = 5; function f(){ return c; } g(f);')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_uncalled_function_is_vacuously_safe(self):
        ast, dom = self._dominance('const c = 5; function f(){ return c; }')
        self.assertTrue(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))

    def test_mutually_recursive_calls_are_refused(self):
        ast, dom = self._dominance(
            'const c = 5; function f(){ return g(); } function g(){ return f(); } f();')
        self.assertFalse(dom.runs_before_function(self._def(ast, 'c'), self._func(ast, 'f')))
