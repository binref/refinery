from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsIdentifier
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
