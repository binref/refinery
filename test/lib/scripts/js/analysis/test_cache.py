from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.liveness import build_liveness
from refinery.lib.scripts.js.model import JsIdentifier, JsVariableDeclaration
from refinery.lib.scripts.js.parser import JsParser


class TestModelCache(TestBase):

    @staticmethod
    def _script(source: str):
        return JsParser(source).parse()

    @staticmethod
    def _first_declaration(script) -> JsVariableDeclaration:
        return next(
            stmt for stmt in script.body if isinstance(stmt, JsVariableDeclaration)
        )

    def test_model_is_memoized_while_the_tree_is_unchanged(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        first = cache.model
        self.assertIs(cache.model, first)

    def test_mutating_the_cached_tree_rebuilds_the_model(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        first = cache.model
        _remove_from_parent(self._first_declaration(script))
        self.assertIsNot(cache.model, first)

    def test_mutating_an_unrelated_tree_keeps_the_cached_model(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        first = cache.model
        unrelated = self._script('var c = 3; var d = 4;')
        _remove_from_parent(self._first_declaration(unrelated))
        self.assertIs(cache.model, first)

    def test_control_flow_is_memoized_while_the_tree_is_unchanged(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        first = cache.control_flow
        self.assertIs(cache.control_flow, first)

    def test_mutating_the_cached_tree_rebuilds_the_control_flow(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        first = cache.control_flow
        _remove_from_parent(self._first_declaration(script))
        self.assertIsNot(cache.control_flow, first)

    def test_shared_control_flow_does_not_change_dominance_or_liveness(self):
        """
        The dominance and liveness models the cache builds share its one `ControlFlowModel`; their
        answers must match models built independently over their own graphs.
        """
        script = self._script(
            'var a = 1; function f(){ var x; x = 1; x = 2; return x; } if (a) { g(a); } f();')
        cache = ModelCache(script)
        model = cache.model
        dom_fresh = build_dominance(model)
        live_fresh = build_liveness(model)
        idents = [n for n in script.walk_in_order() if isinstance(n, JsIdentifier)]
        for p in idents:
            for q in idents:
                self.assertEqual(cache.dominance.dominates(p, q), dom_fresh.dominates(p, q))
        self.assertEqual(
            [id(n) for n in cache.liveness.dead_stores()],
            [id(n) for n in live_fresh.dead_stores()],
        )
