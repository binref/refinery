from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.model import JsVariableDeclaration
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
