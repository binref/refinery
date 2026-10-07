from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.model import JsAssignmentExpression, JsExpressionStatement, JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


class TestValuesAWriteThroughIsRecordedOnlyOnceABindingHoldsThem(TestBase):

    @staticmethod
    def _stored(value: str) -> bool:
        script = JsParser(F'var alias = Object; var self = this; var local = 1; s.v = {value};').parse()
        statement = script.body[-1]
        assert isinstance(statement, JsExpressionStatement)
        store = statement.expression
        assert isinstance(store, JsAssignmentExpression) and store.right is not None
        return ModelCache(script).intrinsic_writes.follows_only_through_bindings(store.right)

    def test_an_intrinsic_the_scan_watches_or_the_global_object(self):
        for value in (
            'Object',
            'Object.prototype',
            'Object.keys',
            'alias',
            'alias.prototype',
            'Math',
            'globalThis',
            'this',
            'self',
            'local || Object',
            '(0, Object)',
            'local ? 1 : Object',
            '(local = Object)',
        ):
            with self.subTest(value=value):
                self.assertTrue(self._stored(value))

    def test_a_value_that_is_neither(self):
        for value in (
            '1',
            '"Object"',
            'local',
            'local.prototype',
            'String.fromCharCode(1)',
            'typeof Object',
            'Object ? 1 : local',
            '(Object, local)',
        ):
            with self.subTest(value=value):
                self.assertFalse(self._stored(value))

    def test_a_property_of_the_global_object(self):
        for value in (
            'window.document',
            'globalThis.location.href',
            'this.x',
            'self.navigator',
        ):
            with self.subTest(value=value):
                self.assertFalse(self._stored(value))

    def test_a_value_the_model_was_not_built_over(self):
        cache = ModelCache(JsParser('var local = 1; s.v = local;').parse())
        self.assertTrue(cache.intrinsic_writes.follows_only_through_bindings(JsIdentifier(name='local')))


class TestBindingsWhoseValuesDenoteARootTheScanWatches(TestBase):

    @staticmethod
    def _denotes(source: str) -> bool:
        cache = ModelCache(JsParser(source).parse())
        binding = cache.model.root_scope.bindings['P']
        return cache.intrinsic_writes.denotes_a_watched_root(binding)

    def test_a_binding_holding_an_intrinsic_directly_or_through_another_name(self):
        for source in (
            'var P = Object.prototype;',
            'var P; P = Object;',
            'var Q = Math; var P = Q;',
            'var P = local || Array;',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._denotes(source))

    def test_a_binding_holding_something_else(self):
        for source in (
            'var P = 1;',
            'var P = {};',
            'var P = String.fromCharCode(1);',
            'var P = window;',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._denotes(source))
