from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

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


class TestAWriteThroughAFormThatForwardsItsValueWritesTheRoot(TestBase):
    """
    A comma, a logical or a conditional expression evaluates to one of its operands, so a property
    written on what one of them evaluates to is written on each name an operand may be.
    """

    @staticmethod
    def _written(source: str) -> frozenset[str]:
        return ModelCache(JsParser(source).parse()).intrinsic_writes.names

    def test_a_key_written_through_a_comma_a_logical_or_a_conditional_writes_each_root(self):
        for source, roots in (
            ('(0, Math).floor = f;', {'Math'}),
            ('(Math || null).floor = f;', {'Math'}),
            ('(c ? Math : JSON).floor = f;', {'Math', 'JSON'}),
            ('(0, Date).now = f;', {'Date'}),
            ('(Date || null).now = f;', {'Date'}),
            ('(c ? Date : Math).now = f;', {'Date', 'Math'}),
        ):
            with self.subTest(source=source):
                self.assertEqual(self._written(source) & roots, roots)

    def test_a_root_handed_to_a_function_writing_through_such_a_form_is_written(self):
        for source in (
            'function patch(m) { (0, m).floor = f; } patch(Math);',
            'function patch(m) { (m || 0).floor = f; } patch(Math);',
        ):
            with self.subTest(source=source):
                self.assertIn('Math', self._written(source))


class TestAFunctionStoringThroughItsParameterInAPatternWritesTheRoot(TestBase):
    """
    A pattern and the head of a `for`-`in` or `for`-`of` loop store through every member they hold,
    so a function storing a property of its parameter there writes the root a call hands it.
    """

    def test_a_root_handed_to_a_function_storing_through_a_pattern_or_a_loop_head_is_written(self):
        for source in (
            'function patch(m) { [m.floor] = [f]; } patch(Math);',
            'function patch(m) { ({ k: m.floor } = { k: f }); } patch(Math);',
            'function patch(m) { for (m.floor of [f]); } patch(Math);',
            'function patch(m) { for (m.floor in o); } patch(Math);',
        ):
            with self.subTest(source=source):
                self.assertIn('Math', ModelCache(JsParser(source).parse()).intrinsic_writes.names)


#: Programs replacing `Math.floor` through a comma, a logical or a conditional expression before
#: calling it, mapped to what Node prints for them.
A_METHOD_REPLACED_THROUGH_A_FORM_THAT_FORWARDS_ITS_VALUE = {
    inspect.cleandoc("""
        (0, Math).floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
    inspect.cleandoc("""
        (Math || null).floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
    inspect.cleandoc("""
        (process.argv.length ? Math : JSON).floor = function () { return 42; };
        console.log(Math.floor(1.5));
    """): '42\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAMethodReplacedThroughAFormThatForwardsItsValue(TestBase):

    def test_the_replaced_method_is_not_folded(self):
        rows = A_METHOD_REPLACED_THROUGH_A_FORM_THAT_FORWARDS_ITS_VALUE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
