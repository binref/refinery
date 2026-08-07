"""
Tests for the deobfuscation pipeline scheduler.
"""
from __future__ import annotations

import unittest

from dataclasses import dataclass, field
from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.pipeline import DeobfuscationPipeline, DeobfuscationTimeout, TransformerGroup


@dataclass(repr=False)
class _MockNode(Node):
    counters: dict[str, int] = field(default_factory=dict)


def _ChangeN(change: int, key: str = 'default'):
    class _ChangeN(Transformer):
        def visit__MockNode(self, node: _MockNode):
            current = node.counters.get(self._key, 0)
            if current < self.ceiling:
                node.counters[self._key] = current + 1
                self.mark_changed()
        ceiling = change
        _key = key
    return _ChangeN


class _SettleAfterOne(_ChangeN(1, 'settle')):
    pass


class _NeverSettle(_ChangeN(1000, 'churn')):
    pass


class TestTransformerGroup(unittest.TestCase):

    def test_group_runs_until_stable(self):
        node = _MockNode()
        group = TransformerGroup('g', _ChangeN(3))
        changed, steps = group.run(node)
        self.assertTrue(changed)
        self.assertEqual(steps, 3)
        self.assertEqual(node.counters['default'], 3)

    def test_group_respects_max_steps(self):
        node = _MockNode()
        group = TransformerGroup('g', _ChangeN(3))
        self.assertEqual(group.run(node, max_steps=0), (True, 3))
        node.counters.clear()
        self.assertEqual(group.run(node, max_steps=3), (True, 3))
        node.counters.clear()
        self.assertEqual(group.run(node, max_steps=5), (True, 3))
        node.counters.clear()
        with self.assertRaises(DeobfuscationTimeout):
            group.run(node, max_steps=2)


class TestDeobfuscationPipeline(unittest.TestCase):

    def test_pipeline_respects_max_steps(self):
        node = _MockNode()
        pipeline = DeobfuscationPipeline([
            TransformerGroup('a', _ChangeN(3, 'a')),
            TransformerGroup('b', _ChangeN(3, 'b')),
        ])
        self.assertEqual(pipeline.run(node, max_steps=0), 6)
        node.counters.clear()
        self.assertEqual(pipeline.run(node, max_steps=6), 6)
        node.counters.clear()
        with self.assertRaises(DeobfuscationTimeout):
            pipeline.run(node, max_steps=5)


class TestDeobfuscationTimeoutReport(unittest.TestCase):

    def test_group_timeout_names_the_transformer_that_kept_changing(self):
        node = _MockNode()
        group = TransformerGroup('grp', _SettleAfterOne, _NeverSettle)
        with self.assertRaises(DeobfuscationTimeout) as context:
            group.run(node, max_steps=4)
        self.assertEqual(context.exception.group, 'grp')
        self.assertEqual(context.exception.transformer, '_NeverSettle')

    def test_pipeline_timeout_names_the_group_that_exhausted_the_budget(self):
        node = _MockNode()
        pipeline = DeobfuscationPipeline([
            TransformerGroup('quiet', _ChangeN(2, 'quiet')),
            TransformerGroup('noisy', _NeverSettle),
        ])
        with self.assertRaises(DeobfuscationTimeout) as context:
            pipeline.run(node, max_steps=5)
        self.assertEqual(context.exception.group, 'noisy')
        self.assertEqual(context.exception.transformer, '_NeverSettle')

    def test_timeout_message_names_group_and_transformer(self):
        node = _MockNode()
        group = TransformerGroup('g', _NeverSettle)
        with self.assertRaises(DeobfuscationTimeout) as context:
            group.run(node, max_steps=1)
        self.assertEqual(
            str(context.exception),
            'transformer _NeverSettle in group g exceeded the step budget')
