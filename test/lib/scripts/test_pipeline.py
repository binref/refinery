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
