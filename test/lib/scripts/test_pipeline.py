"""
Tests for the deobfuscation pipeline scheduler.
"""
from __future__ import annotations

import unittest

from dataclasses import dataclass, field
from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.pipeline import (
    DeobfuscationPipeline,
    DeobfuscationTimeout,
    PipelineObserver,
    TransformerGroup,
)


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


class _TransformerFailure(Exception):
    pass


def _RaiseWith(error: BaseException):
    class _RaiseWith(Transformer):
        def visit__MockNode(self, node: _MockNode):
            raise error
    return _RaiseWith


class _EventLedger(PipelineObserver):

    def __init__(self):
        self.events: list[tuple] = []

    def before(self, group: str, transformer: type[Transformer], ast: Node) -> None:
        self.events.append(('before', group, transformer, ast))

    def after(
        self, group: str, transformer: type[Transformer], ast: Node, changed: bool,
    ) -> None:
        self.events.append(('after', group, transformer, ast, changed))

    def failed(self, group: str, transformer: type[Transformer]) -> None:
        self.events.append(('failed', group, transformer))


class _LedgerThatRaisesInFailed(_EventLedger):

    def failed(self, group: str, transformer: type[Transformer]) -> None:
        super().failed(group, transformer)
        raise RuntimeError('the observer itself is broken')


class TestPipelineObserverWhenATransformerRaises(unittest.TestCase):

    def test_the_group_caller_receives_the_raised_exception_itself(self):
        failure = _TransformerFailure()
        group = TransformerGroup('g', _RaiseWith(failure))
        with self.assertRaises(_TransformerFailure) as context:
            group.run(_MockNode(), observer=_EventLedger())
        self.assertIs(context.exception, failure)

    def test_the_pipeline_caller_receives_the_raised_exception_itself(self):
        failure = _TransformerFailure()
        raising = _RaiseWith(failure)
        ledger = _EventLedger()
        pipeline = DeobfuscationPipeline([
            TransformerGroup('quiet', _ChangeN(1, 'quiet')),
            TransformerGroup('loud', raising),
        ])
        with self.assertRaises(_TransformerFailure) as context:
            pipeline.run(_MockNode(), observer=ledger)
        self.assertIs(context.exception, failure)
        self.assertEqual(ledger.events[-1], ('failed', 'loud', raising))

    def test_every_before_is_answered_exactly_once_and_failed_is_told_no_tree(self):
        node = _MockNode()
        ledger = _EventLedger()
        settling = _ChangeN(1, 'settling')
        raising = _RaiseWith(_TransformerFailure())
        group = TransformerGroup('g', settling, raising)
        with self.assertRaises(_TransformerFailure):
            group.run(node, observer=ledger)
        self.assertEqual(ledger.events, [
            ('before', 'g', settling, node),
            ('after', 'g', settling, node, True),
            ('before', 'g', raising, node),
            ('failed', 'g', raising),
        ])

    def test_a_failed_hook_that_raises_does_not_replace_the_transformers_exception(self):
        failure = _TransformerFailure()
        raising = _RaiseWith(failure)
        ledger = _LedgerThatRaisesInFailed()
        group = TransformerGroup('g', raising)
        with self.assertRaises(_TransformerFailure) as context:
            group.run(_MockNode(), observer=ledger)
        self.assertIs(context.exception, failure)
        self.assertEqual(ledger.events[-1], ('failed', 'g', raising))

    def test_failed_answers_a_raise_that_is_no_exception_subclass(self):
        node = _MockNode()
        ledger = _EventLedger()
        raising = _RaiseWith(KeyboardInterrupt())
        group = TransformerGroup('g', raising)
        with self.assertRaises(KeyboardInterrupt):
            group.run(node, observer=ledger)
        self.assertEqual(ledger.events, [
            ('before', 'g', raising, node),
            ('failed', 'g', raising),
        ])

    def test_a_step_budget_timeout_is_answered_by_after_and_never_by_failed(self):
        node = _MockNode()
        ledger = _EventLedger()
        group = TransformerGroup('g', _NeverSettle)
        with self.assertRaises(DeobfuscationTimeout):
            group.run(node, max_steps=1, observer=ledger)
        self.assertEqual(ledger.events, [
            ('before', 'g', _NeverSettle, node),
            ('after', 'g', _NeverSettle, node, True),
            ('before', 'g', _NeverSettle, node),
            ('after', 'g', _NeverSettle, node, True),
        ])


def _ChangeOnceAfter(key: str, trigger: str):
    class _ChangeOnceAfter(Transformer):
        def visit__MockNode(self, node: _MockNode):
            if node.counters.get(trigger, 0) and not node.counters.get(key, 0):
                node.counters[key] = 1
                self.mark_changed()
    return _ChangeOnceAfter


class TestInvalidationSetsCoverDependents(unittest.TestCase):

    def _groups(self):
        return [
            TransformerGroup('a', _ChangeN(1, 'a')),
            TransformerGroup('b', _ChangeN(1, 'b')),
            TransformerGroup('c', _ChangeN(1, 'c')),
        ]

    def test_a_set_omitting_a_direct_dependent_is_refused(self):
        with self.assertRaises(ValueError):
            DeobfuscationPipeline(
                self._groups(),
                dependencies={'b': {'a'}},
                invalidators={'a': set()},
            )

    def test_a_set_omitting_a_transitive_dependent_is_refused(self):
        with self.assertRaises(ValueError):
            DeobfuscationPipeline(
                self._groups(),
                dependencies={'b': {'a'}, 'c': {'b'}},
                invalidators={'a': {'b'}},
            )

    def test_a_set_listing_every_dependent_is_accepted(self):
        DeobfuscationPipeline(
            self._groups(),
            dependencies={'b': {'a'}, 'c': {'b'}},
            invalidators={'a': {'b', 'c'}, 'b': {'a', 'c'}, 'c': set()},
        )

    def test_a_dependent_sees_the_tree_the_group_it_depends_on_went_on_to_change(self):
        node = _MockNode()
        ledger = _EventLedger()
        pipeline = DeobfuscationPipeline(
            [
                TransformerGroup('a', _ChangeOnceAfter('a', 'b')),
                TransformerGroup('b', _ChangeN(1, 'b')),
            ],
            dependencies={'b': {'a'}},
            invalidators={'a': {'b'}},
        )
        pipeline.run(node, observer=ledger)
        self.assertEqual(
            [(event[1], event[4]) for event in ledger.events if event[0] == 'after'],
            [
                ('a', False),
                ('b', True),
                ('b', False),
                ('a', True),
                ('a', False),
                ('b', False),
            ],
        )
