from __future__ import annotations

import sys
import weakref

from refinery.lib.collector import CollectionTrigger, committed_memory

from .. import TestBase, without_cycle_collector


class _Cycle:
    def __init__(self, size: int):
        self.cycle = self
        self.data = bytearray(B'\x01') * size


class TestCollectionTrigger(TestBase):

    def setUp(self):
        super().setUp()
        if committed_memory() is None:
            self.skipTest('The memory of a process cannot be read on this system.')

    def _trigger_after_dropping_a_cycle(self, growth: int, size: int):
        trigger = CollectionTrigger(growth=growth, interval=0)
        with without_cycle_collector():
            self.assertFalse(trigger())
            cycle = _Cycle(size)
            alive = weakref.ref(cycle)
            del cycle
            collected = trigger()
            survived = alive() is not None
        return collected, survived

    def test_a_cycle_that_grew_the_process_beyond_the_limit_is_collected(self):
        if sys.platform == 'darwin':
            self.skipTest('On macOS, the memory read is the peak of the resident memory.')
        collected, survived = self._trigger_after_dropping_a_cycle(growth=16 << 20, size=64 << 20)
        self.assertTrue(collected)
        self.assertFalse(survived)

    def test_a_cycle_below_the_limit_waits_for_a_later_collection(self):
        collected, survived = self._trigger_after_dropping_a_cycle(growth=1 << 30, size=1 << 20)
        self.assertFalse(collected)
        self.assertTrue(survived)

    def test_the_committed_memory_includes_a_buffer_that_was_never_written(self):
        if sys.platform == 'darwin':
            self.skipTest('On macOS, the memory read is the peak of the resident memory.')
        before = committed_memory()
        buffer = bytearray(64 << 20)
        after = committed_memory()
        assert before is not None and after is not None
        self.assertGreaterEqual(after - before, 60 << 20)
        del buffer
