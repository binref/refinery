import gc
import logging
import random
import refinery
import string
import unittest
import contextlib
import os
import time
import tracemalloc

from samples import SampleStore
from typing import Callable, Iterable


@contextlib.contextmanager
def temporary_chwd(directory):
    old = os.getcwd()
    try:
        os.chdir(directory)
        yield directory
    finally:
        os.chdir(old)


@contextlib.contextmanager
def without_cycle_collector():
    """
    Runs the block with the cycle collector off, after a full collection, and restores it after
    the block.
    """
    enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        if enabled:
            gc.enable()


def fastest_processor_time(runs: Iterable[Callable[[], object]]) -> float:
    """
    The fewest seconds that one of the given runs takes, counted in processor time of the process
    and with the cycle collector off. Processor time does not count the time that the process waits
    for a processor while other processes run, and the pauses of the collector grow with all that
    the process holds, not with the run.
    """
    fastest = float('inf')
    with without_cycle_collector():
        for run in runs:
            start = time.process_time()
            run()
            fastest = min(fastest, time.process_time() - start)
    return fastest


def processor_time_ratio(numerator: float, denominator: float) -> float:
    """
    The ratio of two times that `fastest_processor_time` measured. A denominator of less than 50
    milliseconds raises an error: on Windows, processor time advances in steps of about 16
    milliseconds, which would decide the ratio.
    """
    if denominator < 0.05:
        raise ValueError(F'A time of {denominator * 1000:.0f} milliseconds is too short to divide by.')
    return numerator / denominator


def wontfix(reason: str):
    """
    Marks a test of a defect that will not be fixed, for the given reason: the test states the
    correct behavior, and it never runs.
    """
    if not reason.strip():
        raise ValueError('a test is marked as not to be fixed only for a stated reason')
    return unittest.skip(F'will not be fixed: {reason}')


class NameUnknownException(Exception):
    def __init__(self, name):
        super().__init__('could not resolve: {}'.format(name))


def a_property_of_the_pin_itself(test):
    """
    The `--no-pin` differential (see `test/conftest.py`) removes the pin mechanism, so a test of
    that mechanism — a build count the pin flattens, or the holding behavior itself — holds only
    outside the differential. Every result-equality assertion stays in force there, which is the
    differential's whole point. The option is read when the test is decorated, not when this
    package is imported: the package is imported to load the conftest, before the option has been
    processed, and a condition evaluated then never sees it.
    """
    return unittest.skipIf(
        bool(os.environ.get('REFINERY_TEST_NO_PIN')),
        'the no-pin differential removed the mechanism this test measures',
    )(test)


def a_property_of_the_batch_itself(test):
    """
    The `--no-batch` differential (see `test/conftest.py`) applies every batched pass's edits as
    they are decided, so a test of the batching mechanism — a build count the batch flattens, or
    the single-application behavior itself — holds only outside the differential. Every
    result-equality assertion stays in force there, which is the differential's whole point. The
    option is read when the test is decorated, for the reason `a_property_of_the_pin_itself`
    states.
    """
    return unittest.skipIf(
        bool(os.environ.get('REFINERY_TEST_NO_BATCH')),
        'the no-batch differential removed the mechanism this test measures',
    )(test)


class TestBase(unittest.TestCase):
    _STORE = SampleStore()

    def ldu(self, name, *args, **kwargs):
        import refinery.lib.loader
        unit = refinery.lib.loader.load(name, *args, **kwargs)
        if not unit.args.quiet:
            unit.log_detach()
        return unit

    def generate_random_buffer(self, size):
        return bytes(random.randrange(0, 0x100) for _ in range(size))

    def generate_random_text(self, size):
        return ''.join(string.printable[
            random.randrange(0, len(string.printable))] for _ in range(size)).encode('UTF8')

    def download_sample(self, sha256hash, key=None):
        return download_sample(sha256hash, key)

    def setUp(self):
        random.seed(0xBAADF00D)  # guarantee deterministic 'random' buffers
        logging.disable(logging.CRITICAL)

    def assertContains(self, container, member, msg=None):
        self.assertIn(member, container, msg)

    @contextlib.contextmanager
    def assertNoInstanceSurvives(self, cls: type):
        """
        Fails if an instance of the given class that was created inside the block is still alive
        after it while the cycle collector is off, i.e. if only the collector could free it.
        Instances that existed before the block, like units that a cache keeps, are ignored.
        """
        with without_cycle_collector():
            known = {id(obj) for obj in gc.get_objects() if isinstance(obj, cls)}
            yield
            survivors = [obj for obj in gc.get_objects() if isinstance(obj, cls) and id(obj) not in known]
        self.assertEqual(survivors, [])

    def assertCollectorFreesLessThan(self, limit: int, operation: Callable[[], object]):
        """
        Runs the operation once, then again with the cycle collector off, and fails if the
        collector then frees `limit` bytes or more of what the second run allocated: only the
        collector frees memory that a reference cycle keeps. The first run imports what the
        operation needs and fills its caches, which are not garbage. Memory that existed before
        the second run is not counted, so the operation creates the input it passes along.
        """
        operation()
        with without_cycle_collector():
            tracemalloc.start()
            try:
                operation()
                kept, _ = tracemalloc.get_traced_memory()
                gc.collect()
                left, _ = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertLess(kept - left, limit)

    @classmethod
    def load_pipeline(cls, cmd: str, clear_cache=False) -> refinery.Unit:
        from refinery.units import Unit, LogLevel
        from refinery.lib.loader import load_pipeline
        if clear_cache:
            load_pipeline.cache_clear()
        unit = pl = load_pipeline(cmd)
        while isinstance(unit, Unit):
            unit.log_level = LogLevel.DETACHED
            unit = unit.source
        return pl


def download_sample(sha256hash: str, key: str | None = None) -> bytes:
    """
    The module-level counterpart of `TestBase.download_sample`, for test helpers outside a test
    method. Returns the decoded bytes of the test data store entry with the given sha256.
    """
    return TestBase._STORE.get(sha256hash, key)
