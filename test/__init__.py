import logging
import random
import refinery
import string
import unittest
import contextlib
import os

from samples import SampleStore


@contextlib.contextmanager
def temporary_chwd(directory):
    old = os.getcwd()
    try:
        os.chdir(directory)
        yield directory
    finally:
        os.chdir(old)


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
        return self._STORE.get(sha256hash, key)

    def setUp(self):
        random.seed(0xBAADF00D)  # guarantee deterministic 'random' buffers
        logging.disable(logging.CRITICAL)

    def assertContains(self, container, member, msg=None):
        self.assertIn(member, container, msg)

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
