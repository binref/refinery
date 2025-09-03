import logging
import random
import refinery
import string
import unittest
import pyperclip
import contextlib
import os

try:
    import pytest
except ImportError:
    def thread_group(name: str):
        def dummy(x):
            return x
        return dummy
else:
    def thread_group(name: str): # type:ignore
        return pytest.mark.xdist_group(name=name)

from samples import SampleStore


__all__ = [
    'refinery',
    'thread_group',
    'temporary_clipboard',
    'temporary_chwd',
    'TestBase',
    'NameUnknownException',
]


@contextlib.contextmanager
def temporary_clipboard(data: str = ''):
    backup = pyperclip.paste()
    pyperclip.copy(data)
    try:
        yield None
    finally:
        pyperclip.copy(backup)


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
