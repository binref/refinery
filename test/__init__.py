from typing import Optional, Dict

import hashlib
import logging
import os
import random
import refinery
import string
import unittest
import urllib.request

from refinery.units.crypto.cipher.aes import aes

__all__ = ['refinery', 'TestBase', 'NameUnknownException']


class SampleStore:
    cache: Dict[str, bytes]

    def __init__(self):
        self.cache = {}

    def download(self, sha256hash: str, key: Optional[str] = None):
        key = key or 'REFINERYTESTDATA'
        key = key.encode('latin1')
        sha256hash = sha256hash.lower()
        req = urllib.request.Request(
            F'https://github.com/binref/refinery-test-data/blob/master/{sha256hash}.enc?raw=true')
        try:
            with urllib.request.urlopen(req) as response:
                encoded_sample = response.read()
        except Exception:
            api = os.environ['MALSHARE_API']
            req = urllib.request.Request(
                F'https://malshare.com/api.php?api_key={api}&action=getfile&hash={sha256hash}')
            with urllib.request.urlopen(req) as response:
                result = response.read()
        else:
            result = encoded_sample | aes(mode='CBC', key=key) | bytearray
            if not result or hashlib.sha256(result).hexdigest().lower() != sha256hash:
                raise ValueError('sample did not decode correctly')
        self.cache[sha256hash] = result
        return result

    def get(self, sha256hash: str, key: Optional[str] = None):
        for cached, value in self.cache.items():
            if cached.casefold() == sha256hash.casefold():
                return value
        else:
            return self.download(sha256hash, key)

    def __getitem__(self, sha256hash: str):
        return self.get(sha256hash)


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
    def load_pipeline(cls, cmd: str) -> refinery.Unit:
        from refinery.units import Unit, LogLevel
        from refinery.lib.loader import load_pipeline
        unit = pl = load_pipeline(cmd)
        while isinstance(unit, Unit):
            unit.log_level = LogLevel.DETACHED
            unit = unit.source
        return pl
