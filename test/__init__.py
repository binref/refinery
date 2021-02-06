import hashlib
import logging
import os
import random
import refinery
import string
import sys
import unittest
import urllib.request

__all__ = ['refinery', 'TestBase', 'NameUnknownException']


class NameUnknownException(Exception):
    def __init__(self, name):
        super().__init__('could not resolve: {}'.format(name))


class TestBase(unittest.TestCase):
    _SAMPLE_CACHE = {}

    def ldu(self, name, *args, **kwargs):
        unit = refinery.lib.loader.load(name, *args, **kwargs)
        if not unit.args.quiet:
            unit.log_detach()
        return unit

    def generate_random_buffer(self, size):
        return bytes(random.randrange(0, 0x100) for _ in range(size))

    def generate_random_text(self, size):
        return ''.join(string.printable[
            random.randrange(0, len(string.printable))] for _ in range(size)).encode('UTF8')

    def download_sample(self, sha256hash):
        sha256hash = sha256hash.lower()
        if sha256hash in self._SAMPLE_CACHE:
            return self._SAMPLE_CACHE[sha256hash]
        req = urllib.request.Request(
            F'https://github.com/binref/refinery-test-data/blob/master/{sha256hash}.enc?raw=true')
        try:
            with urllib.request.urlopen(req) as response:
                decryptor = refinery.aes(mode='CBC', key=B'REFINERYTESTDATA')
                result = decryptor(response.read())
                if not result or hashlib.sha256(result).hexdigest().lower() != sha256hash:
                    raise ValueError
        except Exception:
            key = os.environ['MALSHARE_API']
            req = urllib.request.Request(
                F'https://malshare.com/api.php?api_key={key}&action=getfile&hash={sha256hash}')
            with urllib.request.urlopen(req) as response:
                result = response.read()
        self._SAMPLE_CACHE[sha256hash] = result
        return result

    def setUp(self):
        random.seed(0xBAADF00D)  # guarantee deterministic 'random' buffers
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.INFO,
            format='%(message)s'
        )
