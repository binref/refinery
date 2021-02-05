import sys
import os
import unittest
import random
import refinery
import logging
import string
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
        if sha256hash in self._SAMPLE_CACHE:
            return self._SAMPLE_CACHE[sha256hash]
        key = os.environ['MALSHARE_API']
        req = urllib.request.Request(
            F'https://malshare.com/api.php?api_key={key}&action=getfile&hash={sha256hash}')
        with urllib.request.urlopen(req) as response:
            result = self._SAMPLE_CACHE[sha256hash] = response.read()
        return result

    def setUp(self):
        random.seed(0xBAADF00D)  # guarantee deterministic 'random' buffers
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.INFO,
            format='%(message)s'
        )
