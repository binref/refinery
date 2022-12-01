#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import os.path
import re

from .. import TestUnitBase
from . import KADATH1, KADATH2


class TestAutoDecompressor(TestUnitBase):

    def setUp(self):
        super().setUp()
        root = os.path.abspath(inspect.stack()[0][1])
        for _ in range(4):
            root = os.path.dirname(root)
        path = os.path.join(root, 'refinery', 'units', '__init__.py')
        with open(path, 'rb') as stream:
            code = stream.read()
        code = re.sub(br'(?!<\r)\n', b'\r\n', code)
        self.buffers = [
            B'AAFOOBAR/BAR' * 2000,
            code[:16000],
            self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916'),
            KADATH1.encode('utf8'),
            KADATH2.encode('utf8'),
        ]

    def _mangle(self, data):
        yield self.generate_random_buffer(1) + data
        yield self.generate_random_buffer(2) + data
        yield data[1:]
        yield B'\x00\x00\xFE\xCD' + data
        yield B'\x01\x00' + data

    def test_mangled_buffers(self):
        unit = self.load()
        for e in unit.engines:
            if not e.is_reversible:
                continue
            for k, buffer in enumerate(self.buffers, 1):
                try:
                    compressed = e.reverse(buffer)
                except Exception as E:
                    self.assertTrue(False, F'Exception while compressing buffer {k}: {E!s}')
                failures = []
                success = 0
                result, = compressed | unit
                method = result.meta.get("method", "uncompressed")
                self.assertEqual(result, buffer,
                    msg=F'Failed for {e.name}, reported as {method} for buffer #{k}')
                for m, sample in enumerate(self._mangle(compressed), 1):
                    result, = sample | unit
                    if buffer not in result:
                        failures.append(m)
                    else:
                        success += 1
                        if success >= 2: break
                self.assertGreaterEqual(success, 1,
                    msg=F'Failed for {e.name}, buffer {k} failed for these manglings: {failures}.')
