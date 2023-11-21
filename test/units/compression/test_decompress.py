#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import os.path
import time

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
        code = code.replace(B'\r', B'')
        self.buffers = [
            B'AAFOOBAR/BAR' * 2000,
            code[:16000],
            bytes(self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')),
            KADATH1.encode('utf8'),
            KADATH2.encode('utf8'),
        ]

    def _mangle(self, data: bytes, engine: str):
        yield data
        yield B'\xF4' + data
        if engine in ('aplib', 'lzf'):
            return
        yield B'\x01\x40' + data
        yield B'\x00\x00\xFE\xCD' + data
        yield B'\x01\x00' + data

    def test_mangled_buffers(self):
        from refinery.units.compression.decompress import decompress
        unit = decompress()
        for engine in unit.engines:
            if not engine.is_reversible:
                continue
            for k, buffer in enumerate(self.buffers, 1):
                try:
                    compressed = next(buffer | -engine)
                except Exception as E:
                    self.assertTrue(False, F'Exception while compressing buffer {k}: {E!s}')
                    continue
                for m, sample in enumerate(self._mangle(compressed, engine.name), 1):
                    start = time.process_time()
                    result = next(sample | unit)
                    delta = time.process_time() - start
                    self.assertLessEqual(delta, 20, F'buffer {engine.name}({k}.{m}) took {delta} seconds')
                    method = result.meta.get("method", "uncompressed")
                    self.assertEqual(method, engine.name, F'buffer {engine.name}({k}.{m}) incorrectly identified as {method}')
                    _assert = self.assertEqual if m == 1 else self.assertIn
                    _assert(buffer, result, msg=F'buffer {engine.name}({k}.{m}) did not decompress')
