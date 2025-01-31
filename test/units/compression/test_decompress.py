#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time

from .. import TestUnitBase
from . import KADATH1, KADATH2


class TestAutoDecompressor(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.buffers = [buf[:0x5000] for buf in {
            1: B'AAFOOBAR/BAR' * 2000,
            2: bytes(self.download_sample('6a1bc124f945ddfde62b4137d627f3958b23d8a2a6507e3841cab84416c54eea')),
            3: bytes(self.download_sample('07e25cb7d427ac047f53b3badceacf6fc5fb395612ded5d3566a09800499cd7d')),
            4: bytes(self.download_sample('40f97cf37c136209a65d5582963a72352509eb802da7f1f5b4478a0d9e0817e8')),
            5: bytes(self.download_sample('52e488784d46b3b370836597b1565cf18a5fa4a520d0a71297205db845fc9d26'))[0x8000:],
            6: bytes(self.download_sample('38c9b858c32fcc6b484272a182ae6e7f911dea53a486396037d8f7956d2110be')),
            7: bytes(self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')),
            8: KADATH1.encode('utf8'),
            9: KADATH2.encode('utf8'),
        }.values()]

    def _mangle(self, data: bytes, engine: str):
        def prepend(x):
            return x + data

        yield data

        if engine == 'lznt1':
            return

        yield prepend(B'\0\0\0\0')
        yield prepend(B'\xF4')

        if engine in ('aplib', 'lzf'):
            return

        yield prepend(B'\x01\x40')
        yield prepend(B'\x00\x00\xFE\xCD')
        yield prepend(B'\x01\x00')

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
                    self.assertTrue(False, F'Exception while compressing buffer {k} with {engine.name}: {E!s}')
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
