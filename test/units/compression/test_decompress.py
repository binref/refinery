#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import os.path

from .. import TestUnitBase


class TestAutoDecompressor(TestUnitBase):

    def setUp(self):
        super().setUp()
        root = os.path.abspath(inspect.stack()[0][1])
        for _ in range(4):
            root = os.path.dirname(root)
        path = os.path.join(root, 'refinery', 'units', '__init__.py')
        with open(path, 'rb') as stream:
            code = stream.read()
        self.buffers = [
            B'AAFOOBAR/BAR' * 2000,
            code[:16000],
            self.download_from_malshare('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        ]

    def _mangle(self, data):
        yield self.generate_random_buffer(1) + data
        yield self.generate_random_buffer(2) + data
        yield data[1:]
        yield B'\x00\x00\xFE\xCD' + data
        yield B'\x01\x00' + data

    def test_mangled_buffers(self):
        unit = self.load(min_ratio=0.7)
        for e in unit.engines:
            for k, buffer in enumerate(self.buffers, 1):
                compressed = e.reverse(buffer)
                failures = []
                success = 0
                self.assertEqual(unit(compressed), buffer,
                    msg=F'Failed for {e.name}, buffer {k}')
                for m, sample in enumerate(self._mangle(compressed), 1):
                    if buffer not in unit(sample):
                        failures.append(m)
                    else:
                        success += 1
                        if success >= 2: break
                self.assertGreaterEqual(success, 1,
                    msg=F'Failed for {e.name}, buffer {k} failed for these manglings: {failures}.')
