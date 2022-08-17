#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
from .. import TestUnitBase


class TestXKey(TestUnitBase):

    def test_blocksize_1(self):
        data = self.download_sample('b3b7376c5046be978b5558e91a515c1bf57c13a1151d225745c2bdc3183e0a8f')
        for length in (3, 7, 12, 25, 112):
            key = self.generate_random_buffer(length)
            encrypted, = data | self.ldu('xor', key)
            recovered, = encrypted | self.load(slice(1, 128))
            self.assertEqual(recovered, key, F'failure for length={length}')

    def test_blocksize_4(self):
        data = self.download_sample('b3b7376c5046be978b5558e91a515c1bf57c13a1151d225745c2bdc3183e0a8f')
        for length in (2, 3, 7, 12):
            key = self.generate_random_buffer(4 * length)
            arg = struct.unpack(F'<{length}L', key)
            encrypted, = data | self.ldu('add', arg, blocksize=4)
            recovered, = encrypted | self.load(':80:4')
            self.assertEqual(recovered, key, F'failure for length={length}')
