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
            recovered, = encrypted | self.load(slice(1, 128), freq=True)
            self.assertEqual(recovered, key, F'failure for length={length}')

    def test_blocksize_4(self):
        data = self.download_sample('b3b7376c5046be978b5558e91a515c1bf57c13a1151d225745c2bdc3183e0a8f')
        for length in (2, 3, 7, 12):
            key = self.generate_random_buffer(4 * length)
            arg = struct.unpack(F'<{length}L', key)
            encrypted, = data | self.ldu('add', arg, blocksize=4)
            recovered, = encrypted | self.load(':80:4', freq=True)
            self.assertEqual(recovered, key, F'failure for length={length}')

    def test_early_abort(self):
        data = self.download_sample('ccd495bae43f026e05f00ebc74f989d5657e010854ce4d8870e7b9371b0222b9')
        for k in (32, 64, 128, 256):
            test = data | self.load_pipeline(F'carve -dlt2 intarray [| xkey :{k} ]') | bytes
            self.assertEqual(test, B'\x47\xB0')

    def test_frame_scope_regression(self):
        data = self.load_pipeline('emit rep[2000]:A | chop 500 [| autoxor | cfmt {key} ]')()
        self.assertEqual(data, B'AAAA')
