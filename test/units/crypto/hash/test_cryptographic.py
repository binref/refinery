#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestCryptographicHashes(TestUnitBase):

    def test_ripemd128(self):
        data = b'The quick brown fox jumps over the lazy dog'
        self.assertEqual(str(data | self.ldu('ripemd128', '-t')), '3fa9b57f053c053fbe2735b2380db596')

    def test_sha256_regression(self):
        from refinery import __unit_loader__
        __unit_loader__.reload()
        sha256 = __unit_loader__.resolve('sha256')
        self.assertIsNotNone(sha256)
        assert sha256 is not None
        data = b'The quick brown fox jumps over the lazy dog'
        self.assertEqual(data | sha256 | bytes,
            bytes.fromhex('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'))
