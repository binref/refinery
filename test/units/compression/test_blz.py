#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBriefLZ(TestUnitBase):

    def test_decompress_partial(self):
        D = self.load()
        C = self.load(reverse=True)
        M = b'the finest refinery of binaries refines binaries, not finery.'
        self.assertEqual(M | C | D, M)

    def test_compress_rle(self):
        C = self.load(reverse=True)
        D = self.load()
        M = B'B' + B'A' * 80
        X = M | C
        self.assertEqual(len(X), 29)
        self.assertEqual(X | D, M)

    def test_malware_sample(self):
        C = self.load(reverse=True)
        D = self.load()
        M = self.download_from_malshare('2579bc4cd0d5f76d1a2937a0e0eb0256f2a9f2f8a30c1da694be66bfa04dc740')
        self.assertEqual(M | C | D, M)
