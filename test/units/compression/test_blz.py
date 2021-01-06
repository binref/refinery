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
