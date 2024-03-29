#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestCryptographicHashes(TestUnitBase):

    def test_ripemd128(self):
        data = b'The quick brown fox jumps over the lazy dog'
        self.assertEqual(str(data | self.ldu('ripemd128', '-t')), '3fa9b57f053c053fbe2735b2380db596')
