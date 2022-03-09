#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase

from refinery.units.crypto.cipher.camellia import Camellia, FL_FWD, FL_INV


class TestCamellia(TestUnitBase):

    def test_fl_functions(self):
        key = 0x2BFAEDFDEEEAFBFE
        self.assertEqual(FL_INV(FL_FWD(0xDEFACED, key), key), 0xDEFACED)

    def test_invertible(self):
        u = Camellia(B'#BINARY-REFINERY', None)
        m = B'0123456789ABCDEF'
        self.assertEqual(u.block_decrypt(u.block_encrypt(m)), m)

    def test_rfc_3731_128(self):
        K = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
        M = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
        C = bytes.fromhex('67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43')
        u = self.load(K, raw=True)
        self.assertEqual(bytes(C | u), M)

    def test_rfc_3731_192(self):
        K = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77')
        M = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
        C = bytes.fromhex('b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9')
        u = self.load(K, raw=True)
        self.assertEqual(bytes(C | u), M)

    def test_rfc_3731_256(self):
        K = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff')
        M = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
        C = bytes.fromhex('9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09')
        u = self.load(K, raw=True)
        self.assertEqual(bytes(C | u), M)
