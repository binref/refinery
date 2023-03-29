#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestXXTEA(TestUnitBase):

    def test_examples_kryptografie_de(self):
        # https://kryptografie.de/kryptografie/chiffre/xxtea.htm
        sample = B'BeispielklartextBeispielklartext'
        output = bytes.fromhex('179DD68A F1763D52 3256159D 247BC98F 345F2094 1FD305D7 36B1F17F 13636298')
        self.assertEqual(output, sample | self.load(B'Schokoladentorte', reverse=True, raw=True) | bytes)

    def test_single_block(self):
        data = bytes.fromhex(
            'E5D64277DE04505C257954766E686A07F91A333200DBC26B8BFBF2FAC3103C202E6B3C46E1663BC71C5D68'
            '53C0DFB8A1FFC823FBF19A0DC5F048817C900A14E4D2B2DC599F3BB274F030B50167971E72')
        unit = self.load(b'schokoladentorte', raw=True)
        trim = self.ldu('trim', 'h:00')
        goal = 'He raged at the world, at his family, at his life. But mostly he just raged.'
        self.assertEqual(goal, data | unit | trim | str)

    def test_examples_encrypt_with_pkcs7(self):
        data = b'This is a secret message.'
        unit = self.load(b'0123456789abcdef', padding='pkcs7')
        self.assertEqual(data, data | -unit | unit | bytes)

    def test_big_endian_sample(self):
        data = bytes.fromhex('4cbf21be1cf30657918e439b5ce890c5c2c43f248d4f2341872f8c2dfc2191cd')
        unit = self.load(b'0123456789abcdef', swap=True, block_size=2)
        self.assertEqual(data | unit | str, 'This is a secret message.')
