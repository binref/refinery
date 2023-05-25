#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestChaskey(TestUnitBase):

    def test_invertible(self):
        data = bytes(range(0x100))
        for mode in ('CBC', 'CFB', 'OFB', 'PCBC'):
            encrypter = -self.load(range(0x10), iv=range(0x10), mode=mode)
            decrypter = +self.load(range(0x10), iv=range(0x10), mode=mode)
            self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode}')

    def test_donut_01(self):
        # https://github.com/TheWover/donut/blob/master/encrypt.c
        K = bytes.fromhex('5609e9685f58e32940ecec98c522982f')
        M = bytes.fromhex('b8232826fd5e405e69a301a978ea7ad8')
        C = bytes.fromhex('d5608d4da2bf347babf8772fdfedde07')
        unit = self.load(K, raw=True, rounds=16)
        self.assertEqual(M | -unit | bytes, C)

    def test_donut_02(self):
        # https://github.com/TheWover/donut/blob/master/encrypt.c
        # Code was compiled 2023-05-25 and the ciphertext added here as a test.
        M = bytes(77)
        K = bytes.fromhex('5609e9685f58e32940ecec98c522982f')
        R = bytes.fromhex('d001369bef6aa1051d2d2198198d8893')
        C = bytes.fromhex(
            '73963399e85633b0064fa77bdc68e160d70bb5aec5e49999e33a'
            '9148c8a28c24dc382417f1f5329a73a5a0b75eb9decd4bb2b8c9'
            '4eaaf4beaa1db92390c2cf76a99d2327572be11bbaa7e582ae')
        U = self.load(K, mode='ctr', iv=R, raw=True, rounds=16)
        self.assertEqual(M | -U | bytearray, C)
