#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestRijndael(TestUnitBase):

    def test_reversible(self):
        data = self.generate_random_buffer(500)
        for mode in ('CBC', 'CFB', 'OFB', 'PCBC'):
            for block_size in (16, 24, 32):
                for key_size in (16, 24, 32):
                    encrypter = -self.load(range(key_size), iv=range(block_size), mode=mode, block_size=block_size)
                    decrypter = self.load(range(key_size), iv=range(block_size), mode=mode, block_size=block_size)
                    self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode}')

    def test_real_world_block_size_32(self):
        unit = self.load(
            key=bytes.fromhex('2e5f9489983c96aa2165a3fb6a6d55f0e7397c6488da72ff213452b2c7edccb6'),
            iv=bytes.fromhex('47ade3cc7fe9e8c734e5c17c1bc067e7f1ebf0f12597ed73e99570054c9897ab'),
            block_size=32)
        data = bytes.fromhex(
            '51 20 C5 85 3D D5 96 A6 8E E5 D5 4B E3 EA 3F F6 8E D4 C3 C9 E3 6A E0 2B D5 76 57 77'
            '40 8E C6 25 4A 5E 8A 5C 23 67 53 91 EE 97 D0 A4 ED F8 98 ED 38 69 68 93 1C 37 A1 1C'
            '40 E0 FC 16 F2 53 FC E6')
        self.assertEqual(data | unit | str, ' /c SCHTASKS /CREATE /SC HOURLY /TN')

