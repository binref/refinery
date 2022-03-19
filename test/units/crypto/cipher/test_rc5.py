#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase

from refinery.units.crypto.cipher.rc5 import RC5, rc5constants


class TestRC5(TestUnitBase):

    def test_magic_constants(self):
        self.assertEqual(rc5constants(16), (0xB7E1, 0x9E37))
        self.assertEqual(rc5constants(32), (0xB7E15163, 0x9E3779B9))
        self.assertEqual(rc5constants(64), (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15))

    def test_examples_kryptografie_de(self):
        # https://kryptografie.de/kryptografie/chiffre/rc5.htm
        sample = B'BeispielklartextBeispielklartext'
        for (w, r), result in {
            (0x08, 12): 'FDE9091D AF439BD1 2DE6EF5C AC8DA3CC FDE9091D AF439BD1 2DE6EF5C AC8DA3CC',
            (0x10, 16): '89EE3CE5 19048197 22821B38 052FDFAC 89EE3CE5 19048197 22821B38 052FDFAC',
            (0x20, 20): 'D5CB6FAB E83BF333 56263D02 E25A0BB7 D5CB6FAB E83BF333 56263D02 E25A0BB7',
            (0x40, 24): '45757C47 EC1575D0 A6CE92AD E5078A2A 45757C47 EC1575D0 A6CE92AD E5078A2A',
        }.items():
            cipher = RC5(w, r, B'Schokoladentorte')
            ciphertext = cipher.encrypt(sample)
            self.assertEqual(ciphertext, bytes.fromhex(result))
            self.assertEqual(cipher.decrypt(ciphertext), sample)
