#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase

from refinery.units.crypto.cipher.rc6 import RC6


class TestRC6(TestUnitBase):

    def test_example_vectors(self):
        for plaintext, user_key, ciphertext in [
            (
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                '8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e',
            ),
            (
                '02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1',
                '01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78',
                '52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18',
            ),
            (
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                '00 00 00 00 00 00 00 00',
                '6c d6 1b cb 19 0b 30 38 4e 8a 3f 16 86 90 ae 82',
            ),
            (
                '02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1',
                '01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78'
                '89 9a ab bc cd de ef f0',
                '68 83 29 d0 19 e5 05 04 1e 52 e9 2a f9 52 91 d4',
            ),
            (
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                '8f 5f bd 05 10 d1 5f a8 93 fa 3f da 6e 85 7e c2',
            ),
            (
                '02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1',
                '01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78'
                '89 9a ab bc cd de ef f0 10 32 54 76 98 ba dc fe',
                'c8 24 18 16 f0 d7 e4 89 20 ad 16 a1 67 4e 5d 48',
            )
        ]:
            P = bytes.fromhex(plaintext)
            K = bytes.fromhex(user_key)
            C = bytes.fromhex(ciphertext)
            cipher = RC6(32, 20, K)
            ciphertext = cipher.encrypt(P)
            self.assertEqual(ciphertext, C)
            self.assertEqual(cipher.decrypt(C), P)
