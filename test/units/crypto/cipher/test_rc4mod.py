#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestModifiedRC4(TestUnitBase):

    def test_real_world_01(self):
        unit = self.load((
            BR'E0qaj^)K9M76nnztYKRyDUBJHox?I75eS>mFoLo3WbHpxmYY9!yYJ?Qgy_'
            BR'T<?VVMjhY&?NJ6$Z)#yXPn!)C^ry3%*pEtOLlK)XXb$fws_IQg)ox57C66'
            B'\0'
        ), size=0x13AA)
        data = bytes.fromhex(
            '0B EE 83 86 0B C9 B8 9C 0D 11 AB 6A 69 85 B0 A5 37 9A AA CD'
            'F1 66 B2 91 A0 44 72 E8 51 44 AD 3A 2F 4C 6A 62 AC 15 3B EE'
            '55 0A 63 F1 C4 67 CF A6 1E 0F 79 E2 A8 4B 63 5B 45 1F 55 D0'
            'DB 54 F8 8C 94 21 31 48 4D 43 5F 3C 2B 2A A4 22 DE 46 6C D0'
            'E3 0A 51 A9 34 53 63 F7 8E 80 49 FC AE 1F 7A E7 D4 2F 37 23'
            '19 8B 7C 29 49 48 06 25 99 DC 97 B4 30 C4 E1 84'
        )
        self.assertIn(B'This program cannot be run in DOS mode', bytes(data | unit))

    def test_discard(self):
        goal = bytes.fromhex('DF81C217EF2D066F41891527293C7AAD')
        data = b'1RQCmvqeSxBYnXXD'
        self.assertEqual(data | self.load(b'C9J2oU8orRsjZ73J', discard=505) | bytes, goal)
