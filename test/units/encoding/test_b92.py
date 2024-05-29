#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase92(TestUnitBase):
    def test_empty_string_01(self):
        self.assertEqual(B'' | -self.load() | bytes, B'~')

    def test_empty_string_02(self):
        self.assertEqual(B'~' | self.load() | bytes, B'')

    def test_dCode_01(self):
        self.assertEqual(B'dCode' | -self.load() | str, 'E9H]U3B')

    def test_dCode_02(self):
        self.assertEqual(B'E9H]U3B' | self.load() | str, 'dCode')

    def test_b92(self):
        self.assertEqual(B'9A2?VBWl' | self.load() | str, 'Base92')

    def test_generated_01(self):
        data = BR"?\%&%5\i)IamU+3a=Q]sEZ.2ECY&?n[':Bif6(]^9zUTTgUJ:D:"
        goal = BR"THEBINARYREFINERYREFINESTHEFINESTBINARIES"
        self.assertEqual(data | self.load() | bytes, goal)

    def test_generated_02(self):
        data = BR'THEBINARYREFINERYREFINESTHEFINESTBINARIES'
        goal = bytes.fromhex(
            '8F 63 24 5C 12 B3 59 DE B2 55 C1 2C A1 9D EB 25 5C'
            '12 CA 28 F6 32 55 C1 2C A2 8F 33 82 56 6A E0 0C')
        self.assertEqual(data | self.load(lenient=True) | bytes, goal)
