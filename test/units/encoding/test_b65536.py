#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase65536(TestUnitBase):
    def test_empty_string_01(self):
        self.assertEqual(B'' | -self.load() | bytes, B'')

    def test_empty_string_02(self):
        self.assertEqual(B'' | self.load() | bytes, B'')

    def test_dCode_01(self):
        goal = bytes.fromhex("E7 A1 A4 E9 A5 AF E1 95 A5")
        self.assertEqual(B'dCode' | -self.load() | bytes, goal)

    def test_dCode_02(self):
        data = bytes.fromhex("E7 A1 A4 E9 A5 AF E1 95 A5")
        self.assertEqual(data | self.load() | str, 'dCode')

    def test_b65536(self):
        data = bytes.fromhex("E9 99 82 E9 A9 B3 E6 A8 B6 E6 A0 B5 E1 94 B6")
        self.assertEqual(data | self.load() | str, 'Base65536')
