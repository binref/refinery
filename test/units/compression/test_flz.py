#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from . import KADATH1


class TestFLZ(TestUnitBase):

    def test_invertible_01(self):
        data = KADATH1
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=0)
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=1)
        self.assertEqual(data | -unit | unit | str, data)

    def test_invertible_02(self):
        data = KADATH1 * (0x10000 // len(KADATH1) + 1)
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=1)
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=0)
        self.assertEqual(data | -unit | unit | str, data)

    def test_invertible_03(self):
        data = 'Hello World'
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)

    def test_invertible_04(self):
        data = 'Binary Refinery ' * 20
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)