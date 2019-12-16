#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestStringReverse(TestUnitBase):

    def test_constant_01(self):
        palindrome = B'racecar'
        unit = self.load()
        self.assertEqual(unit(palindrome), palindrome)

    def test_constant_02(self):
        unit = self.load()
        self.assertEqual(unit(B'qwertzuiopasdfghjklyxcvbnm'), B'mnbvcxylkjhgfdsapoiuztrewq')
