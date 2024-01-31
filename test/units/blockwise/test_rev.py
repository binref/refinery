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

    def test_blocks_01(self):
        unit = self.load(blocksize=2)
        self.assertEqual(unit(B'AABBCCDDEEFFGGHHIIJJK'), B'JJIIHHGGFFEEDDCCBBAA')
        self.assertEqual(unit(B'AABBCCDDEEFFGGHHIIJ'), B'IIHHGGFFEEDDCCBBAA')

    def test_blocks_02(self):
        unit = self.load(blocksize=3)
        self.assertEqual(unit(B'AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKK'), B'JJJIIIHHHGGGFFFEEEDDDCCCBBBAAA')
        self.assertEqual(unit(B'AAABBBCCCDDDEEEFFFGGGHHHIIIJ'), B'IIIHHHGGGFFFEEEDDDCCCBBBAAA')