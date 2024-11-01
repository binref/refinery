#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase32(TestUnitBase):

    def test_too_much_padding(self):
        unit = self.load()
        self.assertEqual(B'KRSXG5A====' | unit | bytes, B'Test')

    def test_too_little_padding(self):
        unit = self.load()
        self.assertEqual(B'KRSXG5A' | unit | bytes, B'Test')

    def test_correct_existing_padding(self):
        unit = self.load()
        self.assertEqual(B'KRSXG5A=' | unit | bytes, B'Test')
