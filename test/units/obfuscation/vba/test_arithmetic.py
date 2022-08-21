#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestArithmeticEvaluator(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_xor_operator(self):
        self.assertEqual(self.unit.deobfuscate('CLng((0 Xor 0))'), 'CLng((0 Xor 0))')
