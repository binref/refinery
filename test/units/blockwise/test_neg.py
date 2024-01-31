#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestNeg(TestUnitBase):

    def test_neg_example_01(self):
        neg = self.load()
        self.assertEqual(neg(b'\xFF\x00'), b'\x00\xFF')

    def test_neg_idempotence(self):
        for b in (1, 2, 3, 4, 5, 7, 8, 12, 17):
            unit = self.load(blocksize=b)
            data = self.generate_random_buffer(3 * b + 1)
            self.assertEqual(data, unit(unit(data)))
