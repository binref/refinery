#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestStretch(TestUnitBase):

    def test_simple_stretch(self):
        data = B'iIIiIIIIiImain'
        wish = B'iiIIIIiiIIIIIIIIiiIImmaaiinn'
        unit = self.load()
        self.assertEqual(unit(data), wish)

    def test_multi_stretch(self):
        data = B'BINARY REFINERY!'
        wish = B'BBINNNARRY   REEFIIINEERYYY!'
        unit = self.load(2, 1, 3, 1)
        self.assertEqual(unit(data), wish)

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            self.load(1, 2, 0, 3)
        with self.assertRaises(ValueError):
            self.load(1, -2, 0)

    def test_invert(self):
        data = B'born to refine binaries'
        stretch = self.load(2, 4, 1, 3)
        clinch = self.load(2, 4, 1, 3, reverse=True)
        self.assertEqual(data, clinch(stretch(data)))
