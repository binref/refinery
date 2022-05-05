#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestRep(TestUnitBase):

    def test_batman(self):
        unit = self.load('16', '[]')
        self.assertEqual(B'Na' | unit | bytes, B'NaNaNaNaNaNaNaNaNaNaNaNaNaNaNaNa')

    def test_sequence(self):
        unit = self.load('range:4:7', 't')
        self.assertListEqual(list(chunk['t'] for chunk in B"" | unit), list(range(4, 7)))
