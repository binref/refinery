#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestEscVB(TestUnitBase):

    def test_simple_string(self):
        unit = self.load()
        data = B'"This is ""a string""."'
        test = data | unit | bytes
        self.assertEqual(test, B'This is "a string".')
        self.assertEqual(test | -unit | bytes, data)
