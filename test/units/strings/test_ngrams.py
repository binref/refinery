#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestNGrams(TestUnitBase):

    def test_simple_01(self):
        pl = self.load_pipeline('emit ABC | ngrams 1 []')
        self.assertEqual(pl(), B'ABC')

    def test_simple_02(self):
        pl = self.load_pipeline('emit ABC | ngrams 2 []')
        self.assertEqual(pl(), B'ABBC')
