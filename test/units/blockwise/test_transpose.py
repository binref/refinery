#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestTranspose(TestUnitBase):

    def test_simple_transpositions(self):
        hw1 = (
            B'HELLO'
            B'WORLD'
        )
        hw2 = (
            B'HW'
            B'EO'
            B'LR'
            B'LL'
            B'OD'
        )
        self.assertEqual(self.load(blocksize=2)(hw2), hw1)
        self.assertEqual(self.load(blocksize=5)(hw1), hw2)
        self.assertEqual(self.load(blocksize=5, padding=B'X')(hw1), hw2)

    def test_padding(self):
        br1 = (
            B'BINARY'
            B'REFINE'
            B'RY'
        )
        br2 = (
            B'BRR'
            B'IEY'
            B'NFY'
            B'AIY'
            B'RNY'
            B'YEY'
        )
        unit = self.load('-B6', 'Y')
        self.assertEqual(unit(br1), br2)

    def test_without_padding(self):
        br1 = (
            B'BINARY'
            B'REFINE'
            B'RY'
        )
        br2 = (
            B'BRR'
            B'IEY'
            B'NF'
            B'AI'
            B'RN'
            B'YE'
        )
        unit = self.load('-B6')
        self.assertEqual(unit(br1), br2)
