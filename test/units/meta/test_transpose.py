#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestTranspose(TestUnitBase):

    def test_simple_transpositions(self):
        p = self.load_pipeline('emit HELLO WORLD [| transpose ]')
        self.assertEqual(p(), (
            B'HW'
            B'EO'
            B'LR'
            B'LL'
            B'OD'
        ))

        p = self.load_pipeline('emit HELLO WORLD [| transpose X ]')
        self.assertEqual(p(), (
            B'HW'
            B'EO'
            B'LR'
            B'LL'
            B'OD'
        ))

        p = self.load_pipeline('emit HELLO WORLD [| transpose | transpose ]')
        self.assertEqual(p(), (
            B'HELLO'
            B'WORLD'
        ))

    def test_padding(self):
        p = self.load_pipeline('emit BINARY REFINE RY [| transpose Y ]')
        self.assertEqual(p(), (
            B'BRR'
            B'IEY'
            B'NFY'
            B'AIY'
            B'RNY'
            B'YEY'
        ))

    def test_without_padding(self):
        p = self.load_pipeline('emit BINARY REFINERY ROCKS [| transpose ]')
        self.assertEqual(p(), (
            B'BRR'
            B'IEO'
            B'NFC'
            B'AIK'
            B'RNS'
            B'YE'
            RB'R'
            RB'Y'
        ))

    def test_push_pop(self):
        p = self.load_pipeline('emit FOOBAR [| push | chop size//2 | transpose | pop x y z | ccp var:z ]')
        self.assertEqual(p(), B'ORFOOBAR')
