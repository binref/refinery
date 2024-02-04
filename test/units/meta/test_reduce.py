#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestReduce(TestUnitBase):

    def test_concatenation(self):
        pl = L('emit 5 4 3 2 1 0 [| reduce ccp var:t ]')
        self.assertEqual(pl(), B'012345')

    def test_variables_are_retained(self):
        pl = L('emit 5 4 3 2 1 0 [| put q | reduce ccp var:q ]')
        self.assertEqual(pl(), B'012345')

    def test_addition(self):
        pl = L('emit 12 20 8 10000 [| pack -B4 | reduce add t | pack -RB4 ]')
        self.assertEqual(pl(), b'10040')

    def test_just_parameter(self):
        def p(n):
            return n * (n - 1) // 2
        chunk = next(self.load_pipeline(
            'emit range::9 | chop 1 ['
            '| put x le:c:'
            '| reduce add var:t -j 2 | pick 0 0: | pop a:le'
            '| reduce add var:t -j 2 | pick 0 0: | pop b:le'
            '| reduce add var:x | put c le:c:: ]'))
        self.assertEqual(chunk['a'], p(3))
        self.assertEqual(chunk['b'], p(5))
        self.assertEqual(chunk['c'], p(9))
        self.assertEqual(chunk['x'], 0)
