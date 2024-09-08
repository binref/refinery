#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from refinery.lib.loader import load_detached as L
from refinery.lib.loader import load_pipeline
from .. import TestUnitBase


class TestIfExpr(TestUnitBase):

    def test_pick_only_odd_items(self):
        pl = L('emit Marry had a little lamb.') [ self.load('index % 2 == 0') | L('sep " "') ]
        self.assertEqual(pl(), B'Marry a lamb.')

    def test_filter_by_size(self):
        pl = L('emit Tim Ada Jake Elisabeth James Meredith') [ self.load('size > 3') | L('sep') ]
        self.assertEqual(pl(), B'\n'.join([
            B'Jake',
            B'Elisabeth',
            B'James',
            B'Meredith'
        ]))

    def test_comparison_01(self):
        pl = L('emit A BB C D EEE') [ self.load('size', '-ge', '2') ]
        self.assertEqual(pl(), B'BBEEE')

    def test_comparison_02(self):
        pl = L('emit A BB C D EEE') [ self.load('size', '-lt', '2') ]
        self.assertEqual(pl(), B'ACD')

    def test_filter_empty_chunks(self):
        pl = load_pipeline('emit AAA==FCC [| resplit = | b64 | iff | emit . ]')
        self.assertEqual(pl(), B'..')

    def test_single(self):
        pl = load_pipeline('emit a b c c d [| put x | iff x -eq c | p1 ]')
        self.assertEqual(pl(), B'c')

    def test_retain(self):
        pl = load_pipeline('emit a b c d c [| put x | iff x -eq c -r | cfmt {}{} | scope ]')
        self.assertEqual(pl(), B'abccdcc')
