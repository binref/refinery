#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfExpr(TestUnitBase):

    def test_pick_only_odd_items(self):
        pl = L('emit Marry had a little lamb.') [ L('cm') | self.load('index % 2 == 0') | L('cull') | L('sep " "') ]
        self.assertEqual(pl(), B'Marry a lamb.')

    def test_filter_by_size(self):
        pl = L('emit Tim Ada Jake Elisabeth James Meredith') [ L('cm') | self.load('size > 3') | L('cull') | L('sep') ]
        self.assertEqual(pl(), B'\n'.join([
            B'Jake',
            B'Elisabeth',
            B'James',
            B'Meredith'
        ]))
