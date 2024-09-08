#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfStr(TestUnitBase):

    def test_simple_01(self):
        pl = L('emit raffle waffle rattle battle cattle settle') [ self.load('att') ]
        self.assertEqual(pl(), B'rattlebattlecattle')
