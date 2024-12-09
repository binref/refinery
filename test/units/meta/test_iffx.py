#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestIfRex(TestUnitBase):

    def test_filter_identifier_letters(self):
        pl = L('emit range::256') | L('chop 1')[self.load('\\w')]
        self.assertEqual(pl(), B'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz')

    def test_negate(self):
        pl = self.load_pipeline('emit ab bc cb [| iffx -R .b ]')
        self.assertEqual(pl(), b'bc')
