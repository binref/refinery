#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestSnip(TestUnitBase):

    def test_snip_multiple_pieces(self):
        fuse = self.ldu('sep', B'')
        unit = self.load('3:5', '13:19', '21:')[fuse]
        self.assertEqual(unit(B'UJKHEOFKSJEUCLLOWORDDLD'), B'HELLOWORLD')

    def test_snip_negative_slice(self):
        unit = self.load('--', '-4:')
        data = B'FOO BAR BARF'
        self.assertEqual(unit(data), B'BARF')
