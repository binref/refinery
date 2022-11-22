#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestMetaPut(TestUnitBase):

    def test_simple_variable_01(self):
        pl = L('emit "FOO BAR" [| put ff rep[5]:copy::1 | nop | ccp var:ff ]')
        self.assertEqual(pl(), B'FFFFFFOO BAR')

    def test_pop_variable(self):
        pl = L('emit AB CD EF [| put k x::1 | sub eat:k ]')
        self.assertEqual(pl(), B'\x01\x01\x01')

    def test_regression_put_removes_variable(self):
        pl = L('emit BAR [| rex . [| put x | cfmt {x}{offset} ]]')
        self.assertEqual(pl(), B'B0A1R2')
