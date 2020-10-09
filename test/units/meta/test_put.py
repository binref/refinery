#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestMetaPut(TestUnitBase):

    def test_simple_variable_01(self):
        pl = L('emit "FOO BAR" [') | L('put ff rep[5]:copy::1') | L('nop') | L('ccp var:ff ]') # noqa
        self.assertEqual(pl(), B'FFFFFFOO BAR')

    def test_pop_variable(self):
        pl = L('emit AB CD EF [') | L('put k x::1') | L('sub xvar:k ]')
        self.assertEqual(pl(), B'\x01\x01\x01')
