#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestMetaPut(TestUnitBase):

    def test_simple_variable_01(self):
        pl = L('emit "FOO BAR" [') | L('mput ff rep[5]:copy::1') | L('nop') | L('ccp var:ff ]') # noqa
        self.assertEqual(pl(), B'FFFFFFOO BAR')
