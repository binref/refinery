#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestSwap(TestUnitBase):

    def test_swap_variable_01(self):
        pl = L('emit BAZ [') | L('put BAR S:FOO') | L('put FOO S:BAR') | L('swap FOO BAR') | L('cfmt {FOO}{BAR} ]')
        self.assertEqual(pl(), B'FOOBAR')

    def test_swap_variable_02(self):
        pl = L('emit BAZ [') | L('put BAR FOO') | L('swap BAR FOO') | L('cfmt {FOO} ]')
        self.assertEqual(pl(), B'FOO')

    def test_swap_with_data(self):
        pl = L('emit BAR [') | L('put BAR FOO') | L('swap BAR') | L('cfmt {}{BAR}{FOO} ]')
        self.assertEqual(pl(), B'FOOBAR{FOO}')

    def test_swap_skips_invisible_chunks(self):
        pl = L('emit range:65:91') [ L('push') [ L('rex MNO') | L('swap mno') | L('pop') ]| L('ccp var:mno') ] # noqa
        self.assertEqual(pl(), B'MNOABCDEFGHIJKLMNOPQRSTUVWXYZ')
