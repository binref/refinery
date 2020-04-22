#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_commandline as L
from .. import TestUnitBase


class TestMetaPushPop(TestUnitBase):

    def test_simple_variable_01(self):
        pl = L('emit "FOO BAR" [') | L('mpush') | L('snip :4') | L('mpop oof') | L('nop') | L('ccp var:oof ]') # noqa
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_simple_variable_02(self):
        pl = L('emit "FOO BAR" [') | L('mpush [') | L('snip :4') | L('mpop oof ]') | L('nop') | L('ccp var:oof ]') # noqa
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_simple_variable_03(self):
        pl = L('emit "FOO BAR"') | L('mpush [[')  | L('snip :4') | L('mpop oof ]') | L('nop') | L('ccp var:oof ]') # noqa
        self.assertEqual(pl(), B'FOO FOO BAR')
