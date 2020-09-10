#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestMetaPushPop(TestUnitBase):

    def test_simple_variable_01(self):
        pl = L('emit "FOO BAR" [') | L('push') | L('snip :4') | L('pop oof') | L('nop') | L('ccp var:oof ]') # noqa
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_simple_variable_02(self):
        pl = L('emit "FOO BAR" [') | L('push [') | L('snip :4') | L('pop oof ]') | L('nop') | L('ccp var:oof ]') # noqa
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_simple_variable_03(self):
        pl = L('emit "FOO BAR"') | L('push [[')  | L('snip :4') | L('pop oof ]') | L('nop') | L('ccp var:oof ]') # noqa
        self.assertEqual(pl(), B'FOO FOO BAR')

    def test_variable_in_modifier(self):
        pl = L('push [[') | L('pop x ]') | L('cca cca[cca[var:x]:Q]:T') | L('rev ]]')
        self.assertEqual(pl(B'x'), B'xQTx')

    def test_variable_outside_modifier(self):
        pl = L('push [[') | L('pop x ]') | L('cca T') | L('cca var:x') | L('rev ]')
        self.assertEqual(pl(B'x'), B'xTx')
