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

    def test_push_pop_in_frame(self):
        pl = L('rex . [') | L('push [') | L('pop copy ]') | L('swap copy ]')
        self.assertEqual(pl(B'foobar'), B'foobar')

    def test_pop_discard(self):
        pl = L('emit A B C D E [') | L('pop a b 2') | L('cca var:a') | L('cca var:b ]') # noqa
        self.assertEqual(pl(), B'EAB')
