#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_detached as L
from .. import TestUnitBase


class TestReduce(TestUnitBase):

    def test_concatenation(self):
        pl = L('emit 5 4 3 2 1 0 [') | L('reduce ccp var:t ]') # noqa
        self.assertEqual(pl(), B'012345')

    def test_variables_are_retained(self):
        pl = L('emit 5 4 3 2 1 0 [') | L('swap q') | L('reduce -i= ccp var:q ]') # noqa
        self.assertEqual(pl(), B'012345')
