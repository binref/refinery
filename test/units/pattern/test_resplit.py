#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from refinery.lib.loader import load_detached as L


class TestRegexSplitter(TestUnitBase):

    def test_change_separator(self):
        pl = L('emit eeny,meeny,miny,moe') | L('resplit (,) [') | L('scope 1::2') | L('cfmt - ]')
        self.assertEqual(pl(), B'eeny-meeny-miny-moe')

    def test_count_restriction(self):
        pl = L('emit eeny,meeny,miny,moe') | L('resplit -c1 ,')
        self.assertEqual(pl(), B'eeny\nmeeny,miny,moe')

    def test_multibin_argument(self):
        pl = L('emit foobar') [ L('put split oo') | L('resplit xvar:split') ]  # noqa
        self.assertEqual(list(pl), [b'f', b'bar'])
