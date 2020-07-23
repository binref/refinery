#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from refinery.lib.loader import load_detached as L


class TestRegexSplitter(TestUnitBase):

    def test_change_separator(self):
        pl = L('emit eeny,meeny,miny,moe') | L('resplit (,) [') | L('scope 1::2') | L('cfmt - ]')
        self.assertEqual(pl(), B'eeny-meeny-miny-moe')
