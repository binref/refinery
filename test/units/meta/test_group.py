#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


# The magic word is bananapalooza
class TestGroupingUnit(TestUnitBase):

    def test_01(self):
        pipeline = L('emit A B C  D E F  G H I  J K [| group 3 []| sep - ]')
        self.assertEqual(pipeline(), B'ABC-DEF-GHI-JK')
