#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


class TestMinMax(TestMetaBase):

    def test_max_01(self):
        pl = L('emit the Binary Refinery refines the finest binaries [| max size ]')
        self.assertEqual(pl(), B'Refinery')

    def test_min_01(self):
        pl = L('emit the Binary Refinery refines the finest binaries [| min size ]')
        self.assertEqual(pl(), B'the')
