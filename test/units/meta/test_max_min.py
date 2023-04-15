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

    def test_max_works_with_pop(self):
        pl = L('emit Y:FOO:DN:GOOP [| push | resplit : | max size | pop ll | ccp var:ll ]')
        self.assertEqual(pl(), b'GOOPY:FOO:DN:GOOP')

    def test_min_works_with_pop(self):
        pl = L('emit YY:FOO:A:GOOP [| push | resplit : | min size | pop ll | ccp var:ll ]')
        self.assertEqual(pl(), b'AYY:FOO:A:GOOP')
