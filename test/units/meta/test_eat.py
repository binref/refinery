#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestMetaEat(TestUnitBase):

    def test_still_works_as_prefix(self):
        pl = L('emit foo [| put baz bar | cca eat:baz ]')
        self.assertEqual(pl(), B'foobar')

    def test_also_works_as_unit(self):
        pl = L('emit foo [| put baz bar | eat baz ]')
        self.assertEqual(pl(), B'bar')
