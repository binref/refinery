#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


class TestMetaVarClear(TestMetaBase):

    def test_mvc_01(self):
        pl = L('emit FOO [| put x BAR [| put x BOO | mvc x | cca var:x ]]')
        self.assertEqual(pl(), B'FOOBAR')
