#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


class TestMetaVarClear(TestMetaBase):

    def test_mvc_01(self):
        pl = self.load_pipeline('emit FOO [| put x BAR [| put x BOO | mvc x | cfmt {}{x} ]| cfmt {}{x} ]')
        self.assertEqual(pl(), B'FOO{x}BAR')
