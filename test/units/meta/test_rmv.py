#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


class TestRemoveMetaVar(TestMetaBase):

    def test_rmv_01(self):
        pl = self.load_pipeline('emit FOO [| put x BAR [| put x BOO | rmv x | pf {}{x} ]| pf {}{x} ]')
        self.assertEqual(pl(), B'FOO{x}BAR')
