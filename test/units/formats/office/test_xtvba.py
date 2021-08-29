#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestVBAExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        code = list(data | unit)
        self.assertIn(B'http://109.94.209'B'.91/12340.txt', code[0])
