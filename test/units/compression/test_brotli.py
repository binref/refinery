#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBrotli(TestUnitBase):

    def test_decompress_html(self):
        unit = self.load()
        html = self.ldu('xthtml', '**/h1/span/?/b')
        data = self.download_sample('48f4b9329a19cbfb933ceffeb2cc177be0c5d0c049b3b9b07b37205fa03ce75f')
        self.assertEqual(data | unit | html | str, 'BR')
