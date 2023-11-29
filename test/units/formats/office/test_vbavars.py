#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestVBAVars(TestUnitBase):

    def test_blogpost_example(self):
        # https://nvdp01.github.io/analysis/2022/06/29/extracting-vba-userform-field-values.html
        data = self.download_sample('303bc0f4742c61166d05f7a14a25b3c118fa3ba04298b8370071b4ed19f1a987')
        test = data | self.load('tabyAeEx3574.tip') | str
        self.assertEqual(test, 'nnacShtlaeHW\\putratS\\sm')
