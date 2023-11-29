#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestVBAStr(TestUnitBase):

    def test_blogpost_example(self):
        # https://nvdp01.github.io/analysis/2022/06/29/extracting-vba-userform-field-values.html
        data = self.download_sample('303bc0f4742c61166d05f7a14a25b3c118fa3ba04298b8370071b4ed19f1a987')
        test = data | self.load('tabyAeEx3574.tip') | str
        self.assertEqual(test, 'nnacShtlaeHW\\putratS\\sm')

    def test_stomped_document_01(self):
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        unit = self.load()
        strings = list(data | unit)
        self.assertEqual(len(strings), 5)
        self.assertIn(bytes.fromhex('48 EF BF BD 2C 5C 59'), strings)
        self.assertIn(bytes.fromhex('48 EF BF BD 2C 56 37'), strings)
        self.assertIn(b'Tahomae', strings)
        strings = [
            bytes(s | self.ldu('hex') | self.ldu('xor', 'An2Lcw6Gseh'))
            for s in strings if len(s) > 100]
        self.assertEqual(len(strings), 2)
        self.assertTrue(any(B'function a0_0x4511()' in string for string in strings))
