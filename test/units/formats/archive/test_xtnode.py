#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from ... import TestUnitBase


class TestNodeExtractor(TestUnitBase):

    def test_nexe_01(self):
        data = self.download_sample('8603ce73150c3683455435a7ef531b462894bbccffbb340570d90033bd2347a4')
        test = data | self.load() | {'path': str}
        self.assertDictEqual(test, {'installer.js': "console.log('hello world')"})

    def test_pkg_01(self):
        data = self.download_sample('a795f82178219277422a2855eb60dbd475736e8b6f1a4eddd15bb4e5d1ddef93')
        test = data | self.ldu('lzma') | self.load() | {'path': str}
        self.assertListEqual(list(test), ['build/lens-spaces-authenticator.js'])
        test: str = next(iter(test.values()))
        self.assertTrue(test.startswith('module.exports=function(e)'))
