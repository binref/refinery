#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestSZDD(TestUnitBase):

    def test_01(self):
        unit = self.load()
        data = self.download_sample('e5f3ef69a534260e899a36cec459440dc572388defd8f1d98760d31c700f42d5')
        hash = str(data | unit | self.ldu('sha256', text=True))
        self.assertEqual(hash, '96b77284744f8761c4f2558388e0aee2140618b484ff53fa8b222b340d2a9c84')
