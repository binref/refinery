#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from ... import TestUnitBase


class TestNSISExtractor(TestUnitBase):

    def test_modified_archive_deflate1(self):
        data = self.download_sample('e58d7a6fe9d80d757458a5ebc7c8bddd345b355c2bce06fd86d083b5d0ee8384')
        unit = self.load()
        result = data | unit | self.ldu('xt7z') | self.ldu('pemeta') | json.loads
        self.assertEqual(result['Signature']['Fingerprint'], '6509312e581ef5ba12be11ed427a66f8fd80e819')

    def test_modified_archive_lzma1(self):
        data = self.download_sample('19ccf1d4389f624fb166c5828c1633ea4234c976e044e5b61e53000f4a098be8')
        unit = self.load('diskpart.vbe')
        result = str(data | unit | self.ldu('recode') | self.ldu('wshenc'))
        self.assertIn(U'Извините, вы не указали размер диска!', result)
