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

    def test_modified_archive_lzma_solid(self):
        data = self.download_sample('19ccf1d4389f624fb166c5828c1633ea4234c976e044e5b61e53000f4a098be8')
        unit = self.load('diskpart.vbe')
        result = str(data | unit | self.ldu('recode') | self.ldu('wshenc'))
        self.assertIn(U'Извините, вы не указали размер диска!', result)

    def test_modified_archive_lzma_nonsolid(self):
        data = self.download_sample('ff4ef0ee0915af58ea1388f72730c63c746856a64760e17e4fcdfc559a8b4555')
        unit = self.load('csrss.bat')
        result = str(data | unit | self.ldu('recode', 'cp1251'))
        self.assertIn(U'КАК РАСШИФРОВАТЬ ФАЙЛЫ.TXT', result)

    def test_all_modes_and_methods(self):
        data = self.download_sample('bf777a9a51cbea4b27b97c9dd81076e68aceb22edb535fdd0c16321d5ac2f6f8')
        test = data | self.ldu('xtzip') [ self.load('filetwo.txt') ]| {str} # noqa
        self.assertEqual(len(test), 1)
        test = next(iter(test)).splitlines(False)
        for k, line in enumerate([
            r'  /  |                            ',
            r' _$$ |_    __   __   __   ______  ',
            r'/ $$   |  /  | /  | /  | /      \ ',
            r'$$$$$$/   $$ | $$ | $$ |/$$$$$$  |',
            r'  $$ | __ $$ | $$ | $$ |$$ |  $$ |',
            r'  $$ |/  |$$ \_$$ \_$$ |$$ \__$$ |',
            r'  $$  $$/ $$   $$   $$/ $$    $$/ ',
            r'   $$$$/   $$$$$/$$$$/   $$$$$$/  ',
        ], 1):
            self.assertEqual(line, test[k])
