#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase64(TestUnitBase):
    def test_fo8(self):
        unit = self.load()
        self.assertEqual(
            '=gjTP1SRSFETGBDM6ADM6gDMrQFMwoDMwoDMyQFMx0SOw0SMyAjM',
            str(B'PWdqVFAxU1JTRkVUR0JETTZBRE02Z0RNclFGTXdvRE13b0RNeVFGTXgwU093MFNNeUFqTQ==' | unit)
        )
        self.assertEqual(
            '2021-09-10T20:00:00T+08:00:00FLARE-ON8',
            str(B'MjAyMS0wOS0xMFQyMDowMDowMFQrMDg6MDA6MDBGTEFSRS1PTjg=' | unit)
        )

    def test_forward_empty(self):
        self.assertEqual(bytes(B'' | self.load()), B'')

    def test_auto_urlsafe_decoding(self):
        data = self.generate_random_buffer(400)
        encoded = data | self.load(reverse=True, urlsafe=True) | bytes
        decoded = encoded | self.load() | bytes
        self.assertEqual(data, decoded)
