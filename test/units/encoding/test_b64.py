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

    def test_b64_handles(self):
        import base64
        data = self.generate_random_buffer(500)
        unit = self.unit()
        for name, encoding, test in [
            ('base16', base64.b16encode, self.assertFalse),
            ('base32', base64.b32encode, self.assertFalse),
            ('base64', base64.b64encode, self.assertTrue),
            ('base85', base64.b85encode, self.assertFalse),
        ]:
            test(unit.handles(encoding(data)), msg=F'handler test for {name} failed')
