#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestEmailUnpacker(TestUnitBase):

    def test_ascii_01(self):
        data = self.download_sample('a370a9c5defdd25da62ccb33539e6741f1545057f66b59392ffe094157c5fce8')
        unit = self.load(list=True)
        listing = [t.decode('latin1') for t in data | unit]
        for k in range(1, 4):
            self.assertIn(F'body.v{k}.txt', listing)
            self.assertIn(F'body.v{k}.rtf', listing)
        self.assertIn('attachments/request.zip', listing)

    def test_ascii_02(self):
        data = self.download_sample('a370a9c5defdd25da62ccb33539e6741f1545057f66b59392ffe094157c5fce8')
        extract1 = self.load('body.v2.txt')
        extract2 = self.load('*.zip')
        self.assertIn(B'If you are unsure LKQ IT Security advises deleting the email.', extract1(data))
        zipfile = extract2(data)
        self.assertEqual(zipfile[:2], B'PK')
        self.assertIn(B'require.05.21.doc', zipfile)
        self.assertEqual(len(zipfile), 77_848)

    def test_cdfv2_01(self):
        data = self.download_sample('f4d5353552501b7aa0f9bb400e0d0349487dc45cbe5ce82fe5e7de526d37f301')
        out = data | self.load() | {'path': ...}
        self.assertSetEqual(set(out), {
            'headers.txt',
            'headers.json',
            'body.txt',
            'attachments/request.zip',
        })
        self.assertIn(b'figures,12.18.2020.doc', out['attachments/request.zip'])
