#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestImportHash(TestUnitBase):

    def test_sample1(self):
        data = self.download_sample('426ace19debaba6f262dcd3ce429dc8fc0b233f3fa02262375c4641d9f466709')
        unit = self.load()
        self.assertEqual(bytes(data | unit), bytes.fromhex('f34d5f2d4577ed6d9ceec516c1f5a744'))

    def test_sample2(self):
        data = self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load()
        self.assertEqual(bytes(data | unit), bytes.fromhex('dbcb53a36e96d4d8aa08cc2ad23d6d49'))

    def test_sample3(self):
        data = self.download_sample('ce1cd24a782932e1c28c030da741a21729a3c5930d8358079b0f91747dd0d832')
        unit = self.load()
        self.assertEqual(bytes(data | unit), bytes.fromhex('912c0288e088857caa0e79c95b78523c'))
