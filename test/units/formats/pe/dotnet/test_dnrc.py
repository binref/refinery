#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .... import TestUnitBase


class TestDotNetDeserializer(TestUnitBase):

    def test_real_world_01(self):
        unit = self.load('f0787dcf-8df6-f70')
        sample = self.download_from_malshare('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        self.assertTrue(unit(sample).startswith(bytes.fromhex('89 50 4E 47 0D 0A 1A 0A')))

    def test_real_world_02(self):
        unit = self.load('b091b52a-98c2-06')
        sample = self.download_from_malshare('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        self.assertEqual(unit(sample), B'29')
