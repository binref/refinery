#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .... import TestUnitBase


class TestDotNetManagedResourceDeserializer(TestUnitBase):

    def test_real_world_01(self):
        rsrc = self.ldu('dnrc', '70218dfd-5f9f-d4.Resources.resources')
        data = rsrc(self.download_from_malshare('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf'))
        unit = self.load('f0787dcf-8df6-f70')
        self.assertTrue(unit(data).startswith(bytes.fromhex('89 50 4E 47 0D 0A 1A 0A')))

    def test_real_world_02(self):
        rsrc = self.ldu('dnrc', '70218dfd-5f9f-d4.Resources.resources')
        data = rsrc(self.download_from_malshare('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf'))
        unit = self.load('b091b52a-98c2-06')
        self.assertEqual(unit(data), bytes((29, 0, 0, 0)))
