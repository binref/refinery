#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .... import TestUnitBase


class TestDotNetDeserializer(TestUnitBase):

    def test_real_world_01(self):
        unit = self.load('b091b52a-98c2-06')
        sample = self.download_from_malshare('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        self.assertEqual(unit(sample), B'29')
