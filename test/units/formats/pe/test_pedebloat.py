#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestPEDebloat(TestUnitBase):

    def test_section_bloat(self):
        data = self.download_sample('31c353e37946bf459b2a724fbbf2308caf82c96ae48ffcfa798ce5b117f5a8ba')
        bloated = data | self.ldu('xt') | bytearray
        self.assertGreaterEqual(len(bloated), 100_000_000)
        stripped = bloated | self.ldu('pestrip') | self.load(sections=True) | bytearray
        self.assertLessEqual(len(stripped), 10_000_000)
        check = stripped | self.ldu('vsect', '.?0?') | self.ldu('trim', b'\0') | self.ldu('sha256', text=True) | str
        self.assertEqual(check, 'ec018cb120e9c8af36e794d1205f649f1bc5fc3590f21e22b248201cdbd28cdd')

    def test_resource_bloat_01(self):
        data = self.download_sample('a50a4c0a38520a9f02cf59aa70c930b0491d4d67fe338a317b272d7802b6ecfb')
        bloated = data | self.ldu('xt') | bytearray
        self.assertGreaterEqual(len(bloated), 100_000_000)
        stripped = bloated | self.ldu('pestrip') | self.load(aggressive=True, trim_code=True, trim_rsrc=True) | bytearray
        self.assertLessEqual(len(stripped), 5_000_000)

        stripped = bloated | self.ldu('pestrip') | self.load(resources=True) | bytearray
        self.assertLessEqual(len(stripped), 5_000_000)

    def test_resource_bloat_02(self):
        data = self.download_sample('49fce89423749a4b0883430a077dd71d52fca0e25acf201588d0c5d186a1d33a')
        bloated = data | self.ldu('xt') | bytearray
        self.assertGreaterEqual(len(bloated), 100_000_000)
        stripped = bloated | self.ldu('pestrip') | self.load(aggressive=True, trim_code=True, trim_rsrc=True) | bytearray
        self.assertLessEqual(len(stripped), 10_000_000)

        stripped = bloated | self.ldu('pestrip') | self.load(resources=True) | bytearray
        self.assertLessEqual(len(stripped), 15_000_000)
