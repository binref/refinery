#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestPEStrip(TestUnitBase):

    def test_section_bloat(self):
        data = self.download_sample('31c353e37946bf459b2a724fbbf2308caf82c96ae48ffcfa798ce5b117f5a8ba')
        bloated = data | self.ldu('xt') | bytearray
        self.assertGreaterEqual(len(bloated), 100_000_000)
        stripped = bloated | self.load(sections=True) | bytearray
        self.assertLessEqual(len(stripped), 10_000_000)
        check = stripped | self.ldu('vsect', '.?0?') | self.ldu('trim', b'\0') | self.ldu('sha256', text=True) | str
        self.assertEqual(check, 'ec018cb120e9c8af36e794d1205f649f1bc5fc3590f21e22b248201cdbd28cdd')

    def test_resource_bloat(self):
        data = self.download_sample('a50a4c0a38520a9f02cf59aa70c930b0491d4d67fe338a317b272d7802b6ecfb')
        bloated = data | self.ldu('xt') | bytearray
        self.assertGreaterEqual(len(bloated), 100_000_000)
        stripped = bloated | self.load(aggressive=True) | bytearray
        self.assertLessEqual(len(stripped), 5_000_000)
        self.assertEqual(
            '1d8b1a5830ee16507307978f1f690547b8e161b6a0e6af00b71bd4c77396c8ef',
            stripped | self.ldu('sha256', text=True) | str)
