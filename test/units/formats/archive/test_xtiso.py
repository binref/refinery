#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestISOFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = self.download_sample('d4bd4131c785b46d7557be3a94015db09e8e183eaafc6af366e849b0175da681')
        unit = self.load()
        unpacked = unit(data)
        self.assertTrue(unpacked.startswith(b'{\\rtf1'), 'unpacked file is not an RTF document')
        self.assertIn(B'EU48RUK5N4YDFT73I3RIF3H3UH', data)
