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

    def test_real_world_01(self):
        data = self.download_sample('1c4b99cb11181ab2cca65fca41f38b5e7efbc12bf2b46cb1f6e73a029f9d97f0')
        unit = self.load()
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | unit}
        self.assertEqual('4963339bb261a8abc0dfdc95cd37dd3d5624f283402bfd72c6486e19bb5aedd5', chunks[b'start.cmd'])
        self.assertEqual('bdceb5afb4cb92f1bb938948cbe496bfa3de8c8d7b1f242cb133e2b18600256b', chunks[b'macosx.dat'])
        self.assertEqual('36484434a281c6ed81966682dede4cbb5cfb7eed775cdcf001a348939e3bb331', chunks[b'Attachments.lnk'])
