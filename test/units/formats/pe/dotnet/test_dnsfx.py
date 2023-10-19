#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .... import TestUnitBase


class TestDotNetSingleFileApplicationExtractor(TestUnitBase):

    def test_compression(self):
        unit = self.load()
        data = self.download_sample('34dbeb0b19ae70596a1abd00f57002fbef59f390dec759498298e6e93f252db2')
        data = unit(data)
        self.assertTrue(data.startswith(b'\x7B\x0D\x0A\x20\x20'))
        self.assertIn(b'Compression.pdb', data)

    def test_no_compression(self):
        unit = self.load()
        data = self.download_sample('69f32fe40a58e5051c7616b186ababe7466a9e973713c80689c50aea943674eb')
        data = unit(data)
        self.assertTrue(data.startswith(b'\x7B\x0D\x0A\x20\x20'))
        self.assertIn(b'Compression.pdb', data)

