#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from ... import TestUnitBase


class TestTarFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = self.download_sample('080fe4b3b32a1b219440d4ba7d18d08e749b15ecfc0ae56215532cfddbc99452')
        self.assertEqual(data | self.load('hello'), B'this is hello.txt')
        self.assertEqual(data | self.load('world'), B'this is world.txt')
        pe = json.loads(data | self.load('*.exe') | self.ldu('pemeta'))
        self.assertEqual(pe['Debug']['PdbPath'], 'c:\\users\\hainh45\\documents\\visual studio 2013\\Projects\\MessageBox\\Release\\MessageBox.pdb')
