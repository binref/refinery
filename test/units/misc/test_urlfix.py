#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestURLFixer(TestUnitBase):

    def test_01(self):
        self.assertEqual(
            b'HTtP://exAmpLE.COM/path/to/script.php?arg=1' | self.load() | str,
            r'http://example.com/path/to/script.php')

    def test_02(self):
        self.assertEqual(
            b'GOPHER://exAmpLE.COM/path/to/script.php?arg=1#fragmento' | self.load() | str,
            r'gopher://example.com/path/to/script.php')
