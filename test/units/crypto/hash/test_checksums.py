#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestChecksums(TestUnitBase):

    def test_crc32(self):
        self.assertEqual(self.ldu('crc32')(B'binary-refinery'), bytes.fromhex('5BEF0622'))

    def test_adler32(self):
        self.assertEqual(self.ldu('adler32')(B'binary-refinery'), bytes.fromhex('2FEA0617'))

    def test_djb2(self):
        self.assertEqual(self.ldu('djb2')(b'Hello!'), bytes.fromhex('b7332fba'))
