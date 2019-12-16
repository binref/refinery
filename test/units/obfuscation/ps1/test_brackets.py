#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestBracketRemover(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_string_literal_01(self):
        self.assertEqual(self.unit(B'("{0}{2}{1}")'), b'"{0}{2}{1}"')

    def test_string_literal_02(self):
        self.assertEqual(self.unit(B'( ((    \n( "Test")))'), b'( "Test"')

    def test_string_literal_03(self):
        self.assertEqual(self.unit(B'(((\n( "Tes""t")\n)) )'), b'"Tes""t"')

    def test_numeric_literal_01(self):
        self.assertEqual(self.unit(B'(0x12)'), b'0x12')

    def test_numeric_literal_02(self):
        self.assertEqual(self.unit(B'( ((    \n( 0x12)  ))'), b'( 0x12')

    def test_numeric_literal_03(self):
        self.assertEqual(self.unit(B'((31337) )'), b'31337')
