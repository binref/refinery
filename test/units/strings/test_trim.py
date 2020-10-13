#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestFormatString(TestUnitBase):

    def test_left_and_right(self):
        trim = self.load()
        self.assertEqual(trim(b'   abc   '), b'abc')

    def test_left(self):
        trim = self.load('-l')
        self.assertEqual(trim(b'   abc   '), b'abc   ')

    def test_right(self):
        trim = self.load('-r')
        self.assertEqual(trim(b'   abc   '), b'   abc')

    def test_mutli_char_01(self):
        trim = self.load(b'x:')
        self.assertEqual(trim(b'x:x:x::abc'), b':abc')

    def test_mutli_char_02(self):
        trim = self.load(b'ab', b'cd')
        self.assertEqual(trim(b'abcdabef'), b'ef')

    def test_everything_trimmed(self):
        trim = self.load(b'\0')
        self.assertEqual(trim(bytearray(201)), B'')