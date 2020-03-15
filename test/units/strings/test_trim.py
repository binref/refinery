#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestFormatString(TestUnitBase):

    def test_Removal(self):
        trim = self.load()
        self.assertEqual(trim(b'   abc   '), b'abc')

    def test_LeftRemoval(self):
        trim = self.load('-l')
        self.assertEqual(trim(b'   abc   '), b'abc   ')

    def test_RightRemoval(self):
        trim = self.load('-r')
        self.assertEqual(trim(b'   abc   '), b'   abc')

    def test_MultiChar(self):
        trim = self.load(b'x:')
        self.assertEqual(trim(b'x:x:x::abc'), b':abc')

    def test_TwoMultiChar(self):
        trim = self.load(b'ab', b'cd')
        self.assertEqual(trim(b'abcdabef'), b'ef')
