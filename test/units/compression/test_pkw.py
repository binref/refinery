#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestPKW(TestUnitBase):

    def test_simple_string_01(self):
        self.assertEqual(
            # 00000000 00000100 1 00000100010010000100101100011111000000001111111
            b'\x00\x04\x82\x24\x25\x8F\x80\x7F' | self.load() | bytes, b'AIAIAIAIAIAIA')

    def test_simple_string_02(self):
        self.assertEqual(
            # 01100010 01000001 11110010 00001000 11111000 00000111
            # 0 100011 0 100000 1 001001 11 1000 10000 00011111 11100000
            # L  'A'   L  'I'   D   11    0   1
            b'\x01\x04\x62\x41\xF2\x08\xF8\x07' | self.load() | bytes, b'AIAIAIAIAIAIA')

    def test_simple_string_03(self):
        test = (
            b'\x01\x04\x02\x6F\x5A\x08\xB6\x67\xE8\x86\x6A\xA9\x8A\x6D\x28'
            b'\x5E\x56\x6D\xCD\x5B\x5B\x6C\x47\x73\x18\xB6\x8A\x17\xF0\x0F'
        )
        goal = b'I like consistent user interfaces.'
        self.assertEqual(test | self.load() | bytes, goal)

    def test_simple_string_04(self):
        test = (
            b'\x01\x06\x50\x6C\xD3\xD4\x3D\xBC\xAE\x99\x74\x50\x7A\x28\x3A'
            b'\xBC\x77\x34\xDB\x83\xD3\x65\x7C\xAF\xE8\x74\x07\x1C\x88\x7B'
            b'\x16\xC5\x52\xFD\x17\x1C\x0F\xC1\xD6\xC0\xF9\xB5\x31\xA8\x1B'
            b'\xB4\xC1\x2B\x78\x01\xFF'
        )
        goal = b'Hello world! How are you, today? This is a very long text.'
        self.assertEqual(test | self.load() | bytes, goal)
