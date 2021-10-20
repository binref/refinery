#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import pack
from zlib import crc32

from .. import TestUnitBase


class TestStructUnit(TestUnitBase):

    def test_structured_data_01(self):
        size = 456
        body = self.generate_random_buffer(size)
        crc = crc32(body)
        data = pack('=BBHL', 0x07, 0x34, size, crc)
        data += B'Binary Refinery\0'
        data += body
        data += B'\0\0\0\0\0\0\0\0'
        unit = self.load('=B{type:B}HLa{:{2}}')
        out = next(data | unit)
        self.assertEqual(out.meta['type'], 0x34)
        self.assertEqual(out, body)

    def test_no_last_field(self):
        unit = self.load('6sB8s')
        self.assertEqual(bytes(B'Binary Refinery' | unit), B'Refinery')

    def test_zero_length(self):
        unit = self.load('{s:H}{d:s}')
        data = (
            B'\x00\x00'
            B'\x02\x00' b'ok'
            B'\x03\x00' b'foo'
            B'\x03\x00' b'bar'
        )
        self.assertListEqual([B'', b'ok', b'foo', b'bar'], list(data | unit))

    def test_read_all(self):
        unit = self.load('{s:B}{d:s}{x}')
        data = (
            B'\x02' b'ok'
            B'\x03' b'foo'
            B'\x03' b'bar'
        )
        self.assertListEqual([b'\x03foo\x03bar'], list(data | unit))
