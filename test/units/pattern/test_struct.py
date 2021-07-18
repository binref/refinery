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
