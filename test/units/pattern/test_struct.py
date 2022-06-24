#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import pack
from zlib import crc32

from refinery.lib.loader import load_pipeline as L

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

    def test_variable_cleanup(self):
        data = B'\x05ABCDE' B'BINARY' B'REFINERY'
        unit = self.load('B{key:{0}}{_b:6}{_r:8}', '{_b}', '{_r}')
        b, r = data | unit
        self.assertNotIn('_b', b.meta)
        self.assertNotIn('_r', b.meta)
        self.assertNotIn('_b', r.meta)
        self.assertNotIn('_r', r.meta)
        self.assertEqual(b, B'BINARY')
        self.assertEqual(r, B'REFINERY')

    def test_no_last_field(self):
        unit = self.load('6sB6s')
        self.assertEqual(bytes(B'Binary Refinery' | unit), B'Binary Refine')

    def test_zero_length(self):
        unit = self.load('{s:H}{d:s}', multi=True)
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

    def test_auto_batch(self):
        pl = L(R'emit ABCDEF | struct -m {k:B}{:1}{:1} {2} {3} [[| pop a | cfmt {a}{k} ]]')
        self.assertEqual(pl(), B'B65E68')
