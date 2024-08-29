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

    def test_use_variables_in_output(self):
        data = self.download_sample('4537fab9de768a668ab4e72ae2cce3169b7af2dd36a1723ddab09c04d31d61a5')
        test = data | self.load_pipeline('vsect .bss | struct {n:L}{k:n}{c:} {c:rc4[var:k]:snip[::2]}') | bytes
        self.assertIn(B'165.22.5'B'.66', test)

    def test_until(self):
        data = B'1A92750293738'
        test = data | self.load('{k:B}', multi=True, until='k==0x30') | []
        self.assertEqual(len(test), 6)

    def test_argument_assignment_failure_regression_01(self):
        test = self.load_pipeline('emit rep[10]:5szz | struct -m {k:1}{d:3} {k}{d:xor[var:k]} []') | bytes
        self.assertEqual(test, 10 * B'5FOO')

    def test_argument_assignment_failure_regression_02(self):
        test = self.load_pipeline('emit rep[1000]:5szz | struct -m {k:1}{d:3} {k}{d:xor[var:k]} []') | bytes
        self.assertEqual(test, 1000 * B'5FOO')

    def test_correct_leftover_calculation(self):
        test = self.load_pipeline('emit ABCDE | struct -mM {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'ACE')
        test = self.load_pipeline('emit ABCDEF | struct -mM {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'ACE')
        test = self.load_pipeline('emit ABCDE | struct -m {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'AC')
        test = self.load_pipeline('emit ABCDEF | struct -m {a:1}{b:1} {a} []')
        self.assertEqual(test(), b'ACE')

    def test_variables_available_in_pipeline(self):
        data = B'\x02xxREFINERY'
        unit = self.load(r'{k:B}{d}', r'{d:snip[k:]}')
        test = data | unit | bytes
        self.assertEqual(test, B'REFINERY')
