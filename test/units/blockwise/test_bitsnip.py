#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBitSnip(TestUnitBase):

    def test_little_big_endian(self):
        data = bytearray((
            0b00000001,
            0b00000011,
            0b00000111,
            0b00001111,
            0b00011111,
            0b00111111,
            0b01111111,
            0b11111111,
        ))
        self.assertEqual(
            data | self.load(0, slice(5, 8), bigendian=False) | bytes,
            (0b1111_0111_0011_0001_0001_0001_0001_0001).to_bytes(4, 'little'))
        self.assertEqual(
            data | self.load(0, slice(5, 8), bigendian=True) | bytes,
            (0b1000_1000_1000_1000_1000_1001_1011_1111).to_bytes(4, 'big'))

    def test_bytes_to_bits(self):
        data = bytearray((
            0b0101010_1,
            0b0011001_0,
            0b0101011_0,
            0b1000001_1,
            0b1001011_1,
            0b1011111_0,
            0b0100010_0,
            0b1100101_1,
        ))
        self.assertEqual(
            data | self.load() | bytes, (0b10011001).to_bytes(1, 'little'))

    def test_snip_padding(self):
        data = bytes.fromhex('BAAD')
        test = data | self.load('4::8', ':4:8') | bytes
        self.assertEqual(test, bytes((0xB, 0xA, 0xA, 0xD)))
