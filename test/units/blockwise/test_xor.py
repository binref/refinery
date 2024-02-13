#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestXOR(TestUnitBase):

    def test_simple_xor(self):
        a = bytearray(300)
        b = self.generate_random_buffer(150)
        c = a | self.load(b) | bytes
        self.assertEqual(c, 2 * b)

    def test_accu_reduction(self):
        xor1 = self.ldu('xor', 'accu[12]:(A*7+23)')
        xor2 = self.ldu('xor', 'accu[12]:(A*7+23)&0xFF')
        data = bytearray(48)
        self.assertEqual(xor1(data), xor2(data))

    def test_auto_block_01(self):
        self.assertEqual(bytes(5) | self.load('0xAABBCC') | bytes, B'\xCC\xBB\xAA\xCC\xBB')
        self.assertEqual(bytes(5) | self.load('0x00BBCC') | bytes, B'\xCC\xBB\xCC\xBB\xCC')

    def test_auto_block_02(self):
        self.assertEqual(bytes(5) | self.load('0xAABBCC', blocksize=2) | bytes, B'\xCC\xBB\xCC\xBB\xCC')
        self.assertEqual(bytes(5) | self.load('0x00BBCC', blocksize=1) | bytes, B'\xCC\xCC\xCC\xCC\xCC')

    def test_auto_block_resets(self):
        pl = self.load_pipeline('emit rep[5]:H:00 | rep 2 [| xor e:[0xAABBCC,0xBBCC][index] ]')
        self.assertEqual(pl(), (
            B'\xCC\xBB\xAA\xCC\xBB'
            B'\xCC\xBB\xCC\xBB\xCC'))

    def test_xor_idempotence(self):
        buffer = self.generate_random_buffer(1024)
        key = self.generate_random_buffer(12)
        unit = self.load(key)
        self.assertEqual(buffer, unit(unit(buffer)))

    def test_xor_bytes_argument(self):
        buffer = self.generate_random_buffer(1024)
        key = self.generate_random_buffer(12)
        unit = self.load(key)
        self.assertEqual(buffer, unit(unit(buffer)))

    def test_handler_ev(self):
        cm = self.ldu('cm')
        xor = self.load('e:size,0xB0,0x12')
        self.assertEqual(cm[xor](bytes(0x54)), 28 * B'\x54\xB0\x12')

    def test_argument_reset(self):
        xor = self.load('inc:eval:1+1')
        self.assertEqual(xor(bytes(5)), bytes(range(2, 7)))
        self.assertEqual(xor(bytes(5)), bytes(range(2, 7)))

    def test_handler_inc_dec(self):
        xor = self.load('inc:dec:0xCC')
        self.assertEqual(xor(bytes(20)), B'\xCC' * 20)
