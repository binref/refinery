#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestArguments(TestUnitBase):

    def test_binary_instrumented(self):
        add = self.ldu('add', b'\x12')
        sub = self.ldu('sub', b'\x12')
        self.assertEqual(sub(add(b'buffer')), b'buffer')

    def test_binary_commandline(self):
        add = self.ldu('add', '12')
        sub = self.ldu('sub', '12')
        self.assertEqual(sub(add(b'buffer')), b'buffer')

    def test_sequence_argument(self):
        add = self.ldu('add', '(1,2,3)')
        self.assertEqual(add(B'\0\0\0\0\0\0\0'), b'\x01\x02\x03\x01\x02\x03\x01')


class TestArithmeticUnits(TestUnitBase):

    def test_argument_overflow(self):
        for blocksize in (1, 2, 3, 4, 5, 7, 8, 11):
            buffer = self.generate_random_buffer(200 * blocksize)
            key1 = int.from_bytes(self.generate_random_buffer(blocksize), 'big')
            key2 = key1 | (0xDEFACED << (blocksize * 8))
            for unit in ('add', 'sub', 'xor'):
                op1 = self.ldu(unit, str(key1), blocksize=blocksize)
                op2 = self.ldu(unit, str(key2), blocksize=blocksize)
                self.assertEqual(op1(buffer), op2(buffer))
