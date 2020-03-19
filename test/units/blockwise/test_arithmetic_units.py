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


class TestArithmeticUnits(TestUnitBase):

    def test_handler_unpack_01(self):
        add = self.ldu('add', '-B3', 'unpack:#2:H:BEEF')
        self.assertEqual(add(bytes(12)), B'\xEF\xBE\x00' * 4)

    def test_handler_unpack_02(self):
        add = self.ldu('add', '-B3', 'unpack:2:H:BEEF')
        self.assertEqual(add(bytes(12)), B'\xBE\xEF\x00' * 4)

    def test_handler_unpack_03(self):
        add = self.ldu('add', '-B3', 'unpack:#2:H:BEEF', bigendian=True)
        self.assertEqual(add(bytes(12)), B'\x00\xBE\xEF' * 4)

    def test_handler_ev(self):
        xor = self.ldu('xor', 'ev:N,0xB0,0x12')
        self.assertEqual(xor(bytes(0x54)), 28 * B'\x54\xB0\x12')

    def test_argument_reset(self):
        xor = self.ldu('xor', 'inc:ev:2')
        self.assertEqual(xor(bytes(5)), bytes(range(2, 7)))
        self.assertEqual(xor(bytes(5)), bytes(range(2, 7)))

    def test_handler_inc_dec(self):
        xor = self.ldu('xor', 'inc:dec:0xCC')
        self.assertEqual(xor(bytes(20)), B'\xCC' * 20)

    def test_add_wrapping(self):
        add = self.ldu('add', '0xFE')
        self.assertEqual(
            add(b'\x01\x02\x03\x04\x05'),
            b'\xFF\x00\x01\x02\x03'
        )

    def test_sub_wrapping(self):
        sub = self.ldu('sub', '0x10')
        self.assertEqual(
            sub(b'\x12\x11\x10\x0F\x0D'),
            b'\x02\x01\x00\xFF\xFD'
        )

    def test_neg_example_01(self):
        neg = self.ldu('neg')
        self.assertEqual(neg(b'\xFF\x00'), b'\x00\xFF')

    def test_neg_idempotence(self):
        for b in (1, 2, 3, 4, 5, 7, 8, 12, 17):
            unit = self.ldu('neg', blocksize=b)
            data = self.generate_random_buffer(3 * b + 1)
            self.assertEqual(data, unit(unit(data)))

    def test_xor_idempotence(self):
        buffer = self.generate_random_buffer(1024)
        key = self.generate_random_buffer(12)
        unit = self.ldu('xor', key)
        self.assertEqual(buffer, unit(unit(buffer)))

    def test_xor_bytes_argument(self):
        buffer = self.generate_random_buffer(1024)
        key = self.generate_random_buffer(12)
        unit = self.ldu('xor', key)
        self.assertEqual(buffer, unit(unit(buffer)))

    def test_argument_overflow(self):
        for blocksize in (1, 2, 3, 4, 5, 7, 8, 11):
            buffer = self.generate_random_buffer(200 * blocksize)
            key1 = int.from_bytes(self.generate_random_buffer(blocksize), 'big')
            key2 = key1 | (0xDEFACED << (blocksize * 8))
            for unit in ('add', 'sub', 'xor'):
                op1 = self.ldu(unit, str(key1), blocksize=blocksize)
                op2 = self.ldu(unit, str(key2), blocksize=blocksize)
                self.assertEqual(op1(buffer), op2(buffer))


class TestROTR(TestUnitBase):

    def test_byte_swapping(self):
        unit = self.ldu('rotr', '-B', 2, 8)
        self.assertEqual(unit(B'ABCDEFGHI'), B'BADCFEHGI')

    def test_byte_circular(self):
        unit = self.ldu('rotr', '-B', 3, 8)
        self.assertEqual(unit(B'AABAACAAD'), B'ABAACAADA')


class TestBlockopInput(TestUnitBase):

    def test_invalid_expression(self):
        self.assertRaises(Exception, self.ldu, 'blockop', '"§$%$$$§$§$$$UU')
        self.assertRaises(Exception, self.ldu, 'blockop', '(B + 9')

    def test_not_an_expression(self):
        self.assertRaises(Exception, self.ldu, 'blockop', 'def foo(x):\n    return 29')

    def test_invalid_symbols(self):
        self.assertRaises(Exception, self.ldu, 'blockop', '(B ^ 0xFF - Arg)')
        self.assertRaises(Exception, self.ldu, 'blockop', '(B ^ 0xFF - a)')
        self.assertRaises(Exception, self.ldu, 'blockop', 'B ^ 0x34 - A + W[2]')


class TestBlockopAgainstOtherUnits(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.buffer = self.generate_random_buffer(1024)
        self.arg = 'BAADF00D'

    def test_against_add(self):
        bop = self.ldu('blockop', 'B + A', self.arg)
        add = self.ldu('add', self.arg)
        self.assertEqual(add(self.buffer), bop(self.buffer))

    def test_against_sub(self):
        sub = self.ldu('sub', self.arg)
        bop = self.ldu('blockop', 'B - A', self.arg)
        self.assertEqual(sub(self.buffer), bop(self.buffer))

    def test_against_xor_01(self):
        xor = self.ldu('xor', self.arg)
        bop = self.ldu('blockop', 'B ^ A', self.arg)
        self.assertEqual(xor(self.buffer), bop(self.buffer))

    def test_against_xor_02(self):
        xor = self.ldu('xor', self.arg)
        bop = self.ldu('blockop', '(~B & A) | (B & ~A)', self.arg)
        self.assertEqual(xor(self.buffer), bop(self.buffer))

    def test_against_xor_03(self):
        xor = self.ldu('xor', self.arg)
        bop = self.ldu('blockop', '(A | B) & ~(B & A)', self.arg)
        self.assertEqual(xor(self.buffer), bop(self.buffer))

    def test_against_shl(self):
        shl = self.ldu('shl', '3')
        bop = self.ldu('blockop', 'B << 3')
        self.assertEqual(shl(self.buffer), bop(self.buffer))

    def test_against_shr(self):
        shr = self.ldu('shr', '3')
        bop = self.ldu('blockop', 'B >> 3')
        self.assertEqual(shr(self.buffer), bop(self.buffer))

    def test_against_ror(self):
        ror = self.ldu('rotr', '3')
        bop = self.ldu('blockop', '(B >> 3) | (B << 5)')
        self.assertEqual(ror(self.buffer), bop(self.buffer))
