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

    def test_handler_btoi_01(self):
        add = self.ldu('add', '-B3', 'btoi[-2]:H:BEEF')
        self.assertEqual(add(bytes(12)), B'\xEF\xBE\x00' * 4)

    def test_handler_btoi_02(self):
        add = self.ldu('add', '-B3', 'btoi[+2]:H:BEEF')
        self.assertEqual(add(bytes(12)), B'\xBE\xEF\x00' * 4)

    def test_handler_btoi_03(self):
        add = self.ldu('add', '-B3', 'btoi[-2]:H:BEEF', bigendian=True)
        self.assertEqual(add(bytes(12)), B'\x00\xBE\xEF' * 4)

    def test_handler_ev(self):
        cm = self.ldu('cm')
        xor = self.ldu('xor', 'e:size,0xB0,0x12')
        self.assertEqual(cm[xor](bytes(0x54)), 28 * B'\x54\xB0\x12')

    def test_argument_reset(self):
        xor = self.ldu('xor', 'inc:eval:1+1')
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


class TestALUInput(TestUnitBase):

    def test_invalid_expression(self):
        self.assertRaises(Exception, self.ldu, 'alu', '"§$%$$$§$§$$$UU')
        self.assertRaises(Exception, self.ldu, 'alu', '(B + 9')

    def test_not_an_expression(self):
        self.assertRaises(Exception, self.ldu, 'alu', 'def foo(x):\n    return 29')

    def test_eval_bug_01(self):
        data = bytes(range(251, 256))
        wish = bytes(((B + 5) % 255 for B in data))
        result = next(data | self.ldu('alu', '-P0', '(B+5)%255'))
        self.assertEqual(result, wish)
