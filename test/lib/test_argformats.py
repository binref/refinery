#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib import argformats

from .. import TestBase


class TestArgumentFormats(TestBase):

    def test_hex_number_arg(self):
        self.assertEqual(argformats.number('045FAD'), 0x45FAD)
        self.assertEqual(argformats.number('45FADH'), 0x45FAD)

    def test_yara_regular_expression_lowercase(self):
        self.assertEqual(argformats.DelayedRegexpArgument('yara:deefaced')(), BR'\xde\xef\xac\xed')

    def test_no_yara_in_other_handlers(self):
        self.assertEqual(argformats.DelayedArgument('yara:??')(), B'yara:??')

    def test_accumulator(self):
        dm = argformats.DelayedArgument('take[:20]:accu[0x45]:(3*A+3)&0xFF')()
        self.assertEqual(dm, bytes.fromhex('45D2796E4DEAC146D582899EDD9AD176653299CE'))

    def test_reduce_sum_of_odd_numbers(self):
        for k in range(1, 56):
            result = int(argformats.DelayedArgument(F'base[-R]:be:reduce[S+B]:take[:{k}]:accu[1]:A+2')(), 0)
            self.assertEqual(result, k ** 2, F'Failed for {k}.')

    def test_skip_first_character_of_cyclic_key(self):
        key = argformats.DelayedArgument('take[1:16]:cycle:KITTY')()
        self.assertEqual(key, B'ITTYKITTYKITTYK')

    def test_itob(self):
        data = argformats.DelayedArgument('itob:take[:4]:accu[0x1337]:A')()
        self.assertEqual(data, bytes.fromhex('3713371337133713'))

    def test_accu_reduction(self):
        xor1 = self.ldu('xor', 'accu[12]:(A*7+23)')
        xor2 = self.ldu('xor', 'accu[12]:(A*7+23)&0xFF')
        data = bytearray(48)
        self.assertEqual(xor1(data), xor2(data))
