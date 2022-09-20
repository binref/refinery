#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from argparse import ArgumentTypeError

from refinery.lib import argformats
from refinery.lib import loader

from .. import TestBase


class TestArgumentFormats(TestBase):

    def test_hex_number_arg(self):
        self.assertEqual(argformats.number('045FAD'), 0x45FAD)
        self.assertEqual(argformats.number('45FADH'), 0x45FAD)

    def test_accu(self):
        self.assertEqual(
            argformats.multibin('itob[1]:take[:16]:accu:@msvc'),
            bytes.fromhex('26 27 F6 85 97 15 AD 1D D2 94 DD C4 76 19 39 31')
        )

    def test_empty_value_passed_to_itob(self):
        self.assertEqual(argformats.multibin('itob:take[:0]:foo'), b'')

    def test_itob_byte_width(self):
        self.assertEqual(argformats.multibin('itob[1]:eval:(0x00,0x12,0x3412)'), b'\0\x12\x12')

    def test_yara_regular_expression_lowercase(self):
        self.assertEqual(argformats.DelayedRegexpArgument('yara:deefaced')(), BR'\xde\xef\xac\xed')

    def test_no_yara_in_other_handlers(self):
        self.assertEqual(argformats.DelayedArgument('yara:??')(), B'yara:??')

    def test_accumulator(self):
        dm = argformats.DelayedArgument('take[:20]:accu[0x45]:(3*A+3)&0xFF')()
        self.assertEqual(dm, bytes.fromhex('D2796E4DEAC146D582899EDD9AD176653299CE6D'))

    def test_reduce_sum_of_odd_numbers(self):
        for k in range(1, 56):
            result = int(argformats.DelayedArgument(F'base[-R]:be:reduce[S+B]:take[:{k}]:accu[1,0]:A+2')(), 0)
            self.assertEqual(result, k ** 2, F'Failed for {k}.')

    def test_msvc(self):
        pl = loader.load_pipeline('emit rep[32]:H:00 [| put s 0xF23CA2 | xor -B2 accu[s]:@msvc ]')
        self.assertEqual(pl(),
            bytes.fromhex('500BC53065647A48899EE4D7F07166A7643AB3EC9F4343A64DF5C45B4CC4D9B2'))

    def test_skip(self):
        data = argformats.DelayedArgument('take[:10]:accu[0,5]:A+1')()
        self.assertEqual(data, bytes(range(5, 15)))

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

    def test_range_can_use_variables(self):
        pipeline = self.ldu('put', 't', 0x30) [ self.ldu('xor', 'range:t:t+6') ] # noqa
        self.assertEqual(pipeline(bytearray(10)), B'0123450123')

    def test_take_can_use_variables(self):
        pipeline = self.ldu('put', 't', 0x30) [ self.ldu('emit', 'take[:t]:cycle:A') ] # noqa
        self.assertEqual(pipeline(), B'A' * 0x30)

    def test_range_can_be_infinite(self):
        pipeline = self.ldu('put', 't', 0x30) [ self.ldu('xor', 'range:t:') ] # noqa
        self.assertEqual(pipeline(bytearray(10)), B'0123456789')

    def test_slices_can_be_variables(self):
        pipeline = self.ldu('put', 'rg', '2:') [ self.ldu('snip', 'rg') ] # noqa
        self.assertEqual(pipeline(b'FOOBAR'), B'OBAR')

    def test_inc(self):
        result = argformats.DelayedArgument('take[:5]:inc[8]:e:0x30')(B'')
        self.assertEqual(result, b'01234')

    def test_le(self):
        with self.assertRaises(ArgumentTypeError):
            argformats.multibin('le:0x5D000111')
        self.assertEqual(
            argformats.multibin('le:e:0x5D000111'),
            b'\x11\x01\x00\x5D')

    def test_slice_objects_with_handlers(self):
        L = loader.load_pipeline
        p = L('emit h:01000000 | put a [| peek | snip le:var:a | peek ]')
        self.assertEqual(p(), B'\0')

    def test_slice_objects_with_handlers_eat_regression(self):
        L = loader.load_pipeline
        p = L('emit h:01000000 | put a [| peek | snip le:eat:a ]')
        d = next(p)
        self.assertNotIn('a', d.meta)

    def test_variable_arg_regression(self):
        L = loader.load_pipeline
        p = L('emit Helloooo | put s 4 [| terminate rep[var:s]:o ]')
        d = next(p)
        self.assertEqual(d, B'Hell')
