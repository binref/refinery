#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestSub(TestUnitBase):

    def test_sub_wrapping(self):
        sub = self.ldu('sub', '0x10')
        self.assertEqual(
            sub(b'\x12\x11\x10\x0F\x0D'),
            b'\x02\x01\x00\xFF\xFD'
        )

    def test_regression_01(self):
        data = self.download_sample('7a6fbea5635986bc168fa219643d01aff776975acd1c14ed7694bb373a14e172')
        # This will not work because sub will interpret 385 as a U16 type argument.
        # The empty output is expected.
        pipe = self.load_pipeline(
            'xt | snip -r 2::3 | hex | csd intarray | sub 385 | csd hex')
        test = data | pipe | str
        self.assertEqual(test, '')
        # This will work:
        pipe = self.load_pipeline(
            'xt | snip -r 2::3 | hex | csd intarray | sub 129 | csd hex | aes -m CBC XDStoXhavmmrxRPw | xtp url')
        test = data | pipe | str
        goal = 'htt''ps'':/''/nemoc.kliplygah''.shop/8039abe11e59d5c4b1e3405619ca6bd8.xll'
        self.assertEqual(test, goal)
