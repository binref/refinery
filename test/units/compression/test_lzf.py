#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestLZF(TestUnitBase):

    def test_simple_string_01(self):
        unit = self.load()
        data = bytes.fromhex('105468652062696E61727920726566696E65E0000802732074201B40120173748022036965732E')
        goal = B'The binary refinery refines the finest binaries.'
        self.assertEqual(data | unit | bytes, goal)

    def test_simple_string_02(self):
        unit = self.load(fast=True)
        data = B'The binary refinery refines the finest binaries.'
        goal = bytes.fromhex('105468652062696E61727920726566696E65E0000802732074201B40120173748022036965732E')
        self.assertEqual(data | -unit | bytes, goal)

    def test_empty_buffer(self):
        self.assertEqual(B'' | -self.load() | bytes, B'')

    def test_tail_byte_regression_01(self):
        data = bytes.fromhex(
            '6573743D646573742C20747970653D6E742C206D6574617661723D6D657461766172206F7220274E27290D0A0D0A2020'
            '202040636C6173736D6574686F640D0A20202020646566204F7074696F6E280D0A2020202020202020636C732C0D0A20'
            '202020202020202A617267732020203A207374722C0D0A202020202020202063686F69636573203A20456E756D2C0D0A'
            '202020202020202068656C70202020203A20556E696F6E5B6F6D69742C207374725D203D206F6D69742C0D0A20202020'
            '2020202064657374'
        )
        for j in range(20, len(data)):
            check = data[:j]
            out = check | -self.load() | self.load() | bytes
            self.assertEqual(out, check)

    def test_tail_byte_regression_02(self):
        data = b'#!/usr/bin/env python3\r\r\n# -*- coding: utf-8 -*-\r'
        self.assertEqual(data | -self.load() | self.load() | bytes, data)
