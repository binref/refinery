#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestAdd(TestUnitBase):

    def test_handler_btoi_01(self):
        add = self.load('-B3', 'btoi[-2]:H:BEEF')
        self.assertEqual(add(bytes(12)), B'\xEF\xBE\x00' * 4)

    def test_handler_btoi_02(self):
        add = self.load('-B3', 'btoi[+2]:H:BEEF')
        self.assertEqual(add(bytes(12)), B'\xBE\xEF\x00' * 4)

    def test_handler_btoi_03(self):
        add = self.load('-B3', 'btoi[-2]:H:BEEF', bigendian=True)
        self.assertEqual(add(bytes(12)), B'\x00\xBE\xEF' * 4)

    def test_add_wrapping(self):
        add = self.load('0xFE')
        self.assertEqual(
            add(b'\x01\x02\x03\x04\x05'),
            b'\xFF\x00\x01\x02\x03'
        )