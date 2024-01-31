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