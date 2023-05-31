#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestRC4(TestUnitBase):

    def test_discard(self):
        goal = bytes.fromhex('DF81C217EF2D066F41891527293C7AAD')
        data = b'1RQCmvqeSxBYnXXD'
        self.assertEqual(data | self.load(b'C9J2oU8orRsjZ73J', discard=505) | bytes, goal)
