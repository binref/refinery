#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestCLower(TestUnitBase):

    def test_simple_01(self):
        unit = self.load()
        data = B'That is not dead which can eternal lie, And with strange aeons even death may die.'
        wish = B'that is not dead which can eternal lie, and with strange aeons even death may die.'
        self.assertEqual(bytes(data | unit), wish)
