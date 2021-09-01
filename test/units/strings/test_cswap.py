#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestCSwap(TestUnitBase):

    def test_simple_01(self):
        unit = self.load()
        data = B'That is not dead which can eternal lie, And with strange aeons even death may die.'
        wish = B'tHAT IS NOT DEAD WHICH CAN ETERNAL LIE, aND WITH STRANGE AEONS EVEN DEATH MAY DIE.'
        self.assertEqual(bytes(data | unit), wish)
