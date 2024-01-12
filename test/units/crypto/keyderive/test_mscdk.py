#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestCryptDeriveKey(TestUnitBase):

    def test_SHA2(self):
        from hashlib import sha256
        data = B'PASSWORD'
        unit = self.load(32, 'SHA256')
        test = data | unit | bytes
        goal = sha256(data).digest()[:32]
        self.assertEqual(test, goal)
