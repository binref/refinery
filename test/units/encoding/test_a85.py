#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from ..compression import KADATH1

from base64 import a85encode


class TestBase85(TestUnitBase):
    def test_works_with_whitespace(self):
        unit = self.load()
        goal = KADATH1.rstrip('\0').encode('latin1')
        data = a85encode(goal)
        data = data | self.ldu('chop', 60) | bytes
        self.assertEqual(data | unit | bytes, goal)

    def test_basic_base85_encoding(self):
        unit = self.load()
        goal = b"SUFFICIENTLY LONG STRING FOR REFINERY b85"
        data = a85encode(goal)
        self.assertEqual(data | unit | bytes, goal)
