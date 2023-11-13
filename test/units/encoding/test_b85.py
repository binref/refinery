#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from ..compression import KADATH1

from base64 import b85encode


class TestBase85(TestUnitBase):
    def test_works_with_whitespace(self):
        unit = self.load()
        goal = KADATH1.rstrip('\0').encode('latin1')
        data = b85encode(goal)
        data = data | self.ldu('chop', 60) | bytes
        self.assertEqual(data | unit | bytes, goal)
