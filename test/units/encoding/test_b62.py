#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase62(TestUnitBase):

    def test_base62_decode(self):
        unit = self.load()
        data = 'VJGSuERgCoVhl6mJg1x87faFOPIqacI3Eby4oP5MyBYKQy5paDF'
        self.assertEqual(data | unit | bytes, B'flag{4b676ccc1070be66b1a15dB601c8d500}')
