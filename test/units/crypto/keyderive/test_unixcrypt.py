#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestUnixCrypt(TestUnitBase):

    def test_real_world_01(self):
        data = B'refumblery'
        wish = B'AAeeVhTdT61FQ'
        unit = self.load()
        self.assertEqual(unit(data), wish)
