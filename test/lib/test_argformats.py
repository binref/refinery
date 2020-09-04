#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib import argformats

from .. import TestBase


class TestArgumentFormats(TestBase):

    def test_hex_number_arg(self):
        self.assertEqual(argformats.number('045FAD'), 0x45FAD)
        self.assertEqual(argformats.number('45FADH'), 0x45FAD)
