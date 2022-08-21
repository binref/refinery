#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestConstantReplacer(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_regex_matchgroup_regression(self):
        self.assertEqual(self.unit.deobfuscate(r'''
            const a = "\3"
            b = a
        ''').strip(), r'b = "\3"')
