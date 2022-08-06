#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestLZF(TestUnitBase):

    def test_simple_string_01(self):
        unit = self.load()
        data = bytes.fromhex('105468652062696E61727920726566696E65E0000802732074201B40120173748022036965732E')
        goal = B'The binary refinery refines the finest binaries.'
        self.assertEqual(data | unit | bytes, goal)

    def test_simple_string_02(self):
        unit = self.load(fast=True)
        data = B'The binary refinery refines the finest binaries.'
        goal = bytes.fromhex('105468652062696E61727920726566696E65E0000802732074201B40120173748022036965732E')
        self.assertEqual(data | -unit | bytes, goal)
