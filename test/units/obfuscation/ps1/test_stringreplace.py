#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestStringReplace(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_trivial(self):
        self.assertEqual(
            self.unit.deobfuscate('''"Hello World".replace('l', "FOO")'''),
            '"HeFOOFOOo WorFOOd"'
        )
