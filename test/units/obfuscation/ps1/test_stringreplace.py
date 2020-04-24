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

    def test_real_world_01(self):
        data = B'''"UVL0NR"-RepLaCe"UVL",""""-RepLaCe "0NR","'"-CrePLAcE  '31V',"|"))'''
        wish = B'''"""'"))'''
        self.assertEqual(self.unit(data), wish)
