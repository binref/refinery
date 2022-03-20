#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestXXTEA(TestUnitBase):

    def test_examples_kryptografie_de(self):
        # https://kryptografie.de/kryptografie/chiffre/xxtea.htm
        sample = B'BeispielklartextBeispielklartext'
        output = bytes.fromhex('179DD68A F1763D52 3256159D 247BC98F 345F2094 1FD305D7 36B1F17F 13636298')
        self.assertEqual(output, sample | self.load(B'Schokoladentorte', reverse=True, raw=True) | bytes)
