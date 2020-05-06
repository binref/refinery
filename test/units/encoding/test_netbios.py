#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestNetBios(TestUnitBase):

    def test_cyberchef_reference_01(self):
        unit = self.load()
        data = B'ECEJEOEBFCFJCAFCEFEGEJEOEFFCFJCB'
        wish = B'BINARY REFINERY!'
        self.assertEqual(unit(data), wish)

    def test_cyberchef_reference_02(self):
        unit = self.load(B'N', reverse=True)
        data = B'AllHailYawgmoth'.ljust(16, B' ')
        wish = B'ROTZTZRVTOTWTZSWTOUUTUT[T]URTVPN'
        self.assertEqual(unit(data), wish)

    def test_inversion_structured(self):
        D = self.load()
        E = self.load(reverse=True)
        M = bytes(range(256)) * 2
        self.assertEqual(D(E(M)), M)
