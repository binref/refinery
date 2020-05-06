#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestNetBios(TestUnitBase):

    def test_cyberchef_reference_01(self):
        unit = self.load()
        data = B'BINARY REFINERY!'
        wish = B'ECEJEOEBFCFJCAFCEFEGEJEOEFFCFJCB'
        self.assertEqual(unit(data), wish)

    def test_cyberchef_reference_02(self):
        unit = self.load(B'N')
        data = B'AllHailYawgmoth'.ljust(16, B' ')
        wish = B'ROTZTZRVTOTWTZSWTOUUTUT[T]URTVPN'
        self.assertEqual(unit(data), wish)
