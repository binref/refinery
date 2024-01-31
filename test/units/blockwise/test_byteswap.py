#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestByteSwap(TestUnitBase):

    def test_simple_01(self):
        data = bytes.fromhex('FEED1337''C0CAC01A''C0DE')
        self.assertEqual(
            data | self.load(4) | bytearray,
            bytes.fromhex('3713EDFE''1AC0CAC0')
        )

    def test_simple_02(self):
        data = bytes.fromhex('FEED13''37C0CA''C01AC0''DE')
        self.assertEqual(
            data | self.load(3) | bytearray,
            bytes.fromhex('13EDFE''CAC037''C01AC0')
        )

    def test_simple_03(self):
        data = bytes.fromhex('FEED''1337''C0CA''C01A''C0DE')
        self.assertEqual(
            data | self.load(2) | bytearray,
            bytes.fromhex('EDFE''3713''CAC0''1AC0''DEC0')
        )

    def test_simple_04(self):
        data = bytes.fromhex('FEED1337C0CAC01AC0DE')
        self.assertEqual(
            data | self.load(len(data)) | bytearray,
            bytearray(reversed(data))
        )
