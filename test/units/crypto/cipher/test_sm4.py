#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestSM4(TestUnitBase):

    def test_official_vectors(self):
        for k, (msg, key, out) in enumerate([
            ('0123456789ABCDEFFEDCBA9876543210', '0123456789ABCDEFFEDCBA9876543210', '681EDF34D206965E86B3E94F536E4246'),
            ('000102030405060708090A0B0C0D0E0F', 'FEDCBA98765432100123456789ABCDEF', 'F766678F13F01ADEAC1B3EA955ADB594'),
        ], 1):
            msg = bytes.fromhex(msg)
            key = bytes.fromhex(key)
            out = bytes.fromhex(out)
            unit = self.load(key, raw=True)
            self.assertEqual(msg | -unit | bytes, out, F'encrypting example {k}')
            self.assertEqual(out | +unit | bytes, msg, F'decrypting example {k}')
