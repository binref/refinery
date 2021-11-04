#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestSerpent(TestUnitBase):

    def test_reversible(self):
        data = bytes(range(0x100))
        for mode in ('CBC', 'CFB', 'OFB', 'PCBC'):
            encrypter = -self.load(range(0x20), iv=range(0x10), mode=mode)
            decrypter = self.load(range(0x20), iv=range(0x10), mode=mode)
            self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode}')
