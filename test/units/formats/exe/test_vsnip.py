#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase
from . import MACHO_TEST


class TestVirtualAddressSnip(TestUnitBase):

    def test_pe_01(self):
        data = self.download_from_malshare('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load('0x0140002030', ascii=True)
        self.assertEqual(unit(data), B'You will never see me.')

    def test_pe_02(self):
        data = self.download_from_malshare('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load(slice(0x0140002030, 22))
        self.assertEqual(unit(data), B'You will never see me.')

    def test_elf_01(self):
        data = self.download_from_malshare('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        unit = self.load('0x08054203', ascii=True)
        self.assertEqual(unit(data), B' rootkiter : The creator')

    def test_elf_02(self):
        data = self.download_from_malshare('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        addr = bytes(reversed(self.load(slice(0x0804F188, 4))(data))).hex()
        unit = self.load(F'0x{addr}', ascii=True)
        self.assertEqual(unit(data), B'MY ID IS %d, Upper ID is %d')

    def test_macho(self):
        unit = self.load(0x0FB8, ascii=True)
        self.assertEqual(unit(MACHO_TEST), b'audio filter for float32->s16 conversion')
