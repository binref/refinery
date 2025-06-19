#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase
from . import MACHO_TEST

from refinery.lib.loader import load_pipeline as L


class TestVirtualAddressConverter(TestUnitBase):

    def test_pe_01(self):
        data = self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        pl = L("put k 0x0140002030 [| vaddr -R k | pf {k} ]")
        self.assertEqual(pl(data), b'1584')

    def test_pe_02(self):
        data = self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        pos = data.find(B'You will never see me.')
        pl = L(F"put k {pos} [| vaddr k | pf {{k:X}} ]")
        self.assertEqual(pl(data), b'140002030')

    def test_elf_01(self):
        data = self.download_sample('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        pl = L("put k 0x08054204 [| vaddr -R k | pf {k} ]")
        out = pl(data)
        self.assertEqual(out, b'49668')
        start = int(out)
        end = start + 9
        self.assertEqual(data[start:end], B'rootkiter')

    def test_elf_02(self):
        data = self.download_sample('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        pos = data.find(B'rootkiter : The creator')
        pl = L(F"put k {pos} [| vaddr k | pf {{k:X}} ]")
        self.assertEqual(pl(data), b'8054204')

    def test_macho(self):
        data = MACHO_TEST
        pos = data.find(b'audio filter for float32->s16 conversion')
        pl = L(F"put k {pos} [| vaddr k | pf {{k:X}} ]")
        self.assertEqual(pl(data), b'FB8')
