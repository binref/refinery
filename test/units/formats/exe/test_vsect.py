#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib

from ... import TestUnitBase
from . import MACHO_TEST


class TestVirtualAddressSnip(TestUnitBase):

    def test_pe(self):
        unit = self.load(list=True)
        data = self.download_from_malshare('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        self.assertSetEqual(
            {bytes(name) for name in unit(data).split(B'\n')},
            {B'.text', B'.rdata', B'.pdata', B'.rsrc'}
        )
        unit = self.load('.rdata')
        self.assertEqual(hashlib.md5(unit(data)).hexdigest(), '594d833530f81be97e7dae14e3001cd8')

    def test_elf(self):
        unit = self.load(list=True)
        data = self.download_from_malshare('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        self.assertSetEqual(
            {
                bytes(name)
                for name in unit(data).split(B'\n')
            }, {
                B'.interp',
                B'.note.ABI-tag',
                B'.note.gnu.build-id',
                B'.gnu.hash',
                B'.dynsym',
                B'.dynstr',
                B'.gnu.version',
                B'.gnu.version_r',
                B'.rel.dyn',
                B'.rel.plt',
                B'.init',
                B'.plt',
                B'.text',
                B'.fini',
                B'.rodata',
                B'.eh_frame_hdr',
                B'.eh_frame',
                B'.ctors',
                B'.dtors',
                B'.jcr',
                B'.dynamic',
                B'.got',
                B'.got.plt',
                B'.data',
                B'.bss',
                B'.comment',
                B'.shstrtab'
            }
        )
        unit = self.load('.comment')
        self.assertEqual(unit(data), B'GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3\0')

    def test_macho(self):
        unit = self.load(list=True)
        self.assertSetEqual(
            {
                bytes(name) for name in unit(MACHO_TEST).split(B'\n')
            }, {
                B'__TEXT',
                B'__TEXT/__text',
                B'__TEXT/__picsymbol_stub',
                B'__TEXT/__cstring',
                B'__TEXT/__literal8',
                B'__DATA',
                B'__DATA/__data',
                B'__DATA/__dyld',
                B'__DATA/__nl_symbol_ptr',
                B'__DATA/__common',
                B'__LINKEDIT',
            }
        )
        unit = self.load('__TEXT/__cstring')
        self.assertEqual(unit(MACHO_TEST), bytes.fromhex(
            '666C6F61743332746F7331360000000000000000766C6300617564696F2066696C74657220666F7220666C6F617433322D3E'
            '73313620636F6E76657273696F6E00000000617564696F2066696C74657200000000'
        ))
