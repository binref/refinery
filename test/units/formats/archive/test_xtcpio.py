#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestCPIOFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = self.download_sample('0ae14747558a41431488dbe4138cb0e17eae273093b04eab0c493cefb3f3de77')
        unit = self.load(list=True)
        listing = {bytes(name) for name in unit(data).split(B'\n')}
        self.assertSetEqual(listing, {
            B'pkginfo',
            B'root.3/opt/ack/lib.bin/em_data.a',
            B'root.3/opt/ack/lib.bin/i386/ce.a',
            B'root.3/opt/ack/lib.bin/m68020/cg',
            B'root.3/opt/ack/lib.bin/m68k2/cg',
            B'root.3/opt/ack/lib.bin/m68k4/cg',
            B'root.3/opt/ack/lib.bin/ncgg',
            B'root.3/opt/ack/lib.bin/vax4/cg',
            B'root.3/opt/ack/lib/arm/tail_f77',
            B'root.3/opt/ack/lib/arm/tail_m2',
            B'root.3/opt/ack/lib/i386/tail_ac',
            B'root.3/opt/ack/lib/i386/tail_f77',
            B'root.3/opt/ack/lib/i386_xenix/tail_f77',
            B'root.3/opt/ack/lib/i86/tail_ac',
            B'root.3/opt/ack/lib/m68k2/tail_ac',
            B'root.3/opt/ack/lib/minix/tail_ac',
            B'root.3/opt/ack/lib/ns/tail_ac',
            B'root.3/opt/ack/lib/ns/tail_f77',
            B'root.3/opt/ack/lib/pdp/tail_ac',
            B'root.3/opt/ack/lib/xenix3/tail_ac',
            B'root.3/opt/ack/lib/z80/tail_m2',
            B'root.3/opt/ack/modules/lib/libCEopt.a',
            B'root.3/opt/ack/modules/lib/libemopt.a',
        })
