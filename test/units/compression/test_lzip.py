#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from refinery.lib.loader import load_pipeline as L
from refinery.units.formats.pe import get_pe_size
from .. import TestUnitBase


class TestLZIP(TestUnitBase):

    def test_zenpak(self):
        data = self.download_sample('f690f484c1883571a8bbf19313025a1264d3e10f570380f7aca3cc92135e1d2e')
        pipe = L(
            'push [| rex yara:68(....)83E2FC68(....)E8 | struct x{len:L}4x{addr:L}x | pop |'
            ' vsnip addr-0x100:len+0x100 | serpent -r snip[:8]:x::0x100 | lzip ]')
        test = data | pipe | bytearray
        meta = test | self.ldu('pemeta') | json.loads
        self.assertEqual(meta['TimeStamp']['Linker'], '2022-05-04 12:29:18')
        self.assertEqual(meta['TimeStamp']['Export'], '2106-02-07 06:28:15')
        self.assertEqual(get_pe_size(test), 542208)
