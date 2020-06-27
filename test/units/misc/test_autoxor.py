#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import refinery

from .. import TestUnitBase


class TestAutoXOR(TestUnitBase):

    def test_pe_file(self):
        _xor = refinery.xor(0x47)
        wish = self.download_from_malshare('81a1fca7a1fb97fe021a1f2cf0bf9011dd2e72a5864aad674f8fea4ef009417b')
        data = _xor(wish)
        unit = self.load()
        self.assertEqual(unit(data), wish)

    def test_generated_buffer(self):
        wish = B'The binary refinery is the finest finery to refine binaries.'
        data = bytes.fromhex(
            '320E0346040F0807141F461403000F0803141F460F1546120E0346000F08'
            '03151246000F0803141F461209461403000F080346040F0807140F031548'
        )
        unit = self.load()
        exor = refinery.xor(B'e')
        self.assertEqual(exor(unit(data)), wish)
