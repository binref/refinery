#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestAutoXOR(TestUnitBase):

    def test_real_world_01(self):
        from refinery import iff, hex, autoxor, vbastr
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        # flake8: noqa
        out = list(data | vbastr [ iff('size >= 100') | hex | autoxor ])
        self.assertSetEqual({o['key'] for o in out}, {
            B'An2Lcw6Gseh',
            bytes.fromhex('81a09675497f5903f05bec10ff1bacd9bb4140f6c701a3103f47188fb3'),
        })

    def test_real_world_02(self):
        from refinery import sha256, xkey
        data = self.download_sample('1664cb04cdbf4bebf2c6addb92a9ed1f09c6738b3901f1b7e8ae7405008f5039')
        self.assertEqual(data | xkey | bytes, b'Mlitqcfqr')

    def test_very_short_input(self):
        pl = self.load_pipeline('emit A B C "" [| autoxor ]')
        self.assertEqual(pl(), B'\0\0\0')

    def test_chunk_scope_regression(self):
        data = self.generate_random_buffer(2000)
        pl = self.load_pipeline('autoxor [| nop ]')
        self.assertEqual(len(data), data | pl | len)
