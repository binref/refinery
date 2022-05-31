#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestXKey(TestUnitBase):

    def test_real_world_01(self):
        from refinery import iff, hex, autoxor, vbastr
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        # flake8: noqa
        out = list(data | vbastr [ iff('size >= 100') | hex | autoxor ])
        self.assertSetEqual({o['key'] for o in out}, {
            B'An2Lcw6Gseh',
            bytes.fromhex('81a09675497f5903f05bec10ff1bacd9bb4140f6c701a3103f47188fb3'),
        })
