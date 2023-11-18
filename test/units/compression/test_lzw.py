#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestLZW(TestUnitBase):

    def test_flareon10(self):
        secret = bytes.fromhex(
            '2E001BD578C32F7CC2DA752E7832D67BD8237DD98A313D86CC2C812D7CC4'
            'D6743F2782F65734D860C7E932D0B107218F5A0F')
        data = self.download_sample(
            '6086f12f687b39931d17fef48f35c4939ee26ad5335e35c5fbcc5e3ab781c1d8', 'OKFR20ALOEN23UPS')
        L = self.load_pipeline
        test = next(data | L('xt7z forth.tap | xtmagtape [| pick 1 ]| lzw'))
        self.assertIn(secret, test)
