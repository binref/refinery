#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import RefineryPartialResult
from .. import TestUnitBase


class TestLZMA(TestUnitBase):

    def test_decompress_partial(self):
        unit = self.load()
        data = bytes.fromhex(
            '5D000080001CC21B000000000000098033422D25737C688B7F096ACEE292A85F4B2ED837C1A224E0'
            '7184804EBA7DDEE3C1DB5A2E70E333A04680807DD671E56778881DD44D226D28C4AEEB8EA7210B4E'
            '4D6CA529DE629C5A1E9F8124E90BEF12CED5916ED557A54510B141F6663775FE089C43D63D13292B'
            'C5A8A5EBE92390E586EA8DCB46248A7E973C8B1686A49172035BB77B2591BC7F8B432E6A535FA72C'
            '81C7B622DA443A5E0A127062AD14EB37A5D77C670FDA59A6CA14EC2E47926E731DA74FF5BD0AE036'
            'FFFFFFFFFFFFFFFFFFFF00000000'
        )
        with self.assertRaises(RefineryPartialResult) as cm:
            unit(data)
        self.assertIn(B'This program cannot be run in DOS mode.', cm.exception.partial)

    def test_pylzma(self):
        data = bytes.fromhex(
            '5d00008000'
            '00211a49c62443e9e2c2c3e7e5d241eb65b0037ccc7a201a9748aadcd9df87b6d14d3991cf7cc3b069ae5560001783f4f32fffff24eac000'
        )
        goal = b"Binary Refinery Refines Evil Binaries And Benign Finery Alike"
        unit = self.load(alone=True)
        self.assertEqual(bytes(data | unit), goal)

    def test_lzma2_with_size_prefix(self):
        data = self.download_sample('331a59118a5bff2e096e4475cbf78636ab79b03c2f16a3e0c65c9a10366512be')
        test = data | self.load() | bytes
        self.assertIn(B'CGlobalIncludeLuaFile', test)
