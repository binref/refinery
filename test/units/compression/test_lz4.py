#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestLZ4(TestUnitBase):

    def test_decompress_01(self):
        unit = self.load()
        data = bytes.fromhex(
            '04224D186440A729000000F60C4B6576696E277320676F7420746865206D6167'
            '6963202D20616E641000032000604B6576696E2E000000003FAB8D14'
        )
        self.assertEqual(
            b"Kevin's got the magic - and the magic's got Kevin.",
            unit(data)
        )

    def test_reversible_property(self):
        process = self.load()
        reverse = self.load(reverse=True)
        data = self.generate_random_buffer(2 * 0x400000 + 0x31337)
        self.assertEqual(data, process(reverse(data)))
