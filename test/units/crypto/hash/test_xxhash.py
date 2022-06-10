#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase
from refinery.lib.thirdparty.xxhash import xxhash


class TestXXHash(TestUnitBase):

    def test_xxh32_16byte_block(self):
        self.assertEqual(xxhash(b"SetFilePointerEx", seed=1).intdigest(), 0xED2585C8)

    def test_xxh32_longer(self):
        d = xxhash(B'The binary refinery refines the finest binaries.', 12).intdigest()
        self.assertEqual(d, 0x122C6A34)
