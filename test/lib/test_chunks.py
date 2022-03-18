#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib import chunks
from .. import TestBase


class TestChunks(TestBase):

    def test_odd_block_size(self):
        data = bytearray(range(1, 3 * 5 + 2))
        unpacked = list(chunks.unpack(data, 3, bigendian=True))
        self.assertEqual(unpacked, [0x010203, 0x040506, 0x070809, 0x0A0B0C, 0x0D0E0F])
