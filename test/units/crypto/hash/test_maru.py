#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase
from refinery.lib.maru import maru32


class TestMaruHash(TestUnitBase):

    def test_maru32_short(self):
        self.assertEqual(maru32(b"C6XCYXF9F", seed=0x454e028b8c6fa548), 0x80d4b6324a24ceb6)

    def test_maru32_long(self):
        d = maru32(b'HF6FM9RMT3NPMR37TX3FPTFYRFNXTMHWTF7WN94YNP4TMP3FNHM3N9F', 0x454e028b8c6fa548)
        self.assertEqual(d, 0x30CEBE63BE4E30F1)
