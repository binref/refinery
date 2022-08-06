#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import bz2 as bz2_

from refinery.units import Arg, Unit
from refinery.lib.argformats import number


class bz2(Unit):
    """
    BZip2 compression and decompression.
    """
    def __init__(self, level: Arg('-l', type=number[1:9], help='compression level preset between 1 and 9') = 9):
        super().__init__(level=level)

    def process(self, data):
        return bz2_.decompress(data)

    def reverse(self, data):
        return bz2_.compress(data, self.args.level)

    @classmethod
    def handles(self, data: bytearray):
        return data[:3] == B'BZh'
