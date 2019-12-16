#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import bz2 as bz2_

from .. import Unit
from ...lib.argformats import number


class bz2(Unit):
    """
    BZip2 compression and decompression.
    """
    def interface(self, argp):
        argp.add_argument('-l', '--level', type=number[1:9], action='store', default=9,
            help='compression level preset between 0 and 9')
        return super().interface(argp)

    def process(self, data):
        return bz2_.decompress(data)

    def reverse(self, data):
        return bz2_.compress(data, self.args.level)
