#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import gzip

from .. import Unit


class gz(Unit):
    """
    GZip compression and decompression.
    """

    def process(self, data):
        return gzip.decompress(data)

    def reverse(self, data):
        return gzip.compress(data)
