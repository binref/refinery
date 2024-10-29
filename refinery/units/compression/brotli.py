#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit


class brotli(Unit):
    """
    Brotli compression and decompression.
    """

    @Unit.Requires('brotlipy', 'all')
    def _brotli():
        import brotli
        return brotli

    def process(self, data):
        return self._brotli.decompress(bytes(data))

    def reverse(self, data):
        return self._brotli.compress(bytes(data))
