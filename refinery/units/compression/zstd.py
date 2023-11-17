#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit


class zstd(Unit):
    """
    ZStandard (ZSTD) compression and decompression.
    """
    @Unit.Requires('pyzstd', 'all')
    def _pyzstd():
        import pyzstd
        return pyzstd

    def process(self, data):
        return self._pyzstd.ZstdDecompressor().decompress(data)

    def reverse(self, data):
        zc = self._pyzstd.ZstdCompressor()
        zc.compress(data)
        return zc.flush()
