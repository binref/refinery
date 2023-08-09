#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit


class zstd(Unit):
    """
    ZStandard (ZSTD) compression and decompression.
    """
    @Unit.Requires('pyzstd', optional=True)
    def _pyzstd():
        import pyzstd
        return pyzstd

    def process(self, data):
        return self._pyzstd.ZstdDecompressor().decompress(data)

    def reverse(self, data):
        return self._pyzstd.ZstdCompressor().compress(data)
