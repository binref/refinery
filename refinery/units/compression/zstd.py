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
        zd = self._pyzstd.ZstdDecompressor()
        return zd.decompress(data)

    def reverse(self, data):
        zc = self._pyzstd.ZstdCompressor()
        return zc.compress(data) + zc.flush()

    @classmethod
    def handles(self, data: bytearray) -> bool:
        return data[:4] == B'\x28\xB5\x2F\xFD'
