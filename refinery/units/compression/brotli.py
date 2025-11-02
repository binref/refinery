from __future__ import annotations

from refinery.units import Unit


class brotli(Unit):
    """
    Brotli compression and decompression.
    """

    @Unit.Requires('brotli', ['all'])
    def _brotli():
        import brotli
        return brotli

    def process(self, data):
        return self._brotli.decompress(bytes(data))

    def reverse(self, data):
        return self._brotli.compress(bytes(data))
