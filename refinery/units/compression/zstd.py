from __future__ import annotations

from refinery.units import RefineryPartialResult, Unit


class zstd(Unit):
    """
    ZStandard (ZSTD) compression and decompression.
    """
    @Unit.Requires('pyzstd', ['all'])
    def _pyzstd():
        import pyzstd
        return pyzstd

    def process(self, data):
        zd = self._pyzstd.ZstdDecompressor()
        out = zd.decompress(data)
        if zd.needs_input:
            raise RefineryPartialResult('Incomplete ZSTD stream.', out)
        return out

    def reverse(self, data):
        zc = self._pyzstd.ZstdCompressor()
        return zc.compress(data) + zc.flush()

    @classmethod
    def handles(cls, data) -> bool:
        return data[:4] == B'\x28\xB5\x2F\xFD'
