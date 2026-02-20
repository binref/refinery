from __future__ import annotations

from refinery.units import RefineryPartialResult, Unit


class zstd(Unit):
    """
    ZStandard (ZSTD) compression and decompression.
    """
    def process(self, data):
        from refinery.lib.shared.pyzstd import pyzstd
        zd = pyzstd.ZstdDecompressor()
        out = zd.decompress(data)
        if zd.needs_input:
            raise RefineryPartialResult('Incomplete ZSTD stream.', out)
        return out

    def reverse(self, data):
        from refinery.lib.shared.pyzstd import pyzstd
        zc = pyzstd.ZstdCompressor()
        return zc.compress(data) + zc.flush()

    @classmethod
    def handles(cls, data) -> bool:
        return data[:4] == B'\x28\xB5\x2F\xFD'
