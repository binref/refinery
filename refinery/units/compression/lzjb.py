from __future__ import annotations

from refinery.lib.fast.lzjb import lzjb_compress, lzjb_decompress
from refinery.units import Unit


class lzjb(Unit):
    """
    LZJB compression and decompression.

    This LZ-type compression is used in the ZFS file system.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        if len(data) < 3:
            return False
        copy = data[0]
        pos = 1
        for mask in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80):
            if pos >= len(data):
                break
            if copy & mask:
                if pos + 1 >= len(data):
                    return False
                hi = data[pos]
                lo = data[pos + 1]
                match_pos = ((hi & 0x03) << 8) | lo
                if match_pos == 0:
                    return False
                pos += 2
            else:
                pos += 1
        return None

    def reverse(self, src):
        return lzjb_compress(src)

    def process(self, data):
        return lzjb_decompress(data)
