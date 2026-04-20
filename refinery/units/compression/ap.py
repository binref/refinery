from __future__ import annotations

from refinery.lib.fast.aplib import aplib_compress, aplib_decompress
from refinery.units import Unit

__all__ = ['aplib']


class aplib(Unit):
    """
    APLib compression and decompression.

    A lossless compression library frequently used by packers and malware for executable
    compression.
    """

    def reverse(self, buf):
        return aplib_compress(buf)

    def process(self, buf):
        view = memoryview(buf)
        size = 0
        if view[:4] == B'AP32':
            size = int.from_bytes(buf[4:8], 'little')
            if size > 0x80:
                size = 0
            else:
                self.log_info(F'detected aPLib header of size {size}')
        return bytes(aplib_decompress(view[size:]))

    @classmethod
    def handles(cls, data):
        if len(data) < 2:
            return False
        if data[:4] == B'AP32':
            return True
        return None
