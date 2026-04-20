from __future__ import annotations

from refinery.lib.fast.lzw import lzw_decompress
from refinery.lib.structures import StructReaderBits
from refinery.units import Unit


class lzw(Unit):
    """
    LZW decompression based on ancient Unix sources.
    """

    _MAGIC = B'\x1F\x9D'
    _BITS = 0x10

    def process(self, data: bytearray):
        inf = StructReaderBits(memoryview(data))

        if inf.peek(2) != self._MAGIC:
            self.log_info('No LZW signature found, assuming raw stream.')
            maxbits = self._BITS
            block_mode = True
        else:
            inf.seekrel(2)
            maxbits = inf.read_integer(5)
            if inf.read_integer(2) != 0:
                self.log_info('reserved bits were set in LZW header')
            block_mode = bool(inf.read_bit())

        raw = inf.read()
        return lzw_decompress(raw, maxbits, block_mode)

    @classmethod
    def handles(cls, data) -> bool | None:
        if data[:len(cls._MAGIC)] == cls._MAGIC:
            return True
