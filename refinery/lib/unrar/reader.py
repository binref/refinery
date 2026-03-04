"""
Bit-level I/O for RAR decompression.
"""
from __future__ import annotations

MAX_SIZE = 0x8000  # 32 KB input buffer size


class BitInput:
    """
    Bit-level reader matching unrar's BitInput class.
    MSB-first bit ordering. Maintains InAddr (byte) and InBit (bit) positions.
    """
    __slots__ = ('buf', 'in_addr', 'in_bit')

    def __init__(self, data: bytes | bytearray | memoryview):
        self.buf = data
        self.in_addr = 0
        self.in_bit = 0

    def init(self):
        self.in_addr = 0
        self.in_bit = 0

    def getbits(self) -> int:
        """
        Return 16 bits starting from current position (MSB-first, left-aligned).
        Does NOT advance the position.
        """
        addr = self.in_addr
        bit = self.in_bit
        buf = self.buf
        blen = len(buf)

        b0 = buf[addr] if addr < blen else 0
        b1 = buf[addr + 1] if addr + 1 < blen else 0
        b2 = buf[addr + 2] if addr + 2 < blen else 0

        val = (b0 << 16) | (b1 << 8) | b2
        return (val >> (8 - bit)) & 0xFFFF

    def getbits32(self) -> int:
        """
        Return 32 bits starting from current position (MSB-first).
        """
        addr = self.in_addr
        bit = self.in_bit
        buf = self.buf
        blen = len(buf)

        b0 = buf[addr] if addr < blen else 0
        b1 = buf[addr + 1] if addr + 1 < blen else 0
        b2 = buf[addr + 2] if addr + 2 < blen else 0
        b3 = buf[addr + 3] if addr + 3 < blen else 0
        b4 = buf[addr + 4] if addr + 4 < blen else 0

        val = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
        return (val >> (8 - bit)) & 0xFFFFFFFF

    def addbits(self, bits: int):
        """
        Advance the position by the given number of bits.
        """
        total = (self.in_addr << 3) + self.in_bit + bits
        self.in_addr = total >> 3
        self.in_bit = total & 7

    def aligned_addr(self) -> int:
        """
        Return byte-aligned address (skip partial bits).
        """
        if self.in_bit > 0:
            return self.in_addr + 1
        return self.in_addr

    @property
    def remaining(self) -> int:
        """
        Return approximate number of bytes remaining.
        """
        return max(0, len(self.buf) - self.in_addr)
