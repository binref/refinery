from __future__ import annotations

from refinery.units.blockwise import BinaryOperation


class rotr(BinaryOperation):
    """
    Rotate bits of each byte, word, dword, or other integer block to the right.
    """
    def operate(self, value, shift):
        shift %= self.fbits
        return (value >> shift) | (value << (self.fbits - shift))

    def inplace(self, value, shift):
        shift %= self.fbits
        lower = value >> shift
        value <<= self.fbits - shift
        value |= lower
