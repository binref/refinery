from __future__ import annotations

from refinery.units.blockwise import BinaryOperation


class shr(BinaryOperation):
    """
    Shift the bits of each block right, filling with zero bits.
    """
    @staticmethod
    def operate(a, b): return a >> b
    @staticmethod
    def inplace(a, b): a >>= b
