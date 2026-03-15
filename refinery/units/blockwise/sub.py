from __future__ import annotations

from refinery.units.blockwise import BinaryOperationWithAutoBlockAdjustment


class sub(BinaryOperationWithAutoBlockAdjustment):
    """
    Subtract a value from each byte, word, dword, or other integer block in the input.
    """
    @staticmethod
    def operate(a, b):
        return a - b

    @staticmethod
    def inplace(a, b):
        a -= b
