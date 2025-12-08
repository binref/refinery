from __future__ import annotations

from refinery.units.blockwise import BinaryOperationWithAutoBlockAdjustment


class sub(BinaryOperationWithAutoBlockAdjustment):
    """
    Subtract the given argument from each block.
    """
    @staticmethod
    def operate(a, b):
        return a - b

    @staticmethod
    def inplace(a, b):
        a -= b
