#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.units.blockwise import UnaryOperation, FastBlockError

if TYPE_CHECKING:
    from numpy import ndarray


class rev(UnaryOperation):
    """
    The blocks of the input data are output in reverse order. If the length of
    the input data is not a multiple of the block size, the data is truncated.
    """

    def __init__(self, blocksize=None):
        super().__init__(blocksize=blocksize, _truncate=2)

    def inplace(self, block: ndarray):
        return self._numpy.flip(block)

    operate = NotImplemented

    def process(self, data: bytearray):
        if self.bytestream:
            data.reverse()
            return data
        try:
            return self._fastblock(data)
        except FastBlockError:
            b = self.blocksize
            n = len(data)
            q = n // b
            m = q * b
            view = memoryview(data)
            temp = bytearray(b)
            for k in range(0, (q // 2) * b, b):
                lhs = slice(k, k + b)
                rhs = slice(m - k - b, m - k)
                temp[:] = view[rhs]
                data[rhs] = view[lhs]
                data[lhs] = temp
            if m < n:
                del view
                del temp
                del data[m:]
            return data
