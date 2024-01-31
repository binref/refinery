#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.units.blockwise import Arg, UnaryOperation, FastBlockError

if TYPE_CHECKING:
    from numpy import ndarray


class byteswap(UnaryOperation):
    """
    Reverses the order of bytes in each block. Excess bytes that are not an integer multiple of the block
    size are discarded.
    """
    def __init__(self, size: Arg.Number(help='the block size in bytes; the default is {default}.') = 4):
        super().__init__(blocksize=size, _truncate=2)

    def inplace(self, block: ndarray) -> None:
        block.byteswap(True)

    operate = NotImplemented

    def process(self, data):
        try:
            return self._fastblock(data)
        except FastBlockError:
            b = self.blocksize
            n = len(data)
            m = n - n % b
            v = memoryview(data)
            if b == 1:
                self.log_warn('running this unit with a block size of 1 does not have any effect')
                return data
            for k in range(0, m, b):
                _end = k and k - 1 or None
                data[k : k + b] = v[k + b - 1:_end:-1]
            if m < n:
                del v
                del data[m:]
            return data
