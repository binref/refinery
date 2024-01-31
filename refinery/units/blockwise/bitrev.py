#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.blockwise import UnaryOperation


class bitrev(UnaryOperation):
    """
    Reverse the bits of every block. Any excess bytes at the end of the input that are not
    an integer multiple of the block size are ignored.
    """
    @staticmethod
    def operate(arg):
        raise RuntimeError('operate was called before the unit was initialized')

    def __init__(self, bigendian=False, blocksize=None):
        """
        Unreadable bit reversal operations due to:
        https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
        https://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
        """
        super().__init__(bigendian=bigendian, blocksize=blocksize, _truncate=1)

        if self.bytestream:
            def operate(v):
                return ((v * 0x202020202) & 0x10884422010) % 1023
        elif self.blocksize in (2, 4, 8):
            def operate(v):
                s = self.fbits
                m = self.fmask
                w = v
                while s > 1:
                    s >>= 1
                    m = m ^ (m << s)
                    w = ((w << s) & ~m) | ((w >> s) & m)
                return w
        else:
            def operate(v):
                w = v & 0
                for s in range(self.fbits):
                    w |= ((v >> s) & 1) << (self.fbits - s - 1)
                return w
        self.operate = operate
