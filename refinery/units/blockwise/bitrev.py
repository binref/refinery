#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import UnaryOperation


class bitrev(UnaryOperation):
    """
    Reverse the bits of every block.
    """
    @staticmethod
    def operate(arg): pass

    def __init__(self, bigendian=False, blocksize=1):
        """
        Unreadable bit reversal operations due to:
        https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
        https://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
        """
        super().__init__(bigendian=bigendian, blocksize=blocksize)

        if self.bytestream:
            self.operate = lambda v: ((v * 0x202020202) & 0x10884422010) % 1023
        elif self.args.blocksize in (2, 4, 8):
            def operate(v):
                s = self.fbits
                m = self.fmask
                w = v
                while s > 1:
                    s >>= 1
                    m = m ^ (m << s)
                    w = ((w << s) & ~m) | ((w >> s) & m)
                return w
            self.operate = operate
        else:
            def operate(v):
                w = v & 0
                for s in range(self.fbits):
                    w |= ((v >> s) & 1) << (self.fbits - s - 1)
                return w
            self.operate = operate
