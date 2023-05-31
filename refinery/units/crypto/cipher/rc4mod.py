#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from itertools import cycle

from refinery.units.crypto.cipher import Arg, StreamCipherUnit


class rc4mod(StreamCipherUnit):
    """
    Implements a modified version of the RC4 stream cipher where the size of the RC4 SBox can be altered.
    """

    def __init__(
        self, key, stateful=False, discard=0, *,
        size: Arg.Number('-t', help='Table size, {default} by default.', bound=(1, None)) = 0x100
    ):
        super().__init__(key=key, stateful=stateful, discard=discard, size=size)

    def keystream(self):
        size = self.args.size
        tablerange = range(max(size, 0x100))
        b, table = 0, bytearray(k & 0xFF for k in tablerange)
        for a, keybyte in zip(tablerange, cycle(self.args.key)):
            t = table[a]
            b = (b + keybyte + t) % size
            table[a] = table[b]
            table[b] = t
        self.log_debug(lambda: F'SBOX = {table.hex(" ").upper()}', clip=True)
        b, a = 0, 0
        while True:
            a = (a + 1) % size
            t = table[a]
            b = (b + t) % size
            table[a] = table[b]
            table[b] = t
            yield table[(table[a] + t) % size]
