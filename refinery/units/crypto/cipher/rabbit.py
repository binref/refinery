#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure Python implementation of the RABBIT stream cipher.
"""
import struct
from typing import Iterable, Optional, ByteString, List

from . import arg, StreamCipherUnit


class RabbitCipher:

    _COUNTER = 0x4D34D34D, 0xD34D34D3, 0x34D34D34

    def __init__(self, key: ByteString, iv: Optional[ByteString] = B''):
        key = struct.unpack('<8H', key)
        self.c: List[int] = []
        self.x: List[int] = []
        for j in range(8):
            v1, v2, w1, w2 = (
                key[j + 0 & 7],
                key[j + 1 & 7],
                key[j + 4 & 7],
                key[j + 5 & 7]
            )
            if j % 2 == 0:
                self.c.append((w1 << 16) | w2)
                self.x.append((v2 << 16) | v1)
            else:
                self.c.append((v1 << 16) | v2)
                self.x.append((w2 << 16) | w1)
        self.b = 0
        self.hop4()
        self.c = [c ^ v for c, v in zip(self.c, self.x[4:] + self.x[:4])]
        if not iv:
            return
        i0, i2 = struct.unpack('<LL', iv)
        i1 = ((i0 >> 16) | (i2 & 0xFFFF0000))
        i3 = ((i2 << 16) | (i0 & 0x0000FFFF)) & 0xFFFFFFFF
        self.c = [c ^ v for c, v in zip(self.c, 2 * (i0, i1, i2, i3))]
        self.hop4()

    def hop4(self):
        self.hop(False)
        self.hop(False)
        self.hop(False)
        self.hop(False)

    def hop(self, derive=True):
        for k in range(8):
            self.b += self.c[k] + self._COUNTER[k % 3]
            self.b, self.c[k] = divmod(self.b, 0x100000000)
        g = [self._compute_g(*t) for t in zip(self.x, self.c)]
        self.x = g[:]
        for j in range(8):
            if j % 2:
                self.x[j + 1 & 7] += self.r16(g[j])
                self.x[j + 2 & 7] += g[j]
            else:
                self.x[j + 1 & 7] += self.r08(g[j])
                self.x[j + 2 & 7] += self.r16(g[j])
        self.x = [t & 0xFFFFFFFF for t in self.x]
        if derive:
            return self.key

    @staticmethod
    def _compute_g(a, b):
        t = (a + b & 0xFFFFFFFF) ** 2
        return (t ^ (t >> 32)) & 0xFFFFFFFF

    @staticmethod
    def r08(y): return ((y & 0x00FFFFFF) << 0x08) | (y >> 0x18)

    @staticmethod
    def r16(y): return ((y & 0x0000FFFF) << 0x10) | (y >> 0x10)

    @property
    def key(self) -> bytes:
        s = ((self.x[a] & 0xFFFF) ^ (self.x[b] >> 0x10)
            for a, b in ((0, 5), (3, 0), (2, 7), (5, 2), (4, 1), (7, 4), (6, 3), (1, 6)))
        return struct.pack('<8H', *s)

    def __iter__(self):
        while True: yield from self.hop()


class rabbit(StreamCipherUnit):
    """
    RABBIT encryption and decryption.
    """
    key_sizes = 16

    def __init__(self, key, stateful=False, iv: arg('-I', '--iv', help='Optional initialization vector.') = B''):
        super().__init__(key=key, iv=iv, stateful=stateful)

    def keystream(self) -> Iterable[int]:
        if len(self.args.iv) not in (0, 8):
            raise ValueError('The IV length must be exactly 8 bytes.')
        return RabbitCipher(self.args.key, self.args.iv)
