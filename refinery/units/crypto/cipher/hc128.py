#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure Python implementation of HC-128
"""
from itertools import cycle
from typing import Iterable

from . import StreamCipherUnit

__all__ = 'hc128',


def rx(x, k): return (x >> k) ^ (x << (0x20 - k)) & 0xFFFFFFFF
def lx(x, k): return (x << k) ^ (x >> (0x20 - k)) & 0xFFFFFFFF


class hc128cipher:

    def __init__(self, key):
        W = [0] * 0x500

        for i in range(0, 4):
            temp = key[4 * i]
            for k in range(1, 4):
                temp ^= key[4 * i + k] << (8 * k)
            W[i + 0] = temp
            W[i + 4] = temp
        for i in range(4, 8):
            temp = key[4 * i]
            for k in range(1, 4):
                temp ^= key[4 * i + k] << (8 * k)
            W[i + 4] = temp
            W[i + 8] = temp
        for i in range(16, 1280):
            f2 = rx(W[i - 2], 17) ^ rx(W[i - 2], 19) ^ (W[i - 2] >> 10)
            f1 = rx(W[i - 15], 7) ^ rx(W[i - 15], 18) ^ (W[i - 15] >> 3)
            W[i] = (f1 + f2 + W[i - 7] + W[i - 16] + i) & 0xFFFFFFFF

        self.P = P = [W[i + 0x100] for i in range(0x200)]
        self.Q = Q = [W[i + 0x300] for i in range(0x200)]

        for i in range(0, 0x200):
            g1 = (rx(P[i - 3], 10) ^ rx(P[i - 511], 23)) + rx(P[i - 10], 8) & 0xFFFFFFFF
            x0 = P[i - 12] & 0xFF
            x2 = P[i - 12] >> 16 & 0xFF
            h1 = Q[x0] + Q[256 + x2]
            P[i] = ((P[i] + g1) ^ h1) & 0xFFFFFFFF

        for i in range(0, 0x200):
            g2 = (lx(Q[i - 3], 10) ^ lx(Q[i - 511], 23)) + lx(Q[i - 10], 8) & 0xFFFFFFFF
            x0 = Q[i - 12] & 0xFF
            x2 = Q[i - 12] >> 16 & 0xFF
            h2 = P[x0] + P[256 + x2]
            Q[i] = ((Q[i] + g2) ^ h2) & 0xFFFFFFFF

    def __iter__(self):
        P = self.P
        Q = self.Q
        for i in cycle(range(1024)):
            if i < 512:
                g1 = (rx(P[i - 3], 10) ^ rx(P[i - 511], 23)) + rx(P[i - 10], 8) & 0xFFFFFFFF
                P[i] = P[i] + g1 & 0xFFFFFFFF
                x0 = P[i - 12] & 0xFF
                x2 = P[i - 12] >> 16 & 0xFF
                h1 = Q[x0] + Q[256 + x2] & 0xFFFFFFFF
                si = P[i] ^ h1
            else:
                i %= 512
                g2 = (lx(Q[i - 3], 10) ^ lx(Q[i - 511], 23)) + lx(Q[i - 10], 8) & 0xFFFFFFFF
                Q[i] = Q[i] + g2 & 0xFFFFFFFF
                x0 = Q[i - 12] & 0xFF
                x2 = Q[i - 12] >> 16 & 0xFF
                h2 = P[x0] + P[256 + x2] & 0xFFFFFFFF
                si = Q[i] ^ h2
            yield from si.to_bytes(4, 'little')


class hc128(StreamCipherUnit):
    """
    HC-128 encryption and decryption.
    """
    key_sizes = 32

    def keystream(self) -> Iterable[int]:
        return hc128cipher(self.args.key)
